#!/usr/bin/env python3
"""usb_fuzz.py -- resilient, read-only USB control-transfer discovery fuzzer.

A companion to usb_test.py. Where usb_test.py brute-forces control transfers and
saves the ones that return data, usb_fuzz.py adds three things needed to fuzz
real, fragile devices unattended:

  1. **Read-only / non-destructive.** It only issues IN (Device->Host) control
     requests -- it never writes to the target. Safe to point at hardware you
     care about. (OUT/write fuzzing is intentionally NOT implemented.)

  2. **Buffer over-read / memory-leak probing.** It re-requests descriptors and
     status with oversized wLength and flags any response larger than the
     object's real size -- the classic USB descriptor over-read that leaks
     device memory from a buggy stack. (Oversized wLength needs a libusb whose
     MAX_CTRL_BUFFER_LENGTH is raised -- see this repo's Makefile.)

  3. **Self-recovery.** Fragile stacks either re-enumerate (the handle goes
     stale) or hard-wedge (EP0 stops responding) under fuzzing. usb_fuzz.py
     re-acquires the handle on re-enumeration, and -- if a Cynthion running the
     'analyzer' bitstream is attached inline -- power-cycles the target's VBUS to
     clear a hard wedge, then resumes. It records the culprit requests.

Results (each DISTINCT response, plus leak/wedge events) are written as JSON
lines. Duplicate and SETUP-echo responses are filtered.

Requires root for raw USB unless udev rules grant access.

Examples:
  usb_fuzz.py --vid 0x483 --pid 0xa2ca
  usb_fuzz.py --vid 0x04e8 --pid 0x6860 --phases leak,descr,strings,types
  usb_fuzz.py --vid 0xa466 --pid 0x0a53 --phases all --no-recover
"""
import argparse
import hashlib
import json
import struct
import sys
import time
from collections import Counter

import usb.core

# USB PID bytes (for optional decoding of captured tokens/data)
PIDS = {0xa5:"SOF",0x2d:"SETUP",0x69:"IN",0xe1:"OUT",0xc3:"DATA0",0x4b:"DATA1",
        0xd2:"ACK",0x5a:"NAK",0x1e:"STALL"}

# IN request-type recipients: standard/class/vendor x device/interface/endpoint/other
IN_TYPES = {0x80:"std-dev",0x81:"std-if",0x82:"std-ep",0x83:"std-other",
            0xa0:"class-dev",0xa1:"class-if",0xa2:"class-ep",0xa3:"class-other",
            0xc0:"vendor-dev",0xc1:"vendor-if",0xc2:"vendor-ep",0xc3:"vendor-other"}

ALL_PHASES = ["leak","descr","strings","types","wvalue","windex"]


class Fuzzer:
    def __init__(self, args):
        self.a = args
        self.dev = None
        self.res = open(args.out, "a")
        self.seen = set()
        self.stats = Counter()
        self.t0 = time.time()
        # recovery state
        self.eio_run = 0
        self.eio_first = None
        self.consec_fail = 0
        self.recoveries = 0
        self.reacquires = 0
        self.blacklist_exact = set()
        self.blacklist_breq = set()
        self.crash_breq = Counter()

    # -- logging --
    def log(self, m):
        if not self.a.quiet:
            print("%s %s" % (time.strftime("%H:%M:%S"), m), flush=True)

    def record(self, rec):
        self.res.write(json.dumps(rec) + "\n"); self.res.flush()

    def progress(self, tag):
        dt = time.time() - self.t0
        rate = self.stats["tried"] / dt if dt else 0
        s = self.stats
        self.log("[%s] tried=%d hit=%d dup=%d echo=%d stall=%d eio=%d err=%d "
                 "reacq=%d reenum=%d recover=%d leak=%d rate=%.0f/s t=%.0fs" %
                 (tag,s["tried"],s["hit"],s["dup"],s["echo"],s["stall"],s["eio"],
                  s["err"],s["reacquire"],s["reenum"],s["recover"],s["leak"],rate,dt))

    # -- device access / recovery --
    def get_dev(self, secs=60):
        end = time.time() + secs
        while time.time() < end:
            d = usb.core.find(idVendor=self.a.vid, idProduct=self.a.pid)
            if d is not None:
                try: d.set_configuration()
                except Exception: pass
                return d
            time.sleep(1)
        return None

    def power_cycle(self):
        """Reset the target's VBUS via an inline Cynthion analyzer (if present)."""
        if self.a.no_recover:
            time.sleep(2); return
        try:
            an = usb.core.find(idVendor=self.a.analyzer_vid, idProduct=self.a.analyzer_pid)
            if an is None:
                self.log("  (no Cynthion analyzer for power-cycle; waiting)"); time.sleep(3); return
            an.set_configuration()
            # POWER_CONTROL_ENABLE | VBUS_TARGET_A_DISCHARGE, then restore passthrough
            an.ctrl_transfer(0x41, 1, 0x80 | 0x40, 0, None); time.sleep(2.0)
            an.ctrl_transfer(0x41, 1, 0x00, 0, None); time.sleep(3.5)
        except Exception as e:
            self.log("  power-cycle error: %s" % str(e)[:60]); time.sleep(3)

    def reacquire(self):
        self.reacquires += 1; self.stats["reacquire"] = self.reacquires
        if self.reacquires > self.a.max_reacquire:
            self.log("max-reacquire reached; aborting"); self.record({"fatal":"max reacquire"})
            raise SystemExit(3)
        d = self.get_dev(secs=self.a.reacquire_wait)
        if d is None:
            return False
        try:
            d.ctrl_transfer(0x80, 0x06, 0x0100, 0x0000, 18, timeout=800)
            self.dev = d; return True
        except Exception:
            return False

    def recover(self, culprit):
        self.recoveries += 1; self.stats["recover"] = self.recoveries
        bt, br, wv, wi = culprit
        self.log("WEDGE #%d culprit bt=0x%02x br=0x%02x wv=0x%04x wi=0x%04x -- power-cycling"
                 % (self.recoveries, bt, br, wv, wi))
        self.stats["wedge"] += 1
        self.crash_breq[(bt, br)] += 1
        self.blacklist_exact.add(culprit)
        if self.crash_breq[(bt, br)] >= self.a.blacklist_after:
            self.blacklist_breq.add((bt, br))
            self.log("  blacklisting bt=0x%02x br=0x%02x (crashed %d)" % (bt, br, self.crash_breq[(bt, br)]))
        self.record({"wedge": True, "bmRequestType": bt, "bRequest": br,
                     "wValue": wv, "wIndex": wi, "recovery": self.recoveries})
        self.power_cycle()
        self.dev = self.get_dev()
        self.eio_run = 0; self.consec_fail = 0
        if self.dev is None:
            self.log("device gone after recover; abort"); self.record({"fatal":"no device"})
            raise SystemExit(1)
        if self.recoveries >= self.a.max_recover:
            self.log("max-recover reached; device too fragile -- stopping")
            self.record({"fatal":"max recover"}); raise SystemExit(2)

    # -- core probe --
    def _fail(self, kind, culprit):
        self.stats[kind] += 1
        if self.eio_run == 0: self.eio_first = culprit
        self.eio_run += 1; self.consec_fail += 1
        if kind == "eio" and self.eio_run >= self.a.eio_threshold:
            if not self.reacquire(): self.recover(self.eio_first)
            self.eio_run = 0; self.consec_fail = 0; return
        if self.consec_fail >= self.a.lost_threshold:
            if not self.reacquire(): self.recover(self.eio_first)
            else: self.stats["reenum"] += 1
            self.eio_run = 0; self.consec_fail = 0

    @staticmethod
    def _is_echo(bt, br, wv, wi, wl, data):
        exp = struct.pack("<BBHHH", bt, br, wv, wi, wl)
        return len(data) >= 8 and data[:8] == exp and not any(data[8:])

    def probe(self, bt, name, br, wv, wi):
        if (bt, br) in self.blacklist_breq or (bt, br, wv, wi) in self.blacklist_exact:
            return
        self.stats["tried"] += 1
        try:
            data = bytes(self.dev.ctrl_transfer(bt, br, wv, wi, self.a.wlength, timeout=self.a.timeout))
        except usb.core.USBError as e:
            s = str(e).lower(); errno = getattr(e, "errno", None)
            if errno == 32 or "pipe" in s or "stall" in s:
                self.stats["stall"] += 1; self.eio_run = 0; self.consec_fail = 0
            elif errno == 5 or "input/output" in s:
                self._fail("eio", (bt, br, wv, wi))
            elif "tim" in s:
                self._fail("timeout", (bt, br, wv, wi))
            else:
                self._fail("err", (bt, br, wv, wi))
            return
        except Exception:
            self._fail("err", (bt, br, wv, wi)); return
        self.eio_run = 0; self.consec_fail = 0
        if not data: return
        if self._is_echo(bt, br, wv, wi, self.a.wlength, data):
            self.stats["echo"] += 1; return
        h = hashlib.md5(data).digest()
        if h in self.seen: self.stats["dup"] += 1; return
        self.seen.add(h); self.stats["hit"] += 1
        self.record({"bmRequestType": bt, "type": name, "bRequest": br,
                     "wValue": wv, "wIndex": wi, "len": len(data), "data": data.hex()})
        self.log("HIT bt=0x%02x(%s) br=0x%02x wv=0x%04x wi=0x%04x len=%d %s" %
                 (bt, name, br, wv, wi, len(data), data[:24].hex()))

    def leak_test(self, bt, name, br, wv, wi, expected, label):
        for wl in (expected if expected else 1, 0x0100, 0x1000, 0x4000, 0xffff):
            try:
                data = bytes(self.dev.ctrl_transfer(bt, br, wv, wi, wl, timeout=1500))
            except Exception as e:
                self.log("  LEAK %s wl=0x%04x -> err %s" % (label, wl, str(e)[:45])); continue
            nz = sum(1 for b in data[expected:] if b != 0) if len(data) > expected else 0
            over = len(data) > expected
            self.log("  LEAK %s wl=0x%04x -> %d (expected %d)%s" %
                     (label, wl, len(data), expected,
                      "  <== OVER-READ +%d (nonzero=%d)" % (len(data)-expected, nz) if over else ""))
            if over:
                self.stats["leak"] += 1
                self.record({"leak": True, "label": label, "bmRequestType": bt, "bRequest": br,
                             "wValue": wv, "wIndex": wi, "wLength": wl, "expected": expected,
                             "returned": len(data), "nonzero_beyond_expected": nz, "data": data.hex()})

    # -- phases --
    def phase_leak(self):
        self.log("PHASE leak: over-read / memory-leak probe (oversized wLength)")
        self.leak_test(0x80, "std-dev", 0x06, 0x0100, 0x0000, 18, "device-desc")
        try:
            hdr = bytes(self.dev.ctrl_transfer(0x80, 0x06, 0x0200, 0x0000, 9, timeout=1000))
            total = (hdr[2] | (hdr[3] << 8)) if len(hdr) >= 4 else 9
        except Exception:
            total = 9
        self.leak_test(0x80, "std-dev", 0x06, 0x0200, 0x0000, total, "config-desc")
        self.leak_test(0x80, "std-dev", 0x00, 0x0000, 0x0000, 2, "get-status")
        self.leak_test(0x80, "std-dev", 0x08, 0x0000, 0x0000, 1, "get-configuration")
        self.leak_test(0x80, "std-dev", 0x01, 0x0000, 0x0000, 8, "clearfeature-as-in")

    def phase_descr(self):
        self.log("PHASE descr: GET_DESCRIPTOR wValue 0x0000-0xffff")
        for wv in range(0x10000):
            self.probe(0x80, "std-dev", 0x06, wv, 0x0000)
            if wv % 8192 == 0: self.progress("descr 0x%04x" % wv)

    def phase_strings(self):
        self.log("PHASE strings: string descriptors x langid")
        for wv in range(0x0300, 0x0400):
            for wi in (0x0000, 0x0409, 0x0407, 0x0410, 0x0809):
                self.probe(0x80, "std-dev", 0x06, wv, wi)

    def phase_types(self):
        self.log("PHASE types: all IN request-types x bRequest 0-255")
        for bt, name in IN_TYPES.items():
            for br in range(256):
                self.probe(bt, name, br, 0x0000, 0x0000)

    def phase_wvalue(self):
        self.log("PHASE wvalue: all IN types x bRequest x wValue 0-255")
        for bt, name in IN_TYPES.items():
            for br in range(256):
                for wv in range(256):
                    self.probe(bt, name, br, wv, 0x0000)
            self.progress("wvalue %s" % name)

    def phase_windex(self):
        self.log("PHASE windex: all IN types x bRequest x wIndex 0-255")
        for bt, name in IN_TYPES.items():
            for br in range(256):
                for wi in range(256):
                    self.probe(bt, name, br, 0x0000, wi)
            self.progress("windex %s" % name)

    def run(self, phases):
        self.dev = self.get_dev()
        if self.dev is None:
            sys.exit("[-] target %04x:%04x not found" % (self.a.vid, self.a.pid))
        self.log("target found; phases: %s" % ",".join(phases))
        table = {"leak": self.phase_leak, "descr": self.phase_descr,
                 "strings": self.phase_strings, "types": self.phase_types,
                 "wvalue": self.phase_wvalue, "windex": self.phase_windex}
        try:
            for p in phases:
                table[p]()
                self.progress("%s done" % p)
            self.log("ALL PHASES COMPLETE"); self.progress("FINAL")
        except SystemExit:
            self.progress("STOPPED"); raise
        finally:
            if self.blacklist_breq:
                self.log("blacklisted: %s" % sorted("0x%02x/0x%02x" % b for b in self.blacklist_breq))
            self.res.close()


def hexint(x): return int(x, 0)


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--vid", type=hexint, required=True, help="target idVendor (e.g. 0x483)")
    p.add_argument("--pid", type=hexint, required=True, help="target idProduct (e.g. 0xa2ca)")
    p.add_argument("--out", help="results JSONL (default: usb_fuzz_<vid>_<pid>.jsonl)")
    p.add_argument("--phases", default="leak,descr,strings,types",
                   help="comma list of %s, or 'all' (default: leak,descr,strings,types)" % ALL_PHASES)
    p.add_argument("--wlength", type=hexint, default=255, help="wLength for discovery requests (default 255)")
    p.add_argument("--timeout", type=int, default=200, help="per-request timeout ms (default 200)")
    p.add_argument("--no-recover", action="store_true",
                   help="disable Cynthion VBUS power-cycle recovery (only re-acquire on re-enum)")
    p.add_argument("--analyzer-vid", type=hexint, default=0x1d50)
    p.add_argument("--analyzer-pid", type=hexint, default=0x615b)
    p.add_argument("--eio-threshold", type=int, default=5, dest="eio_threshold")
    p.add_argument("--lost-threshold", type=int, default=15, dest="lost_threshold")
    p.add_argument("--max-recover", type=int, default=300, dest="max_recover")
    p.add_argument("--max-reacquire", type=int, default=5000, dest="max_reacquire")
    p.add_argument("--reacquire-wait", type=int, default=6, dest="reacquire_wait",
                   help="seconds to wait for a re-enumerating device (default 6)")
    p.add_argument("--blacklist-after", type=int, default=3, dest="blacklist_after")
    p.add_argument("-q", "--quiet", action="store_true")
    args = p.parse_args()

    if args.out is None:
        args.out = "usb_fuzz_%04x_%04x.jsonl" % (args.vid, args.pid)
    phases = ALL_PHASES if args.phases == "all" else [x.strip() for x in args.phases.split(",")]
    bad = [x for x in phases if x not in ALL_PHASES]
    if bad:
        sys.exit("unknown phase(s): %s (valid: %s)" % (bad, ALL_PHASES))

    Fuzzer(args).run(phases)


if __name__ == "__main__":
    main()
