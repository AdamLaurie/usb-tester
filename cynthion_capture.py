#!/usr/bin/env python3
"""Headless USB capture + decode using a Cynthion running the 'analyzer' bitstream.

Companion to usb_test.py: while usb_test.py brute-forces control transfers at a
target (PC = USB host), a Cynthion wired inline can sniff the resulting bus
traffic and dump/decode it here, replacing PhyWhisperer's capture role. No
Packetry GUI required.

Physical setup (Cynthion analyzer):
    CONTROL   -> this PC (control + capture stream; the device we talk to here)
    TARGET-C  -> the host of the link being sniffed (e.g. the PC running usb_test.py)
    TARGET-A  -> the device under test
Cynthion taps TARGET-C <-> TARGET-A and streams to CONTROL. NOTE: AUX is NOT on
the tap -- the host must be on TARGET-C. Default power routing passes VBUS from
TARGET-C to TARGET-A, so the target is powered by that host.

Requires root (raw USB) unless Cynthion udev rules are installed.

Protocol/format source: ../cynthion/cynthion/python/src/gateware/analyzer/
    top.py (vendor requests, state bits), analyzer.py (record framing),
    events.py (event codes), speeds.py + luna USBSpeed (speed field values).

Examples:
    cynthion_capture.py --probe                 # query version/state/speeds
    cynthion_capture.py -t 5                     # 5s capture at auto speed, decode summary
    cynthion_capture.py -s hs -t 5 -v           # high speed, verbose per-packet
    cynthion_capture.py --power-cycle -t 8       # trigger + capture a fresh enumeration
    cynthion_capture.py --decode capture.bin     # decode an existing raw capture
"""
import argparse
import collections
import sys
import time

import usb.core
import usb.util

VENDOR_ID = 0x1d50
PRODUCT_ID = 0x615b

BULK_ENDPOINT_ADDRESS = 0x81
MAX_BULK_PACKET_SIZE = 512

# bmRequestType: vendor request, interface recipient.
VENDOR_IN = 0xC1   # device-to-host | vendor | interface
VENDOR_OUT = 0x41  # host-to-device | vendor | interface

# USBAnalyzerVendorRequests
GET_STATE = 0
SET_STATE = 1
GET_SPEEDS = 2
GET_MINOR_VERSION = 4

# USBAnalyzerState bits
STATE_ENABLE = 1 << 0          # bit0: start/stop capture
STATE_SPEED_SHIFT = 1          # bits1-2: capture speed (see SPEEDS)
VBUS_FROM_TARGET_C = 1 << 3    # pass TARGET-C VBUS to TARGET-A
VBUS_FROM_CONTROL_HOST = 1 << 4  # power TARGET-A from CONTROL/HOST (this PC)
VBUS_FROM_AUX = 1 << 5
VBUS_TARGET_A_DISCHARGE = 1 << 6  # actively drain TARGET-A VBUS
POWER_CONTROL_ENABLE = 1 << 7  # 1: VBUS to TARGET-A controlled by bits 3-6

# Speed field values (bits1-2), from luna USBSpeed + cynthion USBAnalyzerSpeed:
# HIGH=0b00, FULL=0b01, LOW=0b10, AUTO=0b11. (The gateware's inline comment
# claiming LS=0b11 is wrong -- 0b11 is AUTO.) Values here are pre-shifted.
SPEEDS = {
    "hs": 0b00 << STATE_SPEED_SHIFT,
    "fs": 0b01 << STATE_SPEED_SHIFT,
    "ls": 0b10 << STATE_SPEED_SHIFT,
    "auto": 0b11 << STATE_SPEED_SHIFT,
}

# GET_SPEEDS response bits -> the SPEEDS key each one authorizes.
SUPPORTED_SPEED_FLAGS = {
    0b0001: "auto",
    0b0010: "ls",
    0b0100: "fs",
    0b1000: "hs",
}

# USBAnalyzerEvent codes.
EVENTS = {
    0: "NONE", 1: "CAPTURE_STOP_NORMAL", 2: "CAPTURE_STOP_FULL",
    3: "CAPTURE_STOP_ERROR", 4: "CAPTURE_START_HIGH", 5: "CAPTURE_START_FULL",
    6: "CAPTURE_START_LOW", 7: "CAPTURE_START_AUTO", 8: "SPEED_DETECT_HIGH",
    9: "SPEED_DETECT_FULL", 10: "SPEED_DETECT_LOW", 11: "SPEED_DETECT_AUTO",
    12: "LINESTATE_SE0", 13: "LINESTATE_CHIRP_J", 14: "LINESTATE_CHIRP_K",
    15: "LINESTATE_CHIRP_SE1", 16: "LINESTATE_LS_J", 17: "LINESTATE_LS_K",
    18: "LINESTATE_FS_J", 19: "LINESTATE_FS_K", 20: "LINESTATE_SE1",
    21: "VBUS_INVALID", 22: "VBUS_VALID", 23: "LS_ATTACH", 24: "FS_ATTACH",
    25: "BUS_RESET", 26: "DEVICE_CHIRP_VALID", 27: "HOST_CHIRP_VALID",
    28: "SUSPEND", 29: "RESUME", 30: "LS_KEEPALIVE",
}

# USB PID byte (low nibble = PID, high nibble = complement) -> name.
PIDS = {
    0xa5: "SOF", 0x2d: "SETUP", 0x69: "IN", 0xe1: "OUT",
    0xc3: "DATA0", 0x4b: "DATA1", 0x87: "DATA2", 0x0f: "MDATA",
    0xd2: "ACK", 0x5a: "NAK", 0x1e: "STALL", 0x96: "NYET",
    0x3c: "PRE/ERR", 0x78: "SPLIT", 0xb4: "PING",
}

MAX_PACKET_SIZE_BYTES = 1024 + 1 + 2  # payload cap: 1024 data + PID + CRC16


# --------------------------------------------------------------------------- #
# Device access                                                                #
# --------------------------------------------------------------------------- #

def find_analyzer():
    dev = usb.core.find(idVendor=VENDOR_ID, idProduct=PRODUCT_ID)
    if dev is None:
        sys.exit("[-] Cynthion analyzer (1d50:615b) not found. Is the analyzer "
                 "bitstream loaded ('cynthion run analyzer') and CONTROL connected?")
    try:
        dev.set_configuration()
    except usb.core.USBError as e:
        sys.exit("[-] Could not configure device ({}). Try sudo, or install "
                 "Cynthion udev rules ('cynthion setup').".format(e))
    return dev


def supported_speeds(dev):
    flags = dev.ctrl_transfer(VENDOR_IN, GET_SPEEDS, 0, 0, 1)[0]
    return flags, [name for bit, name in SUPPORTED_SPEED_FLAGS.items() if flags & bit]


def probe(dev):
    minor = dev.ctrl_transfer(VENDOR_IN, GET_MINOR_VERSION, 0, 0, 1)[0]
    state = dev.ctrl_transfer(VENDOR_IN, GET_STATE, 0, 0, 1)[0]
    flags, names = supported_speeds(dev)
    print("[+] Cynthion analyzer reachable")
    print("    protocol minor version : {}".format(minor))
    print("    current state register : 0x{:02x} (capture {})".format(
        state, "ENABLED" if state & STATE_ENABLE else "stopped"))
    print("    supported speeds       : {} (0x{:02x})".format(
        ", ".join(names) or "none", flags))


def set_state(dev, value):
    # The analyzer's register-write handler (LUNA handle_register_write_request)
    # takes the new value from wValue and expects NO data stage (wLength=0).
    dev.ctrl_transfer(VENDOR_OUT, SET_STATE, value, 0, None)


# --------------------------------------------------------------------------- #
# Capture                                                                      #
# --------------------------------------------------------------------------- #

def _read_stream(dev, seconds, out_path):
    total = 0
    deadline = time.time() + seconds if seconds else None
    try:
        with open(out_path, "wb") as f:
            while deadline is None or time.time() < deadline:
                try:
                    data = dev.read(BULK_ENDPOINT_ADDRESS,
                                    MAX_BULK_PACKET_SIZE * 32, timeout=1000)
                except usb.core.USBError as e:
                    if e.errno == 110:  # timeout, no traffic this window
                        continue
                    raise
                if data:
                    f.write(data)
                    total += len(data)
                    print("\r    captured {} bytes".format(total), end="", flush=True)
    except KeyboardInterrupt:
        print("\n[+] interrupted")
    finally:
        set_state(dev, 0)  # stop capture, release power control
        print("\n[+] capture stopped, {} bytes written to {}".format(total, out_path))
    return total


def capture(dev, speed, seconds, out_path, power_cycle=False, off_secs=1.0):
    flags, names = supported_speeds(dev)
    if speed not in names:
        sys.exit("[-] speed '{}' not supported by this board (supports: {}). "
                 "Use one of those.".format(speed, ", ".join(names)))

    ep = dev[0][(0, 0)][0]  # first endpoint of interface 0 (bulk IN 0x81)
    assert ep.bEndpointAddress == BULK_ENDPOINT_ADDRESS
    sp = SPEEDS[speed]

    if power_cycle:
        # Take VBUS control, capture enabled throughout: drop power to TARGET-A
        # (with discharge) so the device fully resets, then restore it so the
        # TARGET-C host sees a fresh attach + enumeration -- all captured.
        off_state = STATE_ENABLE | sp | POWER_CONTROL_ENABLE | VBUS_TARGET_A_DISCHARGE
        on_state = STATE_ENABLE | sp | POWER_CONTROL_ENABLE | VBUS_FROM_CONTROL_HOST
        print("[+] power-cycle capture: speed={} off=0x{:02x} on=0x{:02x} -> {}".format(
            speed, off_state, on_state, out_path))
        set_state(dev, off_state)
        print("    VBUS to TARGET-A off (discharging) for {:.1f}s ...".format(off_secs))
        time.sleep(off_secs)
        set_state(dev, on_state)
        print("    VBUS to TARGET-A on -- capturing enumeration")
    else:
        state = STATE_ENABLE | sp
        print("[+] starting capture: speed={} state=0x{:02x} -> {}".format(
            speed, state, out_path))
        set_state(dev, state)

    return _read_stream(dev, seconds, out_path)


# --------------------------------------------------------------------------- #
# Decode                                                                       #
# --------------------------------------------------------------------------- #

def decode_stream(data):
    """Yield decoded records from a raw analyzer capture.

    Record framing (analyzer.py): a packet record is a 4-byte header
    (16-bit big-endian length + 16-bit timestamp) followed by `length`
    payload bytes padded up to a 16-bit word boundary. An event record is
    a 0xFF marker byte + 8-bit event code + 16-bit timestamp (4 bytes).
    The length's high byte is <= 0x04 for real packets, so 0xFF is an
    unambiguous event marker.
    """
    i, n = 0, len(data)
    while i + 4 <= n:
        b0 = data[i]
        if b0 == 0xFF:
            code = data[i + 1]
            ts = (data[i + 2] << 8) | data[i + 3]
            yield {"kind": "event", "code": code,
                   "name": EVENTS.get(code, "EVENT_%d" % code), "ts": ts}
            i += 4
        elif b0 <= (MAX_PACKET_SIZE_BYTES >> 8):
            length = (b0 << 8) | data[i + 1]
            ts = (data[i + 2] << 8) | data[i + 3]
            i += 4
            if i + length > n:
                break
            payload = bytes(data[i:i + length])
            i += length + (length & 1)  # word alignment
            pid = payload[0] if payload else None
            yield {"kind": "packet", "ts": ts, "length": length,
                   "pid": pid, "pid_name": PIDS.get(pid, "0x%02x" % pid) if pid is not None else "?",
                   "payload": payload}
        else:
            # Should not happen on an aligned stream; skip a byte to resync.
            yield {"kind": "desync", "byte": b0}
            i += 1


def decode_setup(payload):
    """Decode the 8 data bytes of a control SETUP DATA0 packet."""
    d = payload[1:9]  # skip PID
    if len(d) < 8:
        return None
    bmRequestType, bRequest = d[0], d[1]
    wValue = d[2] | (d[3] << 8)
    wIndex = d[4] | (d[5] << 8)
    wLength = d[6] | (d[7] << 8)
    return ("bmRequestType=0x{:02x} bRequest=0x{:02x} wValue=0x{:04x} "
            "wIndex=0x{:04x} wLength=0x{:04x}".format(
                bmRequestType, bRequest, wValue, wIndex, wLength))


def summarize(data, verbose=False):
    events = collections.Counter()
    pids = collections.Counter()
    packets = desync = 0
    setups = []
    pending_setup = False

    for rec in decode_stream(data):
        if rec["kind"] == "event":
            events[rec["name"]] += 1
            if verbose and rec["name"] != "NONE":
                print("  [{:5d}] EVENT {}".format(rec["ts"], rec["name"]))
        elif rec["kind"] == "packet":
            packets += 1
            pids[rec["pid_name"]] += 1
            if rec["pid"] == 0x2d:  # SETUP token
                pending_setup = True
            elif pending_setup and rec["pid"] in (0xc3, 0x4b) and rec["length"] >= 9:
                info = decode_setup(rec["payload"])
                if info:
                    setups.append(info)
                    if verbose:
                        print("  [{:5d}] SETUP {}".format(rec["ts"], info))
                pending_setup = False
            else:
                if rec["pid"] not in (0xa5,):  # don't spam SOFs
                    pending_setup = False
                if verbose and rec["pid"] != 0xa5:
                    print("  [{:5d}] {:6s} len={} {}".format(
                        rec["ts"], rec["pid_name"], rec["length"],
                        rec["payload"][:16].hex()))
        else:
            desync += 1

    print("[+] decode summary")
    print("    packets : {}".format(packets))
    print("    PIDs    : {}".format(dict(pids.most_common())))
    print("    events  : {}".format(dict(events.most_common())))
    if desync:
        print("    desync  : {} byte(s)".format(desync))
    if setups:
        print("    control SETUPs ({}):".format(len(setups)))
        for s in setups[:20]:
            print("      {}".format(s))
        if len(setups) > 20:
            print("      ... and {} more".format(len(setups) - 20))


# --------------------------------------------------------------------------- #

def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--probe", action="store_true",
                   help="query version/state/speeds and exit (no capture)")
    p.add_argument("--decode", metavar="FILE",
                   help="decode an existing raw capture file and exit (no hardware)")
    p.add_argument("-s", "--speed", choices=list(SPEEDS), default="auto",
                   help="capture speed (default: auto; needs a board that supports it)")
    p.add_argument("-t", "--seconds", type=float, default=0,
                   help="capture duration in seconds (0 = until Ctrl-C)")
    p.add_argument("-o", "--output", default="capture.bin",
                   help="raw capture stream output file (default: capture.bin)")
    p.add_argument("--power-cycle", action="store_true",
                   help="drop and restore VBUS to TARGET-A while capturing, to "
                        "trigger a fresh device enumeration (no physical replug)")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="print a per-record decode (events + non-SOF packets)")
    p.add_argument("--no-summary", action="store_true",
                   help="skip decoding the capture afterward (raw dump only)")
    args = p.parse_args()

    if args.decode:
        summarize(open(args.decode, "rb").read(), verbose=args.verbose)
        return

    dev = find_analyzer()
    probe(dev)
    if args.probe:
        return
    total = capture(dev, args.speed, args.seconds, args.output,
                    power_cycle=args.power_cycle)
    if total and not args.no_summary:
        summarize(open(args.output, "rb").read(), verbose=args.verbose)


if __name__ == "__main__":
    main()
