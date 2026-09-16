# usb-tester
Script for black box testing to discover USB messages on the BUS supported by target device

#### It works and it was tested on raspberry pi 4 and Linux. As long you can build the patched libusb on your distro it should be fine. Please note that for ARM/Raspberry Pi you need to cross-compile (install the ARM build utils / gcc).

#### Main goal of the script is to find USB messages supported by target device, either for fuzzing or for fault injection attacks. Using additionally devices like USB hardware triggers (Beagle 480, PhyWhisperer) together with X-Force RED Raiden And/or EMFI you can very deeply test USB stacks on target devices.

## Setup

libusb is vendored as a git submodule (pinned to v1.0.30) and must be patched to raise
`MAX_CTRL_BUFFER_LENGTH` so the large-`wLength` control transfers this tool sends aren't
truncated. A `Makefile` automates the whole thing. Build prerequisites:
`build-essential autoconf automake libtool pkg-config python3-pip`.

```
git clone --recurse-submodules <repo>        # or: git submodule update --init after cloning
make install                                  # native x86_64: patch + build/install libusb + pyusb
```

Raspberry Pi / ARM cross build:

```
make install HOST=arm-linux-gnueabihf CC=arm-linux-gnueabihf-gcc PREFIX=/usr/local/libusb-rpi
```

Run `make help` for the individual targets (`submodule`, `patch`, `libusb`, `install-libusb`, `python-deps`).  

### Examples


### 1. Default bruteforce wValue, wIndex, bmRequest, bRequest  
```
pi@raspberrypi:~/tools/usb-tester $ lsusb
Bus 001 Device 030: ID 0483:a2ca STMicroelectronics 

python3 usb_test.py -v 0x483 -p 0xa2ca
```
### 2. Bruteforce only wIndex
```
python3 usb_test.py -v 0x483 -p 0xa2ca -b Device-to-Host-Standard-Interface -bR GET_DESCRIPTOR -wV 0x2100
```
### 3. Bruteforce only wValue
```
python3 usb_test.py -v 0x483 -p 0xa2ca -b Device-to-Host-Standard-Interface -bR GET_DESCRIPTOR -wI 0x0
```
### 4. Bruteforce wValue and wIndex
```
python3 usb_test.py -v 0x483 -p 0xa2ca -b Device-to-Host-Standard-Interface
```
### 5. Bruteforce wValue and wIndex and bmRequest
```
python3 usb_test.py -v 0x483 -p 0xa2ca -bR GET_DESCRIPTOR
```
### 6. Other possibilities
```
python3 usb_test.py -h
```
