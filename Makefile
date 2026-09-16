# usb-tester build process
#
# libusb is a git submodule (github.com/libusb/libusb, pinned to v1.0.30) that
# must be patched to raise MAX_CTRL_BUFFER_LENGTH before building, otherwise the
# large-wLength control transfers usb_test.py relies on get truncated.
#
# Quick start (native x86_64):   make install
# Raspberry Pi / ARM cross build:
#     make install HOST=arm-linux-gnueabihf CC=arm-linux-gnueabihf-gcc PREFIX=/usr/local/libusb-rpi
#
# Requires: build-essential, autoconf, automake, libtool, pkg-config, python3-pip
# (the submodule is a git checkout, so ./autogen.sh must regenerate configure).

LIBUSB_DIR      := libusb
LIBUSB_HEADER   := $(LIBUSB_DIR)/libusb/os/linux_usbfs.h
CTRL_BUFFER_LEN := 65536

# Install prefix for the patched libusb. Override for cross builds.
PREFIX          ?= /usr/local
# Cross-compile host triplet + compiler (leave empty for a native build).
HOST            ?=
CC              ?=

CONFIGURE_FLAGS := --prefix=$(PREFIX) --disable-udev
ifneq ($(HOST),)
CONFIGURE_FLAGS += --host=$(HOST)
endif
ifneq ($(CC),)
CONFIGURE_FLAGS += CC=$(CC)
endif

LDSOCONF        := /etc/ld.so.conf.d/libusb.conf

.PHONY: all help install submodule patch preflight libusb install-libusb python-deps ldconfig clean sudo-clean

all: help

help:
	@echo "Targets:"
	@echo "  make install         - full setup: submodule + patch + build/install libusb + python deps"
	@echo "  make submodule       - init/update the libusb submodule (pinned to v1.0.30)"
	@echo "  make patch           - raise MAX_CTRL_BUFFER_LENGTH to $(CTRL_BUFFER_LEN) (idempotent)"
	@echo "  make libusb          - patch + autogen + configure + build libusb (no install)"
	@echo "  make install-libusb  - build then 'sudo make install' libusb + register with ldconfig"
	@echo "  make python-deps     - pip install runtime deps (pyusb)"
	@echo "  make clean           - clean build artifacts in the submodule"
	@echo "  make sudo-clean      - forcibly reset the submodule (removes root-owned"
	@echo "                         artifacts left by a previous 'sudo make install')"
	@echo ""
	@echo "Cross build example (Raspberry Pi):"
	@echo "  make install HOST=arm-linux-gnueabihf CC=arm-linux-gnueabihf-gcc PREFIX=/usr/local/libusb-rpi"

install: install-libusb python-deps

# --- libusb submodule ---

submodule: $(LIBUSB_HEADER)

$(LIBUSB_HEADER):
	git submodule update --init --recursive $(LIBUSB_DIR)

# Idempotent: matches any current numeric value and forces it to $(CTRL_BUFFER_LEN).
patch: submodule
	sed -i -E 's/#define[[:space:]]+MAX_CTRL_BUFFER_LENGTH[[:space:]]+[0-9]+/#define MAX_CTRL_BUFFER_LENGTH $(CTRL_BUFFER_LEN)/' $(LIBUSB_HEADER)
	@grep -n MAX_CTRL_BUFFER_LENGTH $(LIBUSB_HEADER)

# Building from a git checkout regenerates configure via autogen.sh, so the
# autotools chain must be present. Fail early with the fix instead of a raw
# "autoreconf: not found" from bootstrap.sh.
preflight:
	@missing=""; \
	for t in autoreconf automake libtoolize gcc make; do \
		command -v $$t >/dev/null 2>&1 || missing="$$missing $$t"; \
	done; \
	if [ -n "$$missing" ]; then \
		echo "Error: missing build prerequisites:$$missing"; \
		echo "Install them with:"; \
		echo "    sudo apt install -y autoconf automake libtool build-essential pkg-config"; \
		echo "(autoreconf comes from the 'autoconf' package.)"; \
		exit 1; \
	fi

libusb: preflight patch
	cd $(LIBUSB_DIR) && ./autogen.sh $(CONFIGURE_FLAGS)
	$(MAKE) -C $(LIBUSB_DIR)

install-libusb: libusb
	sudo $(MAKE) -C $(LIBUSB_DIR) install
	$(MAKE) ldconfig

ldconfig:
	sudo sh -c 'grep -qxF "$(PREFIX)/lib" $(LDSOCONF) 2>/dev/null || echo "$(PREFIX)/lib" >> $(LDSOCONF)'
	sudo ldconfig
	@ldconfig -p | grep libusb || true

python-deps:
	python3 -m pip install -r requirements.txt

clean:
	-$(MAKE) -C $(LIBUSB_DIR) clean 2>/dev/null || true

# Full reset of the submodule working tree, including root-owned build artifacts
# and autom4te.cache left behind when libusb was built/installed under sudo (which
# otherwise make a later non-sudo 'make libusb' fail with Permission denied).
# Removes all untracked/generated files and reverts the MAX_CTRL_BUFFER_LENGTH
# patch; re-run 'make patch'/'make libusb' afterward. safe.directory avoids git's
# dubious-ownership refusal when clearing root-owned files.
sudo-clean:
	-sudo git -C $(LIBUSB_DIR) -c safe.directory='*' clean -fdx
	-sudo git -C $(LIBUSB_DIR) -c safe.directory='*' checkout -- .
