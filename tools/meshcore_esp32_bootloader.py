#!/usr/bin/env python3
"""Request ROM entry on one identified Linux ESP32 TinyUSB CDC application.

This sends only CDC SET_LINE_CODING at 1200 baud. It does not open a tty, send
serial data, reset a USB device/controller, erase flash, or prove ROM entry.
The flasher must independently reidentify the radio and verify its ROM MAC.
"""

from __future__ import annotations

import argparse
import ctypes
from dataclasses import dataclass
import errno
import json
import math
import os
from pathlib import Path
import platform
import re
import stat
import struct
import sys
import time
from typing import Any

import meshcore_usb_reset as usb


BootloaderError = usb.ResetError
LINE_CODING_1200 = struct.pack("<IBBB", 1200, 0, 0, 8)


class ControlTransfer(ctypes.Structure):
    _fields_ = [("request_type", ctypes.c_uint8), ("request", ctypes.c_uint8),
                ("value", ctypes.c_uint16), ("index", ctypes.c_uint16),
                ("length", ctypes.c_uint16), ("timeout", ctypes.c_uint32),
                ("data", ctypes.c_void_p)]


class DisconnectClaim(ctypes.Structure):
    _fields_ = [("interface", ctypes.c_uint32), ("flags", ctypes.c_uint32),
                ("driver", ctypes.c_char * 256)]


class InterfaceIoctl(ctypes.Structure):
    _fields_ = [("interface", ctypes.c_int), ("code", ctypes.c_int),
                ("data", ctypes.c_void_p)]


def ioctl_code(direction: int, number: int, size: int = 0) -> int:
    # Linux asm-generic ioctl ABI used by supported x86, ARM and AArch64 hosts.
    return (direction << 30) | (size << 16) | (ord("U") << 8) | number


USBDEVFS_CONTROL = ioctl_code(3, 0, ctypes.sizeof(ControlTransfer))
USBDEVFS_RELEASEINTERFACE = ioctl_code(2, 16, ctypes.sizeof(ctypes.c_uint))
USBDEVFS_IOCTL = ioctl_code(3, 18, ctypes.sizeof(InterfaceIoctl))
USBDEVFS_CONNECT = ioctl_code(0, 23)
USBDEVFS_DISCONNECT_CLAIM = ioctl_code(2, 27, ctypes.sizeof(DisconnectClaim))
DISCONNECT_ERRORS = {errno.ENODEV, errno.ESHUTDOWN}
SUPPORTED_MACHINES = {"x86_64", "amd64", "i386", "i486", "i586", "i686", "aarch64", "arm64", "riscv64"}


@dataclass(frozen=True)
class NativeUsb:
    mode: str
    interface_path: Path
    product_label: str
    interface_label: str
    interface_class: str
    interface_subclass: str
    interface_protocol: str
    driver: str

    def result(self, selected: usb.UsbPort, status: str) -> dict[str, Any]:
        return {**selected.result(status), "native_mode": self.mode,
                "cdc_interface": selected.interface}


def optional_attribute(path: Path) -> str:
    return usb.read_attribute(path) if path.is_file() else ""


def inspect_native(selected: usb.UsbPort) -> NativeUsb:
    interfaces = []
    try:
        for item in selected.usb_path.iterdir():
            if (item / "bInterfaceNumber").is_file() and \
                    usb.read_attribute(item / "bInterfaceNumber").lower() == selected.interface:
                interfaces.append(item)
    except OSError as exc:
        raise BootloaderError("Cannot inspect the selected USB CDC interface.") from exc
    if len(interfaces) != 1:
        raise BootloaderError("Selected USB interface is missing or ambiguous.")
    interface_path = interfaces[0]
    product = optional_attribute(selected.usb_path / "product")
    label = optional_attribute(interface_path / "interface")
    cls = usb.read_attribute(interface_path / "bInterfaceClass").lower()
    subclass = usb.read_attribute(interface_path / "bInterfaceSubClass").lower()
    protocol = usb.read_attribute(interface_path / "bInterfaceProtocol").lower()
    if not all(re.fullmatch(r"[0-9a-f]{2}", value) for value in (cls, subclass, protocol)):
        raise BootloaderError("Invalid USB interface descriptor.")
    combined = (product + " " + label).lower()
    hardware = bool(re.search(r"usb[\s_-]*jtag|jtag[ /_-]*serial", combined))
    tinyusb = bool(re.search(r"\btinyusb\b", combined))
    cdc = cls == "02" and subclass == "02" and protocol in {"00", "01"}
    mode = "unknown"
    # VID/PID alone cannot distinguish Meshtastic TinyUSB from S3 hardware CDC.
    # The Espressif VID is necessary here, but explicit descriptor evidence is
    # also required. Unknown/custom descriptors never receive a boot request.
    if selected.vendor_id == "303a" and hardware and not tinyusb:
        mode = "hardware_jtag"
    elif selected.vendor_id == "303a" and tinyusb and not hardware and cdc:
        mode = "tinyusb"
    driver_link = interface_path / "driver"
    try:
        driver = driver_link.resolve(strict=True).name if driver_link.is_symlink() else ""
    except OSError as exc:
        raise BootloaderError("Selected USB driver changed during inspection.") from exc
    return NativeUsb(mode, interface_path, product, label, cls, subclass, protocol, driver)


def require_tinyusb(native: NativeUsb) -> None:
    if native.mode != "tinyusb":
        raise BootloaderError("1200-baud USB request requires an identified TinyUSB CDC application; "
                              "hardware USB JTAG/serial and unknown layouts are refused.")
    if native.driver not in {"", "cdc_acm"}:
        raise BootloaderError("Selected CDC interface has an unexpected driver; refusing to detach it.")


def same_descriptors(first: NativeUsb, second: NativeUsb) -> bool:
    return (first.mode, first.interface_path, first.product_label, first.interface_label,
            first.interface_class, first.interface_subclass, first.interface_protocol) == \
           (second.mode, second.interface_path, second.product_label, second.interface_label,
            second.interface_class, second.interface_subclass, second.interface_protocol)


def verify_snapshot(selected: usb.UsbPort, native: NativeUsb) -> NativeUsb:
    """Return a validated physical snapshot without a tty: claiming CDC removes it."""
    attrs = {"usb_serial": "serial", "vendor_id": "idVendor", "product_id": "idProduct"}
    for field, attribute in attrs.items():
        value = usb.read_attribute(selected.usb_path / attribute)
        if field != "usb_serial":
            value = value.lower()
        if value != selected.identity()[field]:
            raise BootloaderError("USB identity changed during bootloader entry.")
    if int(usb.read_attribute(selected.usb_path / "busnum")) != selected.busnum or \
            int(usb.read_attribute(selected.usb_path / "devnum")) != selected.devnum:
        raise BootloaderError("USB address changed during bootloader entry.")
    if usb.read_attribute(selected.usb_path / "bDeviceClass").lower() == "09":
        raise BootloaderError("Refusing a USB hub during bootloader entry.")
    current = inspect_native(selected)
    if not same_descriptors(native, current):
        raise BootloaderError("USB descriptors changed during bootloader entry.")
    return current


def ioctl_structure(descriptor: int, command: int, value: ctypes.Structure) -> int:
    import fcntl
    return fcntl.ioctl(descriptor, command, bytearray(bytes(value)), True)


def request_line_coding(descriptor: int, interface: int, timeout: float) -> int:
    data = ctypes.create_string_buffer(LINE_CODING_1200, len(LINE_CODING_1200))
    transfer = ControlTransfer(0x21, 0x20, 0, interface, len(LINE_CODING_1200),
                               max(1, int(timeout * 1000)), ctypes.addressof(data))
    return ioctl_structure(descriptor, USBDEVFS_CONTROL, transfer)


def release_and_restore(descriptor: int, selected: usb.UsbPort, native: NativeUsb,
                        claim_attempted: bool, claimed: bool) -> None:
    """Never attach a driver to a replacement device or the newly entered ROM."""
    import fcntl
    if not claim_attempted:
        return
    if claimed:
        try:
            fcntl.ioctl(descriptor, USBDEVFS_RELEASEINTERFACE, struct.pack("I", int(selected.interface, 16)))
        except OSError as exc:
            if exc.errno not in DISCONNECT_ERRORS:
                raise BootloaderError("Could not release the selected CDC interface; reselect the radio.") from exc
    if native.driver != "cdc_acm":
        return
    try:
        current = verify_snapshot(selected, native)
    except (BootloaderError, OSError, ValueError):
        return  # Rebooted/disappeared/changed: do not mutate another connection.
    # Reuse that validated snapshot. Reading descriptors again can race the
    # requested reboot and falsely report failure after the request succeeded.
    # Any subsequent rebind still uses the pinned original USB device handle;
    # if that connection disappears, ENODEV/ESHUTDOWN below is harmless.
    if current.driver == "cdc_acm":
        return
    if current.driver:
        raise BootloaderError("CDC driver changed during cleanup; refusing to attach another driver.")
    try:
        ioctl_structure(descriptor, USBDEVFS_IOCTL,
                        InterfaceIoctl(int(selected.interface, 16), USBDEVFS_CONNECT, None))
    except OSError as exc:
        if exc.errno not in DISCONNECT_ERRORS:
            raise BootloaderError("Could not restore the selected CDC driver; reselect or reconnect this radio.") from exc


def enter_bootloader(port: str | Path, expected: dict[str, str], timeout: float = 5,
                     sys_root: Path = Path("/sys"), dev_root: Path = Path("/dev"),
                     proc_root: Path = Path("/proc")) -> dict[str, Any]:
    if sys.platform != "linux":
        raise BootloaderError("Direct USB bootloader entry is supported on Linux only.")
    if os.geteuid() != 0:
        raise BootloaderError("USB bootloader entry requires sudo/root to verify all serial owners.")
    machine = platform.machine().lower()
    if machine not in SUPPORTED_MACHINES and not re.fullmatch(r"armv[5-8]l", machine):
        raise BootloaderError("Unsupported Linux ioctl ABI; refusing direct USB bootloader entry.")
    if not math.isfinite(timeout) or not 1 <= timeout <= 30:
        raise BootloaderError("Bootloader entry timeout must be between 1 and 30 seconds.")
    selected = usb.inspect_port(port, sys_root, dev_root)
    usb.verify_identity(selected, expected)
    native = inspect_native(selected)
    require_tinyusb(native)
    ports = usb.sibling_ports(selected, sys_root, dev_root)
    usb.require_primary_port(selected, ports)
    usb.require_unused(ports, proc_root)
    deadline = time.monotonic() + timeout
    descriptor = None
    claimed = False
    claim_attempted = False
    disconnected = False
    try:
        descriptor = os.open(selected.usb_node(dev_root), os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
        opened = os.fstat(descriptor)
        expected_rdev = os.makedev(189, (selected.busnum - 1) * 128 + selected.devnum - 1)
        if not stat.S_ISCHR(opened.st_mode) or opened.st_rdev != expected_rdev:
            raise BootloaderError("USB device node changed or is not a USB character device.")
        current = usb.inspect_port(port, sys_root, dev_root)
        usb.verify_identity(current, expected)
        if (current.busnum, current.devnum) != (selected.busnum, selected.devnum):
            raise BootloaderError("USB address changed during bootloader entry; reselect the radio.")
        current_native = inspect_native(current)
        require_tinyusb(current_native)
        if current_native != native:
            raise BootloaderError("USB descriptors or driver changed during bootloader entry.")
        current_ports = usb.sibling_ports(current, sys_root, dev_root)
        if {item.port for item in current_ports} != {item.port for item in ports}:
            raise BootloaderError("USB interfaces changed during bootloader entry.")
        usb.require_unused(current_ports, proc_root)
        verify_snapshot(selected, native)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise BootloaderError("Bootloader entry deadline expired; no request was issued.")
        # Atomic conditional detach+claim: only this explicit CDC interface, and
        # only cdc_acm. A different driver/interface owner causes a safe failure.
        with usb.ioctl_deadline(remaining):
            claim_attempted = True
            ioctl_structure(descriptor, USBDEVFS_DISCONNECT_CLAIM,
                            DisconnectClaim(int(selected.interface, 16), 1, b"cdc_acm"))
            claimed = True
            verify_snapshot(selected, native)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise BootloaderError("Bootloader entry deadline expired; no request was issued.")
            try:
                count = request_line_coding(descriptor, int(selected.interface, 16), remaining)
            except OSError as exc:
                if exc.errno not in DISCONNECT_ERRORS:
                    raise
                # The callback can reboot before the USB status stage. This is
                # only an issued request, not proof that the ROM is available.
                disconnected = True
            else:
                if count != len(LINE_CODING_1200):
                    raise BootloaderError("USB bootloader request was not fully accepted; ROM entry is unverified.")
    except OSError as exc:
        raise BootloaderError("USB bootloader request failed (errno " + str(exc.errno) + "); "
                              "reselect the radio before retrying.") from exc
    finally:
        if descriptor is not None:
            try:
                # Rebinding cdc_acm may itself contact EP0. Bound cleanup too;
                # a failed recovery must not leave an unbounded helper running.
                with usb.ioctl_deadline(min(timeout, 3)):
                    release_and_restore(descriptor, selected, native, claim_attempted, claimed)
            finally:
                os.close(descriptor)
    result = native.result(selected, "request_issued")
    result.update({"rom_verified": False, "disconnected_during_request": disconnected})
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", required=True, help="Selected USB tty or /dev/serial/by-id alias")
    parser.add_argument("--inspect", action="store_true", help="Read USB identity and descriptor-based native mode")
    parser.add_argument("--expected-identity", help="JSON captured by --inspect (required for entry request)")
    parser.add_argument("--timeout", type=float, default=5, help="USB request deadline in seconds (1-30)")
    args = parser.parse_args(argv)
    try:
        if sys.platform != "linux":
            raise BootloaderError("Direct USB bootloader entry is supported on Linux only.")
        if not math.isfinite(args.timeout) or not 1 <= args.timeout <= 30:
            raise BootloaderError("Bootloader entry timeout must be between 1 and 30 seconds.")
        if args.inspect:
            selected = usb.inspect_port(args.port)
            usb.require_primary_port(selected, usb.sibling_ports(selected))
            result = inspect_native(selected).result(selected, "inspected")
        else:
            if not args.expected_identity:
                raise BootloaderError("Capture --inspect and provide its --expected-identity JSON before bootloader entry.")
            result = enter_bootloader(args.port, usb.parse_expected_identity(args.expected_identity), args.timeout)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (BootloaderError, ValueError) as exc:
        message = str(exc) if isinstance(exc, BootloaderError) else "Invalid USB identity attributes."
        print(json.dumps({"status": "error", "error": message[:512]}, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
