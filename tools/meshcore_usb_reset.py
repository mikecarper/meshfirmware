#!/usr/bin/env python3
"""Reset one selected Linux USB connection without rebooting or erasing a radio.

Frontends capture --inspect while selecting a port, then pass that JSON back as
--expected-identity when the user requests recovery.  This prevents a recycled
tty number from silently targeting a different device.  Reset requires root so
the ownership check can inspect every process, not only the current user's.
No serial port is opened, no control lines are changed, and no GPIO is used.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
import errno
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys
import time
from typing import Any


USBDEVFS_RESET = 0x5514
IDENTITY_FIELDS = ("usb_path", "usb_serial", "vendor_id", "product_id", "interface")


class ResetError(RuntimeError):
    """An unsafe or unsuccessful recovery, suitable for a user-facing error."""


@dataclass(frozen=True)
class UsbPort:
    port: Path
    usb_path: Path
    usb_serial: str
    vendor_id: str
    product_id: str
    interface: str
    busnum: int
    devnum: int

    def identity(self) -> dict[str, str]:
        return {
            "usb_path": str(self.usb_path),
            "usb_serial": self.usb_serial,
            "vendor_id": self.vendor_id,
            "product_id": self.product_id,
            "interface": self.interface,
        }

    def result(self, status: str) -> dict[str, Any]:
        return {"status": status, "port": str(self.port), "identity": self.identity()}

    def usb_node(self, dev_root: Path) -> Path:
        return dev_root / "bus" / "usb" / f"{self.busnum:03d}" / f"{self.devnum:03d}"


def read_attribute(path: Path) -> str:
    try:
        value = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ResetError(f"Cannot read USB identity attribute {path.name}.") from exc
    if not value or len(value) > 512 or any(ord(char) < 32 for char in value):
        raise ResetError(f"Missing or invalid USB identity attribute {path.name}.")
    return value


def resolve_tty_device(name: str, sys_root: Path) -> Path:
    return (sys_root / "class" / "tty" / name / "device").resolve(strict=True)


def inspect_port(port: str | Path, sys_root: Path = Path("/sys"),
                 dev_root: Path = Path("/dev")) -> UsbPort:
    """Resolve by-id aliases to a physical USB device and one explicit interface."""
    try:
        resolved = Path(port).resolve(strict=True)
        if resolved.parent != dev_root.resolve() or not re.fullmatch(r"tty[A-Za-z0-9]+", resolved.name):
            raise ResetError("Select a real USB tty device, preferably its /dev/serial/by-id path.")
        if not stat.S_ISCHR(resolved.stat().st_mode):
            raise ResetError("Selected port is not a character device.")
        device = resolve_tty_device(resolved.name, sys_root)
        device.relative_to((sys_root / "devices").resolve())
        interface = None
        usb_path = None
        for ancestor in (device, *device.parents):
            if interface is None and (ancestor / "bInterfaceNumber").is_file():
                interface = read_attribute(ancestor / "bInterfaceNumber").lower()
            if (ancestor / "idVendor").is_file() and (ancestor / "idProduct").is_file():
                usb_path = ancestor
                break
        if usb_path is None or interface is None:
            raise ResetError("Selected tty is not an identifiable USB interface.")
        if read_attribute(usb_path / "bDeviceClass").lower() == "09" or re.fullmatch(r"usb\d+", usb_path.name):
            raise ResetError("Refusing to reset a USB hub or root controller.")
        vendor = read_attribute(usb_path / "idVendor").lower()
        product = read_attribute(usb_path / "idProduct").lower()
        if not re.fullmatch(r"[0-9a-f]{4}", vendor) or not re.fullmatch(r"[0-9a-f]{4}", product):
            raise ResetError("Invalid USB vendor/product identity.")
        if not re.fullmatch(r"[0-9a-f]{2}", interface):
            raise ResetError("Invalid USB interface number.")
        serial = read_attribute(usb_path / "serial")
        busnum = int(read_attribute(usb_path / "busnum"))
        devnum = int(read_attribute(usb_path / "devnum"))
        if not 1 <= busnum <= 999 or not 1 <= devnum <= 127:
            raise ResetError("Invalid USB bus/device number.")
        return UsbPort(resolved, usb_path, serial, vendor, product, interface, busnum, devnum)
    except (OSError, ValueError) as exc:
        raise ResetError("Selected USB port disappeared or its physical identity is unavailable.") from exc


def sibling_ports(selected: UsbPort, sys_root: Path = Path("/sys"),
                  dev_root: Path = Path("/dev")) -> list[UsbPort]:
    """Return every tty on this USB device, including a secondary logging tty."""
    found = []
    try:
        names = sorted(path.name for path in (sys_root / "class" / "tty").iterdir())
    except OSError as exc:
        raise ResetError("Cannot inspect USB tty interfaces.") from exc
    for name in names:
        try:
            device = resolve_tty_device(name, sys_root)
        except (OSError, RuntimeError):
            continue
        if device != selected.usb_path and selected.usb_path not in device.parents:
            continue
        # Failure on a sibling is not ignored: its owner would otherwise escape
        # the safety check while the entire physical device is being reset.
        found.append(inspect_port(dev_root / name, sys_root, dev_root))
    if not found:
        raise ResetError("Selected USB device has no available tty interfaces.")
    return found


def require_primary_port(selected: UsbPort, ports: list[UsbPort]) -> None:
    primary_interface = min(port.interface for port in ports)
    primary = [port for port in ports if port.interface == primary_interface]
    if len(primary) != 1 or selected.port != primary[0].port:
        raise ResetError("Select the primary USB tty interface; a secondary or ambiguous interface is unsafe.")


def parse_expected_identity(value: str) -> dict[str, str]:
    try:
        data = json.loads(value)
        if isinstance(data, dict) and "identity" in data:
            data = data["identity"]
        if not isinstance(data, dict) or set(data) != set(IDENTITY_FIELDS):
            raise ValueError("identity fields")
        if not all(isinstance(data[key], str) and data[key] for key in IDENTITY_FIELDS):
            raise ValueError("identity values")
        return data
    except (ValueError, TypeError) as exc:
        raise ResetError("Expected USB identity must be the JSON captured by --inspect.") from exc


def verify_identity(port: UsbPort, expected: dict[str, str]) -> None:
    if port.identity() != expected:
        raise ResetError("USB identity changed since selection; reselect the intended radio before resetting.")


def serial_owners(ports: list[UsbPort], proc_root: Path = Path("/proc")) -> list[int]:
    """Fail closed when any process's tty ownership cannot be checked."""
    try:
        devices = {port.port.stat().st_rdev for port in ports}
        processes = list(proc_root.iterdir())
    except OSError as exc:
        raise ResetError("Cannot verify that the USB serial interfaces are unused.") from exc
    owners = set()
    for process in processes:
        if not process.name.isdigit():
            continue
        try:
            descriptors = list((process / "fd").iterdir())
        except FileNotFoundError:
            continue  # The process exited during the scan.
        except PermissionError as exc:
            raise ResetError("Cannot inspect all serial owners; run reset with sudo/root.") from exc
        except OSError as exc:
            raise ResetError("Cannot inspect process file descriptors safely.") from exc
        for descriptor in descriptors:
            try:
                info = descriptor.stat()
            except FileNotFoundError:
                continue  # The descriptor closed during the scan.
            except PermissionError as exc:
                raise ResetError("Cannot inspect all serial owners; run reset with sudo/root.") from exc
            except OSError as exc:
                if exc.errno in (errno.ESRCH, errno.EBADF):
                    continue
                raise ResetError("Cannot inspect an open file descriptor safely.") from exc
            if stat.S_ISCHR(info.st_mode) and info.st_rdev in devices:
                owners.add(int(process.name))
    return sorted(owners)


def require_unused(ports: list[UsbPort], proc_root: Path) -> None:
    owners = serial_owners(ports, proc_root)
    if owners:
        raise ResetError("USB serial interface is in use by PID(s) " + ", ".join(map(str, owners))
                         + "; stop its terminal/service before USB recovery.")


def wait_for_port(selected: UsbPort, timeout: float, sys_root: Path, dev_root: Path) -> UsbPort:
    deadline = time.monotonic() + timeout
    while True:
        try:
            ports = sibling_ports(selected, sys_root, dev_root)
            matches = [port for port in ports if port.identity() == selected.identity()]
            if len(matches) == 1:
                require_primary_port(matches[0], ports)
                return matches[0]
        except ResetError:
            pass  # A tty can briefly disappear while USB is re-enumerated.
        if time.monotonic() >= deadline:
            raise ResetError("USB reset was issued, but the same radio did not return before the timeout; reselect its port.")
        time.sleep(min(0.1, max(0.0, deadline - time.monotonic())))


@contextmanager
def ioctl_deadline(timeout: float):
    """Interrupt an interruptible Linux ioctl; never spawn a detached reset.

    A driver stuck in uninterruptible kernel sleep cannot be killed by any
    userspace timeout.  Raising from SIGALRM prevents Python retrying an EINTR.
    """
    def expired(_signum, _frame):
        raise ResetError("USB reset timed out; reselect the radio and check its USB state before retrying.")

    previous_handler = signal.signal(signal.SIGALRM, expired)
    previous_timer = signal.setitimer(signal.ITIMER_REAL, timeout)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
        if previous_timer[0]:
            signal.setitimer(signal.ITIMER_REAL, *previous_timer)


def reset_port(port: str | Path, expected: dict[str, str], timeout: float = 10,
               sys_root: Path = Path("/sys"), dev_root: Path = Path("/dev"),
               proc_root: Path = Path("/proc")) -> UsbPort:
    if sys.platform != "linux":
        raise ResetError("Device-only USB reset is supported on Linux only.")
    if os.geteuid() != 0:
        raise ResetError("USB reset requires sudo/root to verify all serial owners.")
    import fcntl

    selected = inspect_port(port, sys_root, dev_root)
    verify_identity(selected, expected)
    ports = sibling_ports(selected, sys_root, dev_root)
    require_primary_port(selected, ports)
    require_unused(ports, proc_root)
    deadline = time.monotonic() + timeout
    descriptor = None
    try:
        descriptor = os.open(selected.usb_node(dev_root), os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        info = os.fstat(descriptor)
        if not stat.S_ISCHR(info.st_mode) or info.st_rdev != os.makedev(189, (selected.busnum - 1) * 128 + selected.devnum - 1):
            raise ResetError("USB device node changed or is not a USB character device.")
        current = inspect_port(port, sys_root, dev_root)
        verify_identity(current, expected)
        if (current.busnum, current.devnum) != (selected.busnum, selected.devnum):
            raise ResetError("USB address changed during recovery; reselect the radio.")
        current_ports = sibling_ports(current, sys_root, dev_root)
        if {item.port for item in current_ports} != {item.port for item in ports}:
            raise ResetError("USB interfaces changed during recovery; reselect the radio.")
        require_unused(current_ports, proc_root)
        # Last identity check immediately before the only hardware mutation.
        final = inspect_port(port, sys_root, dev_root)
        verify_identity(final, expected)
        if (final.busnum, final.devnum) != (selected.busnum, selected.devnum):
            raise ResetError("USB address changed during recovery; reselect the radio.")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ResetError("USB reset deadline expired during safety checks; no reset was issued.")
        with ioctl_deadline(remaining):
            fcntl.ioctl(descriptor, USBDEVFS_RESET, 0)
    except OSError as exc:
        raise ResetError(f"USB connection reset failed ({exc.strerror or 'device unavailable'}).") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return wait_for_port(selected, max(0.0, deadline - time.monotonic()), sys_root, dev_root)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", required=True, help="Selected USB tty or /dev/serial/by-id alias")
    parser.add_argument("--inspect", action="store_true", help="Capture stable USB identity without resetting")
    parser.add_argument("--expected-identity", help="JSON previously returned by --inspect (required for reset)")
    parser.add_argument("--timeout", type=float, default=10, help="Reset and tty return deadline in seconds (1-30)")
    args = parser.parse_args(argv)
    try:
        if sys.platform != "linux":
            raise ResetError("Device-only USB reset is supported on Linux only.")
        if not 1 <= args.timeout <= 30:
            raise ResetError("USB recovery timeout must be between 1 and 30 seconds.")
        if args.inspect:
            selected = inspect_port(args.port)
            require_primary_port(selected, sibling_ports(selected))
            result = selected.result("inspected")
        else:
            if not args.expected_identity:
                raise ResetError("Capture --inspect before resetting and provide its --expected-identity JSON.")
            result = reset_port(args.port, parse_expected_identity(args.expected_identity), args.timeout).result("reset")
        print(json.dumps(result, sort_keys=True))
        return 0
    except ResetError as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
