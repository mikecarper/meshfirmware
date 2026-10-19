#!/usr/bin/env python3
"""Request one 1200-baud/DTR bootloader touch on an identified Linux USB CDC0.

No serial payload is read or written. A request never proves bootloader entry;
the caller must independently recognize the same radio's bootloader afterwards.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import errno
import json
import math
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time
import zipfile

import meshcore_usb_reset as usb


class TouchError(usb.ResetError):
    pass


class TouchDeadline(TouchError):
    pass


@contextmanager
def deadline(seconds):
    if signal.getitimer(signal.ITIMER_REAL) != (0.0, 0.0):
        raise TouchError("An existing timer prevents a bounded serial touch.")
    previous = signal.getsignal(signal.SIGALRM)

    def expired(*_):
        raise TouchDeadline("Serial touch deadline expired; do not repeat an uncertain request.")

    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def disappeared(error):
    """Retry only read-only qualification of a genuinely disappearing endpoint."""
    while error is not None:
        if isinstance(error, OSError) and error.errno in (errno.ENOENT, errno.ENODEV, errno.ENXIO):
            return True
        error = error.__cause__
    return False


def node_identity(path):
    info = Path(path).stat()
    if not stat.S_ISCHR(info.st_mode):
        raise TouchError("Selected USB tty is not a character device.")
    return info.st_dev, info.st_ino, info.st_rdev


def physical_alias(selected, identity, dev_root=Path("/dev")):
    """Use a physical by-path alias, with the guarded inode checked again on open."""
    aliases = []
    for path in (dev_root / "serial" / "by-path").glob("*"):
        try:
            if path.is_symlink() and path.resolve(strict=True) == selected.port and node_identity(path) == identity:
                aliases.append(path)
        except OSError as error:
            if not disappeared(error):
                raise
    if not aliases:
        raise TouchError("The selected CDC0 has no verified physical by-path alias; reselect the radio.")
    # Multiple aliases of this one inode do not represent different radios.
    return sorted(aliases)[0]


def require_unowned(selected, ports, expected, identity, owner_sudo=False):
    if not owner_sudo or os.geteuid() == 0:
        try:
            usb.require_unused(ports, Path("/proc"))
        except usb.ResetError as error:
            if isinstance(error.__cause__, PermissionError):
                raise TouchError("Cannot inspect every serial owner in no-sudo mode; use normal sudo mode or physical bootloader entry.") from error
            raise
        return
    # Only this fixed read-only inspector is elevated. The user's interpreter
    # still owns the serial open/controls; no dependency install runs as root.
    command = ["/usr/bin/sudo", "-n", "/usr/bin/timeout", "--kill-after=1s", "2s",
               sys.executable, str(Path(usb.__file__).resolve()), "--port", str(selected.port),
               "--inspect", "--check-unused", "--expected-identity", json.dumps(expected)]
    result = subprocess.run(command, capture_output=True, timeout=4, check=False)
    if result.returncode != 0:
        raise TouchError("Complete serial-owner inspection failed; close serial clients and check cached sudo access.")
    observed = json.loads(result.stdout)
    if (observed.get("status") != "inspected" or observed.get("identity") != expected
            or observed.get("owners_checked") is not True
            or observed.get("busnum") != selected.busnum or observed.get("devnum") != selected.devnum
            or observed.get("tty_instance") != list(identity)):
        raise TouchError("Privileged serial-owner inspection did not verify this USB endpoint.")


def qualify(port, expected, owner_sudo=False):
    selected = usb.inspect_port(port)
    usb.verify_identity(selected, expected)
    if selected.interface != "00":
        raise TouchError("A bootloader touch requires the primary CDC0 interface, never the logging interface.")
    siblings = usb.sibling_ports(selected)
    usb.require_primary_port(selected, siblings)
    identity = node_identity(selected.port)
    alias = physical_alias(selected, identity)
    require_unowned(selected, siblings, expected, identity, owner_sudo)
    final = usb.inspect_port(alias)
    usb.verify_identity(final, expected)
    if (final.busnum, final.devnum) != (selected.busnum, selected.devnum) or node_identity(final.port) != identity:
        raise TouchError("USB device changed during serial-touch qualification.")
    return selected, alias, identity


def verify_fd(port, selected, identity, expected):
    info = os.fstat(port.fd)
    if not stat.S_ISCHR(info.st_mode) or (info.st_dev, info.st_ino, info.st_rdev) != identity:
        raise TouchError("Opened tty differs from the qualified USB device; no serial controls were sent.")
    current = usb.inspect_port(selected.port)
    usb.verify_identity(current, expected)
    if (current.busnum, current.devnum) != (selected.busnum, selected.devnum) or node_identity(current.port) != identity:
        raise TouchError("USB identity changed before a serial control request.")


def serial_factory(selected, identity, expected, result):
    import serial

    if serial.VERSION != "3.5":
        raise TouchError("Serial touch requires the reviewed pySerial 3.5 open/control ordering.")

    class BoundSerial(serial.Serial):
        def _reconfigure_port(self, *args, **kwargs):
            # pySerial opens the FD before this method. Check it before any
            # inherited termios configuration or DTR/RTS control transfer.
            verify_fd(self, selected, identity, expected)
            result["control_attempted"] = True
            return super()._reconfigure_port(*args, **kwargs)

        def write(self, _):
            raise TouchError("Serial payload writes are forbidden during a bootloader touch.")

        def read(self, *_):
            raise TouchError("Serial payload reads are forbidden during a bootloader touch.")

        def send_break(self, *_, **__):
            raise TouchError("Serial break is forbidden during a bootloader touch.")

    return BoundSerial(port=None, baudrate=1200, timeout=0, write_timeout=0,
                       exclusive=True, rtscts=False, dsrdtr=False)


def touch(port, expected, timeout=10, *, qualifier=qualify, factory=serial_factory,
          clock=time.monotonic, sleep=time.sleep):
    if not math.isfinite(timeout) or not 1 <= timeout <= 30:
        raise TouchError("Serial touch timeout must be between 1 and 30 seconds.")
    result = {"status": "not_requested", "identity": expected, "open_attempts": 0,
              "control_attempted": False, "dtr_low_attempted": False, "port_closed": True,
              "bootloader_verified": False, "application_bytes_written": 0,
              "application_bytes_captured": 0, "cleanup_review_required": False}
    port_object = None
    with deadline(timeout):
        until = clock() + timeout
        while True:
            try:
                selected, alias, identity = qualifier(port, expected)
                break
            except (usb.ResetError, OSError) as error:
                if not disappeared(error) or clock() >= until:
                    raise
                sleep(min(.05, max(0, until - clock())))
        port_object = factory(selected, identity, expected, result)
        port_object.dtr = True
        port_object.rts = False
        port_object.port = str(alias)
        try:
            result["open_attempts"] = 1
            result["port_closed"] = False
            port_object.open()
            sleep(.05)
            verify_fd(port_object, selected, identity, expected)
            result["dtr_low_attempted"] = True
            port_object.dtr = False
            result["status"] = "requested"
        except (OSError, usb.ResetError) as error:
            # Disconnect/EIO can mean a delivered request reset the device.
            # Never repeat the open. The caller may only wait for exact DFU.
            if not result["control_attempted"] or (isinstance(error, usb.ResetError)
                    and not isinstance(error, TouchDeadline) and not disappeared(error)):
                raise
            result["status"] = "uncertain"
            if isinstance(error, TouchDeadline):
                result["deadline_expired"] = True
        finally:
            try:
                port_object.close()
                if port_object.is_open:
                    raise TouchError("Touched serial port did not close.")
                result["port_closed"] = True
            except BaseException:
                result["cleanup_review_required"] = True
                raise
    return result


def package_components(path):
    """Describe the manifest selection, without extracting firmware or claiming runtime."""
    with zipfile.ZipFile(path) as archive:
        if archive.namelist().count("manifest.json") != 1:
            raise TouchError("DFU package needs one manifest.json.")
        info = archive.getinfo("manifest.json")
        if info.file_size > 65536:
            raise TouchError("DFU package manifest is unexpectedly large.")
        manifest = json.loads(archive.read(info))["manifest"]
        allowed = {"application", "bootloader", "softdevice", "softdevice_bootloader"}
        if not isinstance(manifest, dict) or set(manifest) - allowed - {"dfu_version"}:
            raise TouchError("DFU package has an unsupported component manifest.")
        version = manifest.get("dfu_version")
        if version is not None and (type(version) not in (int, float) or version != 0.5):
            raise TouchError("DFU package uses an unsupported legacy dfu_version; expected 0.5.")
        components = {key: value for key, value in manifest.items() if key in allowed and value is not None}
        if not components:
            raise TouchError("DFU package contains no selected firmware component.")
        for component in components.values():
            if not isinstance(component, dict) or any(not isinstance(component.get(key), str)
                    or archive.namelist().count(component[key]) != 1 for key in ("bin_file", "dat_file")):
                raise TouchError("DFU package component files are missing or ambiguous.")
            if component.get("init_packet_data") is not None and not isinstance(component["init_packet_data"], dict):
                raise TouchError("DFU package init_packet_data must be an object.")
        return {"components": sorted(components), "application_only": set(components) == {"application"}}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port")
    parser.add_argument("--expected-identity")
    parser.add_argument("--timeout", type=float, default=10)
    parser.add_argument("--owner-sudo", action="store_true", help="Use cached sudo for read-only complete serial-owner inspection")
    parser.add_argument("--inspect-package", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.inspect_package is not None:
            if args.port or args.expected_identity:
                raise TouchError("Package inspection cannot request a serial touch.")
            result = package_components(args.inspect_package)
        else:
            if sys.platform != "linux" or not args.port or not args.expected_identity:
                raise TouchError("Linux serial touch requires the selected port and its previously captured USB identity.")
            result = touch(args.port, usb.parse_expected_identity(args.expected_identity), args.timeout,
                           qualifier=lambda port, expected: qualify(port, expected, args.owner_sudo))
        print(json.dumps(result, sort_keys=True))
        return 0
    except (usb.ResetError, OSError, ValueError, KeyError, zipfile.BadZipFile, subprocess.SubprocessError) as error:
        message = str(error) if isinstance(error, usb.ResetError) else "Serial touch/package inspection failed; no automatic retry was attempted."
        print(json.dumps({"status": "error", "error": message, "bootloader_verified": False}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
