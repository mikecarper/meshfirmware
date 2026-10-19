#!/usr/bin/env python3
"""Mocked USB/serial/ownership tests; no connected radio or child is used."""

import contextlib
import errno
import json
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import meshcore_serial_touch as touch


EXPECTED = {"usb_path": "/sys/devices/usb1/1-7", "usb_serial": "TEST-RADIO",
            "vendor_id": "2886", "product_id": "8044", "interface": "00"}


class SerialTouchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.selected = touch.usb.UsbPort(Path("/dev/ttyACM99"), Path(EXPECTED["usb_path"]),
            EXPECTED["usb_serial"], "2886", "8044", "00", 1, 7)
        self.identity = (1, 2, 3)
        self.events = []
        self.clock_value = 0.0
        self.serial = None
        self.no_children = patch.object(subprocess, "Popen", side_effect=AssertionError("No real child"))
        self.no_children.start()
        self.addCleanup(self.no_children.stop)

    def clock(self):
        return self.clock_value

    def sleep(self, seconds):
        self.clock_value += seconds
        if getattr(self, "timeout_on_hold", False) and seconds == .05:
            raise touch.TouchDeadline("PRIVATE-TIMEOUT")

    def qualifier(self, port, expected):
        self.assertEqual(port, "/dev/serial/by-id/selected")
        self.assertEqual(expected, EXPECTED)
        self.events.append("qualified")
        return self.selected, Path("/dev/serial/by-path/physical-if00"), self.identity

    def factory(self, selected, identity, expected, result):
        outer = self
        class Port:
            is_open = False
            fd = 9
            def __setattr__(self, key, value):
                if key in ("dtr", "rts", "port"):
                    outer.events.append((key, value, self.is_open))
                if key == "dtr" and value is False and getattr(outer, "dtr_error", False):
                    raise OSError(errno.EIO, "PRIVATE-TTY")
                object.__setattr__(self, key, value)
            def open(self):
                outer.events.append("open")
                if getattr(outer, "guard_error", False):
                    raise touch.TouchError("FD identity differs")
                result["control_attempted"] = True
                self.is_open = True
                if getattr(outer, "open_error", False):
                    raise OSError(errno.EIO, "PRIVATE-TTY")
            def close(self):
                outer.events.append("close")
                if getattr(outer, "close_error", False):
                    raise OSError(errno.EIO, "PRIVATE-CLOSE")
                self.is_open = False
            def write(self, *_):
                raise AssertionError("No payload write")
            def read(self, *_):
                raise AssertionError("No payload read")
        self.serial = Port()
        return self.serial

    def request(self, qualifier=None):
        with patch.object(touch, "deadline", return_value=contextlib.nullcontext()), \
                patch.object(touch, "verify_fd", side_effect=lambda *_: self.events.append("fd_guard")):
            return touch.touch("/dev/serial/by-id/selected", EXPECTED, qualifier=qualifier or self.qualifier,
                               factory=self.factory, clock=self.clock, sleep=self.sleep)

    def test_one_open_physical_alias_controls_before_open_no_payload_or_bootloader_claim(self):
        result = self.request()
        self.assertEqual(self.events[:5], ["qualified", ("dtr", True, False), ("rts", False, False),
                         ("port", "/dev/serial/by-path/physical-if00", False), "open"])
        self.assertEqual(self.events[5:], ["fd_guard", ("dtr", False, True), "close"])
        self.assertEqual(result["status"], "requested")
        self.assertEqual(result["open_attempts"], 1)
        self.assertTrue(result["port_closed"])
        self.assertFalse(result["bootloader_verified"])
        self.assertFalse(result["cleanup_review_required"])
        self.assertEqual(result["application_bytes_written"], 0)
        self.assertEqual(result["application_bytes_captured"], 0)

    def test_open_or_dtr_disconnect_is_uncertain_without_second_attempt(self):
        for where in ("open_error", "dtr_error"):
            with self.subTest(where=where):
                setattr(self, where, True)
                self.events.clear()
                result = self.request()
                self.assertEqual(result["status"], "uncertain")
                self.assertEqual(self.events.count("open"), 1)
                self.assertFalse(self.serial.is_open)
                self.assertNotIn("PRIVATE", json.dumps(result))
                setattr(self, where, False)

    def test_fd_guard_refusal_has_no_controls_retry_or_success(self):
        self.guard_error = True
        with self.assertRaises(touch.TouchError):
            self.request()
        self.assertEqual(self.events.count("open"), 1)
        self.assertFalse(self.serial.is_open)
        self.assertNotIn(("dtr", False, True), self.events)

    def test_one_shot_deadline_after_controls_closes_and_is_only_uncertainty(self):
        self.timeout_on_hold = True
        result = self.request()
        self.assertEqual(result["status"], "uncertain")
        self.assertTrue(result["deadline_expired"])
        self.assertEqual(self.events.count("open"), 1)
        self.assertFalse(self.serial.is_open)

    def test_read_only_disappearance_retries_but_eio_and_mismatch_do_not(self):
        calls = []
        def gone_once(port, expected):
            calls.append(True)
            if len(calls) == 1:
                raise FileNotFoundError(errno.ENOENT, "gone")
            return self.qualifier(port, expected)
        self.assertEqual(self.request(gone_once)["status"], "requested")
        self.assertEqual(len(calls), 2)
        for error in (OSError(errno.EIO, "I/O failed"), touch.TouchError("Wrong serial"), touch.TouchDeadline("done")):
            calls.clear(); self.serial = None
            def refused(*_):
                calls.append(True)
                raise error
            with self.subTest(error=type(error).__name__), self.assertRaises(type(error)):
                self.request(refused)
            self.assertEqual(len(calls), 1)
            self.assertIsNone(self.serial)

    def test_close_failure_cannot_return_a_successful_or_uncertain_result(self):
        self.close_error = True
        with self.assertRaises(OSError):
            self.request()
        self.assertEqual(self.events.count("open"), 1)

    def test_invalid_timeouts_never_qualify(self):
        for timeout in (0, -1, 31, float("nan"), float("inf")):
            with self.subTest(timeout=timeout), self.assertRaises(touch.TouchError):
                touch.touch("unused", EXPECTED, timeout, qualifier=lambda *_: self.fail("No qualification"))

    def test_timer_is_fixed_and_restores_handler(self):
        with patch.object(signal, "getitimer", return_value=(0.0, 0.0)), \
                patch.object(signal, "getsignal", return_value="old"), \
                patch.object(signal, "signal") as handler, patch.object(signal, "setitimer") as timer:
            with touch.deadline(7):
                pass
        self.assertEqual(timer.call_args_list[0].args, (signal.ITIMER_REAL, 7))
        self.assertEqual(timer.call_args_list[-1].args, (signal.ITIMER_REAL, 0))
        self.assertEqual(handler.call_args_list[-1].args, (signal.SIGALRM, "old"))

    def test_existing_timer_refuses_without_changing_it(self):
        with patch.object(signal, "getitimer", return_value=(1.0, 0.0)), patch.object(signal, "setitimer") as timer:
            with self.assertRaises(touch.TouchError), touch.deadline(7):
                self.fail("No operation")
        timer.assert_not_called()

    def test_qualify_rejects_logging_or_mismatched_original_identity_before_open(self):
        secondary = touch.usb.UsbPort(self.selected.port, self.selected.usb_path, self.selected.usb_serial,
                                     "2886", "8044", "02", 1, 7)
        for selected in (secondary, touch.usb.UsbPort(self.selected.port, self.selected.usb_path,
                "OTHER", "2886", "8044", "00", 1, 7)):
            with patch.object(touch.usb, "inspect_port", return_value=selected), \
                    patch.object(touch, "require_unowned") as owned:
                with self.assertRaises(touch.usb.ResetError):
                    touch.qualify(self.selected.port, EXPECTED)
                owned.assert_not_called()

    def test_owner_inspection_never_trusts_incomplete_visibility_in_no_sudo_mode(self):
        denied = touch.usb.ResetError("Cannot inspect descriptors")
        denied.__cause__ = PermissionError("other user")
        with patch.object(touch.usb, "require_unused", side_effect=denied), \
                patch.object(subprocess, "run") as run:
            with self.assertRaisesRegex(touch.TouchError, "no-sudo"):
                touch.require_unowned(self.selected, [self.selected], EXPECTED, self.identity, False)
            run.assert_not_called()
        with patch.object(touch.usb, "require_unused", side_effect=touch.usb.ResetError("busy")):
            with self.assertRaisesRegex(touch.usb.ResetError, "busy"):
                touch.require_unowned(self.selected, [self.selected], EXPECTED, self.identity, False)

    def test_privileged_inspection_is_fixed_read_only_bounded_and_exact_endpoint(self):
        proof = {"status": "inspected", "identity": EXPECTED, "owners_checked": True,
                 "busnum": 1, "devnum": 7, "tty_instance": list(self.identity)}
        with patch.object(touch.os, "geteuid", return_value=1000), \
                patch.object(subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=json.dumps(proof).encode())) as run:
            touch.require_unowned(self.selected, [self.selected], EXPECTED, self.identity, True)
        command = run.call_args.args[0]
        self.assertEqual(command[:6], ["/usr/bin/sudo", "-n", "/usr/bin/timeout", "--kill-after=1s", "2s", sys.executable])
        self.assertIn("--inspect", command)
        self.assertIn("--check-unused", command)
        self.assertNotIn("--reset", command)
        self.assertEqual(run.call_args.kwargs["timeout"], 4)
        for field, bad in (("owners_checked", False), ("devnum", 8), ("tty_instance", [1, 99, 3]),
                           ("identity", dict(EXPECTED, usb_serial="OTHER"))):
            changed = dict(proof, **{field: bad})
            with self.subTest(field=field), patch.object(touch.os, "geteuid", return_value=1000), \
                    patch.object(subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=json.dumps(changed).encode())):
                with self.assertRaises(touch.TouchError):
                    touch.require_unowned(self.selected, [self.selected], EXPECTED, self.identity, True)

    def test_root_uses_full_inspector_without_spawning_sudo(self):
        with patch.object(touch.os, "geteuid", return_value=0), patch.object(touch.usb, "require_unused") as inspect, \
                patch.object(subprocess, "run") as run:
            touch.require_unowned(self.selected, [self.selected], EXPECTED, self.identity, True)
        inspect.assert_called_once_with([self.selected], Path("/proc"))
        run.assert_not_called()

    def test_fd_inode_device_usb_address_and_serial_are_checked_before_controls(self):
        info = SimpleNamespace(st_mode=stat.S_IFCHR, st_dev=1, st_ino=2, st_rdev=3)
        with patch.object(touch.os, "fstat", return_value=info), \
                patch.object(touch.usb, "inspect_port", return_value=self.selected), \
                patch.object(touch, "node_identity", return_value=self.identity):
            touch.verify_fd(SimpleNamespace(fd=9), self.selected, self.identity, EXPECTED)
            for field in ("st_dev", "st_ino", "st_rdev"):
                old = getattr(info, field); setattr(info, field, old + 1)
                with self.subTest(field=field), self.assertRaises(touch.TouchError):
                    touch.verify_fd(SimpleNamespace(fd=9), self.selected, self.identity, EXPECTED)
                setattr(info, field, old)
            changed = touch.usb.UsbPort(self.selected.port, self.selected.usb_path,
                         self.selected.usb_serial, "2886", "8044", "00", 1, 8)
            with patch.object(touch.usb, "inspect_port", return_value=changed), self.assertRaises(touch.TouchError):
                touch.verify_fd(SimpleNamespace(fd=9), self.selected, self.identity, EXPECTED)

    def test_pyserial_fd_guard_precedes_line_coding_and_controls(self):
        events = []
        class Base:
            def __init__(self, **kwargs): self.kwargs = kwargs
            def _reconfigure_port(self, **_): events.append("termios")
        fake = SimpleNamespace(VERSION="3.5", Serial=Base)
        result = {"control_attempted": False}
        with patch.dict(sys.modules, {"serial": fake}), \
                patch.object(touch, "verify_fd", side_effect=lambda *_: events.append("fd_guard")):
            port = touch.serial_factory(self.selected, self.identity, EXPECTED, result)
            port._reconfigure_port(force_update=True)
            self.assertEqual(events, ["fd_guard", "termios"])
            self.assertTrue(result["control_attempted"])
            self.assertEqual(port.kwargs["port"], None)
            self.assertTrue(port.kwargs["exclusive"])
            for name in ("write", "read", "send_break"):
                with self.assertRaises(touch.TouchError): getattr(port, name)(b"payload")
        events.clear(); result["control_attempted"] = False
        with patch.dict(sys.modules, {"serial": fake}), patch.object(touch, "verify_fd", side_effect=touch.TouchError("reused")):
            port = touch.serial_factory(self.selected, self.identity, EXPECTED, result)
            with self.assertRaises(touch.TouchError): port._reconfigure_port(force_update=True)
            self.assertEqual(events, [])
            self.assertFalse(result["control_attempted"])

    def test_package_manifest_reports_application_only_and_combined_without_hardware(self):
        for components in (("application",), ("softdevice_bootloader",), ("application", "bootloader")):
            path = self.root / "package.zip"
            with zipfile.ZipFile(path, "w") as archive:
                manifest = {name: {"bin_file": name + ".bin", "dat_file": name + ".dat"} for name in components}
                archive.writestr("manifest.json", json.dumps({"manifest": manifest}))
                for name in components:
                    archive.writestr(name + ".bin", b"firmware")
                    archive.writestr(name + ".dat", b"metadata")
            result = touch.package_components(path)
            self.assertEqual(result["components"], sorted(components))
            self.assertEqual(result["application_only"], components == ("application",))

    def test_missing_or_unknown_package_components_do_not_claim_application_only(self):
        for manifest in ({"unexpected": {}}, {"application": {"bin_file": "missing", "dat_file": "missing"}}, {}):
            path = self.root / "bad.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("manifest.json", json.dumps({"manifest": manifest}))
            with self.assertRaises(touch.TouchError): touch.package_components(path)

    def test_actual_legacy_manifest_metadata_and_combined_sizes_are_supported(self):
        for name in ("application", "softdevice_bootloader"):
            component = {"bin_file": "firmware.bin", "dat_file": "firmware.dat",
                "init_packet_data": {"application_version": 4294967295, "device_revision": 65535,
                    "device_type": 82, "firmware_crc16": 35831, "softdevice_req": [291]}}
            if name == "softdevice_bootloader": component.update(sd_size=150792, bl_size=40784)
            manifest = {"dfu_version": 0.5, name: component}
            if name == "application": manifest.update(bootloader=None, softdevice=None)
            path = self.root / "legacy.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("manifest.json", json.dumps({"manifest": manifest}))
                archive.writestr("firmware.bin", b"firmware")
                archive.writestr("firmware.dat", b"metadata")
            result = touch.package_components(path)
            self.assertEqual(result, {"components": [name], "application_only": name == "application"})
        for version in (True, "0.5", 1.0, -1):
            manifest["dfu_version"] = version
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("manifest.json", json.dumps({"manifest": manifest}))
            with self.subTest(version=version), self.assertRaises(touch.TouchError):
                touch.package_components(path)


if __name__ == "__main__":
    unittest.main()
