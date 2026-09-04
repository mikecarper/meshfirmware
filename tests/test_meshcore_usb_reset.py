import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import stat
import sys
import tempfile
import types
import unittest
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[1] / "tools" / "meshcore_usb_reset.py"
SPEC = importlib.util.spec_from_file_location("meshcore_usb_reset", MODULE_PATH)
usb = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = usb
SPEC.loader.exec_module(usb)


class FakeSysfs(unittest.TestCase):
    """Portable fake sysfs; no hardware, root access, or symlinks required."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.sys = self.root / "sys"
        self.dev = self.root / "dev"
        self.proc = self.root / "proc"
        self.physical = self.sys / "devices" / "platform" / "usb1" / "1-1"
        self.physical.mkdir(parents=True)
        self.dev.mkdir()
        self.proc.mkdir()
        (self.sys / "class" / "tty").mkdir(parents=True)
        self.mapping = {}
        self.device_numbers = {}
        self.attrs = {
            "idVendor": "303a", "idProduct": "1001", "serial": "CC8DA2E96F34",
            "bDeviceClass": "00", "busnum": "1", "devnum": "9",
        }
        self.write_attrs(self.physical, self.attrs)
        self.port = self.add_tty("ttyACM0", "00", 101)
        real_stat = Path.stat

        def fake_stat(path, *args, **kwargs):
            if path in self.device_numbers:
                return types.SimpleNamespace(st_mode=stat.S_IFCHR | 0o600, st_rdev=self.device_numbers[path])
            return real_stat(path, *args, **kwargs)

        self.addCleanup(mock.patch.stopall)
        mock.patch.object(Path, "stat", fake_stat).start()
        mock.patch.object(usb, "resolve_tty_device", side_effect=lambda name, _root: self.mapping[name]).start()

    def write_attrs(self, directory, attrs):
        for name, value in attrs.items():
            (directory / name).write_text(value, encoding="utf-8")

    def add_tty(self, name, interface, rdev, physical=None):
        physical = physical or self.physical
        interface_path = physical / f"interface-{int(interface, 16)}"
        interface_path.mkdir(parents=True, exist_ok=True)
        (interface_path / "bInterfaceNumber").write_text(interface, encoding="utf-8")
        self.mapping[name] = interface_path
        (self.sys / "class" / "tty" / name).mkdir()
        port = self.dev / name
        port.touch()
        self.device_numbers[port] = rdev
        return port

    def inspect(self, port=None):
        return usb.inspect_port(port or self.port, self.sys, self.dev)

    def test_inspection_has_stable_identity_and_bus_address(self):
        selected = self.inspect()
        self.assertEqual(selected.identity(), {
            "usb_path": str(self.physical), "usb_serial": "CC8DA2E96F34",
            "vendor_id": "303a", "product_id": "1001", "interface": "00",
        })
        self.assertEqual(selected.usb_node(self.dev), self.dev / "bus" / "usb" / "001" / "009")

    def test_refuses_regular_file_as_tty(self):
        self.device_numbers.clear()
        with self.assertRaisesRegex(usb.ResetError, "character device"):
            self.inspect()

    def test_refuses_hub(self):
        (self.physical / "bDeviceClass").write_text("09")
        with self.assertRaisesRegex(usb.ResetError, "hub"):
            self.inspect()

    def test_refuses_missing_serial(self):
        (self.physical / "serial").unlink()
        with self.assertRaisesRegex(usb.ResetError, "serial"):
            self.inspect()

    def test_refuses_non_usb_tty(self):
        (self.physical / "idVendor").unlink()
        with self.assertRaisesRegex(usb.ResetError, "not an identifiable USB"):
            self.inspect()

    def test_refuses_tty_outside_sysfs_devices(self):
        self.mapping["ttyACM0"] = self.root
        with self.assertRaisesRegex(usb.ResetError, "physical identity"):
            self.inspect()

    def test_refuses_invalid_vendor_and_interface(self):
        for attr, value in (("idVendor", "nothex"), ("devnum", "128")):
            with self.subTest(attr=attr):
                self.write_attrs(self.physical, self.attrs)
                (self.physical / attr).write_text(value)
                with self.assertRaises(usb.ResetError):
                    self.inspect()

    def test_siblings_include_secondary_but_not_other_identical_radio(self):
        secondary = self.add_tty("ttyACM1", "02", 102)
        second_radio = self.physical.parent / "1-2"
        second_radio.mkdir()
        self.write_attrs(second_radio, self.attrs)
        self.add_tty("ttyACM2", "00", 103, second_radio)
        selected = self.inspect()
        ports = usb.sibling_ports(selected, self.sys, self.dev)
        self.assertEqual({item.port for item in ports}, {self.port, secondary})
        usb.require_primary_port(selected, ports)

    def test_secondary_interface_is_rejected(self):
        secondary = self.add_tty("ttyACM1", "02", 102)
        selected = self.inspect(secondary)
        with self.assertRaisesRegex(usb.ResetError, "primary"):
            usb.require_primary_port(selected, usb.sibling_ports(selected, self.sys, self.dev))

    def test_multiple_ttys_on_one_interface_are_ambiguous(self):
        self.add_tty("ttyACM1", "00", 102)
        selected = self.inspect()
        with self.assertRaisesRegex(usb.ResetError, "ambiguous"):
            usb.require_primary_port(selected, usb.sibling_ports(selected, self.sys, self.dev))

    def test_identity_verification_detects_every_identity_field(self):
        selected = self.inspect()
        for field in usb.IDENTITY_FIELDS:
            changed = dict(selected.identity(), **{field: "different"})
            with self.subTest(field=field), self.assertRaisesRegex(usb.ResetError, "identity changed"):
                usb.verify_identity(selected, changed)

    def test_identity_parser_accepts_inspection_or_inner_identity(self):
        selected = self.inspect()
        for value in (selected.identity(), selected.result("inspected")):
            self.assertEqual(usb.parse_expected_identity(json.dumps(value)), selected.identity())

    def test_identity_parser_rejects_incomplete_or_malformed_data(self):
        for value in ("null", "[]", "no-json", "{}", '{"usb_serial":"ABC"}'):
            with self.subTest(value=value), self.assertRaises(usb.ResetError):
                usb.parse_expected_identity(value)

    def test_busy_secondary_interface_blocks_entire_usb_device(self):
        self.add_tty("ttyACM1", "02", 102)
        descriptors = self.proc / "123" / "fd"
        descriptors.mkdir(parents=True)
        descriptor = descriptors / "4"
        descriptor.touch()
        self.device_numbers[descriptor] = 102
        selected = self.inspect()
        ports = usb.sibling_ports(selected, self.sys, self.dev)
        self.assertEqual(usb.serial_owners(ports, self.proc), [123])
        with self.assertRaisesRegex(usb.ResetError, "123"):
            usb.require_unused(ports, self.proc)

    def test_unused_ttys_pass(self):
        self.assertEqual(usb.serial_owners([self.inspect()], self.proc), [])

    def test_unreadable_process_fds_fail_closed(self):
        descriptors = self.proc / "123" / "fd"
        descriptors.mkdir(parents=True)
        real_iterdir = Path.iterdir

        def unreadable(path):
            if path == descriptors:
                raise PermissionError("denied")
            return real_iterdir(path)

        with mock.patch.object(Path, "iterdir", unreadable):
            with self.assertRaisesRegex(usb.ResetError, "all serial owners"):
                usb.serial_owners([self.inspect()], self.proc)

    def test_port_return_can_change_tty_number(self):
        selected = self.inspect()
        self.mapping.pop("ttyACM0")
        (self.sys / "class" / "tty" / "ttyACM0").rmdir()
        new_port = self.add_tty("ttyACM3", "00", 104)
        returned = usb.wait_for_port(selected, 0, self.sys, self.dev)
        self.assertEqual(returned.port, new_port)

    def test_port_return_rejects_swapped_serial(self):
        selected = self.inspect()
        (self.physical / "serial").write_text("DIFFERENT")
        with self.assertRaisesRegex(usb.ResetError, "same radio did not return"):
            usb.wait_for_port(selected, 0, self.sys, self.dev)

    def test_port_return_wait_is_bounded(self):
        selected = self.inspect()
        with mock.patch.object(usb, "sibling_ports", return_value=[]), \
                mock.patch.object(usb.time, "monotonic", side_effect=[0, 0, 0, 2]), \
                mock.patch.object(usb.time, "sleep") as sleep:
            with self.assertRaisesRegex(usb.ResetError, "timeout"):
                usb.wait_for_port(selected, 1, self.sys, self.dev)
            sleep.assert_called_once()


class ResetExecutionTests(unittest.TestCase):
    def setUp(self):
        self.selected = usb.UsbPort(Path("/dev/ttyACM0"), Path("/sys/devices/usb1/1-1"),
                                    "CC8DA2E96F34", "303a", "1001", "00", 1, 9)
        self.fake_fcntl = types.SimpleNamespace(ioctl=mock.Mock())
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)

        def patch(*args, **kwargs):
            return self.stack.enter_context(mock.patch(*args, **kwargs))

        patch.dict = lambda *args, **kwargs: self.stack.enter_context(mock.patch.dict(*args, **kwargs))
        patch.dict(sys.modules, {"fcntl": self.fake_fcntl})
        patch.object = lambda *args, **kwargs: self.stack.enter_context(mock.patch.object(*args, **kwargs))
        self.patch = patch
        patch.object(usb.sys, "platform", "linux")
        self.uid = patch.object(usb.os, "geteuid", return_value=0, create=True)
        patch.object(usb.os, "O_CLOEXEC", 0, create=True)
        patch.object(usb.os, "O_NOFOLLOW", 0, create=True)
        patch.object(usb.os, "makedev", return_value=8, create=True)
        self.open = patch.object(usb.os, "open", return_value=5)
        self.close = patch.object(usb.os, "close")
        self.fstat = patch.object(usb.os, "fstat", return_value=types.SimpleNamespace(st_mode=stat.S_IFCHR, st_rdev=8))
        self.inspect = patch.object(usb, "inspect_port", return_value=self.selected)
        self.siblings = patch.object(usb, "sibling_ports", return_value=[self.selected])
        self.unused = patch.object(usb, "require_unused")
        self.wait = patch.object(usb, "wait_for_port", return_value=self.selected)
        self.deadline = patch.object(usb, "ioctl_deadline", side_effect=lambda _timeout: contextlib.nullcontext())

    def reset(self):
        return usb.reset_port("/dev/ttyACM0", self.selected.identity())

    def test_success_uses_only_one_device_reset_ioctl(self):
        self.assertEqual(self.reset(), self.selected)
        self.open.assert_called_once()
        self.assertEqual(str(self.open.call_args.args[0]), str(Path("/dev/bus/usb/001/009")))
        self.fake_fcntl.ioctl.assert_called_once_with(5, 0x5514, 0)
        self.close.assert_called_once_with(5)
        self.assertEqual(self.unused.call_count, 2)
        self.assertEqual(self.inspect.call_count, 3)

    def test_requires_root(self):
        self.uid.return_value = 1000
        with self.assertRaisesRegex(usb.ResetError, "sudo/root"):
            self.reset()
        self.open.assert_not_called()

    def test_changed_identity_never_opens_device(self):
        with self.assertRaisesRegex(usb.ResetError, "identity changed"):
            usb.reset_port("/dev/ttyACM0", dict(self.selected.identity(), usb_serial="DIFFERENT"))
        self.open.assert_not_called()

    def test_busy_port_never_opens_device(self):
        self.unused.side_effect = usb.ResetError("busy")
        with self.assertRaisesRegex(usb.ResetError, "busy"):
            self.reset()
        self.open.assert_not_called()

    def test_owner_appearing_during_reset_preflight_blocks_ioctl(self):
        self.unused.side_effect = [None, usb.ResetError("busy")]
        with self.assertRaisesRegex(usb.ResetError, "busy"):
            self.reset()
        self.fake_fcntl.ioctl.assert_not_called()
        self.close.assert_called_once_with(5)

    def test_recycled_usb_address_is_detected_before_ioctl(self):
        changed = usb.UsbPort(**dict(self.selected.__dict__, devnum=10))
        self.inspect.side_effect = [self.selected, changed]
        with self.assertRaisesRegex(usb.ResetError, "address changed"):
            self.reset()
        self.fake_fcntl.ioctl.assert_not_called()
        self.close.assert_called_once_with(5)

    def test_identity_change_at_last_check_blocks_ioctl(self):
        changed = usb.UsbPort(**dict(self.selected.__dict__, usb_serial="DIFFERENT"))
        self.inspect.side_effect = [self.selected, self.selected, changed]
        with self.assertRaisesRegex(usb.ResetError, "identity changed"):
            self.reset()
        self.fake_fcntl.ioctl.assert_not_called()

    def test_opened_wrong_device_node_is_rejected(self):
        self.fstat.return_value.st_rdev = 99
        with self.assertRaisesRegex(usb.ResetError, "device node changed"):
            self.reset()
        self.fake_fcntl.ioctl.assert_not_called()

    def test_ioctl_failure_closes_descriptor_without_retry(self):
        self.fake_fcntl.ioctl.side_effect = OSError(5, "Input/output error")
        with self.assertRaisesRegex(usb.ResetError, "Input/output error"):
            self.reset()
        self.fake_fcntl.ioctl.assert_called_once()
        self.close.assert_called_once_with(5)
        self.wait.assert_not_called()

    def test_ioctl_deadline_error_closes_without_waiting_or_retrying(self):
        self.fake_fcntl.ioctl.side_effect = usb.ResetError("timed out")
        with self.assertRaisesRegex(usb.ResetError, "timed out"):
            self.reset()
        self.close.assert_called_once_with(5)
        self.wait.assert_not_called()

    def test_expired_preflight_deadline_never_issues_reset(self):
        self.patch.object(usb.time, "monotonic", side_effect=[0, 11])
        with self.assertRaisesRegex(usb.ResetError, "no reset was issued"):
            self.reset()
        self.fake_fcntl.ioctl.assert_not_called()
        self.close.assert_called_once_with(5)

    def test_inspect_cli_never_opens_device(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(usb.main(["--port", "/dev/ttyACM0", "--inspect"]), 0)
        self.assertEqual(json.loads(output.getvalue()), self.selected.result("inspected"))
        self.open.assert_not_called()
        self.uid.assert_not_called()

    def test_missing_expected_identity_is_json_error(self):
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            self.assertEqual(usb.main(["--port", "/dev/ttyACM0"]), 1)
        self.assertEqual(json.loads(output.getvalue())["status"], "error")
        self.open.assert_not_called()

    def test_invalid_timeout_cannot_reset(self):
        for timeout in ("0", "31", "nan", "inf"):
            with self.subTest(timeout=timeout), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(usb.main(["--port", "/dev/ttyACM0", "--timeout", timeout]), 1)
        self.open.assert_not_called()


class DeadlineTests(unittest.TestCase):
    @unittest.skipUnless(hasattr(signal, "SIGALRM"), "Linux/POSIX signal deadline")
    def test_deadline_raises_and_restores_signal_state(self):
        original = signal.getsignal(signal.SIGALRM)
        with self.assertRaisesRegex(usb.ResetError, "timed out"):
            with usb.ioctl_deadline(0.01):
                signal.pause()
        self.assertEqual(signal.getsignal(signal.SIGALRM), original)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))


if __name__ == "__main__":
    unittest.main()
