import contextlib
import ctypes
import errno
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import types
import unittest
from unittest import mock

import test_meshcore_usb_reset as reset_tests

usb = reset_tests.usb


TOOLS = Path(__file__).resolve().parents[1] / "tools"
SPEC = importlib.util.spec_from_file_location("meshcore_esp32_bootloader", TOOLS / "meshcore_esp32_bootloader.py")
boot = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = boot
SPEC.loader.exec_module(boot)


class NativeInspectionTests(unittest.TestCase):
    setUp = reset_tests.FakeSysfs.setUp
    write_attrs = reset_tests.FakeSysfs.write_attrs
    add_tty = reset_tests.FakeSysfs.add_tty
    inspect = reset_tests.FakeSysfs.inspect

    def descriptors(self, product="Heltec V4 - TinyUSB CDC", label="TinyUSB CDC",
                    cls="02", subclass="02", protocol="01"):
        self.write_attrs(self.physical, {"product": product})
        self.write_attrs(self.mapping["ttyACM0"], {"interface": label, "bInterfaceClass": cls,
                                                 "bInterfaceSubClass": subclass, "bInterfaceProtocol": protocol})

    def test_identical_vid_pid_is_not_enough_to_select_tinyusb(self):
        self.descriptors(product="Heltec V4", label="Serial")
        self.assertEqual(boot.inspect_native(self.inspect()).mode, "unknown")

    def test_tinyusb_cdc_product_and_interface_are_identified(self):
        self.descriptors()
        native = boot.inspect_native(self.inspect())
        self.assertEqual(native.mode, "tinyusb")
        boot.require_tinyusb(native)

    def test_hardware_jtag_is_identified_and_refused(self):
        self.descriptors(product="USB JTAG/serial debug unit", label="CDC")
        native = boot.inspect_native(self.inspect())
        self.assertEqual(native.mode, "hardware_jtag")
        with self.assertRaisesRegex(boot.BootloaderError, "hardware USB"):
            boot.require_tinyusb(native)

    def test_conflicting_tinyusb_jtag_descriptors_are_unknown(self):
        self.descriptors(product="USB JTAG/serial debug unit", label="TinyUSB CDC")
        self.assertEqual(boot.inspect_native(self.inspect()).mode, "unknown")

    def test_non_cdc_and_non_espressif_tinyusb_are_refused(self):
        self.descriptors(cls="ff")
        self.assertEqual(boot.inspect_native(self.inspect()).mode, "unknown")
        self.descriptors()
        (self.physical / "idVendor").write_text("239a")
        self.assertEqual(boot.inspect_native(self.inspect()).mode, "unknown")

    def test_missing_interface_descriptor_fails_closed(self):
        self.descriptors()
        (self.mapping["ttyACM0"] / "bInterfaceClass").unlink()
        with self.assertRaises(boot.BootloaderError):
            boot.inspect_native(self.inspect())

    def test_snapshot_detects_descriptor_and_usb_address_changes(self):
        self.descriptors()
        selected = self.inspect()
        native = boot.inspect_native(selected)
        self.assertEqual(boot.verify_snapshot(selected, native), native)
        (self.physical / "product").write_text("USB JTAG/serial debug unit")
        with self.assertRaisesRegex(boot.BootloaderError, "descriptors changed"):
            boot.verify_snapshot(selected, native)
        self.descriptors()
        (self.physical / "devnum").write_text("10")
        with self.assertRaisesRegex(boot.BootloaderError, "address changed"):
            boot.verify_snapshot(selected, native)

    def test_snapshot_detects_identity_swap_without_tty(self):
        self.descriptors()
        selected = self.inspect()
        native = boot.inspect_native(selected)
        (self.physical / "serial").write_text("ANOTHER_RADIO")
        with self.assertRaisesRegex(boot.BootloaderError, "identity changed"):
            boot.verify_snapshot(selected, native)


class EntryExecutionTests(unittest.TestCase):
    def setUp(self):
        self.selected = usb.UsbPort(Path("/dev/ttyACM4"), Path("/sys/devices/usb1/1-1.3.3"),
                                    "441BF669C9C0", "303a", "1001", "00", 1, 9)
        self.native = boot.NativeUsb("tinyusb", self.selected.usb_path / "1-1.3.3:1.0",
                                     "Heltec V4 - TinyUSB CDC", "TinyUSB CDC", "02", "02", "01", "cdc_acm")
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)

        def patch(*args, **kwargs):
            return self.stack.enter_context(mock.patch.object(*args, **kwargs))

        self.patch = patch
        patch(boot.sys, "platform", "linux")
        self.machine = patch(boot.platform, "machine", return_value="aarch64")
        self.uid = patch(boot.os, "geteuid", return_value=0, create=True)
        patch(boot.os, "O_CLOEXEC", 0, create=True)
        patch(boot.os, "O_NOFOLLOW", 0, create=True)
        patch(boot.os, "makedev", return_value=8, create=True)
        self.open = patch(boot.os, "open", return_value=5)
        self.close = patch(boot.os, "close")
        self.fstat = patch(boot.os, "fstat", return_value=types.SimpleNamespace(st_mode=stat.S_IFCHR, st_rdev=8))
        self.inspect = patch(usb, "inspect_port", return_value=self.selected)
        self.native_inspect = patch(boot, "inspect_native", return_value=self.native)
        self.siblings = patch(usb, "sibling_ports", return_value=[self.selected])
        self.unused = patch(usb, "require_unused")
        self.snapshot = patch(boot, "verify_snapshot", return_value=self.native)
        patch(usb, "ioctl_deadline", side_effect=lambda _timeout: contextlib.nullcontext())
        self.fcntl = types.SimpleNamespace(ioctl=mock.Mock(return_value=0))
        self.stack.enter_context(mock.patch.dict(sys.modules, {"fcntl": self.fcntl}))
        self.calls = []

        def ioctl(descriptor, command, value):
            data = ctypes.string_at(value.data, value.length) if isinstance(value, boot.ControlTransfer) else None
            self.calls.append((descriptor, command, value, data))
            return len(data) if data is not None else 0

        self.ioctl = patch(boot, "ioctl_structure", side_effect=ioctl)

    def enter(self, expected=None):
        return boot.enter_bootloader(str(self.selected.port), expected or self.selected.identity())

    def test_exact_seven_byte_request_and_conditional_cdc_claim(self):
        result = self.enter()
        self.assertEqual(result["status"], "request_issued")
        self.assertFalse(result["rom_verified"])
        self.assertFalse(result["disconnected_during_request"])
        self.assertEqual(self.unused.call_count, 2)
        self.assertEqual(len(self.calls), 2)
        descriptor, command, claim, _data = self.calls[0]
        self.assertEqual((descriptor, command), (5, boot.USBDEVFS_DISCONNECT_CLAIM))
        self.assertEqual((claim.interface, claim.flags, claim.driver), (0, 1, b"cdc_acm"))
        descriptor, command, transfer, data = self.calls[1]
        self.assertEqual((descriptor, command), (5, boot.USBDEVFS_CONTROL))
        self.assertEqual((transfer.request_type, transfer.request, transfer.value, transfer.index, transfer.length),
                         (0x21, 0x20, 0, 0, 7))
        self.assertEqual(data, b"\xb0\x04\x00\x00\x00\x00\x08")
        self.fcntl.ioctl.assert_called_once_with(5, boot.USBDEVFS_RELEASEINTERFACE, b"\x00\x00\x00\x00")
        self.close.assert_called_once_with(5)
        self.assertNotIn(0x5514, [item[1] for item in self.calls])

    def test_requires_root_before_opening_anything(self):
        self.uid.return_value = 1000
        with self.assertRaisesRegex(boot.BootloaderError, "sudo/root"):
            self.enter()
        self.open.assert_not_called()

    def test_unknown_ioctl_abi_never_opens_usb(self):
        self.machine.return_value = "mips64"
        with self.assertRaisesRegex(boot.BootloaderError, "Unsupported Linux ioctl ABI"):
            self.enter()
        self.open.assert_not_called()

    def test_wrong_native_mode_never_opens_usb(self):
        self.native_inspect.return_value = boot.NativeUsb(**dict(self.native.__dict__, mode="hardware_jtag"))
        with self.assertRaisesRegex(boot.BootloaderError, "hardware USB"):
            self.enter()
        self.open.assert_not_called()

    def test_changed_identity_never_opens_usb(self):
        with self.assertRaisesRegex(boot.BootloaderError, "identity changed"):
            self.enter(dict(self.selected.identity(), usb_serial="OTHER"))
        self.open.assert_not_called()

    def test_busy_primary_or_secondary_never_opens_usb(self):
        self.unused.side_effect = boot.BootloaderError("busy secondary")
        with self.assertRaisesRegex(boot.BootloaderError, "busy secondary"):
            self.enter()
        self.open.assert_not_called()

    def test_owner_appearing_after_usb_open_blocks_all_ioctls(self):
        self.unused.side_effect = [None, boot.BootloaderError("new owner")]
        with self.assertRaisesRegex(boot.BootloaderError, "new owner"):
            self.enter()
        self.ioctl.assert_not_called()
        self.close.assert_called_once_with(5)

    def test_recycled_usb_address_blocks_request(self):
        changed = usb.UsbPort(**dict(self.selected.__dict__, devnum=10))
        self.inspect.side_effect = [self.selected, changed]
        with self.assertRaisesRegex(boot.BootloaderError, "address changed"):
            self.enter()
        self.ioctl.assert_not_called()

    def test_incorrect_opened_device_node_blocks_request(self):
        self.fstat.return_value.st_rdev = 99
        with self.assertRaisesRegex(boot.BootloaderError, "device node changed"):
            self.enter()
        self.ioctl.assert_not_called()

    def test_changed_descriptors_after_open_block_request(self):
        changed = boot.NativeUsb(**dict(self.native.__dict__, product_label="another TinyUSB CDC"))
        self.native_inspect.side_effect = [self.native, changed]
        with self.assertRaisesRegex(boot.BootloaderError, "descriptors or driver changed"):
            self.enter()
        self.ioctl.assert_not_called()

    def test_last_identity_change_blocks_control_after_claim(self):
        self.snapshot.side_effect = [None, boot.BootloaderError("identity changed"), boot.BootloaderError("gone")]
        with self.assertRaisesRegex(boot.BootloaderError, "identity changed"):
            self.enter()
        self.assertEqual([call[1] for call in self.calls], [boot.USBDEVFS_DISCONNECT_CLAIM])

    def test_disconnect_during_request_is_issued_but_not_rom_verified(self):
        self.patch(boot, "request_line_coding", side_effect=OSError(errno.ENODEV, "disconnected"))
        self.snapshot.side_effect = [None, None, boot.BootloaderError("gone")]
        self.fcntl.ioctl.side_effect = OSError(errno.ENODEV, "disconnected")
        result = self.enter()
        self.assertTrue(result["disconnected_during_request"])
        self.assertFalse(result["rom_verified"])
        self.close.assert_called_once_with(5)

    def test_cleanup_uses_verified_snapshot_without_rereading_disappearing_interface(self):
        self.snapshot.return_value = self.native
        # The callback accepted the request. An additional descriptor read can
        # race the reboot after cleanup has already verified this connection.
        self.native_inspect.side_effect = [
            self.native, self.native,
            boot.BootloaderError("Cannot read bInterfaceClass"),
        ]
        result = self.enter()
        self.assertEqual(result["status"], "request_issued")
        self.assertFalse(result["rom_verified"])
        self.assertEqual(self.native_inspect.call_count, 2)
        self.assertEqual([call[1] for call in self.calls],
                         [boot.USBDEVFS_DISCONNECT_CLAIM, boot.USBDEVFS_CONTROL])
        self.close.assert_called_once_with(5)

    def test_cleanup_unverified_connection_never_rebinds_or_claims_rom_success(self):
        for error in (
                boot.BootloaderError("Cannot read bInterfaceClass"),
                boot.BootloaderError("USB identity changed during bootloader entry."),
                boot.BootloaderError("USB descriptors changed during bootloader entry."),
                OSError(errno.ENODEV, "connection disappeared"),
                ValueError("address attribute disappeared")):
            with self.subTest(error=str(error)):
                self.calls.clear()
                self.close.reset_mock()
                self.snapshot.side_effect = [self.native, self.native, error]
                result = self.enter()
                self.assertEqual(result["status"], "request_issued")
                self.assertFalse(result["rom_verified"])
                self.assertEqual([call[1] for call in self.calls],
                                 [boot.USBDEVFS_DISCONNECT_CLAIM, boot.USBDEVFS_CONTROL])
                self.close.assert_called_once_with(5)

    def test_cleanup_disappearance_preserves_failed_request(self):
        self.snapshot.side_effect = [
            self.native, self.native, boot.BootloaderError("Cannot read bInterfaceClass"),
        ]
        self.patch(boot, "request_line_coding", side_effect=OSError(errno.ETIMEDOUT, "timed out"))
        with self.assertRaisesRegex(boot.BootloaderError, "errno " + str(errno.ETIMEDOUT)):
            self.enter()
        self.assertEqual([call[1] for call in self.calls], [boot.USBDEVFS_DISCONNECT_CLAIM])
        self.close.assert_called_once_with(5)

    def test_cleanup_unexpected_driver_never_rebinds(self):
        changed = boot.NativeUsb(**dict(self.native.__dict__, driver="another_driver"))
        self.snapshot.side_effect = [self.native, self.native, changed]
        with self.assertRaisesRegex(boot.BootloaderError, "driver changed during cleanup"):
            self.enter()
        self.assertEqual([call[1] for call in self.calls],
                         [boot.USBDEVFS_DISCONNECT_CLAIM, boot.USBDEVFS_CONTROL])
        self.close.assert_called_once_with(5)

    def test_cleanup_disconnect_before_rebind_is_not_rom_proof(self):
        unbound = boot.NativeUsb(**dict(self.native.__dict__, driver=""))
        self.snapshot.side_effect = [self.native, self.native, unbound]
        original_ioctl = self.ioctl.side_effect

        def disconnect_rebind(descriptor, command, value):
            if command == boot.USBDEVFS_IOCTL:
                self.calls.append((descriptor, command, value, None))
                raise OSError(errno.ENODEV, "original connection disappeared")
            return original_ioctl(descriptor, command, value)

        self.ioctl.side_effect = disconnect_rebind
        result = self.enter()
        self.assertEqual(result["status"], "request_issued")
        self.assertFalse(result["rom_verified"])
        self.assertEqual([call[1] for call in self.calls],
                         [boot.USBDEVFS_DISCONNECT_CLAIM, boot.USBDEVFS_CONTROL, boot.USBDEVFS_IOCTL])
        self.assertEqual(self.calls[-1][0], 5)
        self.close.assert_called_once_with(5)

    def test_timeout_restores_only_original_cdc_interface(self):
        unbound = boot.NativeUsb(**dict(self.native.__dict__, driver=""))
        self.snapshot.side_effect = [self.native, self.native, unbound]
        self.patch(boot, "request_line_coding", side_effect=OSError(errno.ETIMEDOUT, "timed out"))
        with self.assertRaisesRegex(boot.BootloaderError, "errno " + str(errno.ETIMEDOUT)):
            self.enter()
        self.assertEqual([call[1] for call in self.calls],
                         [boot.USBDEVFS_DISCONNECT_CLAIM, boot.USBDEVFS_IOCTL])
        restore = self.calls[-1][2]
        self.assertEqual((restore.interface, restore.code, restore.data), (0, boot.USBDEVFS_CONNECT, None))
        self.close.assert_called_once_with(5)

    def test_failed_conditional_claim_never_sends_request(self):
        self.ioctl.side_effect = OSError(errno.EBUSY, "busy")
        with self.assertRaisesRegex(boot.BootloaderError, "errno 16"):
            self.enter()
        self.ioctl.assert_called_once()
        self.fcntl.ioctl.assert_not_called()
        self.close.assert_called_once_with(5)

    def test_short_control_transfer_is_not_success(self):
        self.patch(boot, "request_line_coding", return_value=0)
        with self.assertRaisesRegex(boot.BootloaderError, "not fully accepted"):
            self.enter()

    def test_inspection_only_is_read_only_and_does_not_require_root(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(boot.main(["--port", str(self.selected.port), "--inspect"]), 0)
        self.assertEqual(json.loads(output.getvalue())["native_mode"], "tinyusb")
        self.open.assert_not_called()
        self.uid.assert_not_called()

    def test_cli_requires_selection_snapshot(self):
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            self.assertEqual(boot.main(["--port", str(self.selected.port)]), 1)
        self.assertEqual(json.loads(output.getvalue())["status"], "error")
        self.open.assert_not_called()

    def test_invalid_timeout_never_opens_usb(self):
        for value in ("0", "31", "nan", "inf"):
            with self.subTest(value=value), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(boot.main(["--port", str(self.selected.port), "--timeout", value]), 1)
        self.open.assert_not_called()


if __name__ == "__main__":
    unittest.main()
