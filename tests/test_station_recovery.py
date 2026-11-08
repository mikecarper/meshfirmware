"""Exercise real recovery plans against byte-addressed flash and injected failures."""
import hashlib
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import station_recovery as recovery
from meshcore_partition_expansion import canonical_table


def image():
    data = bytearray(b'\xff' * 0x17023)
    for offset in (0, 0x10000):
        data[offset:offset+4] = bytes([0xe9, 3, 2, 0x4f])
        data[offset+12:offset+14] = b'\x09\0'
        data[offset+23] = 1
    data[0x8000:0x9000] = canonical_table(0x1000000)
    return bytes(data)


class Flash:
    def __init__(self):
        self.memory = bytearray(b'\xa5' * recovery.FLASH_SIZE)
        self.memory[0x8000:0x9000] = canonical_table(recovery.FLASH_SIZE)
        self.events = []
        self.corrupt_nvs = False
        self.fail_write = False
        self.capacity_code = 24

    def flash_id(self):
        return (self.capacity_code << 16) | 0x40ef

    def read_flash(self, esp, start, size, **kwargs):
        return bytes(self.memory[start:start+size])

    def write_flash(self, esp, entries):
        if self.fail_write:
            raise RuntimeError('USB disconnected')
        for address, data in entries:
            self.events.append(('write', address, len(data)))
            # Model sector erase boundaries, not just payload byte writes.
            end = (address + len(data) + 4095) & ~4095
            self.memory[address:end] = b'\xff' * (end-address)
            self.memory[address:address+len(data)] = data
        if self.corrupt_nvs:
            self.memory[0x9000] ^= 1

    def verify_flash(self, esp, entries):
        for address, data in entries:
            self.events.append(('verify', address))
            assert bytes(self.memory[address:address+len(data)]) == data

    def erase_flash(self, esp):
        self.events.append(('erase',))
        self.memory[:] = b'\xff' * len(self.memory)

    def write_mem(self, esp, address, value, mask):
        self.events.append(('register', address, value, mask))

    def reset_chip(self, esp, kind):
        self.events.append(('reset', kind))


class RecoveryTests(unittest.TestCase):
    def test_pinned_board_role_matrix(self):
        self.assertEqual(set(recovery.IMAGES), {(b,r) for b in ('g2','g3') for r in ('repeater','room')})
        for target, digest in recovery.IMAGES.values():
            self.assertEqual(len(digest), 64)
            self.assertIn('Station_G', target)

    def test_valid_image_and_checksum(self):
        blob = image()
        recovery.validate_image(blob, hashlib.sha256(blob).hexdigest())
        with self.assertRaisesRegex(RuntimeError, 'checksum'):
            recovery.validate_image(blob, '0' * 64)

    def test_wrong_chip_mode_and_partition_rejected(self):
        for offset, value in [(2, 0), (0x10002, 0), (12, 0), (0x1000c, 0), (3, 0x2f)]:
            data = bytearray(image()); data[offset] = value
            with self.subTest(offset=offset), self.assertRaises(RuntimeError):
                recovery.validate_image(data, hashlib.sha256(data).hexdigest())

    def test_preserve_uses_app_boot_selection_order_and_keeps_data(self):
        flash = Flash()
        table = bytes(flash.memory[0x8000:0x9000])
        nvs = bytes(flash.memory[0x9000:0xe000])
        app1_and_fs = hashlib.sha256(flash.memory[0x650000:]).digest()
        recovery.perform_recovery(flash, flash, image(), False)
        self.assertEqual(flash.events, [
            ('write', 0x10000, len(image())-0x10000), ('verify', 0x10000),
            ('write', 0, 0x8000), ('verify', 0), ('write', 0xe000, 0x2000), ('verify', 0xe000)])
        self.assertEqual(table, bytes(flash.memory[0x8000:0x9000]))
        self.assertEqual(nvs, bytes(flash.memory[0x9000:0xe000]))
        self.assertEqual(app1_and_fs, hashlib.sha256(flash.memory[0x650000:]).digest())

    def test_old_or_damaged_layout_never_written_without_factory(self):
        for table in [b'\xff'*4096, canonical_table(4 << 20), b'\0'*4096]:
            flash = Flash(); flash.memory[0x8000:0x9000] = table
            with self.assertRaisesRegex(RuntimeError, 'No flash was changed'):
                recovery.perform_recovery(flash, flash, image(), False)
            self.assertEqual(flash.events, [])

    def test_factory_is_explicit_full_erase_and_merged_write(self):
        flash = Flash(); flash.memory[0x8000:0x9000] = b'\xff'*4096
        recovery.perform_recovery(flash, flash, image(), True)
        self.assertEqual(flash.events, [('erase',), ('write', 0, len(image())), ('verify', 0)])
        self.assertEqual(flash.memory[0xc90000:], b'\xff' * (0x1000000-0xc90000))

    def test_wrong_capacity_no_writes(self):
        flash = Flash(); flash.capacity_code = 23
        with self.assertRaisesRegex(RuntimeError, 'capacity'):
            recovery.perform_recovery(flash, flash, image(), True)
        self.assertEqual(flash.events, [])

    def test_failed_write_does_not_change_boot_selection(self):
        flash = Flash(); flash.fail_write = True
        with self.assertRaisesRegex(RuntimeError, 'disconnected'):
            recovery.perform_recovery(flash, flash, image(), False)
        self.assertEqual(flash.events, [])
        self.assertEqual(flash.memory[0xe000:0x10000], b'\xa5'*8192)

    def test_nvs_readback_failure_is_reported(self):
        flash = Flash(); flash.corrupt_nvs = True
        with self.assertRaisesRegex(RuntimeError, 'NVS readback'):
            recovery.perform_recovery(flash, flash, image(), False)

    def test_native_finish_uses_masked_clear_then_watchdog(self):
        flash = Flash()
        recovery.finish_native(flash, flash)
        self.assertEqual(flash.events, [('register', 0x6000812c, 0, 1), ('reset', 'watchdog-reset')])

    def test_usb_rename_keeps_identity_not_old_port_number(self):
        a = SimpleNamespace(vid=0x303a, pid=0x1001, serial_number='123', location='1-1', device='COM3')
        b = SimpleNamespace(**{**vars(a), 'device':'COM4'})
        self.assertTrue(recovery.same_port(b, a))
        b.serial_number = '456'
        self.assertFalse(recovery.same_port(b, a))
        a.serial_number = b.serial_number = None
        self.assertTrue(recovery.same_port(b, a))
        b.location = '1-2'
        self.assertFalse(recovery.same_port(b, a))

    def test_live_mac_must_match_native_serial(self):
        selected = SimpleNamespace(vid=0x303a, serial_number='00:01:02:03:04:05')
        chip = SimpleNamespace(CHIP_NAME='ESP32-S3', secure_download_mode=False,
            get_flash_encryption_enabled=lambda:False, get_secure_boot_enabled=lambda:False,
            read_mac=lambda:tuple(range(6)))
        self.assertEqual(recovery.check_device(chip, selected), '000102030405')
        selected.serial_number = '000102030406'
        with self.assertRaisesRegex(RuntimeError, 'identity'):
            recovery.check_device(chip, selected)
        chip.CHIP_NAME = 'ESP32'
        with self.assertRaisesRegex(RuntimeError, 'Wrong chip'):
            recovery.check_device(chip, selected)

    def test_busy_port_never_opened_or_stopped(self):
        with patch.object(recovery.sys, 'platform', 'linux'), patch.object(recovery.shutil, 'which', return_value='/usr/bin/fuser'):
            for code, output in [(0, '1234'), (2, '')]:
                with patch.object(recovery.subprocess, 'run', return_value=SimpleNamespace(returncode=code, stdout=output, stderr='')) as runner:
                    with self.assertRaisesRegex(RuntimeError, 'in use'):
                        recovery.assert_port_idle('/dev/ttyACM0')
                    self.assertEqual(runner.call_args.args[0], ['fuser', '/dev/ttyACM0'])

    def test_boot_confirmation_requires_matching_cli_and_no_crash(self):
        valid = 'Firmware: v1.18.0.1\nver\n -> v1.18.0.1-halo-keymind-cascade-dev-03214a16\nboard\n -> Station G3\n'
        self.assertTrue(recovery.boot_confirmed(valid, 'g3', False))
        self.assertFalse(recovery.boot_confirmed(valid, 'g2', False))
        self.assertFalse(recovery.boot_confirmed('Firmware: v1.18.0.1', 'g3', False))
        self.assertFalse(recovery.boot_confirmed(valid + 'Backtrace:', 'g3', False))
        self.assertFalse(recovery.boot_confirmed(valid + 'Firmware: v1.18.0.1', 'g3', False))
        self.assertFalse(recovery.boot_confirmed(valid.replace('03214a16', 'deadbeef'), 'g3', False))
        self.assertTrue(recovery.boot_confirmed(valid.replace('03214a16', 'deadbeef'), 'g3', True))


class Wizard(unittest.TestCase):
    def options(self, answers):
        args = SimpleNamespace(factory_reset=False, reset_only=False, role=None, manual_boot=False)
        with patch('builtins.input', side_effect=answers):
            recovery.guided_options(args)
        return args

    def test_defaults_keep_settings(self):
        args = self.options(['', '', ''])
        self.assertFalse(args.factory_reset or args.reset_only or args.manual_boot)
        self.assertEqual(args.role, 'repeater')

    def test_factory_room_manual_boot(self):
        args = self.options(['2', 'room', 'yes'])
        self.assertTrue(args.factory_reset and args.manual_boot)
        self.assertFalse(args.reset_only)
        self.assertEqual(args.role, 'room')

    def test_reset_only_and_invalid_input(self):
        self.assertTrue(self.options(['3', 'y']).reset_only)
        for answers in (['9'], ['1', 'wrong'], ['1', 'room', 'wrong']):
            with self.assertRaises(RuntimeError):
                self.options(answers)

    def test_bootstrap_before_any_prompt(self):
        with patch.object(sys, 'argv', ['recovery', '--guided']), \
                patch.object(recovery, 'ensure_runtime', side_effect=SystemExit(0)), \
                patch('builtins.input') as prompt:
            with self.assertRaises(SystemExit):
                recovery.main()
            prompt.assert_not_called()


if __name__ == '__main__':
    unittest.main()
