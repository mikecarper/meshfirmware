"""Real multi-chip images and sector-erasing flash fixtures; no hardware touched."""
import contextlib
import hashlib
import io
from pathlib import Path
import struct
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import esp32_recovery as recovery
from esptool.targets import CHIP_DEFS


def application(chip, capacity=4 << 20, mode=0, payload=b'A' * 32):
    header = bytearray(24)
    header[:4] = bytes([0xe9, 1, mode, (capacity.bit_length()-21) << 4])
    header[12:14] = struct.pack('<H', chip)
    header[23] = 1
    body = bytes(header) + struct.pack('<II', 0x3ffb0000, len(payload)) + payload
    checksum = 0xef
    for b in payload:
        checksum ^= b
    body += b'\0' * (15 - len(body) % 16) + bytes([checksum])
    return body + hashlib.sha256(body).digest()


def table(single=False, factory=False, table_offset=0x8000):
    start = table_offset + 4096
    entries = [('nvs', 1, 2, start, 0x3000), ('otadata', 1, 0, start+0x3000, 0x2000)]
    entries += [('factory' if factory else 'app0', 0, 0 if factory else 0x10, 0x10000, 0x100000)]
    if not single:
        entries += [('app1', 0, 0x11, 0x110000, 0x100000)]
    entries += [('littlefs', 1, 0x83, 0x210000, 0x1f0000)]
    body = b''.join(struct.pack('<2sBBII16sI', b'\xaa\x50', kind, subtype, offset, size, name.encode(), 0)
                    for name, kind, subtype, offset, size in entries)
    body += b'\xeb\xeb' + b'\xff' * 14 + hashlib.md5(body).digest()
    return body.ljust(4096, b'\xff')


def merged(chip=9, base=0, single=False, factory=False, table_offset=0x8000):
    rom = next(c for c in CHIP_DEFS.values() if c.CHIP_NAME.startswith('ESP32') and c.IMAGE_CHIP_ID == chip)
    boot = application(chip)
    app = application(chip, payload=b'B'*32)
    data = bytearray(b'\xff' * (0x10000 + len(app)))
    data[rom.BOOTLOADER_FLASH_OFFSET:rom.BOOTLOADER_FLASH_OFFSET+len(boot)] = boot
    data[table_offset:table_offset+4096] = table(single, factory, table_offset)
    data[0x10000:] = app
    return bytes(data[base:])


class Flash:
    CHIP_NAME = 'ESP32-S3'
    IMAGE_CHIP_ID = 9
    def __init__(self, image):
        self.memory = bytearray(b'\xa5' * (4 << 20))
        at = image.table_offset
        self.memory[at:at+4096] = image.data[at-image.base:at-image.base+4096]
        self.events = []
        self.fail_at = None
        self.flash_code = 22
        self._port = SimpleNamespace(dtr=True)
    def flash_id(self):
        return self.flash_code << 16
    def read_flash(self, esp, start, length, **kwargs):
        return bytes(self.memory[start:start+length])
    def write_flash(self, esp, entries):
        for address, data in entries:
            if self.fail_at == address:
                raise RuntimeError('simulated disconnect')
            self.events.append(('write', address))
            end = (address+len(data)+4095) & ~4095
            self.memory[address:end] = b'\xff' * (end-address)
            self.memory[address:address+len(data)] = data
    def verify_flash(self, esp, entries):
        for address, data in entries:
            assert self.memory[address:address+len(data)] == data
            self.events.append(('verify', address))
    def erase_flash(self, esp):
        self.events.append(('erase',))
        self.memory[:] = b'\xff' * len(self.memory)
    def write_mem(self, esp, address, value, mask):
        self.events.append(('register', address, value, mask))
    def reset_chip(self, esp, mode):
        self.events.append(('reset', mode))


class Recovery(unittest.TestCase):
    def test_all_esptool_esp32_families_and_both_merged_bases(self):
        for rom in CHIP_DEFS.values():
            if not rom.CHIP_NAME.startswith('ESP32'):
                continue
            for base in {0, rom.BOOTLOADER_FLASH_OFFSET}:
                with self.subTest(chip=rom.CHIP_NAME, base=base):
                    image = recovery.inspect_firmware(merged(rom.IMAGE_CHIP_ID, base))
                    self.assertEqual(image.chip, rom.IMAGE_CHIP_ID)
                    self.assertEqual(image.boot_offset, rom.BOOTLOADER_FLASH_OFFSET)
                    self.assertEqual(image.base, base)
                    self.assertEqual(image.flash_bytes, 4 << 20)

    def test_single_slot_factory_and_custom_partition_offset(self):
        for single, factory, offset in [(True, False, 0x8000), (False, True, 0x8000), (True, True, 0x9000)]:
            with self.subTest(single=single, factory=factory, offset=offset):
                image = recovery.inspect_firmware(merged(single=single, factory=factory, table_offset=offset), offset)
                self.assertEqual(image.app['subtype'], 0 if factory else 0x10)
                self.assertEqual(image.table_offset, offset)

    def test_preserve_non_station_layout_and_selection_written_last(self):
        image = recovery.inspect_firmware(merged())
        flash = Flash(image)
        before = bytes(flash.memory)
        recovery.perform_recovery(flash, flash, image, False)
        self.assertEqual([event for event in flash.events if event[0]=='write'], [('write', 0x10000), ('write', 0), ('write', 0xc000)])
        self.assertEqual(flash.memory[0x8000:0xc000], before[0x8000:0xc000])
        self.assertEqual(flash.memory[0x110000:], before[0x110000:])
        self.assertEqual(flash.memory[0xc000:0xe000], b'\xff' * 8192)

    def test_interrupted_app_never_selects_it(self):
        image = recovery.inspect_firmware(merged())
        flash = Flash(image); flash.fail_at = 0x10000
        before = bytes(flash.memory)
        with self.assertRaisesRegex(RuntimeError, 'disconnect'):
            recovery.perform_recovery(flash, flash, image, False)
        self.assertEqual(flash.memory, before)
        self.assertEqual(flash.events, [])

    def test_full_flash_input_cannot_overwrite_saved_data_in_preserve_mode(self):
        data = merged().ljust(4 << 20, b'\xff')
        image = recovery.inspect_firmware(data)
        flash = Flash(image)
        before = bytes(flash.memory)
        recovery.perform_recovery(flash, flash, image, False)
        self.assertEqual(flash.memory[0x8000:0xc000], before[0x8000:0xc000])
        self.assertEqual(flash.memory[0x110000:], before[0x110000:])

    def test_verification_failure_leaves_boot_selection_unchanged(self):
        image = recovery.inspect_firmware(merged())
        flash = Flash(image)
        before = bytes(flash.memory)
        with patch.object(flash, 'verify_flash', side_effect=RuntimeError('readback failed')):
            with self.assertRaisesRegex(RuntimeError, 'readback failed'):
                recovery.perform_recovery(flash, flash, image, False)
        self.assertEqual(flash.memory[:0x10000], before[:0x10000])
        self.assertEqual(flash.events, [('write', 0x10000)])

    def test_layout_mismatch_is_never_an_automatic_erase(self):
        image = recovery.inspect_firmware(merged())
        flash = Flash(image); flash.memory[0x8000:0x9000] = b'\xff'*4096
        with self.assertRaises(recovery.LayoutMismatch):
            recovery.perform_recovery(flash, flash, image, False)
        self.assertEqual(flash.events, [])

    def test_factory_erase_uses_classic_esp32_file_offset(self):
        image = recovery.inspect_firmware(merged(chip=0, base=0x1000))
        flash = Flash(image)
        recovery.perform_recovery(flash, flash, image, True)
        self.assertEqual(flash.events, [('erase',), ('write', 0x1000), ('verify', 0x1000)])
        self.assertEqual(flash.memory[:0x1000], b'\xff'*4096)

    def test_too_small_flash_refuses_before_any_write_or_erase(self):
        image = recovery.inspect_firmware(merged())
        for factory in (True, False):
            flash = Flash(image); flash.flash_code = 21
            with self.assertRaisesRegex(RuntimeError, 'more flash'):
                recovery.perform_recovery(flash, flash, image, factory)
            self.assertEqual(flash.events, [])

    def test_corrupt_truncated_or_application_only_images_rejected(self):
        for blob in (application(9), merged()[:-34], b'\0'*4096):
            with self.assertRaises((RuntimeError, recovery.ExpansionError)):
                recovery.inspect_firmware(blob)
        blob = bytearray(merged()); blob[0x10020] ^= 1
        with self.assertRaisesRegex(RuntimeError, 'checksum'):
            recovery.inspect_firmware(bytes(blob))
        blob = bytearray(merged()); blob[-1] ^= 1
        with self.assertRaisesRegex(RuntimeError, 'digest'):
            recovery.inspect_firmware(bytes(blob))

    def test_wrong_chip_and_secure_device_refuse_before_writes(self):
        image = recovery.inspect_firmware(merged())
        esp = SimpleNamespace(CHIP_NAME='ESP32-C3', IMAGE_CHIP_ID=5, secure_download_mode=False,
            get_secure_boot_enabled=lambda:False, get_flash_encryption_enabled=lambda:False, read_mac=lambda:range(6))
        usb = SimpleNamespace(vid=0x303a, pid=0x1001, serial_number='00:01:02:03:04:05')
        with self.assertRaisesRegex(RuntimeError, 'Wrong chip'):
            recovery.check_device(esp, usb, image)
        esp.CHIP_NAME='ESP32-S3'; esp.IMAGE_CHIP_ID=9
        recovery.check_device(esp, usb, image)
        usb.serial_number='unrelated'
        with self.assertRaisesRegex(RuntimeError, 'MAC'):
            recovery.check_device(esp, usb, image)
        usb.vid=0x10c4
        esp.secure_download_mode=True
        with self.assertRaisesRegex(RuntimeError, 'Secure'):
            recovery.check_device(esp, usb, image)

    def test_native_s3_register_never_written_on_other_chips_or_uart(self):
        image = recovery.inspect_firmware(merged())
        for chip, native in [('ESP32', False), ('ESP32-S3', False), ('ESP32-S3', True), ('ESP32-C3', True), ('ESP32-C6', True), ('ESP32-S2', True)]:
            flash = Flash(image); flash.CHIP_NAME = chip
            recovery.finish_device(flash, flash, native)
            if chip=='ESP32-S3' and native:
                self.assertEqual(flash.events, [('register', 0x6000812c, 0, 1), ('reset', 'watchdog-reset')])
            else:
                self.assertEqual(flash.events, [('reset', 'hard-reset')])
                self.assertFalse(flash._port.dtr)

    def test_native_reenumeration_and_uart_identity_are_distinct(self):
        usb=SimpleNamespace(vid=0x303a,pid=0x1001,serial_number='00:01:02:03:04:05',location='1-2')
        runtime=SimpleNamespace(vid=0x303a,pid=0x1002,serial_number='000102030405',location='1-2')
        self.assertTrue(recovery.same_device(runtime, usb))
        runtime.serial_number='000102030406'
        self.assertFalse(recovery.same_device(runtime, usb))
        usb.vid=0x10c4; runtime.serial_number=usb.serial_number
        self.assertFalse(recovery.same_device(runtime, usb))

    def test_catalog_only_offers_full_esp32_installs_and_keeps_exact_variants(self):
        base=dict(architecture='esp32',action='flash-wipe',name='image.bin',hardware='Board',provider='MeshCore',role='repeater',version='1',url='https://example.com/image.bin')
        rows=[base,dict(base),dict(base,hardware='Board TFT'),dict(base,architecture='nrf52'),dict(base,action='flash-update'),dict(base,name='erase.uf2')]
        result=recovery.catalog_items({'items':rows})
        self.assertEqual([i['hardware'] for i in result], ['Board','Board TFT'])

    def test_guided_default_does_not_choose_factory_reset(self):
        with patch('builtins.input',return_value=''), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(recovery.choose('Operation',['keep','erase'],default=0),'keep')

    def test_no_boot_success_from_usb_banner_or_crash(self):
        valid=' -> v1.18.0.2\n -> Heltec V4 OLED\n'
        self.assertTrue(recovery.boot_confirmed(valid))
        for text in ('USB connected','Firmware: v1.18.0.2',valid+'Backtrace:',valid+'rst:0xc\nrst:0xc\n'):
            self.assertFalse(recovery.boot_confirmed(text))


if __name__ == '__main__':
    unittest.main()
