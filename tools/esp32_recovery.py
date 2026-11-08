#!/usr/bin/env python3
"""Recover ESP32-family boards over USB without querying the broken application."""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import sys
import time
import urllib.parse
import urllib.request

from meshcore_partition_expansion import parse_table, image_header, endf_identity, ExpansionError
from station_recovery import ensure_runtime, available_ports, assert_port_idle, finish_native

CATALOG_URL = 'https://mikecarper.github.io/meshfirmware/catalog.json'
MAX_IMAGE = 128 * 1024 * 1024
BOOT_HELP = '''If USB keeps disappearing, hold the board's BOOT/FLASH button, press and
release RESET/EN, then release BOOT. Alternatively hold BOOT while connecting
USB. Use the board manufacturer's instructions if its buttons differ.
BOOT is not GPIO0 on every ESP32 family. Do not wire a guessed GPIO.
Select manual BOOT mode below, or rerun with --manual-boot.
Close other flashers, serial terminals and services using this radio.'''


class LayoutMismatch(RuntimeError):
    pass


@dataclass
class Firmware:
    data: bytes
    base: int
    chip: int
    chip_name: str
    flash_bytes: int
    table_offset: int
    parts: list[dict]
    boot_offset: int
    boot: bytes
    app: dict
    application: bytes


def fetch(url, limit):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password:
        raise RuntimeError('Downloads require an HTTPS URL without credentials.')
    request = urllib.request.Request(url, headers={'User-Agent': 'meshfirmware-esp32-recovery'})
    with urllib.request.urlopen(request, timeout=60) as response:
        if urllib.parse.urlsplit(response.geturl()).scheme != 'https':
            raise RuntimeError('Download redirected away from HTTPS.')
        data = response.read(limit + 1)
    if len(data) > limit:
        raise RuntimeError('Download exceeds the permitted size.')
    return data


def choose(title, values, label=str, default=None):
    if not values:
        raise RuntimeError('No matching choices. Use a merged firmware BIN for the exact physical board.')
    if len(values) == 1:
        print(title + ': ' + label(values[0]))
        return values[0]
    shown = values
    while True:
        print('\n' + title)
        for number, value in enumerate(shown, 1):
            print(f'  {number}. {label(value)}')
        prompt = 'Number, text to filter, or * to show all'
        if default is not None:
            prompt += ' [Enter: ' + label(values[default]) + ']'
        answer = input(prompt + ': ').strip()
        if not answer and default is not None:
            return values[default]
        if answer.isdigit() and 1 <= int(answer) <= len(shown):
            return shown[int(answer)-1]
        if answer == '*':
            shown = values
        else:
            matches = [v for v in values if answer and answer.casefold() in label(v).casefold()]
            if matches:
                shown = matches
            else:
                print('No match; choose a listed number or enter part of its name.')


def catalog_items(catalog):
    result, seen = [], set()
    for item in catalog.get('items', []):
        if (not isinstance(item, dict) or 'esp32' not in str(item.get('architecture', '')).lower()
                or item.get('action') != 'flash-wipe' or not str(item.get('name', '')).lower().endswith('.bin')
                or any(not isinstance(item.get(k), str) or not item[k] for k in ('hardware', 'provider', 'role', 'version', 'url'))):
            continue
        key = tuple(item[k] for k in ('hardware', 'provider', 'role', 'version', 'url'))
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result


def choose_firmware():
    print('Loading the firmware catalog. Choose the exact physical board and variant; USB cannot identify its wiring.')
    items = catalog_items(json.loads(fetch(CATALOG_URL, 16 * 1024 * 1024)))
    for field, title in (('hardware', 'Board'), ('provider', 'Firmware provider'), ('role', 'Role')):
        value = choose(title, sorted({item[field] for item in items}))
        items = [item for item in items if item[field] == value]
    item = choose('Firmware image (check version and hardware variant)', items,
                  lambda i: f"{i['version']} - {i.get('title', i['role'])} - {i['name']}")
    print('Selected: ' + item['hardware'] + '\n' + item['url'])
    return item


def load_firmware(reference, expected_hash=None):
    if reference.startswith('https://'):
        data = fetch(reference, MAX_IMAGE)
    else:
        path = Path(reference).expanduser()
        if not path.is_file() or path.stat().st_size > MAX_IMAGE:
            raise RuntimeError('Firmware file is missing or too large.')
        data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if expected_hash and (not re.fullmatch('[0-9a-fA-F]{64}', expected_hash) or digest != expected_hash.lower()):
        raise RuntimeError('Firmware SHA256 mismatch. No device opened.')
    print('Firmware SHA256: ' + digest)
    return data


def checked_image(data):
    """Validate the image's own checksum/digest, not just its header magic."""
    from esptool.bin_image import LoadFirmwareImage
    from esptool.targets import CHIP_DEFS
    chip, capacity = image_header(data)
    classes = [c for c in CHIP_DEFS.values() if c.CHIP_NAME.startswith('ESP32') and c.IMAGE_CHIP_ID == chip]
    if len(classes) != 1:
        raise RuntimeError('This firmware chip is not supported by the recovery esptool version.')
    rom = classes[0]
    end = 24
    for _ in range(data[1]):
        if end + 8 > len(data):
            raise RuntimeError('Truncated ESP32 image segment header.')
        size = struct.unpack_from('<I', data, end + 4)[0]
        end += 8 + size
        if end > len(data):
            raise RuntimeError('Truncated ESP32 image segment.')
    end = (end // 16 + 1) * 16
    if data[23]:
        end += 32
    if end > len(data):
        raise RuntimeError('Truncated ESP32 image checksum/digest.')
    parsed = LoadFirmwareImage(rom.CHIP_NAME, data[:end])
    if parsed.calculate_checksum() != parsed.checksum:
        raise RuntimeError('ESP32 image checksum is invalid.')
    if parsed.append_digest and parsed.stored_digest != parsed.calc_digest:
        raise RuntimeError('ESP32 image SHA256 digest is invalid.')
    return rom, capacity, end


def inspect_firmware(data, table_offset=0x8000):
    from esptool.targets import CHIP_DEFS
    if table_offset < 0x8000 or table_offset % 4096:
        raise RuntimeError('Partition offset must be sector aligned and at least 0x8000.')
    candidates = []
    # Some classic ESP32 merged files start at 0x1000; others include padding
    # from zero. Derive offsets from esptool's chip definitions, never filename.
    bases = {0} | {c.BOOTLOADER_FLASH_OFFSET for c in CHIP_DEFS.values() if c.CHIP_NAME.startswith('ESP32')}
    for base in sorted(bases):
        index = table_offset - base
        if index < 0 or data[index:index+2] != b'\xaa\x50':
            continue
        for rom in CHIP_DEFS.values():
            if not rom.CHIP_NAME.startswith('ESP32'):
                continue
            boot_index = rom.BOOTLOADER_FLASH_OFFSET - base
            if boot_index < 0 or boot_index >= index:
                continue
            try:
                boot_rom, capacity, boot_len = checked_image(data[boot_index:index])
            except (RuntimeError, ExpansionError, ValueError):
                continue
            if boot_rom.IMAGE_CHIP_ID != rom.IMAGE_CHIP_ID:
                continue
            parts = parse_table(data[index:index+4096], capacity)
            if any(p['offset'] < table_offset + 4096 for p in parts):
                raise RuntimeError('Partition overlaps the bootloader/partition table.')
            if len(data) + base > capacity or any(p['flags'] & 1 for p in parts):
                raise RuntimeError('Image exceeds its declared flash size or contains protected partitions.')
            factory = [p for p in parts if p['type'] == 0 and p['subtype'] == 0]
            ota0 = [p for p in parts if p['type'] == 0 and p['subtype'] == 0x10]
            preferred = factory or ota0
            if len(preferred) != 1:
                raise RuntimeError('Recovery requires one factory application or OTA slot 0.')
            app = preferred[0]
            start = app['offset'] - base
            payload = data[start:min(start + app['size'], len(data))]
            app_rom, app_capacity, app_len = checked_image(payload)
            if app_rom.IMAGE_CHIP_ID != rom.IMAGE_CHIP_ID or app_capacity > capacity:
                raise RuntimeError('Bootloader and application disagree about chip/flash.')
            # Preserve the EndF/signed trailer and release padding in this app
            # partition, without writing any other partition from the merged BIN.
            ota = [p for p in parts if p['type'] == 1 and p['subtype'] == 0]
            if len(ota) > 1 or (ota and ota[0]['size'] != 0x2000):
                raise RuntimeError('Unsupported OTA selection partition.')
            if not factory and not ota and len([p for p in parts if p['type'] == 0]) != 1:
                raise RuntimeError('Multiple OTA applications without an OTA selection partition.')
            candidates.append(Firmware(data, base, rom.IMAGE_CHIP_ID, rom.CHIP_NAME, capacity,
                                       table_offset, parts, rom.BOOTLOADER_FLASH_OFFSET,
                                       data[boot_index:boot_index+boot_len], app, payload))
    if len(candidates) != 1:
        raise RuntimeError('Select a complete merged USB BIN containing bootloader, partition table and application. '
                           'An app-only WiFi-update BIN cannot repair the boot layout. For custom layouts use --partition-offset.')
    return candidates[0]


def write_plan(image, table, capacity, factory):
    if image.flash_bytes > capacity or len(image.data) + image.base > capacity:
        raise RuntimeError('Selected firmware requires more flash than the physical chip has. Nothing flashed.')
    if factory:
        plan = [(image.base, image.data)]
        # A merged image/full-flash input may carry an OTA record selecting a
        # different app. Boot the application validated above, even after erase.
        for part in image.parts:
            if part['type'] == 1 and part['subtype'] == 0:
                start = part['offset'] - image.base
                erased = b'\xff' * part['size']
                if image.data[start:start+part['size']] != erased:
                    plan.append((part['offset'], erased))
        return plan
    try:
        matches = parse_table(table, capacity) == image.parts
    except ExpansionError:
        matches = False
    if not matches:
        raise LayoutMismatch('Partition layouts differ or the current table is damaged. No writes made. '
                             'Choose explicit factory reset, or use the migration tool to retain an older layout.')
    plan = [(image.app['offset'], image.application), (image.boot_offset, image.boot)]
    # Erased OTA selection boots factory if present, otherwise ota_0. Do this
    # LAST, after the selected first-boot application and bootloader are verified.
    plan += [(p['offset'], b'\xff' * p['size']) for p in image.parts if p['type'] == 1 and p['subtype'] == 0]
    return plan


def check_device(esp, selected, image=None):
    if not esp.CHIP_NAME.startswith('ESP32'):
        raise RuntimeError('Recovery supports ESP32-family chips only. Nothing flashed.')
    if image and esp.IMAGE_CHIP_ID != image.chip:
        raise RuntimeError(f'Wrong chip: firmware is {image.chip_name}, device is {esp.CHIP_NAME}. Nothing flashed.')
    if esp.secure_download_mode or esp.get_flash_encryption_enabled() or esp.get_secure_boot_enabled():
        raise RuntimeError('Secure-boot/encrypted devices require their own signed recovery process. Nothing flashed.')
    mac = ''.join(f'{b:02x}' for b in esp.read_mac())
    if (selected.vid, selected.pid) == (0x303a, 0x1001):
        serial_id = re.sub('[:-]', '', selected.serial_number or '').lower()
        if serial_id != mac:
            raise RuntimeError('Native USB serial does not match the detected chip MAC. Nothing flashed.')
    print(f'Verified {esp.CHIP_NAME}, MAC ' + ':'.join(mac[i:i+2] for i in range(0, len(mac), 2)))


def perform_recovery(esp, api, image, factory):
    capacity = 1 << ((esp.flash_id() >> 16) & 0xff)
    print(f'Physical flash: {capacity // (1024*1024)} MiB; image: {image.chip_name}, {image.flash_bytes // (1024*1024)} MiB')
    table = api.read_flash(esp, image.table_offset, 4096, no_progress=True)
    plan = write_plan(image, table, capacity, factory)
    # NVS and the exact partition bytes are independently read back. All other
    # data partitions and apps are excluded from the preservation write ranges.
    retained = []
    if not factory:
        retained.append((image.table_offset, table))
        for p in image.parts:
            if p['type'] == 1 and p['subtype'] in (2, 4):
                retained.append((p['offset'], api.read_flash(esp, p['offset'], p['size'], no_progress=True)))
    else:
        api.erase_flash(esp)
    for address, data in plan:
        api.write_flash(esp, [(address, data)])
        api.verify_flash(esp, [(address, data)])
    for address, before in retained:
        if api.read_flash(esp, address, len(before), no_progress=True) != before:
            raise RuntimeError('Retained partition/NVS readback mismatch. Startup was not attempted.')


def finish_device(esp, api, native):
    if native and esp.CHIP_NAME == 'ESP32-S3':
        finish_native(esp, api)
    else:
        # esptool dispatches to this chip's reset implementation. The S3 register
        # address must never be applied to C3/C6/classic ESP32 or other families.
        esp._port.dtr = False
        api.reset_chip(esp, 'hard-reset')


def same_device(candidate, selected):
    def serial_id(p):
        return re.sub('[:-]', '', p.serial_number or '').casefold()
    if selected.vid != 0x303a and (candidate.vid, candidate.pid) != (selected.vid, selected.pid):
        return False
    if serial_id(selected):
        return serial_id(candidate) == serial_id(selected)
    return (candidate.vid, candidate.pid, candidate.location) == (selected.vid, selected.pid, selected.location) and bool(selected.location)


def boot_confirmed(text):
    if any(word in text for word in ('Guru Meditation', 'abort() was called', 'Backtrace:', 'Brownout detector', 'assert failed')):
        return False
    if (text.count('Firmware: ') > 1 or len(re.findall(r'(?m)^rst:0x', text)) > 1
            or len(re.findall(r'(?m)^ESP-ROM:', text)) > 1):
        return False
    # Require CLI responses; enumeration and boot banners do not prove recovery.
    return bool(re.search(r'->\s*v\d+\.[^\r\n]+', text)
                and re.search(r'->\s*(?!v\d+\.)(?:[A-Za-z][^\r\n]{2,})', text))


def capture_boot(selected, protocol, duration=25):
    import serial
    from station_recovery import cache_dir
    data = bytearray()
    deadline, last_query, port = time.monotonic() + duration, 0, None
    print('Checking startup for 25 seconds...')
    try:
        while time.monotonic() < deadline:
            try:
                if port is None:
                    matches = [p for p in available_ports() if same_device(p, selected)]
                    if len(matches) != 1:
                        time.sleep(.2)
                        continue
                    port = serial.Serial(port=None, baudrate=115200, timeout=.1, write_timeout=1, exclusive=True)
                    port.dtr = port.rts = False
                    port.port = matches[0].device
                    assert_port_idle(port.port)
                    port.open()
                if protocol == 'meshcore' and time.monotonic() - last_query > 4:
                    port.write(b'\rver\rboard\r')
                    last_query = time.monotonic()
                data.extend(port.read(min(port.in_waiting or 1, 4096)))
                if len(data) > 256 * 1024:
                    break
            except (serial.SerialException, OSError):
                if port:
                    port.close()
                port = None
                time.sleep(.2)
    finally:
        if port:
            port.close()
    destination = cache_dir().parent / 'esp32-recovery' / ('boot-' + time.strftime('%Y%m%d-%H%M%S') + '.log')
    destination.parent.mkdir(parents=True, exist_ok=True)
    with os.fdopen(os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as log:
        log.write(data)
    print('Startup log: ' + str(destination) + '\nLogs can contain node names, WiFi SSIDs and packet traffic; review before sharing.')
    good = protocol == 'meshcore' and boot_confirmed(data.decode('utf8', errors='replace'))
    print('Application CLI is responding; startup confirmed.' if good else
          'Application startup NOT confirmed. Release BOOT, press RESET once, and check the device/log. A verified write alone is not a confirmed recovery.')
    return good


def main():
    parser = argparse.ArgumentParser(description=__doc__, epilog=BOOT_HELP,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--firmware', help='Complete merged USB BIN path or HTTPS URL; omit to choose from catalog')
    parser.add_argument('--sha256', help='Expected firmware SHA256')
    parser.add_argument('--port', help='USB serial port (COM5, /dev/ttyACM0, /dev/ttyUSB0, etc.)')
    parser.add_argument('--partition-offset', type=lambda s:int(s, 0), default=0x8000)
    parser.add_argument('--factory-reset', action='store_true', help='Erase ALL flash and saved identity/settings')
    parser.add_argument('--reset-only', action='store_true', help='Leave the ROM downloader without writing flash')
    parser.add_argument('--manual-boot', action='store_true', help='Already in hardware BOOT mode; do not toggle reset to connect')
    parser.add_argument('--guided', action='store_true')
    parser.add_argument('--yes', action='store_true', help='Confirm explicit --firmware/--reset-only and --port')
    parser.add_argument('--list-ports', action='store_true')
    parser.add_argument('--prepare-only', action='store_true', help='Check firmware without opening a device')
    parser.add_argument('--protocol', choices=('auto', 'meshcore', 'passive'), default='auto')
    args = parser.parse_args()
    if args.factory_reset and args.reset_only:
        parser.error('--factory-reset cannot be combined with --reset-only')
    if args.yes and (args.guided or not args.port or not (args.firmware or args.reset_only)):
        parser.error('--yes requires an explicit port and firmware (or reset-only), without --guided')
    ensure_runtime(__file__)
    if args.list_ports:
        from station_recovery import print_ports
        print_ports(available_ports())
        return 0
    guided = args.guided or len(sys.argv) == 1
    if guided and not args.factory_reset and not args.reset_only:
        choice = choose('Recovery operation', ['Keep settings (matching layout)', 'Factory reset (erase everything)', 'Reset only'], default=0)
        args.factory_reset = choice.startswith('Factory')
        args.reset_only = choice.startswith('Reset')
    metadata = None
    image = None
    if not args.reset_only:
        if not args.firmware:
            source = choose('Firmware source', ['Published firmware catalog', 'Local merged BIN / HTTPS URL'], default=0)
            if source.startswith('Published'):
                try:
                    metadata = choose_firmware()
                except (OSError, ValueError) as error:
                    print('Catalog unavailable: ' + str(error) + '\nYou can select a downloaded merged BIN instead.')
                if metadata:
                    args.firmware = metadata['url']
                    args.sha256 = metadata.get('sha256') or args.sha256
            if not args.firmware:
                args.firmware = input('Firmware file or HTTPS URL: ').strip().strip('"')
        image = inspect_firmware(load_firmware(args.firmware, args.sha256), args.partition_offset)
        print(f'Validated {image.chip_name} firmware; first-boot app at 0x{image.app["offset"]:x}; file flash offset 0x{image.base:x}.')
    if args.prepare_only:
        print('Firmware checks passed. No device opened.')
        return 0
    print(BOOT_HELP)
    if guided and not args.manual_boot:
        args.manual_boot = choose('Connection', ['Try automatic USB reset', 'Already entered BOOT mode with buttons'], default=0).startswith('Already')
    ports = available_ports()
    if args.port:
        ports = [p for p in ports if os.path.realpath(p.device) == os.path.realpath(args.port)]
        if len(ports) != 1:
            raise RuntimeError('The selected USB serial port is absent. Check the port again after entering BOOT mode.')
        selected = ports[0]
    else:
        selected = choose('Select the physical ESP32 board USB port', ports,
                          lambda p:f'{p.device} - {p.description} (serial {p.serial_number or "unknown"})')
    native = selected.vid == 0x303a
    if native and selected.pid != 0x1001 and not args.manual_boot:
        raise RuntimeError('This native USB port needs hardware BOOT entry first. ' + BOOT_HELP)
    print('\nSelected USB port: ' + selected.device)
    if args.firmware:
        print('Firmware: ' + args.firmware)
    print('Factory reset erases identity, passwords, radio/WiFi settings and files.' if args.factory_reset else
          'Reset only: no flash writes.' if args.reset_only else
          'Keep settings: partition table, NVS, filesystems and other app slots are not rewritten. No backup is made.')
    if not args.yes and input('Type ' + ('ERASE' if args.factory_reset else 'RECOVER') + ' to continue: ').strip() != ('ERASE' if args.factory_reset else 'RECOVER'):
        print('Cancelled. Nothing flashed.')
        return 1
    import serial
    from esptool import cmds as api
    port = serial.Serial(port=None, baudrate=115200, timeout=1, exclusive=True)
    port.dtr = port.rts = False
    port.port = selected.device
    try:
        assert_port_idle(selected.device)
        port.open()
        esp = api.detect_chip(port, connect_mode='no-reset' if args.manual_boot else 'usb-reset' if native else 'default-reset', connect_attempts=3)
        check_device(esp, selected, image)
        if image:
            esp = api.run_stub(esp)
            api.attach_flash(esp)
            # 115200 is intentional for UART recovery: speed is less important
            # than stable reads/writes on weak CH340 links and long USB cables.
            try:
                perform_recovery(esp, api, image, args.factory_reset)
            except LayoutMismatch as error:
                print(str(error))
                if not guided or input('To erase ALL identity/settings and install this layout now, type ERASE: ').strip() != 'ERASE':
                    raise
                perform_recovery(esp, api, image, True)
            print('Firmware writes verified.')
        finish_device(esp, api, native)
    finally:
        port.close()
    protocol = args.protocol
    if protocol == 'auto':
        protocol = 'meshcore' if metadata and metadata.get('project') == 'MeshCore' else 'passive'
        if protocol == 'passive' and image:
            try:
                endf_identity(image.application)
                protocol = 'meshcore'
            except ExpansionError:
                pass
    return 0 if capture_boot(selected, protocol) else 2


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (Exception, KeyboardInterrupt) as error:
        print('\nRecovery incomplete: ' + (str(error) or 'cancelled'), file=sys.stderr)
        print('If writes started, keep power connected and recover in hardware BOOT mode.\n' + BOOT_HELP, file=sys.stderr)
        raise SystemExit(1)
