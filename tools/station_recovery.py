#!/usr/bin/env python3
"""USB recovery for Station G2/G3, using meshfirmware's partition/reset policy."""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import urllib.request

from meshcore_partition_expansion import parse_table, image_header, ExpansionError

VERSION = "5.1.0"
RELEASE = "v1.18.0.1-halo-keymind-cascade-dev-03214a16"
BASE_URL = "https://github.com/mikecarper/MeshCore/releases/download/full-profiles-" + RELEASE
ROOT = Path(__file__).resolve().parent.parent
FLASH_SIZE = 0x1000000
# Verified against the published full-profiles release SHA256SUMS.txt.
IMAGES = {
    ("g2", "repeater"): ("Station_G2_repeater_observer_mqtt", "9423ca58eeaf30bbf4f6db311dd1502e8d44d043fc83421c5832ae9af0a60ba2"),
    ("g2", "room"): ("Station_G2_room_server_observer_mqtt", "7e0e7ce1ce5bcdee7c2721ab6eda58d2f92c56653ad60aa23313bfd780d63f3f"),
    ("g3", "repeater"): ("Station_G3_ESP32_repeater", "2d36048d990f3b439e4238766547da2e8ae8eef925b3b3a6e3bf47ea87f23a4a"),
    ("g3", "room"): ("Station_G3_ESP32_room_server", "311e6def81f06b4ec09443c5cbedefe05c15f8fc83c84c3765504d091099ba50"),
}
BOOT_HELP = """Close the browser flasher, serial terminal and any app using this radio.
If automatic connection fails or USB keeps disappearing:
  1. Hold BOOT (GPIO0), press and release RESET, then release BOOT.
     Alternatively, hold BOOT while plugging the USB data cable in.
  2. Run this script again with --manual-boot and select the new USB/COM port.
Use a data cable. Keep power connected until recovery finishes.
"""


def cache_dir():
    base = os.environ.get("LOCALAPPDATA") if os.name == "nt" else os.environ.get("XDG_CACHE_HOME")
    return Path(base or Path.home() / ".cache") / "meshfirmware" / "station-recovery"


def ensure_runtime(entry=None):
    if sys.version_info < (3, 10):
        raise RuntimeError("Install Python 3.10 or newer from https://www.python.org/downloads/ and run again.")
    try:
        import esptool
        if esptool.__version__ == VERSION:
            return
    except ImportError:
        pass
    if os.environ.get("MESH_STATION_RECOVERY_VENV") == "1":
        raise RuntimeError("The isolated esptool installation is incomplete. Remove its cache folder and retry.")
    directory = cache_dir() / ("esptool-" + VERSION)
    python = directory / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    if not python.exists():
        import venv
        print("Preparing an isolated USB recovery tool (no administrator access needed)...", flush=True)
        venv.EnvBuilder(with_pip=True).create(directory)
    check = subprocess.run([str(python), "-c", "import esptool; assert esptool.__version__ == '" + VERSION + "'"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if check.returncode:
        subprocess.run([str(python), "-m", "pip", "install", "--disable-pip-version-check", "esptool==" + VERSION], check=True)
    raise SystemExit(subprocess.call([str(python), str(Path(entry or __file__).resolve()), *sys.argv[1:]],
                                    env={**os.environ, "MESH_STATION_RECOVERY_VENV": "1"}))


def load_image(board, role):
    target, digest = IMAGES[board, role]
    name = target + "-full-usb-wifi-ota-" + RELEASE + "-merged.bin"
    bundled = ROOT / "firmware" / name
    cached = cache_dir() / name
    if bundled.exists():
        data = bundled.read_bytes()
    elif cached.exists():
        data = cached.read_bytes()
    else:
        print("Downloading the pinned 1.18.0.1 recovery image...", flush=True)
        request = urllib.request.Request(BASE_URL + "/" + name, headers={"User-Agent": "meshfirmware-station-recovery"})
        with urllib.request.urlopen(request, timeout=60) as response:
            data = response.read(FLASH_SIZE + 1)
    validate_image(data, digest)
    if not bundled.exists() and not cached.exists():
        cached.parent.mkdir(parents=True, exist_ok=True)
        temp = cached.with_suffix(".partial")
        temp.write_bytes(data)
        temp.replace(cached)
    return data


def validate_image(data, digest):
    if hashlib.sha256(data).hexdigest() != digest:
        raise RuntimeError("Firmware checksum mismatch. Nothing has been flashed; download a fresh recovery bundle.")
    if not 0x10000 < len(data) < 0x650000:
        raise RuntimeError("Unexpected merged image size.")
    for image in (data, data[0x10000:]):
        if image_header(image) != (9, FLASH_SIZE) or image[2] != 2:
            raise RuntimeError("Recovery requires an ESP32-S3 16 MB DIO image.")
    parts = parse_table(data[0x8000:0x9000], FLASH_SIZE)
    geometry = [(p['name'], p['type'], p['subtype'], p['offset'], p['size'], p['flags']) for p in parts]
    if geometry != [
        ('nvs', 1, 2, 0x9000, 0x5000, 0), ('otadata', 1, 0, 0xe000, 0x2000, 0),
        ('app0', 0, 0x10, 0x10000, 0x640000, 0), ('app1', 0, 0x11, 0x650000, 0x640000, 0),
        ('spiffs', 1, 0x82, 0xc90000, 0x360000, 0), ('coredump', 1, 3, 0xff0000, 0x10000, 0),
    ]:
        raise RuntimeError("Recovery image has an unexpected partition layout.")


def write_plan(image, current_table, factory):
    if factory:
        return [(0, image)]
    # Compare complete validated geometry, not only the app slot size. Never
    # relocate saved NVS/SPIFFS, or overwrite data in a different old layout.
    try:
        matches = parse_table(current_table, FLASH_SIZE) == parse_table(image[0x8000:0x9000], FLASH_SIZE)
    except ExpansionError:
        matches = False
    if not matches:
        raise RuntimeError("The existing partition layout is different or damaged. No flash was changed. "
                           "Use --factory-reset to start fresh (erases identity and all settings), "
                           "or use meshfirmware's migration/backup tools to preserve an older layout.")
    # App first, bootloader second, OTA selection LAST. Each phase is verified
    # before selecting app0. Do NOT flash the merged file wholesale here: its
    # padding would erase NVS. Leave the partition table and app1 untouched.
    return [(0x10000, image[0x10000:]), (0, image[:0x8000]), (0xe000, image[0xe000:0x10000])]


def finish_native(esp, api):
    # Same policy as mcfirmware.sh finish_esp32_flash_session(): USB/JTAG RTS
    # alone does not re-sample boot straps. Preserve every other OPTION1 bit.
    api.write_mem(esp, 0x6000812c, 0, 1)
    api.reset_chip(esp, "watchdog-reset")


def available_ports():
    from serial.tools import list_ports
    return sorted((p for p in list_ports.comports() if p.vid is not None), key=lambda p: p.device)


def assert_port_idle(port):
    # pySerial's exclusive flag alone cannot detect an existing non-exclusive
    # Linux reader. Match meshfirmware's refusal to stop other apps/services.
    if sys.platform.startswith('linux') and shutil.which('fuser'):
        owner = subprocess.run(['fuser', port], capture_output=True, text=True)
        if owner.returncode != 1 or owner.stdout.strip() or owner.stderr.strip():
            raise RuntimeError('USB port is in use or its ownership could not be checked. Close its terminal/service first.')


def print_ports(ports):
    for i, port in enumerate(ports, 1):
        print(f"  {i}. {port.device} - {port.description} (USB {port.vid:04x}:{port.pid:04x}, serial {port.serial_number or 'unknown'})")


def choose_port(name):
    ports = available_ports()
    if name:
        matches = [p for p in ports if os.path.realpath(p.device) == os.path.realpath(name)]
        if len(matches) != 1:
            raise RuntimeError("Selected port is absent or is not a USB serial port. Use --list-ports after entering BOOT mode.")
        return matches[0]
    if not ports:
        raise RuntimeError("No USB serial radio found. " + BOOT_HELP)
    print("Select ONLY the Station you intend to recover; USB cannot identify its board model.")
    print_ports(ports)
    value = input("Port number: ").strip()
    if not value.isdigit() or not 1 <= int(value) <= len(ports):
        raise RuntimeError("No port selected. Nothing flashed.")
    return ports[int(value) - 1]


def same_port(candidate, selected):
    if (candidate.vid, candidate.pid) != (selected.vid, selected.pid):
        return False
    if selected.serial_number:
        return candidate.serial_number == selected.serial_number
    return bool(selected.location and candidate.location == selected.location)


def check_device(esp, selected):
    if esp.CHIP_NAME != "ESP32-S3":
        raise RuntimeError("Wrong chip: Station G2/G3 recovery requires ESP32-S3. Nothing flashed.")
    if esp.secure_download_mode or esp.get_flash_encryption_enabled() or esp.get_secure_boot_enabled():
        raise RuntimeError("Secure boot/encrypted devices require their own recovery process. Nothing flashed.")
    mac = ''.join(f'{byte:02x}' for byte in esp.read_mac())
    if selected.vid == 0x303a:
        serial_id = re.sub(r'[:-]', '', selected.serial_number or '').lower()
        if not re.fullmatch(r'[0-9a-f]{12}', serial_id) or serial_id != mac:
            raise RuntimeError("USB identity does not match this chip's MAC. Nothing flashed.")
    print("Verified ESP32-S3 MAC " + ':'.join(mac[i:i+2] for i in range(0, 12, 2)))
    return mac


def perform_recovery(esp, api, image, factory):
    capacity = 1 << ((esp.flash_id() >> 16) & 0xff)
    if capacity != FLASH_SIZE:
        raise RuntimeError("Wrong flash capacity: expected 16 MB. Nothing flashed.")
    table = api.read_flash(esp, 0x8000, 0x1000, no_progress=True)
    try:
        slots = [p for p in parse_table(table, FLASH_SIZE) if p['type'] == 0]
        print('Current app slots: ' + ', '.join(f"{p['name']} at 0x{p['offset']:x}, {p['size']//1024} KiB" for p in slots))
    except ExpansionError:
        print('Current partition table is missing or damaged.')
    plan = write_plan(image, table, factory)
    # Small retained data is read back after the write. SPIFFS remains outside
    # every write/erase range; no full-flash backup is made by this tool.
    nvs = None if factory else api.read_flash(esp, 0x9000, 0x5000, no_progress=True)
    if factory:
        api.erase_flash(esp)
    for address, data in plan:
        api.write_flash(esp, [(address, data)])
        api.verify_flash(esp, [(address, data)])
    if not factory:
        if api.read_flash(esp, 0x8000, 0x1000, no_progress=True) != table:
            raise RuntimeError("Partition readback changed unexpectedly. Application boot was not attempted.")
        if api.read_flash(esp, 0x9000, 0x5000, no_progress=True) != nvs:
            raise RuntimeError("NVS readback changed unexpectedly. Application boot was not attempted.")


def capture_boot(selected, board, reset_only, duration=25):
    import serial
    destination = cache_dir() / ("boot-" + time.strftime("%Y%m%d-%H%M%S") + ".log")
    destination.parent.mkdir(parents=True, exist_ok=True)
    data = bytearray()
    deadline = time.monotonic() + duration
    port = None
    last_query = 0
    print("Checking application startup for 25 seconds...", flush=True)
    try:
        while time.monotonic() < deadline:
            try:
                if port is None:
                    matches = [p for p in available_ports() if same_port(p, selected)]
                    if len(matches) != 1:
                        time.sleep(.2)
                        continue
                    port = serial.Serial(port=None, baudrate=115200, timeout=.1, write_timeout=1, exclusive=True)
                    port.dtr = port.rts = False
                    port.port = matches[0].device
                    port.open()
                if time.monotonic() - last_query > 4:
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
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as out:
        out.write(data)
    text = data.decode('utf-8', errors='replace')
    print("Startup log: " + str(destination))
    print("The log may include your node name, WiFi SSID and packet traffic; review before sharing.")
    good = boot_confirmed(text, board, reset_only)
    if good:
        print("Application startup confirmed. " + ("No flash data was changed." if reset_only else "Station recovery to 1.18.0.1 completed."))
    else:
        print("Application startup NOT confirmed. " + ("No flash data was changed." if reset_only else "Firmware was written and verified, but this is not a confirmed recovery."))
        print("Release BOOT and press RESET once. If it still loops, retain the startup log for diagnosis.")
    return good


def boot_confirmed(text, board, reset_only):
    failures = ('Guru Meditation', 'abort() was called', 'Backtrace:', 'Brownout detector', 'assert failed')
    if any(s in text for s in failures) or text.count('Firmware: ') > 1:
        return False
    version = r'->\s*v\d+\.' if reset_only else r'->\s*v1\.18\.0\.1[^\r\n]*03214a16'
    # Require CLI replies, not only a USB descriptor or a boot banner.
    return bool(re.search(version, text) and re.search(r'->\s*Station ' + board.upper() + r'\b', text))


def guided_options(args):
    if not args.factory_reset and not args.reset_only:
        print('1. Recover, keeping settings (default)\n2. Factory reset (erase everything)\n3. Reset only, no flash writes')
        choice = input('Operation [1]: ').strip() or '1'
        if choice not in ('1', '2', '3'):
            raise RuntimeError('Invalid operation. Nothing flashed.')
        args.factory_reset = choice == '2'
        args.reset_only = choice == '3'
    if not args.reset_only and not args.role:
        choice = input('Firmware role: repeater or room [repeater]: ').strip().lower() or 'repeater'
        if choice not in ('repeater', 'room'):
            raise RuntimeError('Invalid role. Nothing flashed.')
        args.role = choice
    if not args.manual_boot:
        print(BOOT_HELP)
        choice = input('Already entered BOOT mode using the buttons? [y/N]: ').strip().lower()
        if choice not in ('', 'n', 'no', 'y', 'yes'):
            raise RuntimeError('Answer yes or no. Nothing flashed.')
        args.manual_boot = choice in ('y', 'yes')


def main():
    parser = argparse.ArgumentParser(description=__doc__, epilog=BOOT_HELP,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--board', choices=['g2', 'g3'])
    parser.add_argument('--role', choices=['repeater', 'room'])
    parser.add_argument('--guided', action='store_true', help='Ask for operation, firmware role and BOOT mode')
    parser.add_argument('--port', help='Exact USB serial port, such as COM5 or /dev/ttyACM0')
    parser.add_argument('--factory-reset', action='store_true', help='Erase ALL flash, identity, passwords and settings')
    parser.add_argument('--reset-only', action='store_true', help='Leave USB download mode without flashing')
    parser.add_argument('--manual-boot', action='store_true', help='Already held BOOT+RESET; sync without toggling reset lines')
    parser.add_argument('--yes', action='store_true', help='Confirm the explicitly selected operation (requires --board and --port)')
    parser.add_argument('--list-ports', action='store_true')
    parser.add_argument('--prepare-only', action='store_true', help='Download/check firmware without opening a device')
    args = parser.parse_args()
    if args.factory_reset and args.reset_only:
        parser.error('--factory-reset and --reset-only cannot be combined')
    if args.yes and (not args.board or not args.port):
        parser.error('--yes requires explicit --board and --port')
    if args.guided and args.yes:
        parser.error('--guided cannot be combined with --yes')
    # Bootstrap before prompting: the isolated-runtime relaunch must not ask
    # the user to choose the board/operation twice on their first run.
    if not args.prepare_only:
        ensure_runtime()
    if args.guided or len(sys.argv) == 1:
        guided_options(args)
    args.role = args.role or 'repeater'
    if not args.board and not args.list_ports:
        args.board = input("Which physical board? Type g2 or g3: ").strip().lower()
        if args.board not in ('g2', 'g3'):
            raise RuntimeError("Board must be g2 or g3. Nothing flashed.")
    image = None if args.reset_only or args.list_ports else load_image(args.board, args.role)
    if args.prepare_only:
        print('Recovery image checksum and layout verified; no device opened.')
        return 0
    if args.list_ports:
        print_ports(available_ports())
        return 0
    selected = choose_port(args.port)
    native = (selected.vid, selected.pid) == (0x303a, 0x1001)
    if selected.vid == 0x303a and not native:
        raise RuntimeError("Enter hardware BOOT mode first, then rerun with --manual-boot. " + BOOT_HELP)
    print(f"\nStation {args.board.upper()}, {args.role}, USB {selected.device}")
    if args.reset_only:
        print('Reset only: no flash writes or erase.')
    elif args.factory_reset:
        print('FACTORY RESET: erases ALL identity, contacts, passwords, WiFi and radio settings.')
        print('New identity; USA Cascade defaults: 910.525 MHz / BW62.5 / SF7 / CR5. Reconfigure for your network.')
    else:
        print('Rollback to 1.18.0.1; keep NVS and filesystem settings when the layout matches.')
        print('Newer-only settings may not be understood by the older firmware. No backup is made.')
    print(BOOT_HELP)
    word = 'ERASE' if args.factory_reset else 'RECOVER'
    if not args.yes and input(f'Type {word} to continue: ').strip() != word:
        print('Cancelled. Nothing flashed.')
        return 1
    import serial
    from esptool import cmds as api
    # Keep one open, exclusive ROM connection across identification, all writes,
    # verification and reset. Never switch to another tty/COM port mid-write.
    port = serial.Serial(port=None, baudrate=115200, timeout=1, exclusive=True)
    port.dtr = port.rts = False
    port.port = selected.device
    try:
        assert_port_idle(selected.device)
        port.open()
        esp = api.detect_chip(port, connect_mode='no-reset' if args.manual_boot else 'usb-reset' if native else 'default-reset', connect_attempts=3)
        check_device(esp, selected)
        if not args.reset_only:
            esp = api.run_stub(esp)
            api.attach_flash(esp)
            if not native:
                esp.change_baud(460800)
            perform_recovery(esp, api, image, args.factory_reset)
        if native:
            finish_native(esp, api)
        else:
            # Release DTR/BOOT explicitly before the UART hard reset.
            port.dtr = False
            api.reset_chip(esp, 'hard-reset')
    finally:
        port.close()
    return 0 if capture_boot(selected, args.board, args.reset_only) else 2


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (Exception, KeyboardInterrupt) as error:
        print('\nRecovery incomplete: ' + (str(error) or 'cancelled'), file=sys.stderr)
        print('No success is assumed. If writes had started, keep power connected and rerun in BOOT mode.', file=sys.stderr)
        print(BOOT_HELP, file=sys.stderr)
        raise SystemExit(1)
