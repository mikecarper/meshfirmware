# Recover a Station G2 or G3 over USB

Use this when a Station reboots repeatedly or will not start after an update.
It restores the published **1.18.0.1 Full firmware**, rather than reinstalling
alpha2. Repeater is the default; Room Server is also supported.

1. Extract the entire recovery ZIP. Keep its `tools` and `firmware` folders.
2. Connect the Station with a USB **data** cable. Close other flashers and serial apps.
3. Windows: double-click **recover-station.cmd**. Linux/macOS: run
   **`sh recover-station.sh`** from the extracted folder.
4. Select the physical board and its USB/COM port. Review the selection and type
   `RECOVER`. Leave the power connected until the script finishes.

Python 3.10 or newer is required ([download](https://www.python.org/downloads/)).
On Linux, install your distribution's `python3-venv` package if Python reports
that venv/ensurepip is missing. The first run installs esptool 5.1.0 in a separate
user cache; internet is required for that installation. Bundled firmware is
checked against pinned SHA256 hashes. No administrator access is requested.

## If USB keeps disappearing

Hold **BOOT / GPIO0**, press and release **RESET**, then release BOOT.
Alternatively, hold BOOT while connecting USB, then release it.
This enters the ESP32's ROM downloader without running the broken application.
Rerun with `--manual-boot`; the USB/COM port may have changed.

Windows examples (Command Prompt in the extracted folder):

```bat
recover-station.cmd --board g3 --port COM5 --manual-boot
recover-station.cmd --board g2 --role room --port COM5 --manual-boot
```

Linux/macOS examples (substitute your actual port):

```sh
sh recover-station.sh --list-ports
sh recover-station.sh --board g3 --port /dev/ttyACM0 --manual-boot
sh recover-station.sh --board g2 --port /dev/cu.usbmodem123 --manual-boot
```

## What is kept

Normal recovery requires the existing expanded 16 MB partition layout to match
this release. It repairs the bootloader, writes and verifies the application,
and selects that application for startup. **NVS and the filesystem are kept**:
identity, passwords, saved radio settings and other stored configuration remain.
The partition table and second application slot are not rewritten. Newer-only
settings may not be understood by the older firmware. No backup is made.

USB identifiers cannot distinguish G2/G3 from other ESP32-S3 boards. Select the
correct physical Station. The script checks the chip, flash size and native USB
serial against the chip MAC, and keeps the same connection throughout flashing.

## If the layout is different, or preserved settings still prevent startup

**Factory reset erases everything, including the node identity, contacts,
passwords, WiFi and radio settings.** It installs the complete merged image with
its matching partition table. It requires typing `ERASE`:

```bat
recover-station.cmd --board g3 --factory-reset --manual-boot
```

```sh
sh recover-station.sh --board g3 --factory-reset --manual-boot
```

The new node starts with USA Cascade defaults: 910.525 MHz, BW62.5, SF7, CR5.
Reconfigure it for your network/region before deployment. For an older layout
whose settings must be retained, use meshfirmware's existing backup/migration
workflow instead of factory reset.

## Reset only, without installing firmware

Add `--reset-only` to exit a stuck ROM downloader without writing flash:

```sh
sh recover-station.sh --board g3 --reset-only --manual-boot
```

For native USB/JTAG, this uses meshfirmware's proven ESP32-S3 finish sequence:
clear only `FORCE_DOWNLOAD_BOOT` bit 0 at `0x6000812c`, then watchdog-reset.
External UART adapters use their normal hard reset. No eFuses are changed.

The script then checks CLI replies for 25 seconds. A successful write or a
visible USB port alone is **not** reported as successful recovery. If application
startup is not confirmed, release BOOT and press RESET once; retain the startup
log if it still fails. Logs can contain node names, WiFi SSIDs and packet traffic;
review them before sharing.

This is a recovery/rollback tool, not a confirmed fix for the reported G3 alpha2
startup failure. A mismatched USB installation is one possible cause; the G3's
startup log is still needed to identify that report's cause.

[Validation and limits](docs/test-results/station-recovery-2026-11-08.md).
