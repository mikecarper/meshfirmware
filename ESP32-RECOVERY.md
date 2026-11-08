# Recover a boot-looping ESP32 over USB

Choose **Recover boot-looping ESP32** at the first menu in `mcfirmware.sh` or
`firmware.cmd`. Recovery talks directly to the chip's ROM downloader; it does
not need the broken firmware to answer commands.

1. Choose **Keep settings** (default), **Factory reset**, or **Reset only**.
2. Select your exact board, firmware provider, role and image from the catalog.
   You can also select a local merged USB `.bin` or paste its HTTPS URL.
3. Connect a USB data cable and select the board's USB/COM port.
4. Review the firmware and operation. Type `RECOVER`, or `ERASE` for factory reset.
5. Leave power connected until verification and the startup check finish.

Recovery supports ESP32, S2, S3, C2, C3, C6 and the other ESP32 families supported
by the included esptool 5.1.0. Board pin mappings, radio hardware, screen and
PSRAM cannot be identified from the chip: choose the correct physical variant.
The tool checks the image chip against the detected chip and checks physical
flash capacity. It retains the firmware's flash mode and clock settings.

## If the USB port keeps disappearing

Hold the board's **BOOT/FLASH** button, press and release **RESET/EN**, then
release BOOT. Alternatively hold BOOT while connecting USB. Select **Already
entered BOOT mode with buttons** in recovery. The port number may change.
Follow the manufacturer's instructions for boards with a different button
arrangement. BOOT is not GPIO0 on every ESP32 family.

Close serial terminals, browser flashers and services using that board first.
The tool does not stop other programs or switch to another device mid-flash.

## What is preserved

**Keep settings** requires the existing partition table to match the selected
firmware. It writes and verifies the first-boot application and bootloader,
then clears OTA selection to boot that application. It keeps the partition
table, NVS, filesystems and other application slots. NVS and partition-table
bytes are checked again before startup. No backup is made.

If the layout differs, it stops before writing. The wizard offers an explicit
factory reset in the same session; it never silently erases or migrates data.
Use the existing migration workflow if an older layout's settings must be kept.
A replacement firmware version may interpret saved settings differently.

**Factory reset** erases all flash, including identity, passwords, WiFi/radio
settings and files, then installs the complete merged image and its layout.
It clears any old boot-slot selection after verification so the checked
first-boot application starts.
Reconfigure the node for your network before deployment.

**Reset only** exits ROM download mode without installing or erasing firmware.
The S3 native-USB workaround is used only on S3. Other families use esptool's
chip-specific reset implementation. No eFuses are changed.

## Standalone scripts and command-line use

Extract the complete [recovery ZIP](https://github.com/mikecarper/meshfirmware/releases/download/esp32-recovery-v1.1/ESP32-USB-Recovery-v1.1.zip).
Windows: double-click `recover-esp32.cmd`. Linux/macOS: `sh recover-esp32.sh`.
Keep the `tools` folder. Python 3.10 or newer is required; Linux may also need
its `python3-venv` package. USB tools are installed in a separate user cache.
The catalog and first tool installation require internet access.

```sh
bash mcfirmware.sh --recover-esp32
sh recover-esp32.sh --firmware /path/to/board-merged.bin --port /dev/ttyUSB0 --manual-boot
sh recover-esp32.sh --firmware /path/to/board-merged.bin --prepare-only
sh recover-esp32.sh --reset-only --port /dev/ttyACM0 --manual-boot
```

```bat
recover-esp32.cmd --firmware "C:\Downloads\board-merged.bin" --port COM5 --manual-boot
```

Add `--factory-reset` only to deliberately erase everything. `--sha256 HASH`
checks a known publisher checksum. Custom builds with a nonstandard partition
table location can use `--partition-offset 0x...`.

Merged files starting at zero or at the chip's bootloader offset are recognized
from their contents. An application-only WiFi-update BIN cannot repair a broken
boot layout and is rejected. Secure-boot/encrypted devices need their own signed
recovery process. Raw firmware images must contain a valid bootloader, partition
table and first-boot application; multi-file ZIPs and UF2 files are not accepted.

The tool verifies image checksums/digests and each flash write. It then checks
startup for 25 seconds. Known MeshCore firmware is queried through its ASCII CLI;
other firmware is observed without sending application commands. Use
`--protocol meshcore` for older local MeshCore images without embedded identity.
Binary-only companions and other firmware may need a manual application check.
**A successful write or visible USB port alone is not reported as recovered.**
Exit 2 means startup was not confirmed; inspect the device and saved startup log.
Logs can contain node names, WiFi SSIDs and packet traffic; review before sharing.

The older [Station G2/G3 rollback scripts](STATION-RECOVERY.md) remain available
for the pinned 1.18.0.1 recovery images.
