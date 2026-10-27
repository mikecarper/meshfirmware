# Mesh firmware updater

Select, download, and flash [MeshCore](https://github.com/meshcore-dev/MeshCore)
or [Meshtastic](https://github.com/meshtastic/firmware) firmware over USB.

[Open the browser USB flasher](https://mikecarper.github.io/meshfirmware/)
(hardware preview; desktop Chrome/Edge, no local helper).
See [browser features and limits](web/README.md).

## Windows

1. [Download firmware.cmd](https://github.com/mikecarper/meshfirmware/blob/main/firmware.cmd?raw=true).
2. Save it as `firmware.cmd`, not `firmware.cmd.txt`.
3. Connect your node, double-click the file, and follow the menus.

Required tools are installed automatically; existing tools update in the background.

For Linux, see the [quick starts and videos below](#linux).

Merged/full installs and wipes erase stored settings. Back up first and keep
the node powered until the operation finishes.

## Backup and restore

Windows offers a backup-only option; both platforms offer backup before flashing.
Logical MeshCore backups require running firmware, not ROM/DFU mode.

Windows saves backups beside `firmware.cmd`: `mc.config_backup.*.json` for
MeshCore and `mt.config_backup.*.yaml` for Meshtastic. To restore a MeshCore
companion, run [restore.cmd](restore.cmd) from the checkout. See
[backup and restore details](docs/advanced.md#meshcore-backup-before-flashing)
for Linux and moving settings to another board.

## More help

- [ESP32 partition expansion](docs/advanced.md#check-esp32-partitions-before-an-update)
- [USB recovery and bootloader entry](docs/advanced.md#recover-a-stalled-usb-connection-linux)
- [Python and backup dependencies](docs/advanced.md#meshcore-usb-backup-dependencies)
- [Advanced usage, tests, and build instructions](docs/advanced.md)

Windows Video
-----

https://github.com/user-attachments/assets/ab68cb5e-63d5-4c73-ac4a-fdb76702fb20

# Linux






## MeshCore Quick start
Copy and run this in your linux terminal 
```bash
cd ~ && git clone https://github.com/mikecarper/meshfirmware.git && cd meshfirmware && ./mcfirmware.sh
```
<details>
  <summary>Readable Code</summary>  
    
```bash
cd ~
git clone https://github.com/mikecarper/meshfirmware.git
cd meshfirmware
./mcfirmware.sh
```

</details>

### Raspberry Pi USB host warning

`mcfirmware.sh`, `mcsetup.sh`, and `mtfirmware.sh` check whether they are running
on a Raspberry Pi whose active USB host controller uses the legacy `dwc_otg`
driver. When that bus is still at its default high speed, the scripts warn that
some hub/radio combinations can repeatedly re-enumerate or lock the host. The
warning specifically identifies a connected Terminus `1a40:0101` hub when
present.

The scripts can add `dwc_otg.speed=1` to the Pi's single-line `cmdline.txt` and
create a one-time `.meshfirmware-backup`, but only after an explicit **Yes**.
They ask separately before rebooting. A reboot is required to activate the
setting. The mitigation caps that DWC USB bus at 12 Mbps, so USB Ethernet and
storage become slower; USB radio serial devices commonly already run at 12
Mbps. Set `MESHFIRMWARE_PI_USB_CHECK=0` to suppress this startup check.

### Recover a stalled USB connection (Linux)

`mcsetup.sh` has a **U) Reset USB connection** action and offers recovery when
the radio does not answer its initial clock query. The MeshCore flasher,
`mcfirmware.sh`, records the selected identity without resetting it and offers
device-only USB recovery only from its manual post-failure recovery menu.

This is the device-only USB reset used to recover a stalled Station G2 USB
interface. It reconnects USB; it does **not** reboot the radio CPU, enter the
bootloader, erase flash, change settings, or toggle a GPIO relay. It is
separate from the firmware's `reboot` command and the flasher's bootloader-entry
sequence. It cannot repair a radio whose firmware itself is hung.

Recovery is optional (default **No**) and requires Linux and `sudo`. No healthy
probe triggers it automatically. Close any
serial terminal or stop the service using that radio first; recovery refuses
busy ports rather than stopping programs. The tools save the selected USB
identity before probing, reject hubs or a different/replaced device, and only
continue with a verified returning port. If recovery fails, select the radio
again instead of retrying a possibly reused tty number. The flasher's
`MCFIRMWARE_NO_SUDO=1` mode does not perform USB resets.

On Raspberry Pi, the reset helper also resolves the live host-controller
driver from sysfs. It refuses to issue `USBDEVFS_RESET` through the legacy
`dwc_otg` driver because cancelling an active USB request can freeze the Pi.
When `mcsetup.sh` finds an unresponsive radio on that driver, it offers to test
the existing tty with Picocom, reboot the Raspberry Pi after confirmation,
continue without recovery, or quit. Picocom is installed through the detected
package manager when needed and is launched without resetting the serial
control lines on exit. If the tty is unavailable, use the radio's normal
bootloader entry or physically reconnect only that radio, then reselect it.
The script does not offer to replace `dwc_otg` with `dwc2`: live testing on a
Zero 2 W with nested hubs found repeated whole-tree disconnects under `dwc2`.

Before reading the clock and repeater settings, `mcsetup.sh` checks
`get usb.logging`. When logging is enabled, it offers to send
`set usb.logging off reboot` once and then exits cleanly while the radio
reconnects. Continuous debug and packet output can otherwise prevent the
serial reader's idle timeout and make individual setting reads appear stalled.
When logging is off, or an nRF52 exposes its logging stream on the separate
interface `02` tty, setup retains the verified baud and uses a 0.2-second idle
window with a 0.5-second hard deadline for single-value settings. A known noisy command tty is restricted to
the verified baud and a two-second ceiling; multiline commands retain their
separate, longer read behavior.

The shared Python helper is included in a checkout. Single-script downloads
fetch a copy with a checksum pinned by the script; a missing or mismatched
helper disables recovery. This Linux feature does not change `mcsetup.cmd`
or `firmware.cmd` on Windows.

Bootloader entry after the user confirms a flash is separate and still uses the
mode transition required by that board. Generic ESP32 UART recovery no longer
combines a 1200-baud touch with DTR/RTS: after a failed connection it offers one
identity-resolved DTR/RTS toggle, default **No**. Native ESP32 1200-baud fallback
is also explicitly confirmed before it can re-enumerate a device.

### Button-free ESP32-S3 handoff from Meshtastic/TinyUSB

The MeshCore flashers distinguish **software TinyUSB CDC** from **hardware
USB-Serial/JTAG** using the USB product/interface descriptors. Both can use
VID/PID `303a:1001`, so those numbers alone do not select a reset method.

For a confirmed TinyUSB application, such as Meshtastic, `mcfirmware.sh` sends
the CDC **1200-baud line-coding request directly** after the flash is confirmed.
It does not open the tty first, so serial-open DTR/RTS handling cannot prevent
that request. The dependency-free Linux helper uses only the selected CDC
interface, checks its physical identity and all sibling tty owners, and
restores any detached driver if no handoff occurs. This control request is not
a whole-device or host USB reset; the `dwc_otg` reset restriction stays in place.

`firmware.cmd` uses an identity-guarded 1200-baud serial touch for TinyUSB on
Windows. Hardware USB/JTAG keeps its own reset sequence; external UART bridges
keep the normal UART reset. Unknown native modes stop instead of guessing.
No Windows USB driver replacement is required.

A request acknowledgement or disconnect is **not** considered a successful
flash session. The flasher must find the same physical radio after the handoff
and verify its ROM chip MAC before erase/write. Native 12-hex USB serials are
also checked against that MAC. Each later destructive phase retains its
existing identity gate.

For native ESP32-S3 USB/JTAG, automatic return to the application requires
**esptool 5 or newer**. The flasher clears only the `FORCE_DOWNLOAD_BOOT` bit
and uses an RTC watchdog reset, which re-samples the boot strapping pins.
An ordinary USB/JTAG RTS reset can leave the radio in download mode. External
UART bridges keep their normal hard-reset behavior. ESP32-S3 UART finish explicitly
uses the default DTR/RTS reset before `run`, followed by hard reset, including
when the chip was already in ROM. This releases BOOT instead of leaving the
board in download mode after a no-reset serial reopen.

The hardware USB/JTAG product name and tty can remain unchanged when an
application boots. They identify the transport, not whether ROM or application
code is running. A successful final reset ends the verified ROM session;
the flasher must not send another blind ROM probe just because an application
reply is missing. Confirm application startup through its CLI. This reset path
was tested on a Heltec V4 with byte-for-byte partition and both app-slot
readbacks, followed by the expected running-image hash through the MeshCore CLI.

Native ESP32-S3 automation adapters that reuse the Linux session functions
should keep writes and readbacks at `--after "$NORESET"`, then call
`finish_esp32_flash_session "$DEVICE_PORT"` within the already identity-qualified
session. Keep its immediate chip-MAC checks and guarded finish together; do not
replace the native-S3 finish with `--after hard-reset run` or another ROM probe
after reset.

The short 8-12 second probe/reset timeout is not a bulk-transfer budget. An
external adapter should allow at least 600 seconds for a roughly 2.56 MB
application readback at 115200 baud, with a larger budget for larger images.
The Linux data-read path does not impose the short probe timeout. Finish all
readback comparisons before the guarded reset, then verify the running
application separately through its CLI.

See Espressif's [USB/JTAG reset/strapping explanation](https://github.com/espressif/esptool/issues/970#issuecomment-2056650681).

This TinyUSB behavior comes from Espressif's
[1200-baud bootloader hook](https://github.com/espressif/arduino-esp32/blob/2.0.17/cores/esp32/USBCDC.cpp)
and [ESP32-S3 ROM handoff](https://github.com/espressif/arduino-esp32/blob/2.0.17/cores/esp32/esp32-hal-tinyusb.c).
It is separate from Meshtastic's nRF52 DFU and firmware OTA commands.

If Linux cannot enumerate the USB device at all (for example descriptor error
`-71`), there is no CDC interface to send this request to. Changing reset
syntax cannot repair that condition. Re-establish the selected device's USB
connection first; do not reset a whole hub or replace the Pi's USB host driver.
A battery or second supply can keep the radio CPU running even when USB power
is removed. A missing device is never replaced with another cached tty.

### Linux nRF52 USB bootloader entry

`mcfirmware.sh` keeps the original USB selection while a radio briefly
disconnects or changes tty numbers. It waits up to ten seconds for that same
selection, without choosing another available radio. Before a bootloader
touch, the checksum-pinned helper requires CDC0, a matching physical by-path
alias, and the same USB identity and opened character-device inode before
changing line coding. It uses the existing adafruit-nrfutil Python environment
and sends one 1200-baud/DTR transition, with no application payload or serial
capture. The touch itself is bounded to ten seconds; read-only qualification
can retry a disappearing candidate, but the serial open is attempted once.
Complete serial-owner inspection includes the radio's logging siblings. Normal
mode uses cached sudo only for that bounded, read-only inspection; serial
controls still run as the user. No-sudo mode never elevates and refuses the
touch if it cannot inspect every owner's descriptors. No package installation
or helper download runs inside this privileged inspection.

A disconnect during the touch can leave its delivery uncertain. The script
then checks only that radio for a recognized DFU bootloader, without repeating
the touch. A returning application or an unverified endpoint cannot authorize
DFU. If the selected device does not return, use its physical bootloader entry
and reselect it. `MCFIRMWARE_NRF52_SELECTION_WAIT_SECONDS` accepts 0-30 seconds;
`MCFIRMWARE_SERIAL_TOUCH_TIMEOUT_SECONDS` accepts 1-30 seconds.

The DFU manifest summary distinguishes application-only packages from packages
containing bootloader or SoftDevice images. An application-only package contains
neither bootloader nor SoftDevice replacement; intentional combined packages
remain supported. Update/wipe choices and backup defaults are unchanged.
Successful DFU output confirms the package transfer. The final message explicitly
leaves application startup unverified, so a completed transfer is not mistaken
for a working radio.

Offline checks:

```bash
python3 -B tests/test_meshcore_serial_touch.py
bash tests/test_mcfirmware_serial_touch.sh
```

### nRF52 RAK board safety check

`mcfirmware.sh` checks RAK3401 and RAK4631/WisMesh Tag firmware before any
erase or DFU command. It compares identity strings embedded in the firmware
payload with the node's reported board/model and stable USB identity. A
matching pair continues automatically.

A mismatch, ambiguous identity, or unknown RAK payload cancels by default. If
the mismatch is intentional, the script displays a one-time token such as
`unknown-to-rak4631` (`connected-device-to-firmware-target`). Type that exact token at
the prompt to continue. Enter or any other response cancels without erasing or
flashing.

For deliberate unattended use, pass only the exact token printed by the
script:

```bash
MCFIRMWARE_BOARD_OVERRIDE=unknown-to-rak4631 ./mcfirmware.sh
```

This override is intentionally specific to the detected firmware/device pair;
`yes`, `force`, and a token for another pair are rejected.

For nRF52 `flash-wipe + flash`, a firmware provider or cached catalog may be
missing the board's `.erase` entry. The script looks up the selected board in
the official MeshCore catalog and refreshes that catalog if needed. It keeps
the selected firmware or bootloader file and the active provider unchanged.
Only an exact, unique board match is selected automatically; otherwise you
must choose an erase package for the physical board or cancel. If no erase
packages are available, the script stops before erase or DFU. The one-time
board override does not bypass this erase-package lookup.


Linux Video
-----
https://github.com/user-attachments/assets/b3b24479-f17f-46ef-be97-504467e60aea


# Meshtastic Quick start
Copy and run this in your linux terminal 
```bash
cd ~ && git clone https://github.com/mikecarper/meshfirmware.git && cd meshfirmware && ./mtfirmware.sh
```
<details>
  <summary>Readable Code</summary>  
    
```bash
cd ~
git clone https://github.com/mikecarper/meshfirmware.git
cd meshfirmware
./mtfirmware.sh
```





</details>


Linux Video
-----

https://github.com/user-attachments/assets/06fc7b59-ed03-44d7-a4d1-a0492dec5d16




# Linux Compile the firmware
Copy and run this in your linux terminal 
```bash
cd ~ && git clone https://github.com/mikecarper/meshfirmware.git && cd meshfirmware && chmod +x mtcompile.sh && ./mtcompile.sh
```
<details>
  <summary>Readable Code</summary>  
    
```bash
cd ~
git clone https://github.com/mikecarper/meshfirmware.git
cd meshfirmware
chmod +x mtcompile.sh
./mtcompile.sh
```

</details>

Linux Video
-----

https://github.com/user-attachments/assets/20117724-6e62-4c17-8879-aebb1ef48456




Overview
--------

The [script](https://github.com/mikecarper/meshfirmware/blob/main/firmware.sh) does the following:

*   Updates a local cache file with GitHub release data if it is older than 6 hours.

*   Falls back to using the cached data if no internet connection is detected.

*   Parses the JSON release data to build a list of firmware release versions.

*   Appends labels (such as _(alpha)_, _(beta)_, _(rc)_, or _(pre-release)_) based on the release tag.

*   Prepends the ! label if the release has known issues.

*   Uses lsusb to detect connected USB devices.

*   If more than one matching USB device exists, the user is prompted to choose the correct one.

*   Matches the detected device against available firmware files.

*   If more than one matching firmware file exists, the user is prompted to choose the correct one.

*   For ESP32 devices, the script adjusts the update script (e.g., changes baud rate from 115200 to 1200) as required.  
    Also allows the user to choose between an update or an install operation

*   Stops any systemd service locking the device before proceeding and restarts it afterward.



### Raspberry Pi USB speed recommendation

On Raspberry Pis using the legacy dwc_otg USB host, mcfirmware.sh, mcsetup.sh,
and mtfirmware.sh count physical devices on the affected bus (excluding hubs).
The recommendation uses a three-tier scale:

1. **Favor USB 1.1:** only nodes, node bootloaders, or serial adapters.
2. **Middle ground:** USB Ethernet/Wi-Fi adapters alone or alongside nodes.
   USB 1.1 may suit light traffic; USB 2.0 preserves higher throughput.
   The script does not measure traffic demand, and the 12 Mbps cap is shared
   across the entire USB bus.
3. **Favor USB 2.0:** storage/SD-card readers or unknown peripherals, even when
   nodes or networking are also present. An empty bus also defaults to this tier.

Generic serial adapters are labeled as possible nodes because USB descriptors
cannot prove which firmware is running. Node DFU/UF2 drives are recognized through
bootloader identity or mounted UF2 metadata belonging to that same USB device;
ordinary storage is not assumed to be a bootloader just because it also has a
serial interface. The check does not mount drives or reset devices.

Tiers 1 and 2 offer the existing opt-in boot setting and reboot prompts, with
the network throughput tradeoff stated in the tier-2 prompt. Tier 3 only gives
advice, including how to remove an existing 12 Mbps cap. Devices on other USB
controllers do not affect the recommendation.

Usage
-----

Run the script with the following syntax:

```bash
./mtfirmware.sh [OPTIONS]   
```

### Options

*   \--version VERSION  
    Specify a firmware release version to auto-select (searches for tags containing the provided string).

*   \--install  
    Set the operation mode to **install** (used instead of update).

*   \--update  
    Set the operation mode to **update** (this is the default if not otherwise specified).

*   \--run  
    Automatically update firmware without prompting the user.

*   \-h, --help  
    Display the help message and exit.
