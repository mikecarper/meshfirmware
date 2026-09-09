# Alt CLI firmware selector for MeshCore & Meshtastic projects
Scripts that automates the process of selecting, downloading, and applying firmware updates from the [meshcore-dev/MeshCore](https://github.com/meshcore-dev/MeshCore) & [meshtastic/firmware](https://github.com/meshtastic/firmware) GitHub repository via the USB port.  

# Windows Quick start - MeshCore & Meshtastic in one script
[Download firmware.cmd (right click save)](https://github.com/mikecarper/meshfirmware/blob/main/firmware.cmd?raw=true)  
Make sure file is named firmware.cmd and not firmware.cmd.txt  
double click and run the file firmware.cmd  

The Windows flasher recognizes the serial-only Seeed XIAO/XIAO Sense DFU
products (`2886:0044` / `2886:0045`) as well as T1000-E (`2886:0057`), while
still rejecting their application-mode IDs and rechecking the selected USB
identity after COM-port changes. It selects esptool 4/5 command spellings
automatically. Native stderr warnings do not abort successful operations in
Windows PowerShell 5; a nonzero tool exit still stops the flash.

Normal MeshCore identification leaves DTR/RTS deasserted on native ESP32
USB-Serial/JTAG devices (including Heltec V4), whose hardware interprets
those signals as reset/download controls. This prevents the probe from
accidentally entering download mode. nRF52 CDC and USB-UART probing retain
their existing control-line behavior; intentional flashing resets are unchanged.

Regression checks (no connected radio needed):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tests/test_firmware_usb_identity.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File tests/test_firmware_native_commands.ps1
```

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
Use the radio's normal bootloader entry or physically reconnect only that
radio, then reselect it. The script does not offer to replace `dwc_otg` with
`dwc2`: live testing on a Zero 2 W with nested hubs found repeated whole-tree
disconnects under `dwc2`.

The shared Python helper is included in a checkout. Single-script downloads
fetch a copy with a checksum pinned by the script; a missing or mismatched
helper disables recovery. This Linux feature does not change `mcsetup.cmd`
or `firmware.cmd` on Windows.

Bootloader entry after the user confirms a flash is separate and still uses the
mode transition required by that board. Generic ESP32 UART recovery no longer
combines a 1200-baud touch with DTR/RTS: after a failed connection it offers one
identity-resolved DTR/RTS toggle, default **No**. Native ESP32 1200-baud fallback
is also explicitly confirmed before it can re-enumerate a device.

### nRF52 RAK board safety check

`mcfirmware.sh` checks RAK3401 and RAK4631/WisMesh Tag firmware before any
erase or DFU command. It compares identity strings embedded in the firmware
payload with the node's reported board/model and stable USB identity. A
matching pair continues automatically.

A mismatch, ambiguous identity, or unknown RAK payload cancels by default. If
the mismatch is intentional, the script displays a one-time token such as
`rak3401-to-rak4631` (`firmware-to-connected-device`). Type that exact token at
the prompt to continue. Enter or any other response cancels without erasing or
flashing.

For deliberate unattended use, pass only the exact token printed by the
script:

```bash
MCFIRMWARE_BOARD_OVERRIDE=rak3401-to-rak4631 ./mcfirmware.sh
```

This override is intentionally specific to the detected firmware/device pair;
`yes`, `force`, and a token for another pair are rejected.


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
