# Alt CLI firmware selector for MeshCore & Meshtastic projects
Scripts that automates the process of selecting, downloading, and applying firmware updates from the [meshcore-dev/MeshCore](https://github.com/meshcore-dev/MeshCore) & [meshtastic/firmware](https://github.com/meshtastic/firmware) GitHub repository via the USB port.  

# Windows Quick start - MeshCore & Meshtastic in one script
[Download firmware.cmd (right click save)](https://github.com/mikecarper/meshfirmware/blob/main/firmware.cmd?raw=true)  
Make sure file is named firmware.cmd and not firmware.cmd.txt  
double click and run the file firmware.cmd  

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

### Recover a stalled USB connection (Linux)

`mcsetup.sh` has a **U) Reset USB connection** action and offers recovery when
the radio does not answer its initial clock query. The MeshCore flasher,
`mcfirmware.sh`, offers USB connection recovery before probing the selected
radio and in its manual recovery menu.

This is the device-only USB reset used to recover a stalled Station G2 USB
interface. It reconnects USB; it does **not** reboot the radio CPU, enter the
bootloader, erase flash, change settings, or toggle a GPIO relay. It is
separate from the firmware's `reboot` command and the flasher's bootloader-entry
sequence. It cannot repair a radio whose firmware itself is hung.

Recovery is optional (default **No**) and requires Linux and `sudo`. Close any
serial terminal or stop the service using that radio first; recovery refuses
busy ports rather than stopping programs. The tools save the selected USB
identity before probing, reject hubs or a different/replaced device, and only
continue with a verified returning port. If recovery fails, select the radio
again instead of retrying a possibly reused tty number. The flasher's
`MCFIRMWARE_NO_SUDO=1` mode does not perform USB resets.

The shared Python helper is included in a checkout. Single-script downloads
fetch a copy with a checksum pinned by the script; a missing or mismatched
helper disables recovery. This Linux feature does not change `mcsetup.cmd`
or `firmware.cmd` on Windows.

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
