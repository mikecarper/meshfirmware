# 3rd party firmware selector for the Meshtastic project
The CMD and Bash script automates the process of selecting, downloading, and applying firmware updates from the [meshtastic/firmware](https://github.com/meshtastic/firmware) GitHub repository via the USB port.

# Windows Quick start
[Download mtfirmware.cmd (right click save)](https://github.com/mikecarper/meshfirmware/blob/main/mtfirmware.cmd?raw=true)  
Make sure file is named mtfirmware.cmd and not mtfirmware.cmd.txt  
double click and run the file mtfirmware.cmd

Windows Video
-----

https://github.com/user-attachments/assets/ab68cb5e-63d5-4c73-ac4a-fdb76702fb20




# Linux Quick start
Copy and run this in your linux terminal 
```bash
cd ~ && git clone https://github.com/mikecarper/meshfirmware.git && cd meshfirmware && chmod +x mtfirmware.sh && ./mtfirmware.sh
```
<details>
  <summary>Readable Code</summary>  
    
```bash
cd ~
git clone https://github.com/mikecarper/meshfirmware.git
cd meshfirmware
chmod +x mtfirmware.sh
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

