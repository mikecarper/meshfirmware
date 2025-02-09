# Meshtastic Firmware Selector
This Bash script automates the process of selecting, downloading, and applying firmware updates from the [meshtastic/firmware](https://github.com/meshtastic/firmware) GitHub repository. It is designed to simplify firmware management for meshtastic devices by handling everything from release selection to device update.

# Quick start
Copy and run this in your linux terminal 
```bash
cd ~ && wget -qO - https://raw.githubusercontent.com/mikecarper/meshfirmware/refs/heads/main/firmware.sh | bash
```

# Do it the correct way
```bash
cd ~
git clone https://github.com/mikecarper/meshfirmware.git
cd meshfirmware
chmod +x firmware.sh
./firmware.sh
```
As one line
```
cd ~ && git clone https://github.com/mikecarper/meshfirmware.git && cd meshfirmware && chmod +x firmware.sh && ./firmware.sh
```


Overview
--------

The script performs the following key tasks:

1.  **Cache Management & Internet Check:**
    
    *   Checks if an internet connection is available.
        
    *   Updates a local cache file with GitHub release data if it is older than 6 hours.
        
    *   Falls back to using the cached data if no internet connection is detected.
        
2.  **Release Selection:**
    
    *   Parses the JSON release data to build a list of firmware release versions.
        
    *   Appends labels (such as _(alpha)_, _(beta)_, _(rc)_, or _(pre-release)_) based on the release tag.
        
    *   Supports automatic selection of a release version via the --version command-line option or presents an interactive menu if not provided.
        
3.  **Firmware Download & Extraction:**
    
    *   Identifies firmware assets whose filenames start with firmware- and end with the chosen version string.
        
    *   Downloads any missing firmware zip assets to a dedicated download directory.
        
    *   Unzips the downloaded assets into a structured folder layout (firmware///).
        
4.  **Device Detection & Firmware Matching:**
    
    *   Uses lsusb to detect connected USB devices.
        
    *   Normalizes firmware filenames to extract the product name.
        
    *   Matches the detected device against available firmware files.
        
    *   If more than one matching firmware file exists, the user is prompted to choose the correct one.
        
5.  **Operation Mode (Update vs Install):**
    
    *   Allows the user (or command-line arguments) to choose between an update or an install operation.
        
    *   For ESP32 devices, the script adjusts the update script (e.g., changes baud rate from 115200 to 1200) as required.
        
    *   Stops any systemd service locking the device before proceeding and restarts it afterward.
        
6.  **Dependency Checks & Execution:**
    
    *   Ensures that necessary dependencies (e.g., Python, pipx, esptool, meshtastic CLI, jq, curl) are installed.
        
    *   Uses the first available Python interpreter to run esptool.
        
    *   Optionally runs the update/install script automatically if the --run option is provided.
        

Usage
-----

Run the script with the following syntax:

```bash
./firmware.sh [OPTIONS]   
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
    
