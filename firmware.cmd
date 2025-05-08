# 2>NUL & @powershell -nop -ep bypass "(gc '%~f0')-join[Environment]::NewLine|iex" && @EXIT /B 0

#Example execute:
# powershell -ExecutionPolicy ByPass -File c:\git\meshfirmware\firmware.ps1


# Flag to track if Ctrl-C has been pressed
$scriptOver = $false

# Register a Ctrl-C handler:
$null = Register-ObjectEvent -InputObject ([System.Console]) `
    -EventName CancelKeyPress -Action {
        # $EventArgs is in scope here:
        $EventArgs.Cancel = $true
        
        if (-not $scriptOver) {
            # First Ctrl-C press: prompt user
            Write-Host "`nCaught Ctrl-C." -ForegroundColor Yellow
            $scriptOver = $true
            Read-Host "Press Enter to exit (via Ctrl-C)"
        } else {
            # Second Ctrl-C press: exit without prompt
            Write-Host "`nExiting script..." -ForegroundColor Red
            exit
        }
    }

$ScriptPath = $PSScriptRoot
if ([string]::IsNullOrEmpty($ScriptPath)) {
    $ScriptPath = (Get-Location).Path
}


$CACHE_TIMEOUT_SECONDS=6 * 3600 # 6 hours


        $GITHUB_API_URL="https://api.github.com/repos/meshtastic/firmware/releases"
          $REPO_API_URL="https://api.github.com/repos/meshtastic/meshtastic.github.io/contents"
 $WEB_HARDWARE_LIST_URL="https://raw.githubusercontent.com/meshtastic/web-flasher/refs/heads/main/public/data/hardware-list.json"
 
         $FIRMWARE_ROOT="${ScriptPath}\meshtastic_firmware"
          $DOWNLOAD_DIR="${ScriptPath}\meshtastic_firmware\downloads"
         $RELEASES_FILE="${ScriptPath}\meshtastic_firmware\releases.json"
         $HARDWARE_LIST="${ScriptPath}\meshtastic_firmware\hardware-list.json"
		   $BLEOTA_FILE="${ScriptPath}\meshtastic_firmware\bleota.json"
		   
    $VERSIONS_TAGS_FILE="${ScriptPath}\meshtastic_firmware\01versions_tags.txt"
  $VERSIONS_LABELS_FILE="${ScriptPath}\meshtastic_firmware\02versions_labels.txt"
       $CHOSEN_TAG_FILE="${ScriptPath}\meshtastic_firmware\03chosen_tag.txt"
   $MATCHING_FILES_FILE="${ScriptPath}\meshtastic_firmware\07matching_files.txt"
     $ARCHITECTURE_FILE="${ScriptPath}\meshtastic_firmware\11architecture.txt"



$cleanupFiles = @(
    $VERSIONS_TAGS_FILE,
    $VERSIONS_LABELS_FILE,
    $CHOSEN_TAG_FILE,
    $MATCHING_FILES_FILE,
    $ARCHITECTURE_FILE
)

# delete any that exist
foreach ($f in $cleanupFiles) {
    if (Test-Path $f) {
        Remove-Item $f -Force -ErrorAction SilentlyContinue
    }
}




function NormalizeString {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline = $true)]
        [string] $InputString
    )
    process {
        # remove -, _, and any whitespace, then lowercase
        ($InputString -replace '[-_\s]', '').ToLower()
    }
}

# helper to convert a byte count into KB/MB/GB/TB automatically
function FormatSize {
    param([ulong]$Bytes)
    $x = switch ($Bytes) {
        { $_ -ge 1TB } { "{0:N2} TB" -f ($Bytes/1TB); break }
        { $_ -ge 1GB } { "{0:N2} GB" -f ($Bytes/1GB); break }
        { $_ -ge 1MB } { "{0:N2} MB" -f ($Bytes/1MB); break }
        { $_ -ge 1KB } { "{0:N2} KB" -f ($Bytes/1KB); break }
        default        { "$Bytes bytes" }
    }
	return $x
}


# Function to fetch the latest stable Python version from GitHub
function Get-LatestPythonVersion {
    $url = "https://api.github.com/repos/actions/python-versions/releases/latest"
    $release = Invoke-RestMethod -Uri $url -Headers @{Accept = "application/vnd.github.v3+json"}
    $latestVersion = $release.tag_name
    return $latestVersion
}

function get_esptool_cmd() {
	try {
		# Check if Python is installed and get the version
		$pythonVersion = & $pythonCommand --version
		Write-Progress -Status "Checking Versions" -Activity "Python interpreter found: $pythonVersion"
		# Set the ESPTOOL command to use Python
		$ESPTOOL_CMD = "$pythonCommand -m esptool"  # Construct as a single string
	} catch {
		# If Python is not found, check for esptool in the system PATH
		Write-Host "Python interpreter not found. Checking for esptool..."

		$esptoolPath = Get-Command esptool -ErrorAction SilentlyContinue

		if ($esptoolPath) {
			# If esptool is found, set the ESPTOOL command
			$ESPTOOL_CMD = "esptool"  # Set esptool command
		} else {
			# If neither Python nor esptool is found, fallback to python -m esptool
			Write-Host "esptool not found. Falling back to python -m esptool."
			$ESPTOOL_CMD = "python -m esptool"  # Fallback to Python esptool
		}
	}
	
	$run = run_cmd "$ESPTOOL_CMD version"
	$esptoolVersion = $run | Select-Object -Last 1
	if ($pythonVersion) {
		Write-Progress -Status "Checking Versions" -Activity "Python interpreter found: $pythonVersion esptool version: $esptoolVersion"
	}
	else {
		Write-Progress -Status "Checking Versions" -Activity "esptool version: $esptoolVersion"
	}

	
	return $ESPTOOL_CMD
}

function run_cmd($ESPTOOL_CMD) {
    # Create two temporary files for capturing standard output and error
    $tempOutputFile = Join-Path -Path $ScriptPath -ChildPath "esptool_output.txt"
    $tempErrorFile = Join-Path -Path $ScriptPath -ChildPath "esptool_error.txt"

    # Ensure we split the command and arguments properly into an array
    $commandParts = $ESPTOOL_CMD.Split(" ")

    # Start the process and capture both standard output and error to separate files
    Start-Process -FilePath $commandParts[0] -ArgumentList $commandParts[1..$commandParts.Length] -PassThru -Wait -NoNewWindow -RedirectStandardOutput $tempOutputFile -RedirectStandardError $tempErrorFile | out-null

    # Get the content of both the output and error files
    $content = Get-Content $tempOutputFile

    # Clean up the temporary files
    Remove-Item $tempOutputFile -Force
    Remove-Item $tempErrorFile -Force

    # Return only the filtered content
    return $content
}


function check_requirements() {
	# Check if Python is installed
	$global:pythonCommand = Get-Command python -ErrorAction SilentlyContinue
	if (-not $pythonCommand) {
		# Get the latest stable Python version
		$latestPythonVersion = Get-LatestPythonVersion
		Write-Host "Python is not installed."

		# Ask the user if they want to install Python
		$installPython = Read-Host "Do you want to install Python $latestPythonVersion now? (Y/N)"
		if ($installPython -eq 'Y' -or $installPython -eq 'y') {
			Write-Host "Downloading and installing Python $latestPythonVersion..."

			# Set Python installer URL for Windows
			$pythonInstallerUrl = "https://www.python.org/ftp/python/$latestPythonVersion/python-$latestPythonVersion-amd64.exe"
			$installerPath = "$env:TEMP\python_installer.exe"

			# Download the Python installer
			Invoke-WebRequest -Uri $pythonInstallerUrl -OutFile $installerPath

			# Run the installer silently with 'Add Python to PATH' option enabled
			Start-Process -FilePath $installerPath -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1" -Wait

			# Clean up the installer
			Remove-Item $installerPath

			Write-Host "Python $latestPythonVersion has been installed successfully."

			# Recheck if Python is installed
			$global:pythonCommand = Get-Command python -ErrorAction SilentlyContinue
			if (-not $pythonCommand) {
				Write-Host "Python installation failed. Please check your system."
				exit
			}
		} else {
			Write-Host "Please install Python manually and run the script again."
			exit
		}
	}

	# Check if meshtastic is installed
	$meshtasticCommand = Get-Command meshtastic -ErrorAction SilentlyContinue
	if (-not $meshtasticCommand) {
		Write-Host "Meshtastic is not installed. Installing..."

		# Check if pip3 is installed
		$pip3Command = Get-Command pip3 -ErrorAction SilentlyContinue
		if (-not $pip3Command) {
			Write-Host "pip3 is not installed. Installing pip3..."
			# Download the get-pip.py script
			$getPipUrl = "https://bootstrap.pypa.io/get-pip.py"
			$getPipScriptPath = "$env:TEMP\get-pip.py"
			Invoke-WebRequest -Uri $getPipUrl -OutFile $getPipScriptPath

			# Run the script to install pip3
			python $getPipScriptPath

			# Clean up the get-pip.py script
			Remove-Item $getPipScriptPath
		}

		# Install or upgrade meshtastic using pip3
		pip3 install --upgrade "meshtastic[cli]"
		Write-Host "Meshtastic installed/updated successfully."
	}
	else {
		Write-Progress -Activity "Update meshtastic command line tool"
		pip3 install --upgrade "meshtastic[cli]" | out-null
	}
	
	$null = & python -m patch --version 2>$null
	if ($LASTEXITCODE -ne 0) {
		pip3 install --upgrade "patch"
		Write-Host "patch installed/updated successfully."
	}
	else {
		Write-Progress -Activity "Update patch command line tool"
		pip3 install --upgrade "patch" | out-null
	}

	Write-Progress -Activity "Update pip command line tool"
	python.exe -m pip install --upgrade pip *> out-null
	Write-Progress -Activity " " -Status " " -Completed
}


function getallUSBCom($output) {
	# Get all Serial Ports and filter for USB serial devices by checking Description and DeviceID
	#$comDevices = Get-WmiObject Win32_SerialPort
	$comDevices = Get-WmiObject -Class Win32_PnPEntity | Where-Object { $_.DeviceID -like "*USB*" -and $_.Name -like "*(com*" }
	
	# Initialize the array for storing the results
	$usbComDevices = @()

	foreach ($device in $comDevices) {
		#$device
		# Extract COM port from the Name property
		if ($device.Name -match 'COM(\d+)') {
			$comPort = $matches[0]  # The full COM port string like COM3 or COM5
		}

		# Split the string by "\" and get the last part
		$HardwareID = $device.HardwareID.Split("\")[-1]

		# Add the device information to $usbComDevices
		$usbComDevices += [PSCustomObject]@{
			drive_letter      = $comPort
			device_name       = $HardwareID
			friendly_name     = $device.Name
			firmware_revision = "--"
		}
	}

	return $usbComDevices
}

function runMeshtasticCommand($selectedComPort, $command) {
	# Define a temporary file to capture the output
	$tempOutputFile = Join-Path -Path $ScriptPath -ChildPath "meshtastic_output$selectedComPort.txt"
	$tempErrorFile = Join-Path -Path $ScriptPath -ChildPath "meshtastic_error$selectedComPort.txt"

	# Start the meshtastic process with a hidden window and capture the process ID
	#Write-Host "Running meshtastic command on port $selectedComPort"
	Write-Progress -Activity "running meshtastic --port $selectedComPort $command"
	$process = Start-Process "meshtastic" -ArgumentList "--port $selectedComPort $command" -PassThru -WindowStyle Hidden -RedirectStandardOutput $tempOutputFile -RedirectStandardError $tempErrorFile
	$processWait = $process.WaitForExit($timeoutMeshtastic * 1000)  # Timeout is in milliseconds
	
	
	$meshtasticOutput = ""
	$meshtasticError = ""
	# Check if the process exited within the timeout
	if ($processWait) {
		# If the process exits within the timeout, capture the output
		$meshtasticOutput = Get-Content $tempOutputFile -Raw
		$meshtasticError = Get-Content $tempErrorFile -Raw
		$process.Dispose()
	} else {
		# If the process did not exit within the timeout, forcefully kill it
		$meshtasticError = "Timed Out"
		$process.Kill()
	}
	Start-Sleep -Seconds 1
	
	# Clean up: remove temporary files
	try {
		Remove-Item $tempOutputFile -Force | out-null
		Remove-Item $tempErrorFile -Force | out-null
	} catch {
		Write-Warning "ERROR: Could not delete temporary files. Make sure no other process is using them."
	}
	return ,$meshtasticOutput, $meshtasticError
}

function getMeshtasticNodeInfo($selectedComPort) {
	$result = runMeshtasticCommand $selectedComPort "--info --no-nodes"
	$meshtasticOutput = $result[0]
	$meshtasticError  = $result[1]
	
		
	if ($meshtasticError) {
		Write-Host "Error"
		Write-Host $meshtasticError
		if ($meshtasticError -eq "Timed Out") {
			return $meshtasticError 
		}
	}

	
	$meshtasticOutput = $meshtasticOutput -replace '(\{|\}|\,)', "$1`n"

	$deviceInfo = New-Object PSObject -property @{
		Name        = ""
		HWName      = ""
		HWNameShort = ""
		FWVersion   = ""
	}

	$splitted = $meshtasticOutput -split "`n"
	$splitted | ForEach-Object {
		# Split each line into key-value pairs
		$i = $_ -split ":", 2
		if ($i.Count -eq 2) {
			# Ensure that the line contains both key and value
			$key = $i[0].Trim() -replace '"', ""
			$value = $i[1].Trim() 

			# Matching keys and storing values
			if ($key -like "*Owner*") {
				$deviceInfo.Name = $value
			}
			if ($key -like "*pioEnv*") {
				$deviceInfo.HWName = $value -replace '"', ""  # Removing any quotes in the value
			}
			if ($key -like "*hwModel*") {
				$deviceInfo.HWNameShort = $value -replace '"', ""  # Removing any quotes in the value
			}
			if ($key -like "*firmwareVersion*") {
				$deviceInfo.FWVersion = $value -replace '"', ""  # Removing any quotes in the value
			}
		}
	}


	return $deviceInfo
}

function selectUSBCom() {
    param (
        [Parameter(Mandatory=$true)]
        $availableComPorts
    )
	# Display a menu with available COM ports
	$validPort = $false
	while (-not $validPort) {
		# Ask the user to enter the COM port to operate on
		$selectedComPort = Read-Host "Enter the COM port to operate on"

		# Normalize the input to ensure both 'COM7' and '7' are valid
		if ($selectedComPort -match '^\d+$') {
			# If it's just a number, prepend "COM" to it
			$selectedComPort = "COM$selectedComPort"
		}

		# Check if the selected COM port exists in the list of USB COM devices
		if ($availableComPorts -contains $selectedComPort) {
			Write-Host "Selected COM port is valid: $selectedComPort"
			# Proceed with further operations on the selected COM port
			$validPort = $true
		} else {
			Write-Host "Invalid COM port: $selectedComPort  Please select a valid COM port."
		}
	}

	Write-Progress -Activity " " -Status " " -Completed
    return $selectedComPort
}

function USBDeview() {

	if (-not (Test-Path $usbDeviewPath)) {
		Write-Host "USBDeview.exe not found. Downloading and extracting..."

		# Download the zip file
		Invoke-WebRequest -Uri $downloadUrl -OutFile $zipFilePath

		# Extract the zip file
		Expand-Archive -Path $zipFilePath -DestinationPath $extractFolderPath -Force

		# Check if the extraction was successful and move the exe to the desired location
		$extractedExePath = Join-Path -Path $extractFolderPath -ChildPath "USBDeview.exe"

		if (Test-Path $extractedExePath) {
			# Move the USBDeview.exe to the ScriptPath
			Move-Item -Path $extractedExePath -Destination $usbDeviewPath -Force
			Write-Host "USBDeview.exe extracted and moved successfully."
		} else {
			Write-Host "ERROR: Failed to extract USBDeview.exe."
		}

		# Clean up: Remove the downloaded zip file and extracted folder
		Remove-Item -Path $zipFilePath -Force
		Remove-Item -Path $extractFolderPath -Recurse -Force
	}

	# Define a path for the usb_devices.xml file
	$usbDevicesOutputPath = Join-Path -Path $ScriptPath -ChildPath "usb_devices.xml"
	if (Test-Path $usbDevicesOutputPath) {
		Remove-Item -Path $usbDevicesOutputPath -Force
	}

	# Run USBDeview and output the connected devices in XML format
	Write-Progress -Status "Getting USB Devices" -Activity "Running $ScriptPath\USBDeview.exe /sort DriveLetter /TrayIcon 0 /DisplayDisconnected 0 /sxml $usbDevicesOutputPath"
	$usbDevices = Start-Process -FilePath "$ScriptPath\USBDeview.exe" -ArgumentList "/sort DriveLetter /TrayIcon 0 /DisplayDisconnected 0 /sxml $usbDevicesOutputPath" -PassThru -Wait -NoNewWindow

	# Check if the XML output file exists
	if (Test-Path $usbDevicesOutputPath) {
		# Load the XML file
		[xml]$xmlContent = Get-Content -Path $usbDevicesOutputPath

		# Extract and display device information (e.g., drive letter, description, etc.)
		$usbDevicesList = $xmlContent.usb_devices_list.item

		# Filter out devices with drive letters starting with 'COM' and display relevant details
		$comDevices = $usbDevicesList | Where-Object { $_.drive_letter -like "COM*" }
		
		return $comDevices
	} else {
		Write-Host "Error: usb_devices.xml not found. USBDeview was not ran successfully."
		exit
	}
}

# Function to get and display the USB devices
function getUsbComDevices() {
	[CmdletBinding()]
    param(
        [switch] $SkipInfo = $false
    )
	$usbComDevices = @()
    #$comDevices = USBDeview  
	$comDevices = getallUSBCom

    # Process each device and store the relevant details in $usbComDevices
    $comDevices | ForEach-Object {
		if (-not $SkipInfo) {
			Write-Progress -Status "Checking USB Devices" -Activity "Checking for meshtastic on $($_.drive_letter)"
			$deviceInfo = getMeshtasticNodeInfo $_.drive_letter
		}
		else {
			$deviceInfo = "Timed Out"
		}
		if ($deviceInfo -eq "Timed Out") {
			$usbComDevices += [PSCustomObject]@{
				COMPort           = $_.drive_letter
				DeviceName        = $_.device_name
				FriendlyName      = $_.friendly_name
				FirmwareVersion   = $_.firmware_revision
				Meshtastic 	      = $deviceInfo
			} 
		}
        else {
			$usbComDevices += [PSCustomObject]@{
				ComPort           = $_.drive_letter
				DeviceName        = $deviceInfo.HWName
				FriendlyName      = $deviceInfo.Name
				FirmwareVersion   = $deviceInfo.FWVersion
				Meshtastic	 	  = $deviceInfo.HWNameShort
			} 
		}
    }
	return $usbComDevices
}

function getUSBComPort() {
	$selectedComPort = 0 
	# Run in a loop until we get valid $comDevices
	do {
		$usbComDevices = getUsbComDevices

		# If there are no USB COM devices, display an error and loop again
		if ($usbComDevices.Count -eq 0) {
			Write-Host "No valid COM devices found. Please check the connection." -ForegroundColor Red
			Start-Sleep -Seconds 5  # Wait before trying again
		} else {
			$availableComPorts = $usbComDevices | Select-Object -ExpandProperty ComPort
			if ($availableComPorts.Count -eq 1) {
				$meshtasticVersion = $usbComDevices | Select-Object -ExpandProperty FirmwareVersion
				$hwModelSlug = $usbComDevices | Select-Object -ExpandProperty Meshtastic
				$selectedComPort = "$availableComPorts"
				#Write-Host "$selectedComPort. Version: $meshtasticVersion. Hardware: $hwModelSlug."
			}
			else {
				# If we found valid COM devices, let the user select one
				$tableOutput = $usbComDevices | Sort-Object -Property ComPort | Format-Table -Property ComPort, DeviceName, FriendlyName, FirmwareVersion, Meshtastic | Out-String
				# Remove lines that are empty or only contain spaces
				$tableOutput = $tableOutput -split "`n" | Where-Object { $_.Trim() -ne "" } | Out-String
				
				Write-Host ""
				Write-Host $tableOutput
				$selectedComPort = selectUSBCom -availableComPorts $availableComPorts
				
				# now filter out the single object whose ComPort matches
				$device = $usbComDevices |
					Where-Object { $_.ComPort -eq $selectedComPort }

				# and pull out the fields you care about
				$hwModelSlug       = $device.Meshtastic
				$meshtasticVersion = $device.FirmwareVersion

				#Write-Host "$selectedComPort. Version: $meshtasticVersion. Hardware: $hwModelSlug."
				
			}
		}

	} while ($usbComDevices.Count -eq 0 -and $selectedComPort -eq 0)  # Continue looping until we have at least one valid COM device
	return ,$selectedComPort, $hwModelSlug, $meshtasticVersion, $usbComDevices
}






# Check for an active internet connection.
function CheckInternet {
    $domain = [uri]$GITHUB_API_URL
    $domain = $domain.Host
    try {
        # Ping the domain to check for internet connection.
        if (Test-Connection -ComputerName $domain -Count 1 -Quiet) {
            return $true
        } else {
            return $false
        }
    } catch {
        return $false
    }
}

# Update the GitHub release cache if needed.
function UpdateReleases {
    if (-not (CheckInternet)) {
		Write-Progress -Activity "No internet connection; using cached release data if available."
		Return
	}
	if ((Test-Path $RELEASES_FILE) -and (Get-Date).AddSeconds(-$CACHE_TIMEOUT_SECONDS) -lt (Get-Item $RELEASES_FILE).LastWriteTime) {
		Write-Progress -Activity "Using cached release data (up to date within the last 6 hours)."
		return
	}
	
	# Create the firmware directory if it doesn't exist
	if (-not (Test-Path $FIRMWARE_ROOT)) {
		New-Item -ItemType Directory -Path $FIRMWARE_ROOT | Out-Null
	}

	# Ensure the directory for $RELEASES_FILE exists
	$releasesDir = [System.IO.Path]::GetDirectoryName($RELEASES_FILE)
	if (-not (Test-Path $releasesDir)) {
		New-Item -ItemType Directory -Path $releasesDir | Out-Null
	}

	Write-Progress -Activity "Updating release cache from GitHub..."
	# Download into a temp file first
	$tmpFile = [System.IO.Path]::GetTempFileName()
	try {
		Invoke-WebRequest -Uri $GITHUB_API_URL -OutFile $tmpFile -ErrorAction Stop
	} catch {
		Write-Host "Failed to download release data."
		Remove-Item $tmpFile
		return
	}

	# Check if the downloaded file is valid JSON
	try {
		$jsonContent = Get-Content $tmpFile | ConvertFrom-Json
	} catch {
		Write-Host "Downloaded file is not valid JSON. Aborting."
		Remove-Item $tmpFile
		return
	}

	# Filter out "download_count" keys from the JSON.
	$filteredTmp = [System.IO.Path]::GetTempFileName()
	$jsonContent | ConvertTo-Json -Depth 10 | ForEach-Object { 
		$_ -replace '"download_count":\s*\d+,', ''
	} | Set-Content -Path $filteredTmp

	# Use the filtered JSON for further processing.
	if (-not (Test-Path $RELEASES_FILE)) {
		Move-Item $filteredTmp $RELEASES_FILE
		Remove-Item $tmpFile
	} else {
		# Compare the MD5 hashes of the cached file and the newly filtered file.
		$oldMd5 = Get-FileHash $RELEASES_FILE -Algorithm MD5
		$newMd5 = Get-FileHash $filteredTmp -Algorithm MD5
		if ($oldMd5.Hash -ne $newMd5.Hash) {
			Write-Progress -Activity "Release data changed. Updating cache and removing cached version lists. $($oldMd5.Hash) $($newMd5.Hash)"
			Remove-Item $RELEASES_FILE
			Move-Item $filteredTmp $RELEASES_FILE
			Remove-Item $VERSIONS_TAGS_FILE, $VERSIONS_LABELS_FILE | Out-Null
		} else {
			Write-Progress -Activity "Release data is unchanged. $($oldMd5.Hash) $($newMd5.Hash)"
			
			# Update the LastWriteTime of the RELEASES_FILE to the current time
			Set-ItemProperty -Path $RELEASES_FILE -Name LastWriteTime -Value (Get-Date)
			
			Remove-Item $filteredTmp
		}
		Remove-Item $tmpFile
	}
}

function UpdateHardwareList {    
    # Check if the file exists and if it's older than 6 hours
    if (-not (Test-Path $HARDWARE_LIST) -or ((Get-Date) - (Get-Item $HARDWARE_LIST).LastWriteTime).TotalMinutes -gt 360) {
        Write-Progress -Activity "Downloading resources.ts from GitHub..."
        
        # Create the directory if it doesn't exist
        $directory = [System.IO.Path]::GetDirectoryName($HARDWARE_LIST)
        if (-not (Test-Path $directory)) {
            New-Item -Path $directory -ItemType Directory
        }

        # Download the file
        Invoke-WebRequest -Uri $WEB_HARDWARE_LIST_URL -OutFile $HARDWARE_LIST
    }
}



# Function to build the release menu and save version tags and labels.
function BuildReleaseMenuData {
    $tmpfile = New-TemporaryFile

    $ReleasesJson = Get-Content -Path "$RELEASES_FILE" -Raw
    $ReleasesJson = $ReleasesJson -replace '[^\x00-\x7F]', '' # Remove non-ASCII characters.

    # Parse the JSON manually
    $jsonData = $ReleasesJson | ConvertFrom-Json

    # Loop through each release to build the entries.
    foreach ($release in $jsonData) {
        $tag = $release.tag_name
        $prerelease = $release.prerelease
        $draft = $release.draft
        $body = $release.body
        $created_at = $release.created_at

        $suffix = ""
        $date = $created_at

        if ($tag -match "[Aa]lpha") {
            $suffix = "$suffix (alpha)"
        } elseif ($tag -match "[Bb]eta") {
            $suffix = "$suffix (beta)"
        } elseif ($tag -match "[Rr][Cc]") {
            $suffix = "$suffix (rc)"
        }

        if ($draft -eq $true) {
            $suffix = "$suffix (draft)"
        } elseif ($prerelease -eq $true) {
            $suffix = "$suffix (pre-release)"
        }

        $tag = $tag.Substring(1)  # Remove the 'v' from the version tag
        $label = "{0,-14} {1}" -f $tag, $suffix

        if ($body -match '⚠️') {
            $label = "! $label"
        } elseif ($body -match 'Known issue') {
			$label = "! $label"
		} elseif ($body -match 'Revocation') {
			$label = "! $label"
		}
		else {
            $label = "  $label"
        }

        # Write the entry to the temporary file.
        "$date`t$tag`t$label" | Out-File -Append -FilePath $tmpfile
    }

    # Check if any subdirectory name in FIRMWARE_ROOT (skip "downloads") is not in the tag_names from above.
    Get-ChildItem -Path $FIRMWARE_ROOT | ForEach-Object {
        $folder = $_
        if ($folder.PSIsContainer -and $folder.Name -ne "downloads") {
            $folderName = $folder.Name.ToLower()

            if ($folderName -match "^v") {
                $folderName = $folderName.Substring(1)
            }

            $found = $false
            $content = Get-Content -Path $tmpfile
            foreach ($line in $content) {
                if ($line -match $folderName) {
                    $found = $true
                    break
                }
            }

            if (-not $found) {
                $firstFile = Get-ChildItem -Path $folder.FullName -File -Filter "firmware-*" | Select-Object -First 1
                if ($firstFile) {
                    $mtime = (Get-Date (Get-Item $firstFile.FullName).LastWriteTime -UFormat "%Y-%m-%dT%H:%M:%SZ")
                } else {
                    $mtime = (Get-Date (Get-Item $folder.FullName).LastWriteTime -UFormat "%Y-%m-%dT%H:%M:%SZ")
                }

                $label = "! $folderName $mtime (nightly)"
                "$mtime`t$folderName`t$label" | Out-File -Append -FilePath $tmpfile
            }
        }
    }

    # Sort all entries by date in descending order (newest first)
    $sortedEntries = Get-Content -Path $tmpfile | Sort-Object -Descending

    # Build arrays from the sorted entries.
    $versionsTags = @()
    $versionsLabels = @()

    foreach ($entry in $sortedEntries) {
        $fields = $entry -split "`t"
        $versionsTags += $fields[1]
        $versionsLabels += $fields[2]
    }

    # Save the arrays for later use.
    $versionsTags | Out-File -FilePath $VERSIONS_TAGS_FILE
    $versionsLabels | Out-File -FilePath $VERSIONS_LABELS_FILE
    Write-Host ""
}




function SelectRelease {
    param([string] $VersionArg)
	
	Write-Progress -Activity " " -Status " " -Completed

    # load the cached lists
    $versionsTags   = Get-Content $VERSIONS_TAGS_FILE
    $versionsLabels = Get-Content $VERSIONS_LABELS_FILE
    $count          = $versionsLabels.Count
    if ($count -eq 0) { throw "No releases cached." }

    # find first stable index
    $latestStableIndex = 0
    for ($i = 0; $i -lt $count; $i++) {
        if ($versionsLabels[$i] -notlike '! *' -and $versionsLabels[$i] -notlike '* (pre-release)*') {
            $latestStableIndex = $i
            break
        }
    }

    if ($VersionArg) {
        $chosen = $versionsTags.FindIndex({ $_ -like "*$VersionArg*" })
        if ($chosen -lt 0) { throw "No matching release for '$VersionArg'" }
    }
    else {
        # layout maths
        $termWidth      = $Host.UI.RawUI.WindowSize.Width
        $maxLabelLength = ($versionsLabels | Measure-Object Length -Maximum).Maximum
        $indexWidth     = $count.ToString().Length
        $colLabelWidth  = $maxLabelLength + 2
        $colWidth       = $indexWidth + 2 + $colLabelWidth + 8
        $numPerRow      = [Math]::Max(1, [int]($termWidth / $colWidth))

        # 1) BUILD the array of PSCustomObject{text, color}
        $formatted = for ($i = 0; $i -lt $count; $i++) {
            $label = $versionsLabels[$i].Trim()
            $text  = "{0:D$indexWidth}) {1,-$colLabelWidth}" -f ($i+1), $label

            # pick a color
            if ($label -match '[Nn]ightly') {
                $color = 'Red'
            }
            elseif ($i -eq $latestStableIndex) {
                $color = 'Cyan'
            }
            elseif ($label -match '\(pre-release\)' -and -not $script:PreColored) {
                $script:PreColored = $true
                $color = 'Yellow'
            }
            elseif ($label -notmatch '\(pre-release\)' -and -not $script:StableColored) {
                $script:StableColored = $true
                $color = 'Green'
            }
            else {
                $color = 'White'
            }

            [PSCustomObject]@{ Text = $text; Color = $color }
        }

		# 2) reverse in-place (oldest → newest)
		[Array]::Reverse($formatted)

		# 3) print in rows unchanged
		$row = 0
        foreach ($item in $formatted) {
            Write-Host -NoNewline $item.Text -ForegroundColor $item.Color
            $row++
            if ($row % $numPerRow -eq 0) { Write-Host }
        }
        if ($row % $numPerRow -ne 0) { Write-Host }

		# 4) prompt
		do {
			$sel = Read-Host -Prompt "Enter number of your selection (1-$count)"
			$sel = $sel.TrimStart('0')
			$sel = [int]$sel

			$tag = ''
			try {
				$tag = $versionsLabels[$sel-1].Trim().TrimStart('!').Trim()
				if ($tag -match '^\S+') {
					$tag = $matches[0].Trim()
				}
			}
			catch {$tag = ''}
		} until (-not ([string]::IsNullOrEmpty($tag)))
    }

    # save & return
	Write-Host "Picked $tag"
    $tag | Out-File -Encoding ascii -NoNewline $CHOSEN_TAG_FILE
    return $tag
}




function DownloadAssets {
    <#
    .SYNOPSIS
      Download all firmware-* assets for the chosen release (skipping any “debug” builds).
    #>

    # 1) Read & parse the cached release JSON
    $jsonRaw = Get-Content -Path $RELEASES_FILE -Raw
    $jsonRaw = $jsonRaw -replace '[^\x00-\x7F]', ''
    try {
        $allReleases = $jsonRaw | ConvertFrom-Json
    } catch {
        Throw "Failed to parse JSON from '$RELEASES_FILE': $_"
    }

    # 2) Determine the chosen tag
    $chosenTag = (Get-Content -Path $CHOSEN_TAG_FILE -Raw).Trim()
    if (-not $chosenTag) {
        Throw "No chosen tag found in '$CHOSEN_TAG_FILE'."
    }
    $downloadPattern = "-$chosenTag"

    # 3) Find the release object
    $release = $allReleases |
        Where-Object { $_.tag_name.TrimStart('v') -eq $chosenTag } |
        Select-Object -First 1
    if (-not $release) {
        Throw "Release with tag '$chosenTag' not found."
    }

    # 4) Filter its assets
    $assets = $release.assets |
        Where-Object { $_.name -match '^firmware-' -and $_.name -notmatch 'debug' }
    if (-not $assets) {
        Throw "No firmware assets found for release '$chosenTag'."
    }

    # 5) Prepare download dir & remove stale temps
    if (-not (Test-Path $DOWNLOAD_DIR)) {
        New-Item -Path $DOWNLOAD_DIR -ItemType Directory | Out-Null
    }
    Get-ChildItem -Path $DOWNLOAD_DIR -Filter '*.tmp*' -File |
        Remove-Item -Force

    # 6) Download loop
    $hadExisting = $false
    foreach ($asset in $assets) {
        $name = $asset.name
        $url  = $asset.browser_download_url
        $dest = Join-Path $DOWNLOAD_DIR $name

        if (Test-Path $dest) {
			Write-Progress -Activity "Already have $name"
            $hadExisting = $true
            continue
        }

        if ($hadExisting) { Write-Host ""; $hadExisting = $false }

        $tmpFile = Join-Path $DOWNLOAD_DIR ("{0}.tmp" -f ([Guid]::NewGuid()))
        try {
            Invoke-WebRequest -Uri $url -OutFile $tmpFile -UseBasicParsing -ErrorAction Stop
            Move-Item -Path $tmpFile -Destination $dest -Force
        } catch {
            Write-Host "Failed to download $name" -ForegroundColor Red
            Remove-Item -Path $tmpFile -ErrorAction SilentlyContinue
        }
    }

    # 7) Save the pattern marker
	Write-Progress -Activity " " -Status " " -Completed
}



function UnzipAssets {
    param(
        [string] $ReleasesFile  = $RELEASES_FILE,
        [string] $ChosenTagFile = $CHOSEN_TAG_FILE,
        [string] $DownloadDir   = $DOWNLOAD_DIR,
        [string] $FirmwareRoot  = $FIRMWARE_ROOT
    )

    # 1) Read chosen tag
    $chosenTag = (Get-Content -Path $ChosenTagFile -Raw).Trim()
    if (-not $chosenTag) {
        Throw "No chosen tag found in '$ChosenTagFile'."
    }

    # 2) Load & parse all releases
    $jsonRaw = Get-Content -Path $ReleasesFile -Raw
    $jsonRaw = $jsonRaw -replace '[^\x00-\x7F]', ''
    try {
        $allReleases = $jsonRaw | ConvertFrom-Json
    } catch {
        Throw "Failed to parse JSON from '$ReleasesFile': $_"
    }

    # 3) Locate the release object by tag (strip leading 'v')
    $release = $allReleases |
        Where-Object { $_.tag_name.TrimStart('v') -eq $chosenTag } |
        Select-Object -First 1
    if (-not $release) {
        Throw "Release '$chosenTag' not found in JSON."
    }

    # 4) Filter for firmware-… zip assets (exclude debug)
    $assets = $release.assets |
        Where-Object { 
            $_.name -match '^firmware-' -and 
            $_.name -notmatch 'debug'
        }
    if (-not $assets) {
        Throw "No matching firmware assets found for release '$chosenTag'."
    }

    # 5) Unzip each asset to <FirmwareRoot>\<tag>\<product>\…
    foreach ($asset in $assets) {
        $name      = $asset.name
        $localFile = Join-Path $DownloadDir $name

        if ($name -match '^firmware-([^-\s]+)-.+\.zip$') {
            $product   = $Matches[1]
            $targetDir = Join-Path $FirmwareRoot "$chosenTag\$product"

            # ensure folder exists
            New-Item -Path $targetDir -ItemType Directory -Force | Out-Null

            # if empty, unzip
            $hasFiles = Get-ChildItem -Path $targetDir -File -Recurse -ErrorAction SilentlyContinue
            if (-not $hasFiles) {
                Expand-Archive -Path $localFile -DestinationPath $targetDir -Force
            }
            else {
				Write-Progress -Activity "Skipping $name - target folder already populated."
            }
        }
        else {
            Write-Host "Asset '$name' does not match expected naming convention; skipping."
        }
    }
		Write-Progress -Activity " " -Status " " -Completed
} 






function GetHardwareInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Slug,

        [Parameter(Mandatory)]
        [string] $ListPath
    )

    if (-not (Test-Path $ListPath)) {
        Throw "Hardware list not found at path: $ListPath"
    }
	
	# normalize the lookup slug
    $normSlug = NormalizeString $Slug

    # Load & parse JSON
    $hardwareList = Get-Content -Path $ListPath -Raw | ConvertFrom-Json

    # Find matching entry
    foreach ($entry in $HardwareList) {
        # build a list of normalized candidate keys for this entry
        $candidates = @(
            NormalizeString $entry.hwModelSlug
            NormalizeString $entry.platformioTarget
            NormalizeString $entry.displayName
        )

        if ($candidates -contains $normSlug) {
            break
        }
    }

    if (-not $entry) {
        Throw "No hardware entry found for slug '$Slug'"
    }

    # Determine if those optional properties actually exist, otherwise default to $false
    $requiresDfu = if ($entry.PSObject.Properties.Name -contains 'requiresDfu') { $entry.requiresDfu } else { $false }
    $hasInkHud   = if ($entry.PSObject.Properties.Name -contains 'hasInkHud')   { $entry.hasInkHud   } else { $false }
    $hasMui      = if ($entry.PSObject.Properties.Name -contains 'hasMui')      { $entry.hasMui      } else { $false }

    # Build and return a PSCustomObject
    return [PSCustomObject]@{
        Slug         = $entry.hwModelSlug
        Architecture = $entry.architecture
        DisplayName  = $entry.displayName
        RequiresDfu  = $requiresDfu
        HasInkHud    = $hasInkHud
		HasMui       = $hasMui
    }
}



function MakeConfigBackup {
	[CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $HWNameShort,

        [Parameter(Mandatory)]
        $selectedComPort
    )
	
	Write-Host "Making a config backup"

	# Generate the backup config name
	$backupConfigName = "$ScriptPath\config_backup.${HWNameShort}.${selectedComPort}.$([System.DateTime]::Now.ToString('yyyyMMddHHmmss')).yaml"

	# Start the loop for backup process
	while ($true) {
		try {
			# Run the meshtastic command and redirect output to the backup config file
			Write-Host "Running meshtastic --port $selectedComPort --export-config > $backupConfigName"
			# Start the Meshtastic process and redirect both stdout and stderr to the backup config file
			$process = Start-Process -FilePath "meshtastic" -ArgumentList "--port $selectedComPort --export-config" -PassThru -Wait -NoNewWindow -RedirectStandardOutput "$backupConfigName" -RedirectStandardError "$backupConfigName.error"

			# Check if the file has been created and output the file size
			if (Test-Path "$backupConfigName") {
				$fileSize = (Get-Item "$backupConfigName").Length
				if ("$fileSize" -gt 0) {
					if (-not (Test-Path "$backupConfigName.error") -or ((Get-Item "$backupConfigName.error").length -eq 0)) {
						Write-Host "Backup configuration created: $backupConfigName. $fileSize bytes"
						if (Test-Path "$backupConfigName.error") {
							Remove-Item "$backupConfigName.error" -Force | out-null
						}
						break
					}
					else {
						$content = Get-Content "$backupConfigName.error" -Raw
						Write-Host "Error from meshtastic:"
						Write-Host $content
					}
				}
			}
			Write-Host "Failed to create backup configuration."
			$response = Read-Host "Press Enter to try again or type 'skip' to skip the creation"
			if ($response -eq "skip") {
				Write-Host "Skipping config backup."
				break
			}
			Start-Sleep -Seconds 1
		} catch {
			# If there's an error, print the warning message
			Write-Host "Error caught: $($_.Exception.Message)"
			Write-Host "Warning: Timed out waiting for connection completion. Config backup not done." -ForegroundColor Red

			# Prompt the user for input to either try again or skip
			$response = Read-Host "Press Enter to try again or type 'skip' to skip the creation"

			if ($response -eq "skip") {
				Write-Host "Skipping config backup."
				break
			}
			
			# Wait for 1 second before retrying
			Start-Sleep -Seconds 1
		}
	}
	
}

function GetFirmwareFiles($HWNameShort) {
	$ChosenTagFile = $CHOSEN_TAG_FILE
	$FirmwareRoot  = $FIRMWARE_ROOT
	$HWNameShortNorm = $HWNameShort | NormalizeString

	$chosenTag = (Get-Content -Path $CHOSEN_TAG_FILE -Raw).Trim()
	$FolderPath = "$FirmwareRoot\$chosenTag"

    if (-not (Test-Path $FolderPath)) {
        throw "Folder not found: $FolderPath"
    }

    $matching = Get-ChildItem -Path $FolderPath -File -Recurse | Where-Object {
        # must start with firmware-, then some name, then -<digit> (the version), and end in .bin/.uf2/.zip
        $_.Name -match '^firmware-.+?.(?:bin|uf2|zip)$' -and  $_.Name -notmatch '-ota\.'
      } |
      ForEach-Object {
        # capture everything after firmware- up to the dash before the version
        if ($_.Name -match "^firmware-(.+?)-$chosenTag.*") {
			$match = $matches[1]
            $normalized = $match | NormalizeString
			if ($HWNameShortNorm -like "*$normalized*" -or $normalized -like "*$HWNameShortNorm*") {
                [PSCustomObject]@{
                    BaseName = $match
                    FullName = $_.FullName
                    NameLen  = $_.Name.Length
                }
			}
        }
      } | Sort-Object NameLen

	$best = $matching | Select-Object -First 1 
	if ($best) {
		$HWNameShortNorm = $best.BaseName | NormalizeString
		$matchingDeep = Get-ChildItem -Path $FolderPath -File -Recurse | Where-Object {
			# must start with firmware-, then some name, then -<digit> (the version), and end in .bin/.uf2/.zip
			$_.Name -match '^firmware-.+?.(?:bin|uf2|zip)$' -and  $_.Name -notmatch '-ota\.'
		  } |
		  ForEach-Object {
			# capture everything after firmware- up to the dash before the version
			if ($_.Name -match "^firmware-(.+?)-$chosenTag.*") {
				$match = $matches[1]
				$normalized = $match | NormalizeString
				if ($HWNameShortNorm -like "*$normalized*" -or $normalized -like "*$HWNameShortNorm*") {
					[PSCustomObject]@{
						BaseName = $match
						FullName = $_.FullName
						NameLen  = $_.Name.Length
					}
				}
			}
		  } | Sort-Object NameLen
	} 

	# write all the full paths to your output file
	$matchingDeep | Select-Object -ExpandProperty FullName | Set-Content -Path $MATCHING_FILES_FILE
	
	$best = $matchingDeep | Sort-Object NameLen | Select-Object -First 1 
	if ($best) {
		return $best.BaseName
	} else {
		Write-Warning "No matching firmware file found $HWNameShortNorm"
	}
}

function SelectMatchingFile {
    param(
        [string]$MatchingFilesFile = $MATCHING_FILES_FILE
    )

    # Read all candidate full paths
    $fullPaths = Get-Content -Path $MatchingFilesFile | Where-Object { $_.Trim() -ne '' }
    if ($fullPaths.Count -eq 0) {
        Write-Host "No matching files found in '$MatchingFilesFile'." -ForegroundColor Red
        return $null
    }

    # If only one, auto-select it (display just the filename)
    if ($fullPaths.Count -eq 1) {
        $leaf = Split-Path -Path $fullPaths[0] -Leaf
        Write-Host "Only one firmware file found: $fullPaths" -ForegroundColor Yellow
        return $fullPaths
    }
	
	$fullPaths = $fullPaths | Sort-Object

    # Otherwise, show menu of filenames
    Write-Host "Select a firmware file to use:" -ForegroundColor Cyan
    for ($i = 0; $i -lt $fullPaths.Count; $i++) {
        $leaf = Split-Path -Path $fullPaths[$i] -Leaf
        Write-Host ("{0,2}) {1}" -f ($i + 1), $leaf)
    }

    # Prompt until valid selection
    do {
        $sel = Read-Host -Prompt ("Enter the number of your choice (1-{0})" -f $fullPaths.Count)
    } until (
        ($sel -as [int]) -and 
        $sel -ge 1 -and 
        $sel -le $fullPaths.Count
    )

    # Return the full path corresponding to the chosen index
    return $fullPaths[$sel - 1]
}

function GetModelFromNode {
    # Iterate all removable drives (DriveType=2)
    foreach ($vol in Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=2") {
        $drive = $vol.DeviceID    # e.g. "E:"
        $infoFile = Join-Path $drive 'INFO_UF2.TXT'
        if (Test-Path $infoFile) {
            # Read the file and look for a line starting with "Model:"
            foreach ($line in Get-Content $infoFile -ErrorAction SilentlyContinue) {
                if ($line -match '^\s*Model:\s*(.+)$') {
                    return ,$matches[1].Trim(), $drive
                }
            }
        }
    }
    return ,$null, $null   # no INFO_UF2.TXT found or no Model: line
}




function SelectHardware {
    param(
        [string] $HardwareListFile = $HARDWARE_LIST
    )

    if (-not (Test-Path $HardwareListFile)) {
        Throw "Hardware list file not found: $HardwareListFile"
    }

    # Load and parse the JSON
    $hardware = Get-Content $HardwareListFile -Raw | ConvertFrom-Json

    # Sort by displayName
    $sorted = $hardware | Sort-Object displayName

    # Show a numbered menu
    for ($i = 0; $i -lt $sorted.Count; $i++) {
        $num = $i + 1
        Write-Host ("[{0}] {1}" -f $num, $sorted[$i].displayName)
    }

    # Prompt until we get a valid selection
    do {
        $sel = Read-Host "Enter the number of your choice (1-$($sorted.Count))"
    } until ($sel -as [int] -and $sel -ge 1 -and $sel -le $sorted.Count)

    $chosen = $sorted[$sel - 1]

    # Return the slug
    return $chosen.hwModelSlug
}






function UpdateBleOta {
    param(
        [string] $selectedFile
    )
	
	$RepoApiUrl = $REPO_API_URL
	$FirmwareRoot = $FIRMWARE_ROOT
	$BleOtaFile = $BLEOTA_FILE
	$CacheTimeoutSeconds = $CACHE_TIMEOUT_SECONDS
	

    if (-not (CheckInternet)) {
		Write-Host "Offline - using local BLE-OTA binaries if present."
		return
	}
	
	# Ensure firmware root exists
	New-Item -Path $FirmwareRoot -ItemType Directory -Force | Out-Null

	$needUpdate = -not (Test-Path $BleOtaFile) -or
				  ((Get-Date) -gt ((Get-Item $BleOtaFile).LastWriteTime.AddSeconds($CacheTimeoutSeconds)))

	if ($needUpdate) {
		Write-Host "Checking if Bluetooth-OTA bin files need updating…"

		$tmp = [IO.Path]::GetTempFileName()
		try {
			Invoke-RestMethod -Uri $RepoApiUrl -OutFile $tmp -ErrorAction Stop
		} catch {
			Write-Warning "Failed to download release data."
			Remove-Item $tmp -ErrorAction SilentlyContinue
			return
		}

		# Validate JSON
		try {
			(Get-Content $tmp -Raw) | ConvertFrom-Json | Out-Null
		} catch {
			Write-Warning "Downloaded file is not valid JSON. Aborting."
			Remove-Item $tmp -ErrorAction SilentlyContinue
			return
		}

		if (-not (Test-Path $BleOtaFile)) {
			Move-Item $tmp $BleOtaFile
		} else {
			$oldHash = (Get-FileHash $BleOtaFile -Algorithm MD5).Hash
			$newHash = (Get-FileHash $tmp         -Algorithm MD5).Hash
			if ($oldHash -ne $newHash) {
				Write-Host "Release data changed. Updating cache."
				Move-Item $tmp $BleOtaFile -Force
			} else {
				# just bump the timestamp
				(Get-Item $BleOtaFile).LastWriteTime = Get-Date
				Remove-Item $tmp -ErrorAction SilentlyContinue
			}
		}
	}

	# Load the directory listing
	$dirs = (Get-Content $BleOtaFile -Raw) | ConvertFrom-Json

	# find up to 3 firmware* dirs, newest first
	$folders = $dirs |
		Where-Object { $_.type -eq 'dir' -and $_.name.StartsWith('firmware') } |
		Sort-Object name -Descending |
		Select-Object -First 3 -ExpandProperty name

	$found = $null
	$attempt = 0
	foreach ($f in $folders) {
		$attempt++
		$url = "$RepoApiUrl/$f"
		Write-Host "Attempt $attempt - Checking folder '$f'…"
		$contents = Invoke-RestMethod -Uri $url
		$fileUrls = $contents |
			Where-Object { $_.type -eq 'file' -and $_.name.StartsWith('bleota') } |
			Select-Object -ExpandProperty download_url
		if ($fileUrls) {
			$found = $f
			break
		}
	}

	if (-not $found) {
		Throw "No 'bleota*' files found in the first 3 firmware folders."
	}

	# Figure out where to put them (same folder as the selected firmware file)
	$destFolder = Split-Path $selectedFile -Parent

	# Download any missing bleota files
	$contents = Invoke-RestMethod -Uri "$RepoApiUrl/$found"
	$fileUrls = $contents |
		Where-Object { $_.type -eq 'file' -and $_.name.StartsWith('bleota') } |
		Select-Object -ExpandProperty download_url

	foreach ($u in $fileUrls) {
		$fn = Split-Path $u -Leaf
		$dst = Join-Path $destFolder $fn
		if (-not (Test-Path $dst)) {
			Write-Host "Downloading $fn"
			Invoke-RestMethod -Uri $u -OutFile $dst
		}
	}

    Write-Host ""
}




function ApplyPatch() {
	param(
        [string] $selectedFile
    )
	
	$destFolder = Split-Path $selectedFile -Parent
	$patchPath = "$destFolder\fix.patch"

@'
diff --git a/device-install.bat b/device-install.bat
index 3ffca0b..e80233a 100644
--- a/device-install.bat
+++ b/device-install.bat
@@ -170,12 +170,34 @@ IF %BIGDB16% EQU 1 CALL :LOG_MESSAGE INFO "BigDB 16mb partition selected."
 SET "BASENAME=!FILENAME:firmware-=!"
 CALL :LOG_MESSAGE DEBUG "Computed firmware basename: !BASENAME!"
 
+REM Extract the folder containing that file
+for %%F in ("%FILENAME%") do set "FWFOLDER=%%~dpF"
+
+REM Trim off any trailing backslash
+if "!FWFOLDER:~-1!"=="\" set "FWFOLDER=!FWFOLDER:~0,-1!"
+
+REM Pull just the folder name (e.g. "esp32s3")
+for %%D in ("!FWFOLDER!") do set "PLATFORM=%%~nD"
+CALL :LOG_MESSAGE DEBUG "platform folder is !PLATFORM!"
+
+REM If PLATFORM ends in "s3", pick the s3 OTA image
+if /I "!PLATFORM:~-2!"=="s3" (
+    set "OTA_FILENAME=bleota-s3.bin"
+    goto :OTA_DONE
+)
+
+REM If PLATFORM ends in "c3", pick the c3 OTA image
+if /I "!PLATFORM:~-2!"=="c3" (
+    set "OTA_FILENAME=bleota-c3.bin"
+    goto :OTA_DONE
+)
+
 @REM Account for S3 and C3 board's different OTA partition.
 FOR %%a IN (%S3%) DO (
     IF NOT "!FILENAME:%%a=!"=="!FILENAME!" (
         @REM We are working with any of %S3%.
         SET "OTA_FILENAME=bleota-s3.bin"
-        GOTO :end_loop_s3
+        GOTO :OTA_DONE
     )
 )
 
@@ -183,14 +205,13 @@ FOR %%a IN (%C3%) DO (
     IF NOT "!FILENAME:%%a=!"=="!FILENAME!" (
         @REM We are working with any of %C3%.
         SET "OTA_FILENAME=bleota-c3.bin"
-        GOTO :end_loop_c3
+        GOTO :OTA_DONE
     )
 )
 
 @REM Everything else
 SET "OTA_FILENAME=bleota.bin"
-:end_loop_s3
-:end_loop_c3
+:OTA_DONE
 CALL :LOG_MESSAGE DEBUG "Set OTA_FILENAME to: !OTA_FILENAME!"
 
 @REM Check if (--web) is enabled and prefix BASENAME with "littlefswebui-" else "littlefs-".

'@ | Set-Content -Encoding utf8 -NoNewline $patchPath
	
	Push-Location  $destFolder
	run_cmd "python -m patch -p1 fix.patch"
	Pop-Location
}








# Get release info
check_requirements
UpdateReleases
BuildReleaseMenuData
$tag = SelectRelease
DownloadAssets
UnzipAssets


# Find nodes
$result = GetModelFromNode
$DFU_node = $result[0]
$Drive = $result[1]
if ($DFU_node) {
	$HWNameShort = $DFU_node
	Write-Host "Found Device in DFU update state $HWNameShort"
	$selectedComPort = "NA"
}
else {
	# Get node info
	UpdateHardwareList
	$result = getUSBComPort
	$selectedComPort = $result[0]
	$HWNameShort     = $result[1]
	$OldVersion      = $result[2]
	$devicesBefore   = $result[3]
}

$HWNameFile = GetFirmwareFiles $HWNameShort
if (-not $HWNameFile -and $selectedComPort -eq "NA") {
	# Get node info
	UpdateHardwareList
	$result = getUSBComPort
	$selectedComPort = $result[0]
	$HWNameShort     = $result[1]
	$OldVersion      = $result[2]
	$devicesBefore   = $result[3]
	$HWNameFile = GetFirmwareFiles $HWNameShort
}
if ($HWNameFile) {
	$SelectedFirmwareFile = SelectMatchingFile
}
else {
	$HWNameFile = SelectHardware
	GetFirmwareFiles $HWNameFile
	$SelectedFirmwareFile = SelectMatchingFile
}





$hw = GetHardwareInfo -Slug $HWNameFile -ListPath $HARDWARE_LIST
Write-Host "Selected hardware:   $($hw.DisplayName)"
Write-Host "  Architecture:      $($hw.Architecture)"
Write-Host "  Requires DFU:      $($hw.RequiresDfu)"
Write-Host "  Has Ink HUD:       $($hw.HasInkHud)"
Write-Host "  Has Meshtastic UI: $($hw.HasMui)"
Write-Host "  New Firmware:      $SelectedFirmwareFile"

if ($selectedComPort -ne "NA") {
	MakeConfigBackup $HWNameFile $selectedComPort
}

if ($hw.Architecture -like 'esp32*') {
	$ESPTOOL_CMD = get_esptool_cmd

	Write-Host ""
	Write-Host "  1) Enter firmware-update (DFU) mode and then run firmware update script"
	Write-Host "  2) Run firmware update script"
	$choice = Read-Host -Prompt 'Enter number of your selection'
	
	#UpdateBleOta -selectedFile $SelectedFirmwareFile
	
	if ($choice -eq 1) {
		Read-Host "Press Enter to put node into Device Firmware Update (DFU) mode via baud $baud"
		Write-Host "number of USB COM devices: $($devicesBefore.Count)"
		Write-Host "Running $ESPTOOL_CMD --baud $baud --port $selectedComPort chip_id"
		$output = run_cmd "$ESPTOOL_CMD --baud $baud --port $selectedComPort chip_id"
		Write-Host $output
		Start-Sleep -Seconds 8
		
		$devicesAfter = getUsbComDevices -SkipInfo
		Write-Host "number of USB COM devices: $($devicesAfter.Count)"
		$choice = 2
	}
	if ($choice -eq 2) {
		$fi = Get-Item $SelectedFirmwareFile
		$baseName = $fi.Name 

		if ($baseName -like '*-update*') {
			$bat = Join-Path $fi.DirectoryName 'device-update.bat'
		} else {
			$bat = Join-Path $fi.DirectoryName 'device-install.bat'
		}

		$cmd = "$bat -f $baseName -p $selectedComPort"
		ApplyPatch $SelectedFirmwareFile
		Write-Host ""
		Write-Host $cmd
		Read-Host -Prompt 'Press enter to run that'
		$destFolder = Split-Path $SelectedFirmwareFile -Parent
		Push-Location  $destFolder
		cmd /c $cmd
		Pop-Location
		break
	}
}
else {
	if ($selectedComPort -ne "NA") {
		Read-Host "Press Enter to put node into Device Firmware Update (DFU) mode via meshtastic --port $selectedComPort --enter-dfu"
		
		$before = Get-PSDrive -PSProvider FileSystem | Select-Object -ExpandProperty Name
		
		$result = runMeshtasticCommand $selectedComPort "--enter-dfu"
		$meshtasticOutput = $result[0]
		$meshtasticError  = $result[1]
		Write-Host $meshtasticOutput
		Write-Host $meshtasticError
		
		while ((Get-Date) -lt $endTime -and -not $newDrive) {
			Start-Sleep -Seconds 1
			$after = Get-PSDrive -PSProvider FileSystem | Select-Object -ExpandProperty Name
			# any name in $after that wasn't in $before?
			$newDrive = $after | Where-Object { $_ -notin $before }
		}
	}
	else {
		$newDrive = $Drive
	}

	if ($newDrive) {
		Write-Host "DFU mount is drive `"$newDrive`""
		$dest = Join-Path -Path $newDrive -ChildPath (Split-Path $SelectedFirmwareFile -Leaf)
		Read-Host "Press Enter Copy the Firmware to $dest"
		Copy-Item -Path $SelectedFirmwareFile -Destination $dest -Force -ErrorAction Stop

		Write-Host "Done." -ForegroundColor Green
	} else {
		Write-Warning "Timed out waiting for DFU drive (no new PSDrive after $timeout seconds)"
	}
}




   
# When the user finally hits Enter, the script will exit naturally.
$scriptOver = $true
Read-Host 'Press Enter to exit (via end of script)'
