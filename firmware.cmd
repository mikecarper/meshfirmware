# 2>NUL & @powershell -nop -ep bypass "(gc '%~f0')-join[Environment]::NewLine|iex" & goto :eof

#Example execute:
# powershell -ExecutionPolicy ByPass -File c:\git\meshfirmware\firmware.ps1

# Typical defaults: gray text on a dark-blue (or black) background
$Host.UI.RawUI.ForegroundColor = 'Gray'
$Host.UI.RawUI.BackgroundColor = 'Black'    # or 'DarkBlue' if you prefer

Write-Host ""
Write-Host ""
Write-Host ""
Write-Host ""

# Flag to track if Ctrl-C has been pressed
$scriptOver = $false

# Register a Ctrl-C handler:
$null = Register-ObjectEvent -InputObject ([System.Console]) -EventName CancelKeyPress -Action {
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

$pythonCommand = ""
$PORTABLE_PYTHON_DIR="${ScriptPath}\winpython"
$PORTABLE_PYTHON_URL="https://api.github.com/repos/winpython/winpython/releases/latest"

$MT_REPO_API_URL="https://api.github.com/repos/meshtastic/meshtastic.github.io/contents"
$MT_WEB_HARDWARE_LIST_URL="https://raw.githubusercontent.com/meshtastic/web-flasher/refs/heads/main/public/data/hardware-list.json"

$MC_CONFIG_URL = "https://flasher.meshcore.dev/config.json"
$MC_RELEASE_URL = "https://flasher.meshcore.dev/releases"

$timeoutMeshtastic = 10 # Timeout duration in seconds
$baud = 1200 # 115200
$CACHE_TIMEOUT_SECONDS = 6 * 3600 # 6 hours

function SetProjectVars($selectedNodeProject) {
	if ($selectedNodeProject -eq "MeshCore") {
		$global:REPO_OWNER           	= "meshcore-dev"
		$global:REPO_NAME            	= "MeshCore"
	}
	if ($selectedNodeProject -eq "Meshtastic") {
		$global:REPO_OWNER           	= "meshtastic"
		$global:REPO_NAME            	= "firmware"
	}

	$global:GITHUB_API_URL 				= "https://api.github.com/repos/$REPO_OWNER/$REPO_NAME/releases"
	 
	$global:FIRMWARE_ROOT        	  	= Join-Path $ScriptPath ("{0}_{1}" -f $REPO_OWNER, $REPO_NAME)
	$global:DOWNLOAD_DIR				= Join-Path $FIRMWARE_ROOT "downloads"
	
	$global:HARDWARE_LIST				= Join-Path $FIRMWARE_ROOT "hardware-list.json"
	$global:BLEOTA_FILE					= Join-Path $FIRMWARE_ROOT "bleota.json"
	$global:GITHUB_FILE              	= Join-Path $FIRMWARE_ROOT "github.json"
	$global:CONFIG_FILE              	= Join-Path $FIRMWARE_ROOT "config.json"
	$global:RELEASES_FILE            	= Join-Path $FIRMWARE_ROOT "releases.json"
	
	$global:SELECTED_DEVICE_FILE     	= Join-Path $FIRMWARE_ROOT "01device.txt"
	$global:ARCHITECTURE_FILE        	= Join-Path $FIRMWARE_ROOT "02architecture.txt"
	$global:ERASE_URL_FILE           	= Join-Path $FIRMWARE_ROOT "03erase.txt"
	$global:SELECTED_ROLE_FILE       	= Join-Path $FIRMWARE_ROOT "04role.txt"
	$global:SELECTED_VERSION_FILE    	= Join-Path $FIRMWARE_ROOT "05version.txt"
	$global:SELECTED_TYPE_FILE       	= Join-Path $FIRMWARE_ROOT "06type.txt"
	$global:SELECTED_URL_FILE        	= Join-Path $FIRMWARE_ROOT "07selected_url.txt"
	$global:DOWNLOADED_FILE_FILE     	= Join-Path $FIRMWARE_ROOT "08downloaded_file.txt"
	$global:DEVICE_PORT_FILE         	= Join-Path $FIRMWARE_ROOT "09device_port_file.txt"
	$global:DEVICE_PORT_NAME_FILE    	= Join-Path $FIRMWARE_ROOT "10device_port_name_file.txt"
	$global:AUTODETECT_DEVICE_FILE   	= Join-Path $FIRMWARE_ROOT "11autodetect_device_file.txt"
	$global:ESPTOOL_FILE             	= Join-Path $FIRMWARE_ROOT "12esptool_file.txt"
	$global:ERASE_FILE_FILE          	= Join-Path $FIRMWARE_ROOT "13erase_file.txt"
	
	$global:VERSIONS_TAGS_FILE			= Join-Path $FIRMWARE_ROOT "01versions_tags.txt"
	$global:VERSIONS_LABELS_FILE		= Join-Path $FIRMWARE_ROOT "02versions_labels.txt"
	$global:CHOSEN_TAG_FILE				= Join-Path $FIRMWARE_ROOT "03chosen_tag.txt"
	$global:MATCHING_FILES_FILE			= Join-Path $FIRMWARE_ROOT "07matching_files.txt"

	$cleanupFiles = @(
		$SELECTED_DEVICE_FILE,
		$ARCHITECTURE_FILE,
		$ERASE_URL_FILE,
		$SELECTED_ROLE_FILE,
		$SELECTED_VERSION_FILE,
		$SELECTED_TYPE_FILE,
		$SELECTED_URL_FILE,
		$DOWNLOADED_FILE_FILE,
		$DEVICE_PORT_FILE,
		$DEVICE_PORT_NAME_FILE,
		$AUTODETECT_DEVICE_FILE,
		$ESPTOOL_FILE,
		$ERASE_FILE_FILE,

		$VERSIONS_TAGS_FILE,
		$VERSIONS_LABELS_FILE,
		$CHOSEN_TAG_FILE,
		$MATCHING_FILES_FILE,
		$ARCHITECTURE_FILE
	)
	
	# delete any that exist
	foreach ($f in $cleanupFiles) {
		if (Test-Path $f) {
			Remove-Item $f -Force -ErrorAction Ignore | Out-Null
		}
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


function GetPortablePython {
	$rel    = Invoke-RestMethod -Uri $PORTABLE_PYTHON_URL -Headers @{ 'User-Agent' = 'PowerShell' } -ErrorAction Stop

	# pick the newest 64-bit portable ZIP (e.g. Winpython64-3.13.3.0dot.zip)
	$asset  = $rel.assets |
			  Where-Object  { $_.name -match '(?i)^winpython(?:32|64)?[ _.-]?.*?dot(?:[a-z]*\d*)?\.zip$' } |
			  Sort-Object   -Property name -Descending |
			  Select-Object -First 1

	if (-not $asset) {
		throw "No matching zip found in the latest release of $repo."
	}

	$target = Join-Path $FIRMWARE_ROOT $asset.name
	# make sure the directory exists
	if (-not (Test-Path $FIRMWARE_ROOT)) {
		New-Item -ItemType Directory -Path $FIRMWARE_ROOT -Force | Out-Null
	}
	
	if (-not (Test-Path $target) -or ((Get-Item $target).Length -eq 0)) {
		Write-Host "Downloading $($asset.name) $($asset.browser_download_url) $target"
		Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $target -UseBasicParsing -Headers @{ 'User-Agent' = 'PowerShell' } -ErrorAction Stop
	}
	
	# 1) unzip to a temp workspace
	$tempDir = Join-Path $env:TEMP ("wpytmp_" + [guid]::NewGuid())
	Expand-Archive -LiteralPath $target -DestinationPath $tempDir -Force

	# 2) locate license.txt ***inside the extracted tree***
	$license = Get-ChildItem -Path $tempDir -Recurse -Filter license.txt `
			  | Select-Object -First 1
	if (-not $license) {
		Remove-Item $tempDir -Recurse -Force
		throw "license.txt not found in the WinPython zip aborting."
	}

	$zipRootDir = $license.Directory.FullName    # 'level where license.txt is found'

	# 3) make final destination & move contents
	New-Item -ItemType Directory -Path $PORTABLE_PYTHON_DIR -Force | Out-Null
	Move-Item -Path (Join-Path $zipRootDir '*') -Destination $PORTABLE_PYTHON_DIR -Force

	# 4) clean up the temp workspace
	Remove-Item $tempDir -Recurse -Force
}

# Function to fetch the latest stable Python version from GitHub
function Get-LatestPythonVersion {
    $url = "https://api.github.com/repos/actions/python-versions/releases/latest"
    $release = Invoke-RestMethod -Uri $url -Headers @{Accept = "application/vnd.github.v3+json"}
    $latestVersion = $release.tag_name
    return $latestVersion
}

function get_esptool_cmd() {
	$esptoolPath = Get-Command esptool -ErrorAction SilentlyContinue
	if ($esptoolPath) {
		# If esptool is found, set the ESPTOOL command
		$ESPTOOL_CMD = "esptool"  # Set esptool command
		$versionOutput = (& esptool version 2>&1 | Out-String).TrimEnd()
	} else {
		try {
			# Check if Python is installed and get the version
			$pythonVersion = & $pythonCommand --version
			Write-Progress -Status "Checking Versions" -Activity "Python interpreter found: $pythonVersion"
			# Set the ESPTOOL command to use Python
			$ESPTOOL_CMD = "$pythonCommand -m esptool"  # Construct as a single string
			$versionOutput = (& $pythonCommand -m esptool version 2>&1 | Out-String).TrimEnd()
		}

		 catch {
			$ESPTOOL_CMD = "python -m esptool"  # Fallback to Python esptool
			$versionOutput = (& python -m esptool version 2>&1 | Out-String).TrimEnd()
		}
	}
	
	$esptoolVersion = $versionOutput
	$script:ESPTOOL_VERSION = $esptoolVersion
	$script:ESPTOOL_WRITE_FLASH = "write_flash"
	$script:ESPTOOL_ERASE_FLASH = "erase_flash"
	$script:ESPTOOL_READ_FLASH_STATUS = "read_flash_status"
	if ($esptoolVersion -match '(?i)\besptool\s+v(\d+)') {
		$majorVersion = [int]$matches[1]
		if ($majorVersion -ge 5) {
			$script:ESPTOOL_WRITE_FLASH = "write-flash"
			$script:ESPTOOL_ERASE_FLASH = "erase-flash"
			$script:ESPTOOL_READ_FLASH_STATUS = "read-flash-status"
		}
	}
	if ($pythonVersion) {
		Write-Progress -Status "Checking Versions" -Activity "Python interpreter found: $pythonVersion esptool version: $esptoolVersion"
	}
	else {
		Write-Progress -Status "Checking Versions" -Activity "esptool version: $esptoolVersion"
	}

	
	return $ESPTOOL_CMD
}

if (-not ([type]::GetType('NativeMethods', $false))) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class NativeMethods {
    [DllImport("shell32.dll", SetLastError = true)]
    public static extern IntPtr CommandLineToArgvW(
        [MarshalAs(UnmanagedType.LPWStr)] string lpCmdLine,
        out int pNumArgs);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr LocalFree(IntPtr hMem);
}
'@
}

function Split-CommandLine {
    param([string]$cmd)

    [int]   $argc = 0
    [IntPtr]$argv = [NativeMethods]::CommandLineToArgvW($cmd, [ref]$argc)
    if ($argv -eq [IntPtr]::Zero) { throw "Cannot parse: $cmd" }

    try {
        # Copy the unmanaged pointer array into a managed IntPtr[]
        $ptrArr = New-Object IntPtr[] $argc
        [Runtime.InteropServices.Marshal]::Copy($argv, $ptrArr, 0, $argc)

        # Convert each pointer to a managed string
        $ptrArr | ForEach-Object {
            [Runtime.InteropServices.Marshal]::PtrToStringUni($_)
        }
    }
    finally {
        [NativeMethods]::LocalFree($argv) | Out-Null
    }
}

function run_cmd {
    param(
        [Parameter(Mandatory)][string] $CommandLine,
        [switch] $Stream          # -Stream → live to console
    )
	

    # --- split exe + args -----------------------------------------------
    $parts = Split-CommandLine $CommandLine
    $exe   = $parts[0]
    $args  = if ($parts.Count -gt 1) { $parts[1..($parts.Count-1)] } else { @() }
	Write-Progress -Activity "$exe" -Status "$args"

    # --- stream or capture ----------------------------------------------
    if ($Stream) {
		try {
			$proc = Start-Process -FilePath $exe -ArgumentList $args -NoNewWindow -Wait -PassThru
			return $proc.ExitCode
		}
		finally {
			Write-Progress -Activity " " -Status " " -Completed
		}
    }

    $output = & $exe @args 2>&1 | Out-String   # capture as ONE string
	Write-Progress -Activity " " -Status " " -Completed
    return $output.TrimEnd()
}


function check_requirements() {
	# Check if Python is installed
	$null = & python --version 2>$null
	if ($LASTEXITCODE -eq 0) {
		$global:pythonCommand = "python"
	}
	else {
		$testPythonCommand = "$PORTABLE_PYTHON_DIR\python\python.exe"
		if (Test-Path -Path $testPythonCommand -PathType Leaf) {
			$null = & $testPythonCommand --version 2>$null
			if ($LASTEXITCODE -eq 0) {
				$global:pythonCommand = $testPythonCommand
			}
		}
		if ([string]::IsNullOrWhiteSpace($global:pythonCommand)) {
			GetPortablePython

			$testPythonCommand = "$PORTABLE_PYTHON_DIR\python\python.exe"
			
			$null = & $testPythonCommand --version 2>$null
			if ($LASTEXITCODE -eq 0) {
				$global:pythonCommand = $testPythonCommand
			}
		}
	}
	Write-Progress -Activity "Update pip command line tool"
	& $pythonCommand -m ensurepip --upgrade *> $null
    & $pythonCommand -m pip install --upgrade pip *> $null

	# Check if meshtastic is installed
	& $pythonCommand -m pip show meshtastic *> $null
	$meshtasticInstalled = ($LASTEXITCODE -eq 0)
	if (-not $meshtasticInstalled) {
		Write-Host "Meshtastic is not installed. Installing..."

		# Install or upgrade meshtastic using pip3
		& $pythonCommand -m pip install --upgrade --no-warn-script-location "meshtastic[cli]"
	}
	else {
		Write-Progress -Activity "Update meshtastic command line tool"
		& $pythonCommand -m pip install --upgrade --no-warn-script-location "meshtastic[cli]" | out-null
	}
	
	# Check if esptool is installed
	& $pythonCommand -m pip show esptool *> $null
	$meshtasticInstalled = ($LASTEXITCODE -eq 0)
	if (-not $meshtasticInstalled) {
		Write-Host "esptool is not installed. Installing..."

		# Install or upgrade esptool using pip3
		& $pythonCommand -m pip install --upgrade --no-warn-script-location "esptool"
	}
	else {
		Write-Progress -Activity "Update esptool command line tool"
		& $pythonCommand -m pip install --upgrade --no-warn-script-location "esptool" | out-null
	}

	# Check if adafruit-nrfutil is installed
	& $pythonCommand -m pip show adafruit-nrfutil *> $null
	$nrfutilInstalled = ($LASTEXITCODE -eq 0)
	if (-not $nrfutilInstalled) {
		Write-Host "adafruit-nrfutil is not installed. Installing..."
		& $pythonCommand -m pip install --upgrade --no-warn-script-location "adafruit-nrfutil"
	}
	else {
		Write-Progress -Activity "Update adafruit-nrfutil command line tool"
		& $pythonCommand -m pip install --upgrade --no-warn-script-location "adafruit-nrfutil" | out-null
	}

	Write-Progress -Activity " " -Status " " -Completed
}


function getallUSBCom($output) {
	# Get all Serial Ports and filter for USB serial devices by checking Description and DeviceID
	#$comDevices = Get-WmiObject Win32_SerialPort
	$comDevices = Get-WmiObject -Class Win32_PnPEntity | Where-Object { $_.DeviceID -like "*USB*" -and $_.Name -like "*(com*" }
	
	# Initialize the array for storing the results
	$usbComDevices = @()

	foreach ($device in $comDevices) {
		$comPort = $null
		$comNum  = $null
		
		# Extract COM port from Name
		if ($device.Name -match 'COM(\d+)') {
			$comPort = $matches[0]      # e.g. COM3
			$comNum  = [int]$matches[1] # e.g. 3
		}

		# Some devices may not have HardwareID as expected
		$hardwareId = if ($device.HardwareID) {
			($device.HardwareID -split '\\')[-1]
		} else {
			"--"
		}

		# Add the device information to $usbComDevices
		$usbComDevices += [PSCustomObject]@{
			drive_letter      = $comPort
			device_name       = $HardwareID
			friendly_name     = $device.Name
			firmware_revision = "--"
			_com_sort         = $comNum   # temp sort key
		}
	}

	return $usbComDevices |
		Sort-Object @{ Expression = { if ($null -ne $_._com_sort) { $_._com_sort } else { [int]::MaxValue } } }, friendly_name |
		Select-Object drive_letter, device_name, friendly_name, firmware_revision
}

function runMeshtasticCommand($selectedComPort, $command) {
	# Define a temporary file to capture the output
	$tempOutputFile = Join-Path -Path $ScriptPath -ChildPath "meshtastic_output$selectedComPort.txt"
	$tempErrorFile = Join-Path -Path $ScriptPath -ChildPath "meshtastic_error$selectedComPort.txt"

	# Start the meshtastic process with a hidden window and capture the process ID
	#Write-Host "Running meshtastic command on port $selectedComPort"
	Write-Progress -Activity "running $pythonCommand -m meshtastic --port $selectedComPort $command"
	$process = Start-Process "$pythonCommand" -ArgumentList " -m meshtastic --port $selectedComPort $command" -PassThru -WindowStyle Hidden -RedirectStandardOutput $tempOutputFile -RedirectStandardError $tempErrorFile
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

	$deviceInfo = New-Object PSObject -property @{
		Success     = $false
		ComPort     = $selectedComPort
		Baud        = 0
		Project     = "Meshtastic"
		ExtraInfo   = ""
		Name        = ""
		HWName      = ""
		HWNameShort = ""
		FWVersion   = ""
	}
	
	if ($meshtasticError) {
		return $deviceInfo
	}
	$meshtasticOutput = $meshtasticOutput -replace '(\{|\}|\,)', "$1`n"
	$deviceInfo.Success = $true

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
				$deviceInfo.ExtraInfo = $value
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

function Remove-Ansi {
    param([string]$s)
    if (-not $s) { return "" }

    # Remove ANSI CSI sequences (covers color codes and more)
    $s = [regex]::Replace($s, "`e\[[0-?]*[ -/]*[@-~]", "")
    # Some consoles stringify color codes as literal "[34m" text; strip those too
    $s = [regex]::Replace($s, '(?i)\[(?:\d{1,3}(?:;\d{1,3})*)m', "")

    # Optionally remove other control chars except tab/newline/carriage return
    $s = [regex]::Replace($s, "[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", "")

    return $s
}

function Strip-Prefix([string]$s) {
    if (-not $s) { return "" }
    $s = Remove-Ansi $s
    return (($s -replace "`r","") -replace '^[\s>]*(->|>)+\s*','').Trim()
}

function Test-IsLogLine {
    param([string]$s)
    if (-not $s) { return $false }

    $t = (Remove-Ansi $s)
    $t = ($t -replace "`r","")
    $t = ($t -replace '^[\s>]*(->|>)+\s*','').Trim()

    return (
        $t -match '^[\W_]*(DEBUG|TRACE|INFO|WARN|ERROR)\s*(?:\:|\|)\s*' -or
        $t -match '^[\W_]*\[[^\]]+\]\s*(DEBUG|TRACE|INFO|WARN|ERROR)\b' -or
        $t -match '^\s*\[[^\]]+\]\s*$' -or
        $t -match '\[SerialConsole\].*\bState\s*:\s*\w+\b'
    )
}

function Get-VersionTokenFromText {
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) { return "" }

    $patterns = @(
        '(?i)\b(?:powersaving|easyskymesh)[a-z0-9._\-+]*\d+(?:\.\d+)+(?:[A-Za-z0-9._\-+]*)\b',
        '(?i)\bv?\d+(?:\.\d+)+(?:[A-Za-z0-9._\-+]*)\b',
        '(?i)\b[a-z][a-z0-9_-]*\d+(?:\.\d+)+(?:[A-Za-z0-9._\-+]*)\b'
    )

    foreach ($pattern in $patterns) {
        $m = [regex]::Match($Text, $pattern)
        if ($m.Success) {
            return $m.Value
        }
    }

    return ""
}

function Get-UsableSerialResponse {
    param(
        [string]$Text,
        [ValidateSet('Generic', 'Board', 'Version', 'Name')]
        [string]$Kind = 'Generic',
        [int]$MaxLength = 32
    )

    if (-not $Text) { return "" }

    $t = Strip-Prefix $Text
    if (-not $t) { return "" }
    if (Test-IsLogLine $t) { return "" }

    if ($MaxLength -gt 0 -and $t.Length -gt $MaxLength) {
        $t = $t.Substring(0, $MaxLength).Trim()
    }

    $length = [Math]::Max(1, $t.Length)
    $cleanChars = [regex]::Matches($t, '[A-Za-z0-9 _\-\.\(\)\[\]/:+]').Count
    $questionChars = [regex]::Matches($t, '\?').Count

    if ($cleanChars -eq 0) { return "" }
    if (($cleanChars / $length) -lt 0.45) { return "" }

    switch ($Kind) {
        'Board' {
            if ($t -notmatch '[A-Za-z0-9]') { return "" }
            if ($questionChars -gt 0) { return "" }
        }
        'Version' {
            $versionToken = Get-VersionTokenFromText -Text $t
            if (-not $versionToken) { return "" }
            $t = $versionToken
            if ($t -match '(?i)\b(DEBUG|TRACE|INFO|WARN|ERROR)\b') { return "" }
            if ($questionChars -gt [Math]::Ceiling($length * 0.20)) { return "" }
        }
        'Name' {
            if ($questionChars -gt [Math]::Ceiling($length * 0.30)) { return "" }
        }
    }

    return $t
}

# Send a line and read whatever comes back for a short window
function Invoke-SerialCommand {
    param(
        [Parameter(Mandatory=$true)][System.IO.Ports.SerialPort]$Port,
        [Parameter(Mandatory=$true)][string]$Line,

        # Hard cap per attempt (send + read)
        [int]$TotalMs = 800,

        # Return early once we have a line and RX is quiet this long
        [int]$IdleMs = 120,

        # Optional: return immediately on first good line
        [switch]$ReturnFirstLine,

        # Retry behavior
        [int]$Attempts = 3,
        [int]$RetryDelayMs = 80,

        # Optional: do an extra "read only" pass before re-sending
        [int]$ExtraReadMs = 220,

        # Optional progress knobs
        [switch]$ShowProgress = $true,
        [int]$ProgressId = 42,
        [string]$Activity = "Serial"
    )

    if (-not $Port -or -not $Port.IsOpen) { return "" }

    # Lines to ignore (add more patterns as needed)
	$ignorePatterns = @(
		'^[\W_]*(DEBUG|TRACE|INFO|WARN|ERROR)\s*(?:\:|\|)\s*',
		'^[\W_]*\[[^\]]+\]\s*(DEBUG|TRACE|INFO|WARN|ERROR)\b',
		'.*\[SerialConsole\].*\bState\s*:\s*\w+\b',
		'^\s*#',
		'^\s*;',
		'^\s*$'
	)

    function Is-IgnoredLine([string]$t) {
        if (-not $t) { return $true }

        # Strip common prompt prefixes like "->" or ">"
        $t = ($t -replace '^[\s>]*(->|>)+\s*','').Trim()
        if (-not $t) { return $true }

        foreach ($pat in $ignorePatterns) {
            if ($t -match $pat) { return $true }
        }
        return $false
    }

    function Read-UsefulLine {
        param(
            [int]$ReadMs,
            [string]$CommandEcho
        )

        $sw   = [System.Diagnostics.Stopwatch]::StartNew()
        $idle = [System.Diagnostics.Stopwatch]::StartNew()

        $buf = New-Object System.Text.StringBuilder
        $lastGood = ""
        $processed = 0
        $lastPct = -1

        while ($sw.ElapsedMilliseconds -lt $ReadMs) {
            if ($ShowProgress) {
                $pct = [int](($sw.ElapsedMilliseconds * 100) / [Math]::Max(1,$ReadMs))
                if ($pct -ne $lastPct) {
                    $lastPct = $pct
                    Write-Progress -Id $ProgressId -Activity $Activity -Status "$($Port.PortName) @ $($Port.BaudRate) : $Line (rx)" -PercentComplete $pct
                }
            }

            try { $chunk = $Port.ReadExisting() } catch { $chunk = "" }

            if ($chunk) {
                [void]$buf.Append($chunk)
                $idle.Restart()
            } else {
                Start-Sleep -Milliseconds 10
            }

            # Parse only complete new lines (avoid reprocessing)
            $text = ($buf.ToString() -replace "`r","")
            $endedWithNL = $text.EndsWith("`n")
            $parts = $text -split "`n", -1

            $maxIndex = $parts.Count - 1
            if (-not $endedWithNL) { $maxIndex-- }  # last part is partial

            for ($i = $processed; $i -le $maxIndex; $i++) {
                $t = $parts[$i].Trim()

                # Skip exact echo of command
                if ($t -eq $CommandEcho) { continue }

                if (Is-IgnoredLine $t) { continue }
				if (Test-IsLogLine $t) { continue }

                # Strip prompt prefixes again after ignore check
                $t = ($t -replace '^[\s>]*(->|>)+\s*','').Trim()
                if (-not $t) { continue }

                $lastGood = $t
                if ($ReturnFirstLine) {
                    return $lastGood
                }
            }

            if ($maxIndex -ge $processed) {
                $processed = $maxIndex + 1
            }

            # Early exit: we have a line and the stream has been quiet long enough
            if ($lastGood -and $idle.ElapsedMilliseconds -ge $IdleMs) {
                break
            }
        }

        if (-not $lastGood -and $parts.Count -gt 0) {
            $tail = $parts[$parts.Count - 1].Trim()
            if ($tail -and $tail -ne $CommandEcho -and -not (Is-IgnoredLine $tail) -and -not (Test-IsLogLine $tail)) {
                $tail = ($tail -replace '^[\s>]*(->|>)+\s*','').Trim()
                if ($tail) {
                    $lastGood = $tail
                }
            }
        }

        return $lastGood
    }

    for ($attempt = 1; $attempt -le $Attempts; $attempt++) {
        $statusBase = "$($Port.PortName) @ $($Port.BaudRate) : $Line (try $attempt/$Attempts)"
        if ($ShowProgress) {
            Write-Progress -Id $ProgressId -Activity $Activity -Status "$statusBase (send)" -PercentComplete 0
        }

        # Clear noise before send
        try { $Port.DiscardInBuffer() } catch { break }

        # Send
        try { $Port.WriteLine($Line) } catch { break }

        # Read response
        $resp = Read-UsefulLine -ReadMs $TotalMs -CommandEcho $Line
		# If a log line slipped through, do not consume an attempt
		if ($resp -and (Test-IsLogLine $resp)) {
			# net effect: for-loop increments it back, so attempt number stays the same
			$attempt--
			Start-Sleep -Milliseconds 20
			continue
		}

		if ($resp) {
			if ($ShowProgress) { Write-Progress -Id $ProgressId -Activity $Activity -Completed }
			return $resp
		}

        # If nothing, do an extra read-only pass (sometimes response arrives late)
        if ($ExtraReadMs -gt 0) {
			$resp2 = Read-UsefulLine -ReadMs $ExtraReadMs -CommandEcho $Line

			if ($resp2 -and (Test-IsLogLine $resp2)) {
				$attempt--
				Start-Sleep -Milliseconds 20
				continue
			}

			if ($resp2) {
				if ($ShowProgress) { Write-Progress -Id $ProgressId -Activity $Activity -Completed }
				return $resp2
			}
        }

        if ($attempt -lt $Attempts) {
            Start-Sleep -Milliseconds $RetryDelayMs
        }
    }

    if ($ShowProgress) { Write-Progress -Id $ProgressId -Activity $Activity -Completed }
    return ""
}

# Open a serial port and return the SerialPort object
function Open-SerialPort {
    param(
        [Parameter(Mandatory=$true)][string]$ComPort,
        [int]$Baud = 115200,
        [int]$ReadTimeoutMs = 300,
        [int]$WriteTimeoutMs = 300,
        [bool]$Dtr = $true,
        [bool]$Rts = $true
    )

    $sp = New-Object System.IO.Ports.SerialPort $ComPort, $Baud, "None", 8, "One"
    $sp.NewLine      = "`r`n"        # CRLF
    $sp.Encoding     = [System.Text.Encoding]::ASCII
    $sp.ReadTimeout  = $ReadTimeoutMs
    $sp.WriteTimeout = $WriteTimeoutMs
    $sp.Handshake    = [System.IO.Ports.Handshake]::None

    $sp.DtrEnable    = $Dtr
    $sp.RtsEnable    = $Rts

    $sp.Open()

    # Give CDC/firmware a beat after open / DTR assert
    Start-Sleep -Milliseconds 120

    return $sp
}

function Invoke-SerialCommandWithRetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $SerialPort,

        [Parameter(Mandatory=$true)]
        [string]$Command,

        [int]$MaxAttempts = 3,
        [int]$TotalMs = 2000,
        [int]$ProgressId = 42,
        [string]$Activity = "Serial"
    )

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        $response = Invoke-SerialCommand $SerialPort $Command `
            -TotalMs $TotalMs `
            -ProgressId $ProgressId `
            -Activity $Activity
		Write-Verbose ("{0} -> {1}" -f $Command, $response)
        if (-not [string]::IsNullOrWhiteSpace($response) -and $response -ne "Unknown command") {
            return $response
        }
    }

    return $null
}

function getMeshCore {
    param(
        [Parameter(Mandatory=$true)][string]$ComPort,
        [int[]]$Bauds = @(115200),
        [int]$CmdTimeoutMs = 500
    )

    foreach ($baud in $Bauds) {
        $sp = $null
        try {
            Write-Progress -Id 41 -Activity "Probing serial" -Status "$ComPort @ $baud" -PercentComplete 0

            $sp = Open-SerialPort -ComPort $ComPort -Baud $baud -ReadTimeoutMs 1000 -WriteTimeoutMs 1000 -Dtr $true -Rts $true
			$VersionCmdTimeoutMs = [Math]::Max($CmdTimeoutMs, 1500)
			
			$null = Invoke-SerialCommandWithRetry -MaxAttempts 1 -SerialPort $sp -Command "board" -TotalMs $CmdTimeoutMs -ProgressId 42 -Activity "Serial" # clear buffer
			
			$hw = Get-UsableSerialResponse `
				-Text (Invoke-SerialCommandWithRetry -MaxAttempts 3 -SerialPort $sp -Command "board" -TotalMs $CmdTimeoutMs -ProgressId 42 -Activity "Serial") `
				-Kind Board
			if ([string]::IsNullOrWhiteSpace($hw)) {
				Write-Verbose ("MeshCore probe: no usable board response on {0} @ {1}; skipping remaining serial queries for this probe." -f $ComPort, $baud)
				continue
			}
			$name = Get-UsableSerialResponse `
				-Text (Invoke-SerialCommandWithRetry -MaxAttempts 1 -SerialPort $sp -Command "get name" -TotalMs $CmdTimeoutMs -ProgressId 42 -Activity "Serial") `
				-Kind Name
			$ver = Get-UsableSerialResponse `
				-Text (Invoke-SerialCommandWithRetry -MaxAttempts 1 -SerialPort $sp -Command "ver" -TotalMs $VersionCmdTimeoutMs -ProgressId 42 -Activity "Serial") `
				-Kind Version
				
			$version = Get-UsableSerialResponse `
				-Text (Invoke-SerialCommandWithRetry -MaxAttempts 1 -SerialPort $sp -Command "version" -TotalMs $VersionCmdTimeoutMs -ProgressId 42 -Activity "Serial") `
				-Kind Version
			$fwVersion = if ($ver) { $ver } elseif ($version) { $version } else { "" }
				
			Write-Verbose ("MeshCore probe: hw='{0}' name='{1}' ver='{2}' version='{3}' chosen='{4}'" -f $hw, $name, $ver, $version, $fwVersion)

			if ($name) {
				$extrainfo = "$name Baud: $baud"
			}
			elseif ($hw -or $fwVersion) {
				$extrainfo = "Baud: $baud"
			}

            if ($hw -or $fwVersion) {
                Write-Progress -Id 41 -Activity "Probing serial" -Completed
                return [pscustomobject]@{
                    Success      = $true
                    ComPort      = $ComPort
                    Baud         = $baud
					Project      = "MeshCore"
					ExtraInfo    = $extrainfo
					HWName       = $hw
                    HWNameShort  = $hw
                    FWVersion    = $fwVersion
                }
            }
        } catch {
            # try next baud
        } finally {
            if ($sp -and $sp.IsOpen) { $sp.Close() }
        }
    }

    Write-Progress -Id 41 -Activity "Probing serial" -Completed
    return [pscustomobject]@{
        Success     = $false
        ComPort     = $ComPort
        Baud        = 0
		Project     = "MeshCore"
		Name        = ""
		HWName      = ""
        HWNameShort = ""
        FWVersion   = ""
    }
}

# Function to get and display the USB devices
function getUsbComDevices {
    [CmdletBinding()]
    param(
        [switch] $SkipInfo = $false
    )

    $usbComDevices = @()
    $comDevices = getallUSBCom

    foreach ($d in $comDevices) {
        $deviceInfo = $null

        if (-not $SkipInfo) {
            Write-Progress -Status "Checking USB Devices" -Activity "Checking for Meshtastic on $($d.drive_letter)"
            $deviceInfo = getMeshtasticNodeInfo $d.drive_letter

            if (-not $deviceInfo.Success) {
                Write-Progress -Status "Checking USB Devices" -Activity "Checking for MeshCore on $($d.drive_letter)"
                $deviceInfo = getMeshCore -ComPort $d.drive_letter
            }

            # optional debug print only (does not affect returned rows)
            #Write-Host ($deviceInfo | ConvertTo-Json -Compress)
        }
        else {
            # define a consistent "no info" object
            $deviceInfo = [pscustomobject]@{
                Success     = $false
                ComPort     = $d.drive_letter
                Project     = ""
                Name        = ""
                HWName      = ""
                HWNameShort = ""
                FWVersion   = ""
            }
        }

        if (-not $deviceInfo.Success) {
            $usbComDevices += [pscustomobject]@{
                ComPort         = $d.drive_letter
                DeviceName      = $d.device_name
                Project         = $d.friendly_name
                FirmwareVersion = $d.firmware_revision
                ExtraInfo       = ""
            }
        }
        else {
            $usbComDevices += [pscustomobject]@{
                ComPort         = $d.drive_letter
                DeviceName      = $(if ([string]::IsNullOrWhiteSpace($deviceInfo.HWName)) { $d.device_name } else { $deviceInfo.HWName })
                Project         = $deviceInfo.Project
                FirmwareVersion = $(if ([string]::IsNullOrWhiteSpace($deviceInfo.FWVersion)) { $d.firmware_revision } else { $deviceInfo.FWVersion })
                ExtraInfo       = $deviceInfo.ExtraInfo
            }
        }
    }

    return $usbComDevices
}

function getUSBComPort() {
	[CmdletBinding()]
    param(
        [switch] $SkipInfo = $false
    )
	
	$selectedComPort = 0 
	# Run in a loop until we get valid $comDevices
	do {
		if ($SkipInfo) {
			$usbComDevices = getUsbComDevices -SkipInfo
		}
		else {
			$usbComDevices = getUsbComDevices
		}
		$usbComDevices = $usbComDevices | Sort-Object @{ Expression = { [int](($_.ComPort -replace '^[^\d]*','')) } }
		#Write-Host $usbComDevices

		# If there are no USB COM devices, display an error and loop again
		if ($usbComDevices.Count -eq 0) {
			Write-Host "No valid COM devices found. Please check the connection. Trying again in 5 seconds." -ForegroundColor Red
			Start-Sleep -Seconds 5  # Wait before trying again
		} else {
			$availableComPorts = $usbComDevices | Select-Object -ExpandProperty ComPort
			if ($availableComPorts.Count -eq 1) {
				$FirmwareVersion = $usbComDevices | Select-Object -ExpandProperty FirmwareVersion
				$hwModelSlug = $usbComDevices | Select-Object -ExpandProperty DeviceName
				$selectedComPort = $usbComDevices | Select-Object -ExpandProperty ComPort
				$selectedNodeProject = $usbComDevices | Select-Object -ExpandProperty Project
			}
			else {
				# If we found valid COM devices, let the user select one
				$tableOutput = $usbComDevices | Format-Table -Property ComPort, DeviceName, Project, FirmwareVersion, ExtraInfo | Out-String
				# Remove lines that are empty or only contain spaces
				$tableOutput = $tableOutput -split "`n" | Where-Object { $_.Trim() -ne "" } | Out-String
				
				Write-Host ""
				Write-Host $tableOutput
				$selectedComPort = selectUSBCom -availableComPorts $availableComPorts
				
				# now filter out the single object whose ComPort matches
				$device = $usbComDevices |
					Where-Object { $_.ComPort -eq $selectedComPort }

				# and pull out the fields you care about
				$hwModelSlug     = $device.DeviceName
				$FirmwareVersion = $device.FirmwareVersion
				$selectedNodeProject = $device.Project

				
				
			}
		}

	} while ($usbComDevices.Count -eq 0 -and $selectedComPort -eq 0)  # Continue looping until we have at least one valid COM device

	return $selectedComPort, $hwModelSlug, $FirmwareVersion, $usbComDevices, $selectedNodeProject
}

function Select-FlashTarget {
    while ($true) {
        Write-Host ""
        Write-Host "What do you want to flash to?"
        Write-Host "  1) Meshtastic"
        Write-Host "  2) MeshCore"
        # Write-Host "  3) Reticulum"

        $choice = Read-Host "Enter choice (1-2)"

        switch ($choice.Trim()) {
            "1" { return "Meshtastic" }
            "2" { return "MeshCore" }
            # "3" { return "Reticulum" }
            default {
                Write-Host "Invalid selection. Please enter 1 or 2." -ForegroundColor Yellow
            }
        }
    }
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
			Remove-Item $RELEASES_FILE -ErrorAction Ignore | Out-Null
			Move-Item $filteredTmp $RELEASES_FILE
			Remove-Item $VERSIONS_TAGS_FILE, $VERSIONS_LABELS_FILE -ErrorAction Ignore | Out-Null
		} else {
			Write-Progress -Activity "Release data is unchanged. $($oldMd5.Hash) $($newMd5.Hash)"
			
			# Update the LastWriteTime of the RELEASES_FILE to the current time
			Set-ItemProperty -Path $RELEASES_FILE -Name LastWriteTime -Value (Get-Date)
			
			Remove-Item $filteredTmp
		}
		Remove-Item $tmpFile
	}
}

function MT_UpdateHardwareList {
    # Check if the file exists and if it's older than 6 hours
    if (-not (Test-Path $HARDWARE_LIST) -or ((Get-Date) - (Get-Item $HARDWARE_LIST).LastWriteTime).TotalMinutes -gt 360) {
        Write-Progress -Activity "Downloading resources.ts from GitHub..."
        
        # Create the directory if it doesn't exist
        $directory = [System.IO.Path]::GetDirectoryName($HARDWARE_LIST)
        if (-not (Test-Path $directory)) {
            New-Item -Path $directory -ItemType Directory
        }

        # Download the file
        Invoke-WebRequest -Uri $MT_WEB_HARDWARE_LIST_URL -OutFile $HARDWARE_LIST
    }
	Write-Progress -Activity " " -Status " " -Completed
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
    Get-ChildItem -Path $FIRMWARE_ROOT -Directory | ForEach-Object {
        $folder = $_
        if ($folder.PSIsContainer -and $folder.Name -ne "downloads" -and $folder.Name -ne "winpython") {
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
            Write-Progress -Activity "$url"
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
                Write-Progress -Activity "$name"
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
        [string] $ListPath,
		[string] $SelectedFirmwareFile,
		[string] $selectedComPort,
		[string] $HWNameFile,
		[string] $Version
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
    $requiresDfu     = if ($entry.PSObject.Properties.Name -contains 'requiresDfu')     { $entry.requiresDfu     } else { $false }
    $hasInkHud       = if ($entry.PSObject.Properties.Name -contains 'hasInkHud')       { $entry.hasInkHud       } else { $false }
    $hasMui          = if ($entry.PSObject.Properties.Name -contains 'hasMui')          { $entry.hasMui          } else { $false }
	$partitionScheme = if ($entry.PSObject.Properties.Name -contains 'partitionScheme') { $entry.partitionScheme } else { "4MB" }

    # Build and return a PSCustomObject
    return [PSCustomObject]@{
        Slug         = $entry.hwModelSlug
        Architecture = $entry.architecture
        DisplayName  = $entry.displayName
        RequiresDfu  = $requiresDfu
        HasInkHud    = $hasInkHud
		HasMui       = $hasMui
		FirmwareFile = $SelectedFirmwareFile
		ComPort      = $selectedComPort
		HWNameFile   = $HWNameFile
		Version      = $Version
		FlashSize    = $partitionScheme
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
			Write-Host "Running -m meshtastic meshtastic --port $selectedComPort --export-config > $backupConfigName"
			# Start the Meshtastic process and redirect both stdout and stderr to the backup config file
			$process = Start-Process -FilePath "$pythonCommand" -ArgumentList " -m meshtastic --port $selectedComPort --export-config" -PassThru -Wait -NoNewWindow -RedirectStandardOutput "$backupConfigName" -RedirectStandardError "$backupConfigName.error"

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
		if ($HWNameShortNorm -ne "timedout") {
			Write-Warning "No matching firmware file found $HWNameShortNorm"
		}
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

        # Determine if the file is "recommended"
        $recommended = $false
        if (
            ($leaf -like '*-tft-*' -and $leaf -like '*-update*') -or
            ($leaf -like '*-inkhud-*' -and $leaf -like '*-update*') -or
            ($leaf -like '*-inkhud-*' -and $leaf -like '*.uf2')
        ) {
            $recommended = $true
        }

        $display = ("{0,2}) {1}" -f ($i + 1), $leaf)
        if ($recommended) {
            $display += " <- Recommended"
        }

        Write-Host $display
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



function GetHW() {
	# Find nodes
	$result = GetModelFromNode
	$DFU_node = $result[0]
	$Drive = $result[1]
	$HWNameShort = ""
	$HWNameFile = ""
	$SelectedFirmwareFile = ""
	$FirmwareVersion = ""
	$hwModelSlug = ""
	$selectedNodeProject = ""
	if ($DFU_node) {
		$HWNameShort = $DFU_node
		$hwModelSlug = $HWNameShort
		Write-Host "Found Device in DFU update state $HWNameShort"
		$selectedComPort = "NA"

	}
	else {
		# Get node info

		$result = getUSBComPort
		$selectedComPort     = $result[0]
		$hwModelSlug         = $result[1]
		$FirmwareVersion     = $result[2]
		$usbComDevices       = $result[3]
		$selectedNodeProject = $result[4]
	}
	Write-Host "$selectedComPort. Device: $hwModelSlug. Firmware: $FirmwareVersion."
	$selectedNodeProject = Select-FlashTarget
	Write-Host "Selected target: $selectedNodeProject" -ForegroundColor Green

	SetProjectVars $selectedNodeProject

	if ($selectedNodeProject -eq "Meshtastic") {
		MT_UpdateHardwareList
		UpdateReleases
		BuildReleaseMenuData

		$tag = SelectRelease
		DownloadAssets
		UnzipAssets
		if (-not $HWNameFile) {
			if ($HWNameShort) {
				$HWNameFile = $HWNameShort
			}
			else {
				$HWNameFile = SelectHardware
			}
		}
		$null = GetFirmwareFiles $HWNameFile
		$SelectedFirmwareFile = SelectMatchingFile
		$hw = GetHardwareInfo -Slug $HWNameFile -ListPath $HARDWARE_LIST -SelectedFirmwareFile $SelectedFirmwareFile -selectedComPort $selectedComPort -HWNameFile $HWNameFile -Version $FirmwareVersion
		$hw | Add-Member -NotePropertyName Project -NotePropertyValue "Meshtastic" -Force



		Write-Host "Selected hardware:   $($hw.DisplayName)"
		Write-Host "  Architecture:      $($hw.Architecture)"
		Write-Host "  Requires DFU:      $($hw.RequiresDfu)"
		Write-Host "  Has Ink HUD:       $($hw.HasInkHud)"
		Write-Host "  Has Meshtastic UI: $($hw.HasMui)"
		Write-Host "  New Firmware:      $($hw.FirmwareFile)"
		Write-Host "  COM Port:          $($hw.ComPort)"
		
		if ($hw.ComPort -ne "NA" -and $hw.Version -ne "--") {
			MakeConfigBackup $hw.HWNameFile $hw.ComPort
		}
		
	}
	if ($selectedNodeProject -eq "MeshCore") {
		$hw = [PSCustomObject]@{
			ComPort      = $selectedComPort
			HWNameFile   = $hwModelSlug
		}
		$null = ChooseMeshCoreFirmware $hw
		
		$script:Device 			= Read-TextFileIfExists $SELECTED_DEVICE_FILE
		$script:Role 			= Read-TextFileIfExists $SELECTED_ROLE_FILE
		$script:Architecture 	= Read-TextFileIfExists $ARCHITECTURE_FILE
		$script:EraseUrl 		= Read-TextFileIfExists $ERASE_URL_FILE
		$script:Version 		= Read-TextFileIfExists $SELECTED_VERSION_FILE
		$script:FWType    		= Read-TextFileIfExists $SELECTED_TYPE_FILE
		$script:URL     		= Read-TextFileIfExists $SELECTED_URL_FILE
		$script:DownloadedFirmwareFile = Resolve-MeshCoreFirmwareFile -SelectedReference $URL
		
		$hw = [PSCustomObject]@{
			ComPort      	= $selectedComPort
			HWNameFile   	= $Device
			Architecture 	= $Architecture
			EraseUrl 		= $EraseUrl
			Version 		= $Version
			FWType			= $FWType
			URL				= $URL
			FirmwareFile	= $DownloadedFirmwareFile
			Project			= "MeshCore"
		}

		Write-Host "Selected hardware:   $($hw.HWNameFile)"
		Write-Host "  Architecture:      $($hw.Architecture)"
		Write-Host "  Flash type:        $($hw.FWType)"
		Write-Host "  Firmware source:   $($hw.URL)"
		Write-Host "  New Firmware:      $($hw.FirmwareFile)"
		Write-Host "  COM Port:          $($hw.ComPort)"
	}
	

	Write-Progress -Activity " " -Status " " -Completed
	return $hw
}

# Update the release cache if needed.
function UpdateMTAllCaches {
    # 1) GitHub releases (normalized)
    UpdateJsonCache `
        -Url $GITHUB_API_URL `
        -OutFile $GITHUB_FILE `
        -Normalize $NormalizeGitHubReleases `
        -OnChangeDelete @($VERSIONS_TAGS_FILE, $VERSIONS_LABELS_FILE)

    # 2) flasher config.json (no normalization)
    UpdateJsonCache `
        -Url $MC_CONFIG_URL `
        -OutFile $CONFIG_FILE

    # 3) flasher releases (no normalization, unless you want similar churn filtering)
    UpdateJsonCache `
        -Url $MC_RELEASE_URL `
        -OutFile $RELEASES_FILE `
        -OnChangeDelete @($VERSIONS_TAGS_FILE, $VERSIONS_LABELS_FILE)
}

function Load-JsonFile {
    param([Parameter(Mandatory=$true)][string]$Path)
    if (-not (Test-Path $Path)) { return $null }
    $raw = Get-Content -Path $Path -Raw
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
    return ($raw | ConvertFrom-Json)
}

function Save-TextFile {
    param([Parameter(Mandatory=$true)][string]$Path,
          [string]$Value)
    $dir = [System.IO.Path]::GetDirectoryName($Path)
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    Set-Content -Path $Path -Value $Value -Encoding UTF8
}

function Read-TextFileIfExists {
    param([Parameter(Mandatory=$true)][string]$Path)
    if (Test-Path $Path) { return (Get-Content -Path $Path -Raw).Trim() }
    return ""
}

function Resolve-MeshCoreFirmwareSource {
    param(
        [Parameter(Mandatory=$true)][string]$SelectedReference
    )

    $trimmed = $SelectedReference.Trim()
    if ([string]::IsNullOrWhiteSpace($trimmed)) {
        throw "No MeshCore firmware source was selected."
    }

    if (Test-Path -LiteralPath $trimmed) {
        return [pscustomobject]@{
            Kind  = "local"
            Value = (Resolve-Path -LiteralPath $trimmed).Path
        }
    }

    if ($trimmed -match '^\s*https?://') {
        return [pscustomobject]@{
            Kind  = "url"
            Value = $trimmed
        }
    }

    if ($trimmed.StartsWith('/releases/download/')) {
        return [pscustomobject]@{
            Kind  = "url"
            Value = "https://github.com/$REPO_OWNER/$REPO_NAME$trimmed"
        }
    }

    if ($trimmed.StartsWith('/firmware/')) {
        return [pscustomobject]@{
            Kind  = "url"
            Value = "https://flasher.meshcore.dev$trimmed"
        }
    }

    if ($trimmed.StartsWith('firmware/')) {
        return [pscustomobject]@{
            Kind  = "url"
            Value = "https://flasher.meshcore.dev/$trimmed"
        }
    }

    if ($trimmed -match '^[A-Za-z]:[\\/]' -or $trimmed.StartsWith('\\')) {
        throw "Local firmware file not found: $trimmed"
    }

    return [pscustomobject]@{
        Kind  = "url"
        Value = "https://flasher.meshcore.dev/firmware/$trimmed"
    }
}

function Resolve-MeshCoreFirmwareFile {
    param(
        [Parameter(Mandatory=$true)][string]$SelectedReference,
        [string]$DownloadDir = $DOWNLOAD_DIR,
        [string]$CacheFile = $DOWNLOADED_FILE_FILE
    )

    $source = Resolve-MeshCoreFirmwareSource -SelectedReference $SelectedReference
    if ($source.Kind -eq "local") {
        Save-TextFile -Path $CacheFile -Value $source.Value
        return $source.Value
    }

    if (-not (Test-Path $DownloadDir)) {
        New-Item -ItemType Directory -Path $DownloadDir -Force | Out-Null
    }

    $cleanName = Get-CleanNameForExtensionCheck $source.Value
    $leafName = ""
    if ($source.Kind -eq "url") {
        try {
            $uri = [uri]$source.Value
            $leafName = Split-Path -Leaf $uri.AbsolutePath
        }
        catch {
            $leafName = ""
        }
    }

    if ([string]::IsNullOrWhiteSpace($leafName)) {
        $leafName = [System.IO.Path]::GetFileName($cleanName)
    }
    if ([string]::IsNullOrWhiteSpace($leafName) -and ($cleanName -match '([^/\\\?#]+)$')) {
        $leafName = $matches[1]
    }
    if ([string]::IsNullOrWhiteSpace($leafName)) {
        throw "Could not determine firmware filename from source: $($source.Value)"
    }

    $localFile = Join-Path $DownloadDir $leafName
    if ((Test-Path $localFile) -and ((Get-Item $localFile).Length -gt 0)) {
        Save-TextFile -Path $CacheFile -Value $localFile
        return $localFile
    }

    $cachedFile = Read-TextFileIfExists $CacheFile
    if ((-not [string]::IsNullOrWhiteSpace($cachedFile)) -and
        (Test-Path $cachedFile) -and
        ((Split-Path -Path $cachedFile -Leaf) -eq $leafName) -and
        ((Get-Item $cachedFile).Length -gt 0)) {
        Save-TextFile -Path $CacheFile -Value $cachedFile
        return $cachedFile
    }

    $tmpFile = Join-Path $DownloadDir ("{0}.tmp" -f ([Guid]::NewGuid()))
    try {
        Write-Host "Downloading firmware: $($source.Value)"
        Invoke-WebRequest -Uri $source.Value -OutFile $tmpFile -UseBasicParsing -Headers @{ 'User-Agent' = 'mcfirmware' } -ErrorAction Stop
        if ((Get-Item $tmpFile).Length -le 0) {
            throw "Downloaded firmware file is empty: $($source.Value)"
        }
        Move-Item -Path $tmpFile -Destination $localFile -Force
        Save-TextFile -Path $CacheFile -Value $localFile
        return $localFile
    }
    catch {
        throw "Failed to download firmware from $($source.Value): $($_.Exception.Message)"
    }
    finally {
        if (Test-Path $tmpFile) {
            Remove-Item -Path $tmpFile -Force -ErrorAction Ignore
        }
    }
}


function Prompt-Menu {
    param(
        [Parameter(Mandatory=$true)][string]$Title,
        [Parameter(Mandatory=$true)][string[]]$Options,
        [string]$Prompt = "Choice",
        [int]$DefaultIndex = -1,
        [switch]$AllowFreeText
    )

    while ($true) {
        Write-Host ""
        Write-Host $Title
        for ($i = 0; $i -lt $Options.Count; $i++) {
            "{0,3}) {1}" -f ($i + 1), $Options[$i] | Write-Host
        }

        $p = $Prompt
        if ($DefaultIndex -ge 1 -and $DefaultIndex -le $Options.Count) {
            $p = "$Prompt (Enter = $DefaultIndex)"
        }
        $ans = Read-Host $p

        if ([string]::IsNullOrWhiteSpace($ans) -and $DefaultIndex -ge 1) {
            return [pscustomobject]@{ IsIndex = $true; Index = $DefaultIndex; Text = "" }
        }

        if ($ans -match '^[0-9]+$') {
            $n = [int]$ans
            if ($n -ge 1 -and $n -le $Options.Count) {
                return [pscustomobject]@{ IsIndex = $true; Index = $n; Text = "" }
            }
            Write-Host "Invalid selection."
            continue
        }

        if ($AllowFreeText) {
            return [pscustomobject]@{ IsIndex = $false; Index = -1; Text = $ans }
        }

        Write-Host "Invalid selection."
    }
}

function Get-CleanNameForExtensionCheck {
    param([Parameter(Mandatory=$true)][string]$RawValue)
    if ([string]::IsNullOrWhiteSpace($RawValue)) { return "" }
    # Strip query/fragment: everything after ? or #
    return (($RawValue.Trim()) -split '[\?#]', 2)[0].Trim()
}

function Get-LeafNameForSelection {
    param([Parameter(Mandatory=$true)][string]$RawValue)

    $clean = Get-CleanNameForExtensionCheck -RawValue $RawValue
    if ([string]::IsNullOrWhiteSpace($clean)) { return "" }

    $uri = $null
    if ([uri]::TryCreate($clean, [System.UriKind]::Absolute, [ref]$uri) -and $uri.Scheme -match '^(?i)https?$') {
        $leaf = Split-Path -Leaf $uri.AbsolutePath
        if (-not [string]::IsNullOrWhiteSpace($leaf)) {
            return $leaf
        }
    }

    $leaf = [System.IO.Path]::GetFileName($clean)
    if ([string]::IsNullOrWhiteSpace($leaf) -and ($clean -match '([^/\\]+)$')) {
        $leaf = $matches[1]
    }

    return $leaf
}

# -----------------------------
# Device matching helpers (port name -> likely device)
# -----------------------------

function Normalize-Id {
    param([string]$s)
    if ($null -eq $s) { return "" }
    $t = $s.ToLowerInvariant()
    $t = [regex]::Replace($t, '[^0-9a-z]+', '_')
    $t = [regex]::Replace($t, '_{2,}', '_')
    $t = $t.Trim('_')
    return $t
}

function Contains-Word {
    param([string]$hay, [string]$needle)
    if ([string]::IsNullOrWhiteSpace($needle)) { return $false }
    $h = Normalize-Id $hay
    $n = Normalize-Id $needle
    if ([string]::IsNullOrWhiteSpace($h) -or [string]::IsNullOrWhiteSpace($n)) { return $false }
    return [regex]::IsMatch($h, "(^|_)$([regex]::Escape($n))(_|$)")
}

function Is-GoodTail {
    param([string]$tail)
    if ([string]::IsNullOrWhiteSpace($tail)) { return $false }
    $t = Normalize-Id $tail
    if ($t.Length -lt 3) { return $false }
    $bad = @(
        "esp32","nrf52","usb","serial","uart","ttl",
        "cp210","cp2102","cp210x","ch340","ftdi",
        "sx1262","sx126x","sx1276","sx127x"
    )
    return ($bad -notcontains $t)
}

function Pick-MatchingDevice {
    param(
        [Parameter(Mandatory=$true)][string]$UsbString,
        [Parameter(Mandatory=$true)][string[]]$Devices,
        [Parameter(Mandatory=$true)][string]$VENDORLIST,
        [Parameter(Mandatory=$true)][string]$RADIOLIST
    )

    $usbSlug = Normalize-Id $UsbString

    for ($i = 0; $i -lt $Devices.Count; $i++) {
        $name = $Devices[$i]
        $base = Normalize-Id $name

        $core = $base
        $core = [regex]::Replace($core, "\b($VENDORLIST)\b_?", "")
        $core = [regex]::Replace($core, "_{2,}", "_").Trim("_")

        $core = [regex]::Replace($core, "(^|_)($RADIOLIST)(_|$)", '$1$3')
        $core = [regex]::Replace($core, "_{2,}", "_").Trim("_")

        if ([string]::IsNullOrWhiteSpace($core)) { $core = $base }

        $toks = @()
        if (-not [string]::IsNullOrWhiteSpace($core)) { $toks = $core.Split("_") }
        $n = $toks.Count

        $cand3 = ""
        $cand2 = ""
        $cand1 = ""

        if ($n -ge 3) { $cand3 = "{0}_{1}_{2}" -f $toks[$n-3], $toks[$n-2], $toks[$n-1] }
        if ($n -ge 2) { $cand2 = "{0}_{1}"     -f $toks[$n-2], $toks[$n-1] }
        if ($n -ge 1) { $cand1 = $toks[$n-1] }

        if (Is-GoodTail $cand3 -and (Contains-Word $usbSlug $cand3)) { return [pscustomobject]@{ Match=$name; MatchIdx=$i+1 } }
        if (Is-GoodTail $cand2 -and (Contains-Word $usbSlug $cand2)) { return [pscustomobject]@{ Match=$name; MatchIdx=$i+1 } }
        if (Is-GoodTail $cand1 -and (Contains-Word $usbSlug $cand1)) { return [pscustomobject]@{ Match=$name; MatchIdx=$i+1 } }
        if (Contains-Word $usbSlug $base)                             { return [pscustomobject]@{ Match=$name; MatchIdx=$i+1 } }
    }

    # Optional alias
    if ($usbSlug -like "*station_g2*") {
        return [pscustomobject]@{ Match="UnitEng Station G2"; MatchIdx=31 }
    }

    return $null
}

# -----------------------------
# Custom firmware selection
# -----------------------------

function Choose-CustomFirmwareFile {
    # Uses globals: $ARCHITECTURE, $ROLE, sets: $CHOSEN_FILE, $VERSION
	$archLc = ([string]$ARCHITECTURE).ToLowerInvariant()
    $requiredExt = ".zip"
    $extra = ""

    if ($archLc -eq "esp32") {
        $requiredExt = ".bin"
        $extra = "The merged files will do a full erase"
    }

    Write-Host "Rule: ARCHITECTURE='$ARCHITECTURE' requires files ending with $requiredExt $extra"

    $roleLc = ([string]$ROLE).ToLowerInvariant()
    switch -Wildcard ($roleLc) {
        "companion*" {
            Write-Host " https://files.brazio.org/meshcore/nightly/companion/"
            Write-Host " https://analyzer.letsmesh.net/observer/onboard?type=companion"
            Write-Host " https://cloud.weyhmueller.org/s/meshcore-stuff?dir=/WiFi+Companion+Patcher"
        }
        "repeater*" {
            Write-Host " https://files.brazio.org/meshcore/nightly/repeater/"
            Write-Host " https://analyzer.letsmesh.net/observer/onboard?type=repeater"
            Write-Host " https://github.com/IoTThinks/EasySkyMesh/releases/tag/PowerSaving10"
        }
        "room*" {
            Write-Host " https://files.brazio.org/meshcore/nightly/room-server/"
            Write-Host " https://analyzer.letsmesh.net/observer/onboard?type=room"
        }
    }

    while ($true) {
        $input = Read-Host "Enter full filename or url"
        if ([string]::IsNullOrWhiteSpace($input)) { Write-Host "Empty input. Try again."; continue }

        $leafName = Get-LeafNameForSelection $input
        $isValid = $false
        if ($requiredExt -eq ".bin") {
            $isValid = ((Get-EspFileNameMode -Name $leafName) -ne 'unknown')
        } else {
            $isValid = ($leafName.ToLowerInvariant().EndsWith($requiredExt))
        }
        if (-not $isValid) {
            Write-Host "ERROR: Selection must end with $requiredExt"
            continue
        }

        $script:CHOSEN_FILE = $input
        $script:VERSION     = "custom"
        return $true
    }
}

# -----------------------------
# Filter: show only newest two branches (X.Y)
# -----------------------------

function Filter-LastTwoBranches {
    param([Parameter(Mandatory=$true)][string[]]$In)

    # Clean
    $clean = $In | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ -ne "" }
    if (-not $clean -or $clean.Count -eq 0) { return @() }

    # Extract X.Y branches (unique, sorted desc)
	$branches = foreach ($s in $clean) {
		$t = ($s -replace '^[Vv]\s*', '')
		$parts = ($t -split '[\.\-]', 3)
		if ($parts.Count -ge 2 -and $parts[0] -match '^[0-9]+$' -and $parts[1] -match '^[0-9]+$') {
			"{0}.{1}" -f $parts[0], $parts[1]
		}
	}

	# Unique + sorted desc
	$branches = $branches |
		Where-Object { $_ } |
		Sort-Object {
			$p = $_.Split('.')
			([int]$p[0] * 100000) + [int]$p[1]
		} -Descending |
		Select-Object -Unique


    if (-not $branches -or $branches.Count -eq 0) { return @() }
    $choose = $branches | Select-Object -First 2
    if ($choose.Count -eq 0) { return @() }

    # Filter original strings that start with one of chosen branches (allow V prefix)
    $escaped = $choose | ForEach-Object { [regex]::Escape($_) }
    $re = "^\s*[Vv]?(?:{0})(?:\.|$)" -f ($escaped -join "|")

    $out = $clean | Where-Object { $_ -match $re } | Sort-Object {
        # Best-effort version sort: take leading digits/dots after optional V
        $m = [regex]::Match($_, '^\s*[Vv]?([0-9]+(\.[0-9]+)*)')
        if ($m.Success) { [version]($m.Groups[1].Value) } else { [version]"0.0" }
    } -Descending | Select-Object -Unique

    return @($out)
}

# -----------------------------
# Version selection fallback using /releases endpoint
# -----------------------------

function Choose-VersionFromReleases {
    param(
        [Parameter(Mandatory=$true)][string]$Device,
        [Parameter(Mandatory=$true)][string]$Role,
        [Parameter(Mandatory=$true)][string]$Architecture,
        [Parameter()][AllowEmptyString()][string]$EraseUrl,
        [Parameter(Mandatory=$true)][string]$Title
    )

    $releases = Load-JsonFile $RELEASES_FILE
    if (-not $releases) { throw "ERROR: could not load releases cache: $RELEASES_FILE" }

    $script:VERSION = Read-TextFileIfExists $SELECTED_VERSION_FILE
    $script:TYPE    = Read-TextFileIfExists $SELECTED_TYPE_FILE
    if (-not $script:CHOSEN_FILE) { $script:CHOSEN_FILE = "" }

    if ([string]::IsNullOrWhiteSpace($script:VERSION)) {
        $versions = $releases | ForEach-Object { $_.version } | Where-Object { $_ } | Sort-Object -Unique -Descending
        if (-not $versions -or $versions.Count -eq 0) { throw "ERROR: no versions in /releases endpoint" }

        if ($versions.Count -eq 1) {
            $script:VERSION = $versions[0]
            Write-Host "Auto-selected version from fallback: $($script:VERSION)"
        } else {
            $versionsShow = Filter-LastTwoBranches -In $versions
            $menu = @($versionsShow + @("Custom"))

            while ([string]::IsNullOrWhiteSpace($script:VERSION)) {
                $archLc = ([string]$Architecture).ToLowerInvariant()
                $requiredExt = if ($archLc -eq "esp32") { ".bin" } else { ".zip" }

                $sel = Prompt-Menu -Title "[3] Select version:" -Options $menu -Prompt "Choice" -AllowFreeText
                if ($sel.IsIndex) {
                    $choice = $menu[$sel.Index - 1]
                    if ($choice -eq "Custom") {
                        if (Choose-CustomFirmwareFile) { break }
                        Write-Host "Custom selection failed; please choose again."
                        continue
                    } else {
                        $script:VERSION = $choice
                        break
                    }
                } else {
                    # Free text URL/path
                    $input = $sel.Text
                    $leafName = Get-LeafNameForSelection $input
                    $isValid = $false
                    if ($requiredExt -eq ".bin") {
                        $isValid = ((Get-EspFileNameMode -Name $leafName) -ne 'unknown')
                    } else {
                        $isValid = ($leafName.ToLowerInvariant().EndsWith($requiredExt))
                    }
                    if (-not $isValid) {
                        Write-Host "ERROR: Selection must end with $requiredExt"
                        continue
                    }
                    $script:CHOSEN_FILE = $input
                    $script:VERSION     = "custom"
                    break
                }
            }
        }
    }

    # Auto-select TYPE based on chosen file name extension (if custom)
    $candidate = if (-not [string]::IsNullOrWhiteSpace($script:CHOSEN_FILE)) { $script:CHOSEN_FILE } else { $script:VERSION }
    if (-not [string]::IsNullOrWhiteSpace($candidate)) {
        $clean = Get-CleanNameForExtensionCheck $candidate
        $name  = [System.IO.Path]::GetFileName($clean)
        $nameMode = Get-EspFileNameMode -Name $name
        if ($nameMode -eq 'install') {
            $script:TYPE = "flash-wipe"
            Write-Host "Auto-selected type: flash-wipe"
        } elseif ($nameMode -eq 'update') {
            $script:TYPE = "flash-update"
            Write-Host "Auto-selected type: flash-update"
        } elseif ($clean.ToLowerInvariant().EndsWith(".zip")) {
            # leave TYPE empty so normal selection logic can run
            $script:TYPE = ""
        }
    }

    # If still need TYPE and this is not custom, derive from config file keys
    if ([string]::IsNullOrWhiteSpace($script:TYPE)) {
        $config = Load-JsonFile $CONFIG_FILE
        if (-not $config) { throw "ERROR: could not load config: $CONFIG_FILE" }

        $types = @()
        $dev = $config.device | Where-Object { $_.name -eq $Device } | Select-Object -First 1
        if ($dev) {
            $fw = $dev.firmware | Where-Object { $_.role -eq $Role }
            foreach ($f in $fw) {
                $keys = @()
                if ($f.github -and $f.github.files) {
                    $keys = $f.github.files.PSObject.Properties.Name
                }
                $types += $keys
            }
        }
        $types = $types | Where-Object { $_ } | Sort-Object -Unique

        if ($types.Count -eq 1) {
            $script:TYPE = $types[0]
            Write-Host "Auto-selected type: $($script:TYPE)"
        } elseif ($types.Count -eq 2 -and ($types -contains "flash") -and ($types -contains "download")) {
            $script:TYPE = "flash"
            Write-Host "Auto-selected type: flash"
        } else {
            $sel = Prompt-Menu -Title "[4] Select type:" -Options $types -Prompt "Choice"
            $script:TYPE = $types[$sel.Index - 1]
        }
    }

    # Select URL (if not already custom)
    if ([string]::IsNullOrWhiteSpace($script:CHOSEN_FILE)) {
        $config = Load-JsonFile $CONFIG_FILE
        if (-not $config) { throw "ERROR: could not load config: $CONFIG_FILE" }

        $dev = $config.device | Where-Object { $_.name -eq $Device } | Select-Object -First 1
        $regex = ""

        if ($dev) {
            $fw = $dev.firmware | Where-Object { $_.role -eq $Role -and ($Title -eq "" -or $_.title -eq $Title) } | Select-Object -First 1
            if (-not $fw) { $fw = $dev.firmware | Where-Object { $_.role -eq $Role } | Select-Object -First 1 }
            if ($fw -and $fw.github -and $fw.github.files) {
                $regex = $fw.github.files.$($script:TYPE)
            }
        }

        $roleAlt = $Role
        if ($Role -eq "companionBle" -or $Role -eq "companionUsb") { $roleAlt = "companion" }

        $match = $releases | Where-Object { $_.version -eq $script:VERSION -and $_.type -eq $roleAlt } | Select-Object -First 1
        if ($match -and $match.files) {
            $file = $match.files | Where-Object { $_.name -match $regex } | Select-Object -First 1
            if ($file) { $script:CHOSEN_FILE = $file.url }
        }
    }

    # Persist selections
    Save-TextFile $SELECTED_DEVICE_FILE  $Device
    Save-TextFile $SELECTED_ROLE_FILE    $Role
    Save-TextFile $ARCHITECTURE_FILE     $Architecture
    Save-TextFile $ERASE_URL_FILE        $EraseUrl
    Save-TextFile $SELECTED_VERSION_FILE $script:VERSION
    Save-TextFile $SELECTED_TYPE_FILE    $script:TYPE
    Save-TextFile $SELECTED_URL_FILE     $script:CHOSEN_FILE
}


function UpdateJsonCache {
    param(
        [Parameter(Mandatory=$true)][string]$Url,
        [Parameter(Mandatory=$true)][string]$OutFile,
        [int]$TimeoutSec = 20,
        [scriptblock]$Normalize = $null,
        [string[]]$OnChangeDelete = @()
    )

    if (-not (CheckInternet)) {
        Write-Host "No internet; using cached: $OutFile"
        return
    }

    if (Test-Path $OutFile) {
        $ageSec = ((Get-Date) - (Get-Item $OutFile).LastWriteTime).TotalSeconds
        if ($ageSec -lt $CACHE_TIMEOUT_SECONDS) {
            Write-Host "Using cached (fresh): $OutFile"
            return
        }
    }

    $dir = [System.IO.Path]::GetDirectoryName($OutFile)
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    Write-Host "Updating cache: $Url"

    $headers = @{
        "User-Agent" = "mcfirmware"
        "Accept"     = "application/json"
    }

    $tmp = [System.IO.Path]::GetTempFileName()
    try {
        Invoke-WebRequest -Uri $Url -Headers $headers -TimeoutSec $TimeoutSec -OutFile $tmp -ErrorAction Stop

        # Validate JSON by parsing it
        $obj = Get-Content -Path $tmp -Raw | ConvertFrom-Json

        # Optional normalization (eg remove download_count)
        if ($Normalize) {
            & $Normalize $obj
        }

        # Re-serialize in a stable way for hashing/writing
        $json = $obj | ConvertTo-Json -Depth 50
        Set-Content -Path $tmp -Value $json -Encoding UTF8

        if (-not (Test-Path $OutFile)) {
            Move-Item -Path $tmp -Destination $OutFile -Force
            return
        }

        $oldMd5 = (Get-FileHash -Path $OutFile -Algorithm MD5).Hash
        $newMd5 = (Get-FileHash -Path $tmp    -Algorithm MD5).Hash

        if ($oldMd5 -ne $newMd5) {
            Write-Host "Cache changed: $OutFile"
            Move-Item -Path $tmp -Destination $OutFile -Force
            if ($OnChangeDelete.Count -gt 0) {
                Remove-Item -Path $OnChangeDelete -ErrorAction Ignore
            }
        } else {
            Write-Host "Cache unchanged: $OutFile"
            (Get-Item $OutFile).LastWriteTime = Get-Date
        }
    } catch {
        Write-Host "Cache update failed for $Url : $($_.Exception.Message)"
    } finally {
        Remove-Item -Path $tmp -Force -ErrorAction Ignore
    }
}

function ChooseMeshCoreFirmware {
	param(
        [Parameter(Mandatory = $false)]
        [psobject]$Hw
    )
	if ($Hw) {
        if ($Hw.PSObject.Properties['ComPort'] -and -not [string]::IsNullOrWhiteSpace($Hw.ComPort)) {
            $script:COM_PORT = $Hw.ComPort
        }

        if ($Hw.PSObject.Properties['HWNameFile'] -and -not [string]::IsNullOrWhiteSpace($Hw.HWNameFile)) {
            $script:DEVICE = $Hw.HWNameFile
        }
    }
	
	UpdateMTAllCaches
	$config = Get-Content $CONFIG_FILE -Raw | ConvertFrom-Json
	
    $script:DEVICE       = Read-TextFileIfExists $SELECTED_DEVICE_FILE
    $script:ARCHITECTURE = Read-TextFileIfExists $ARCHITECTURE_FILE
    $script:ERASE_URL    = Read-TextFileIfExists $ERASE_URL_FILE
    $script:ROLE         = Read-TextFileIfExists $SELECTED_ROLE_FILE
    $script:VERSION      = Read-TextFileIfExists $SELECTED_VERSION_FILE
    $script:TYPE         = Read-TextFileIfExists $SELECTED_TYPE_FILE
	#$script:devicePortName = Read-TextFileIfExists $DEVICE_PORT_NAME_FILE
	#$script:deviceName     = Read-TextFileIfExists $DEVICE_PORT_FILE
	
    if (-not $script:CHOSEN_FILE) { $script:CHOSEN_FILE = "" }

    # Step 1: Device
    if ([string]::IsNullOrWhiteSpace($script:DEVICE)) {
        $devices = @($config.device | ForEach-Object { $_.name } | Where-Object { $_ } | Sort-Object -Unique)
        if ($devices.Count -eq 0) { throw "ERROR: no .device[].name entries found in $CONFIG_FILE" }

        if ($devices.Count -eq 1) {
            $script:DEVICE = $devices[0]
            Write-Host "Auto-selected device: $($script:DEVICE)"
        } else {


            $match = $null
            if (-not [string]::IsNullOrWhiteSpace($devicePortName)) {
                $match = Pick-MatchingDevice -UsbString $devicePortName -Devices $devices -VENDORLIST $VENDORLIST -RADIOLIST $RADIOLIST
            }

            while ([string]::IsNullOrWhiteSpace($script:DEVICE)) {
                Write-Host ""
                Write-Host "[1] Select device (0 = Auto-detect):"
                Write-Host "  0) Auto-detect"
                for ($i = 0; $i -lt $devices.Count; $i++) {
                    "  {0}) {1}" -f ($i + 1), $devices[$i] | Write-Host
                }
                $customIndex = $devices.Count + 1
                Write-Host ("  {0}) Custom" -f $customIndex)
                Write-Host ""

                if ($match) {
                    $choice = Read-Host ("Choice (Detected {0} on {1}, Enter will pick {2})" -f $match.Match, $deviceName, $match.MatchIdx)
                    if ([string]::IsNullOrWhiteSpace($choice)) { $choice = [string]$match.MatchIdx }
                } else {
                    if ($devicePortName -or $deviceName) { Write-Host "$devicePortName -> $deviceName" }
                    $choice = Read-Host "Choice"
                }

                if ($choice -eq "0") {
                    Write-Host "Auto-detection requested."
                    # TODO: implement Autodetect-Device to set $AUTODETECT_DEVICE_FILE (port name)
                    # Autodetect-Device
                    $devicePortName = Read-TextFileIfExists $AUTODETECT_DEVICE_FILE
                    $match = $null
                    if (-not [string]::IsNullOrWhiteSpace($devicePortName)) {
                        $match = Pick-MatchingDevice -UsbString $devicePortName -Devices $devices -VENDORLIST $VENDORLIST -RADIOLIST $RADIOLIST
                    }
                    $script:DEVICE = Read-TextFileIfExists $SELECTED_DEVICE_FILE
                    continue
                }

                if ($choice -match '^[1-9][0-9]*$') {
                    $n = [int]$choice
                    if ($n -ge 1 -and $n -le $devices.Count) {
                        $script:DEVICE = $devices[$n - 1]
                        break
                    }
                    if ($n -eq $customIndex) {
                        $script:DEVICE = "CustomFirmware"
                        break
                    }
                }

                Write-Host "Invalid selection."
            }
        }
    }

    # Custom firmware branch
    if ($script:DEVICE -eq "CustomFirmware") {
        Write-Host "Custom firmware selected."
        Write-Host "Is this an ESP32 or NRF52 device?"
        Write-Host "  1) esp32"
        Write-Host "  2) nrf52"

        while ($true) {
            $ans = Read-Host "Choice (1/2)"
            if ($ans -eq "1") { $script:ARCHITECTURE = "esp32"; break }
            if ($ans -eq "2") { $script:ARCHITECTURE = "nrf52"; break }
            Write-Host "Please enter 1 or 2."
        }

        Write-Host "You selected: $($script:ARCHITECTURE)"
        while ([string]::IsNullOrWhiteSpace($script:CHOSEN_FILE)) {
            Start-Sleep -Milliseconds 100
            $script:ROLE = "custom"
            if (Choose-CustomFirmwareFile) {
                $script:ROLE    = "custom"
                $script:VERSION = "custom"
                $script:TYPE    = "custom"
                break
            }
            Write-Host "Custom selection failed; please choose again."
        }
    }

    # Step 2: Architecture and erase URL
    $devObj = $config.device | Where-Object { $_.name -eq $script:DEVICE } | Select-Object -First 1
    if ([string]::IsNullOrWhiteSpace($script:ARCHITECTURE) -and $devObj) {
        $script:ARCHITECTURE = $devObj.type
    }

    $script:ERASE_URL = ""
    if ($devObj -and $devObj.erase) {
        $script:ERASE_URL = "https://flasher.meshcore.dev/firmware/$($devObj.erase)"
    }

    # Step 3: Role
    $script:TITLE = ""
    if ([string]::IsNullOrWhiteSpace($script:ROLE)) {
        $roles  = @()
        $titles = @()
        $labels = @()

        foreach ($fw in @($devObj.firmware)) {
            if (-not $fw.role) { continue }
            $role  = [string]$fw.role
            $title = [string]$fw.title
            if ([string]::IsNullOrWhiteSpace($title) -or $title -eq "null") {
                switch ($role) {
                    "companionBle" { $title = "Companion radio" }
                    "companionUsb" { $title = "Companion radio" }
                    "repeater"     { $title = "Repeater" }
                    "roomServer"   { $title = "Room Server" }
                    default        { $title = $role }
                }
            }
            $roles  += $role
            $titles += $title
        }

        # Unique role+title pairs (best-effort)
        $pairs = @()
        for ($i = 0; $i -lt $roles.Count; $i++) {
            $pairs += [pscustomobject]@{ Role=$roles[$i]; Title=$titles[$i] }
        }
        $pairs = $pairs | Sort-Object Role, Title -Unique

        $roles  = @($pairs | ForEach-Object { $_.Role })
        $titles = @($pairs | ForEach-Object { $_.Title })

        if ($roles.Count -eq 0) { throw "ERROR: no firmware roles found for device $($script:DEVICE)" }

        for ($i = 0; $i -lt $roles.Count; $i++) {
            $suffix = ""
            switch ($roles[$i]) {
                "companionBle" { $suffix = " (BLE) Phone" }
                "companionUsb" { $suffix = " (USB) Computer" }
            }
            $labels += ($titles[$i] + $suffix)
        }

        if ($roles.Count -eq 1) {
            $script:ROLE  = $roles[0]
            $script:TITLE = $titles[0]
            Write-Host "Auto-selected role: $($script:ROLE) ($($labels[0]))"
        } else {
            $sel = Prompt-Menu -Title "[2] Select role for $($script:DEVICE):" -Options $labels -Prompt "Choice"
            $idx = $sel.Index - 1
            $script:ROLE  = $roles[$idx]
            $script:TITLE = $titles[$idx]
            Write-Host "Selected role: $($script:ROLE) ($($labels[$idx]))"
        }

        switch ($script:ROLE) {
            "companionBle" { $script:TRANSPORT = "ble" }
            "companionUsb" { $script:TRANSPORT = "usb" }
            default        { $script:TRANSPORT = "" }
        }
    }

    # Step 4: Version
    if ([string]::IsNullOrWhiteSpace($script:VERSION)) {
        # Try version keys from config
        $fwMatch = @($devObj.firmware | Where-Object { $_.role -eq $script:ROLE })
        $verKeys = @()
        foreach ($fw in $fwMatch) {
            if ($script:TITLE -and $fw.title -and $fw.title -ne $script:TITLE) { continue }
            if ($fw.version) {
                $verKeys += $fw.version.PSObject.Properties.Name
            }
        }
        $verKeys = $verKeys | Where-Object { $_ } | Sort-Object -Unique -Descending

        if (-not $verKeys -or $verKeys.Count -eq 0) {
            Choose-VersionFromReleases -Device $script:DEVICE -Role $script:ROLE -Architecture $script:ARCHITECTURE -EraseUrl $script:ERASE_URL -Title $script:TITLE
			return
        }

        if ($verKeys.Count -eq 1) {
            $script:VERSION = $verKeys[0]
            Write-Host "Auto-selected version: $($script:VERSION)"
        } else {
            $show = Filter-LastTwoBranches -In $verKeys
            $sel = Prompt-Menu -Title "[3] Select version:" -Options $show -Prompt "Choice"
            $script:VERSION = $show[$sel.Index - 1]
        }
    }

    # Step 5: Type
    if ([string]::IsNullOrWhiteSpace($script:TYPE)) {
        $types = @()
        foreach ($fw in @($devObj.firmware | Where-Object { $_.role -eq $script:ROLE })) {
            if ($script:TITLE -and $fw.title -and $fw.title -ne $script:TITLE) { continue }
            $v = $fw.version.$($script:VERSION)
            if ($v -and $v.files) {
                $types += @($v.files | ForEach-Object { $_.type })
            }
        }
        $types = $types | Where-Object { $_ } | Sort-Object -Unique

        if ($types.Count -eq 0) { throw "ERROR: no file types found for $($script:DEVICE) / $($script:ROLE) / $($script:VERSION)" }

        if ($types.Count -eq 1) {
            $script:TYPE = $types[0]
            Write-Host "Auto-selected type: $($script:TYPE)"
        } elseif ($types.Count -eq 2 -and ($types -contains "flash") -and ($types -contains "download")) {
            $script:TYPE = "flash"
            Write-Host "Auto-selected type: flash"
        } else {
            $sel = Prompt-Menu -Title "[4] Select type:" -Options $types -Prompt "Choice"
            $script:TYPE = $types[$sel.Index - 1]
        }
    }

    # Step 6: Filename
    if ([string]::IsNullOrWhiteSpace($script:CHOSEN_FILE)) {
        $chosenName = ""
        foreach ($fw in @($devObj.firmware | Where-Object { $_.role -eq $script:ROLE })) {
            if ($script:TITLE -and $fw.title -and $fw.title -ne $script:TITLE) { continue }
            $v = $fw.version.$($script:VERSION)
            if ($v -and $v.files) {
                $m = $v.files | Where-Object { $_.type -eq $script:TYPE } | Select-Object -First 1
                if ($m) { $chosenName = [string]$m.name; break }
            }
        }
        if ([string]::IsNullOrWhiteSpace($chosenName)) { throw "ERROR: could not select a firmware filename" }

        $script:CHOSEN_FILE = $chosenName
        Save-TextFile $SELECTED_URL_FILE ("firmware/$chosenName")
    } else {
        Save-TextFile $SELECTED_URL_FILE $script:CHOSEN_FILE
    }

    # Persist selection files
    Save-TextFile $SELECTED_DEVICE_FILE  $script:DEVICE
    Save-TextFile $ARCHITECTURE_FILE     $script:ARCHITECTURE
    Save-TextFile $ERASE_URL_FILE        $script:ERASE_URL
    Save-TextFile $SELECTED_ROLE_FILE    $script:ROLE
    Save-TextFile $SELECTED_VERSION_FILE $script:VERSION
    Save-TextFile $SELECTED_TYPE_FILE    $script:TYPE
}


function flashESP32() {
    param(
        [Parameter(Mandatory)][pscustomobject]$hw      # must expose Architecture, SelectedFirmwareFile, selectedComPort/Drive
    )

	$strategy = Get-EspFlashStrategy -Path $hw.FirmwareFile

	if ($strategy.ClassifiedMode -eq 'data') {
		Write-Warning "Selected file looks like a data image, not a firmware image: $($strategy.Path)"
		Write-Warning "Classification: $($strategy.Classification)"
		return $false
	}

	if ($strategy.ClassifiedMode -eq 'unknown') {
		Write-Warning "Could not confidently classify ESP image layout for $($strategy.Path)"
		Write-Warning "Falling back to filename-based mode: $($strategy.SelectedMode)"
	}
	elseif ($strategy.ClassifiedMode -ne $strategy.FileNameMode) {
		Write-Warning "Filename suggests '$($strategy.FileNameMode)' but image layout looks like '$($strategy.ClassifiedMode)'. Using '$($strategy.SelectedMode)'."
	}

	if ($strategy.SelectedMode -eq 'install') {
		return (installFlashViaEspTool $hw)
	}
	return (updateFlashViaEspTool $hw)
}

function updateFlashViaEspTool {
	param(
        [Parameter(Mandatory)][pscustomobject]$hw 
    )
	
	$SelectedFirmwareFile = $hw.FirmwareFile
	$selectedComPort = $hw.ComPort
	$fi = Get-Item $hw.FirmwareFile
	$baseName = $fi.Name

	
	$destFolder = Split-Path $SelectedFirmwareFile -Parent
	Push-Location  $destFolder
	

	$ESPTOOL_CMD = get_esptool_cmd
	$WriteFlashCommand = $script:ESPTOOL_WRITE_FLASH
		
	
	Write-Host ""
	Write-Host ""
	Write-Host ""


	$attempt      = 0          # counter for Write-Progress
	$delaySeconds = 3          # pause between retries

	# Wake up port
	while ($true) {
		$attempt++

		if ($attempt -gt 5) {
			Write-Progress -Status "Unplug and replug the device" -Activity "Waiting for $selectedComPort. Attempt: $attempt"
		}
		else {
			Write-Progress -Status "Putting device into 1200 baud update mode" -Activity "Waiting for $selectedComPort. Attempt: $attempt"
		}

		# run esptool and capture *all* output
		$output = run_cmd "$ESPTOOL_CMD --baud 1200 --port $selectedComPort chip_id"

		if ($output -match 'device attached to the system is not') {
			if ($attempt -eq 5) {
				Write-Host $output             # echo the error so the user sees it
				Write-Warning "Turn on the screen on the device"
				Write-Warning "Unplug and repug the device"
				
				[console]::Beep()
				Read-Host "Press enter to Continue"

			}
			Start-Sleep -Seconds $delaySeconds
			
			$devicesAfter = getUSBComPort -SkipInfo
			$selectedComPort = $devicesAfter[0]
			
			continue
		}
			
		Write-Progress -Completed -Activity " " -Status "Port ready after $attempt attempt(s)"
		#Write-Host $output
		break       
	}

		
	Start-Sleep -Seconds 12
	$devicesAfter = getUSBComPort -SkipInfo
	$selectedComPortPart2 = $devicesAfter[0]
	Write-Host "Flashing $SelectedFirmwareFile at 0x10000. Write application firmware."
	Write-Host "$ESPTOOL_CMD --baud 115200 --port $selectedComPortPart2 $WriteFlashCommand 0x10000 $SelectedFirmwareFile"
	Write-Host ""
	run_cmd "$ESPTOOL_CMD --baud 115200 --port $selectedComPortPart2 $WriteFlashCommand 0x10000 $SelectedFirmwareFile" -Stream

	
	Write-Host ""
	Pop-Location
	return $true
}

function Get-FirstExistingLocalFileName {
	param(
		[Parameter(Mandatory)][string]$Folder,
		[string[]]$Candidates
	)

	foreach ($candidate in $Candidates) {
		if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
		if (Test-Path (Join-Path $Folder $candidate)) {
			return $candidate
		}
	}

	return ""
}

function Get-EspFileNameMode {
	param(
		[Parameter(Mandatory)][string]$Name
	)

	$lower = $Name.ToLowerInvariant()
	if ($lower -match '(?:\.factory|-merged|freshinstall(?:[-_.]|$)).*\.bin$' -or
		$lower -match '(?:^|[-_.])freshinstall(?:[-_.]|$)') {
		return 'install'
	}

	if ($lower -match '(?:^|[-_.])(upgrade|update)(?:[-_.]|$)' -and $lower.EndsWith('.bin')) {
		return 'update'
	}

	if ($lower.EndsWith('.bin')) {
		return 'update'
	}

	return 'unknown'
}

function Get-EspBinClassification {
	param(
		[Parameter(Mandatory)][string]$Path
	)

	if (-not (Test-Path $Path)) {
		throw "Cannot classify missing file: $Path"
	}

	$fs = [System.IO.File]::OpenRead($Path)
	try {
		function Read-HexAtOffset {
			param(
				[System.IO.FileStream]$Stream,
				[long]$Offset,
				[int]$Length
			)

			$buf = New-Object byte[] $Length
			$Stream.Seek($Offset, [System.IO.SeekOrigin]::Begin) | Out-Null
			$read = $Stream.Read($buf, 0, $Length)
			if ($read -le 0) { return "" }
			return (($buf[0..($read - 1)] | ForEach-Object { '{0:x2}' -f $_ }) -join '')
		}

		$b0 = Read-HexAtOffset -Stream $fs -Offset 0x0 -Length 1
		$b1000 = Read-HexAtOffset -Stream $fs -Offset 0x1000 -Length 1
		$b8000 = Read-HexAtOffset -Stream $fs -Offset 0x8000 -Length 2
		$b10000 = Read-HexAtOffset -Stream $fs -Offset 0x10000 -Length 1

		$result = "AMBIGUOUS"
		if ($b8000 -eq 'aa50' -and $b10000 -eq 'e9' -and ($b0 -eq 'e9' -or $b1000 -eq 'e9' -or $b1000 -eq 'cc' -or $b1000 -eq 'ff')) {
			$result = "LIKELY_MERGED"
		}
		elseif ($b0 -eq 'e9' -and $b8000 -ne 'aa50' -and $b10000 -eq 'e9') {
			$result = "MULTI_IMAGE_NO_PARTITION_TABLE"
		}
		elseif ($b0 -eq 'e9' -and $b8000 -ne 'aa50' -and $b10000 -ne 'e9') {
			$result = "LIKELY_SINGLE"
		}
		elseif ($b0 -eq '01' -and $b1000 -eq '02' -and $b8000 -eq 'ffff' -and $b10000 -eq 'ff') {
			$result = "DATA_IMAGE"
		}
		elseif ($b0 -ne 'e9' -and $b1000 -ne 'e9' -and $b8000 -ne 'aa50' -and $b10000 -ne 'e9') {
			$result = "NON_ESP_OR_UNKNOWN"
		}

		return [pscustomobject]@{
			Path           = $Path
			B0             = $b0
			B1000          = $b1000
			B8000          = $b8000
			B10000         = $b10000
			Classification = $result
		}
	}
	finally {
		$fs.Dispose()
	}
}

function Get-EspFlashStrategy {
	param(
		[Parameter(Mandatory)][string]$Path
	)

	$class = Get-EspBinClassification -Path $Path
	$baseName = Split-Path -Path $Path -Leaf
	$fileNameMode = Get-EspFileNameMode -Name $baseName

	$classifiedMode = switch ($class.Classification) {
		'LIKELY_MERGED' { 'install' }
		'MULTI_IMAGE_NO_PARTITION_TABLE' { 'update' }
		'LIKELY_SINGLE' { 'update' }
		'DATA_IMAGE' { 'data' }
		'NON_ESP_OR_UNKNOWN' { 'unknown' }
		default { 'unknown' }
	}

	$selectedMode = if ($classifiedMode -in @('install', 'update')) { $classifiedMode } else { $fileNameMode }

	return [pscustomobject]@{
		Path           = $Path
		FileNameMode   = $fileNameMode
		ClassifiedMode = $classifiedMode
		SelectedMode   = $selectedMode
		Classification = $class.Classification
		Markers        = $class
	}
}

function Install-SimpleMergedEspImage {
	param(
        [Parameter(Mandatory)][string]$ImagePath,
        [Parameter(Mandatory)][string]$ComPort
    )

	$destFolder = Split-Path $ImagePath -Parent
	Push-Location $destFolder
	try {
		if (-not (Test-Path $ImagePath)) {
			throw "File does not exist: $ImagePath"
		}

		$ESPTOOL_CMD = get_esptool_cmd
		$EraseFlashCommand = $script:ESPTOOL_ERASE_FLASH
		$WriteFlashCommand = $script:ESPTOOL_WRITE_FLASH

		Write-Host ""
		Write-Host ""
		Write-Host ""
		Write-Host "Setting baud to 1200 for firmware update mode. $ESPTOOL_CMD --baud 1200 --port $ComPort chip_id"
		$null = run_cmd "$ESPTOOL_CMD --baud 1200 --port $ComPort chip_id"
		Start-Sleep -Seconds 1
		$devicesAfter = getUSBComPort -SkipInfo
		$selectedComPortPart2 = $devicesAfter[0]

		Write-Host "Erasing the flash."
		Write-Host "$ESPTOOL_CMD --baud 115200 --port $selectedComPortPart2 $EraseFlashCommand"
		run_cmd "$ESPTOOL_CMD --baud 115200 --port $selectedComPortPart2 $EraseFlashCommand" -Stream

		Write-Host ""
		Write-Host "Flashing $ImagePath at 0x00. Write merged firmware image."
		Write-Host "$ESPTOOL_CMD --baud 115200 --port $selectedComPortPart2 $WriteFlashCommand 0x00 $ImagePath"
		Write-Host ""
		run_cmd "$ESPTOOL_CMD --baud 115200 --port $selectedComPortPart2 $WriteFlashCommand 0x00 $ImagePath" -Stream

		Write-Host ""
		return $true
	}
	finally {
		Pop-Location
	}
}

function installFlashViaEspTool {
	param(
        [Parameter(Mandatory)][pscustomobject]$hw 
    )
	
	$SelectedFirmwareFile = $hw.FirmwareFile
	$selectedComPort = $hw.ComPort
	$fi = Get-Item $SelectedFirmwareFile
	$baseName = $fi.Name
	$destFolder = Split-Path $SelectedFirmwareFile -Parent

	# Support both modern metadata-driven images and legacy bleota-based layouts.
	$progName = $baseName -replace '\.factory\.bin$', '' -replace '\.bin$', ''
	$metadataFile = Join-Path $destFolder "$progName.mt.json"
	$metadata = $null
	if (Test-Path $metadataFile) {
		try {
			$metadata = Get-Content -Path $metadataFile -Raw | ConvertFrom-Json
		}
		catch {
			Write-Warning "Could not parse metadata file: $metadataFile"
			Write-Warning $_.Exception.Message
			Write-Warning "Falling back to legacy OTA naming."
		}
	}

	$installImage = $SelectedFirmwareFile
	if ($baseName -notlike '*.factory.bin') {
		$factoryCandidate = Join-Path $destFolder "$progName.factory.bin"
		if (Test-Path $factoryCandidate) {
			$installImage = $factoryCandidate
		}
	}

	$OTA_OFFSET = '0x260000'
	$SPIFFS_OFFSET = '0x300000'
	if ($hw.FlashSize -eq '8MB') {
		$OTA_OFFSET = '0x340000'
		$SPIFFS_OFFSET = '0x670000'
	}
	elseif ($hw.FlashSize -eq '16MB') {
		$OTA_OFFSET = '0x650000'
		$SPIFFS_OFFSET = '0xc90000'
	}

	if ($metadata) {
		$metaOtaOffset = (($metadata.part | Where-Object { $_.subtype -eq 'ota_1' } | Select-Object -First 1).offset)
		if ($metaOtaOffset) { $OTA_OFFSET = $metaOtaOffset }

		$metaSpiffsOffset = (($metadata.part | Where-Object { $_.subtype -eq 'spiffs' } | Select-Object -First 1).offset)
		if ($metaSpiffsOffset) { $SPIFFS_OFFSET = $metaSpiffsOffset }
	}

	$otaCandidates = @()
	if ($metadata) {
		$otaCandidates += @($metadata.files | Where-Object { $_.part_name -eq 'app1' -or $_.name -match '^mt-.*-ota\.bin$' } | Select-Object -ExpandProperty name)
		if ($metadata.mcu) {
			$otaCandidates += "mt-$($metadata.mcu)-ota.bin"
		}
	}
	$archMcu = ($hw.Architecture -replace '[^A-Za-z0-9]', '').ToLower()
	if ($archMcu) {
		$otaCandidates += "mt-$archMcu-ota.bin"
	}
	if ($hw.Architecture -like '*-s3') {
		$otaCandidates += 'bleota-s3.bin'
	}
	if ($hw.Architecture -like '*-c3') {
		$otaCandidates += 'bleota-c3.bin'
	}
	$otaCandidates += 'bleota.bin'

	$existingOtaFile = Get-FirstExistingLocalFileName -Folder $destFolder -Candidates $otaCandidates

	$spiffsCandidates = @()
	if ($metadata) {
		$spiffsCandidates += @($metadata.files | Where-Object { $_.part_name -eq 'spiffs' } | Select-Object -ExpandProperty name)
	}
	$spiffsCandidates += "littlefs-$($progName -replace '^firmware-', '').bin"

	$existingSpiffsFile = Get-FirstExistingLocalFileName -Folder $destFolder -Candidates $spiffsCandidates

	$useCompanionImages = ($null -ne $metadata) -or
		(-not [string]::IsNullOrWhiteSpace($existingOtaFile)) -or
		(-not [string]::IsNullOrWhiteSpace($existingSpiffsFile))
	if (-not $useCompanionImages) {
		return (Install-SimpleMergedEspImage -ImagePath $installImage -ComPort $selectedComPort)
	}

	$OTA_FILENAME = $existingOtaFile
	if (-not $OTA_FILENAME) {
		$OTA_FILENAME = $otaCandidates | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 1
	}

	$SPIFFS_FILENAME = $existingSpiffsFile
	if (-not $SPIFFS_FILENAME) {
		$SPIFFS_FILENAME = $spiffsCandidates | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 1
	}

	$webUiCandidate = $SPIFFS_FILENAME -replace '^littlefs-', 'littlefswebui-'
	if ($baseName -notlike '*-update*' -and $SelectedFirmwareFile -notlike '*-tft-*' -and (Test-Path (Join-Path $destFolder $webUiCandidate))) {
		$choice = Read-Host "`nFlash the Web UI as well?  [Y]es / [N]o (default N)"

		if ($choice -match '^[Yy]') {
			$SPIFFS_FILENAME = $webUiCandidate
		}
	}
	#Write-Host "OTA_OFFSET set to:        $OTA_OFFSET"
	#Write-Host "OTA_FILENAME set to:      $OTA_FILENAME"
	#Write-Host "SPIFFS_OFFSET set to:     $SPIFFS_OFFSET"
	#Write-Host "SPIFFS_FILENAME set to:   $SPIFFS_FILENAME"
	
	Push-Location  $destFolder
	
	foreach ($file in @($installImage, $OTA_FILENAME, $SPIFFS_FILENAME)) {
		if (-not (Test-Path $file)) {
			Write-Warning "File does not exist: $file"
			Write-Warning "Terminating."
			Return $false
		}
	}


	$ESPTOOL_CMD = get_esptool_cmd
	$EraseFlashCommand = $script:ESPTOOL_ERASE_FLASH
	$WriteFlashCommand = $script:ESPTOOL_WRITE_FLASH
		
	
	Write-Host ""
	Write-Host ""
	Write-Host ""
	Write-Host "Setting baud to 1200 for firmware update mode. $ESPTOOL_CMD --baud 1200 --port $selectedComPort chip_id"
	$a = run_cmd "$ESPTOOL_CMD --baud 1200 --port $selectedComPort chip_id"
	Start-Sleep -Seconds 1
	$devicesAfter = getUSBComPort -SkipInfo
	$selectedComPortPart2 = $devicesAfter[0]
	Write-Host "Erasing the flash."
	Write-Host "$ESPTOOL_CMD --baud 115200 --port $selectedComPortPart2 $EraseFlashCommand"
	run_cmd "$ESPTOOL_CMD --baud 115200 --port $selectedComPortPart2 $EraseFlashCommand" -Stream
	Write-Host ""
	Write-Host "Flashing $installImage at 0x00. Write Meshtastic Firmware."
	Write-Host "$ESPTOOL_CMD --baud 115200 --port $selectedComPortPart2 $WriteFlashCommand 0x00 $installImage"
	Write-Host ""
	run_cmd "$ESPTOOL_CMD --baud 115200 --port $selectedComPortPart2 $WriteFlashCommand 0x00 $installImage" -Stream


	Write-Host ""
	Write-Host ""
	Write-Host ""
	Write-Host "Waiting 12 seconds"
	Start-Sleep -Seconds 12
	$devicesAfter = getUSBComPort -SkipInfo
	$selectedComPort = $devicesAfter[0]
	Write-Host "Setting baud to 1200 for firmware update mode. $ESPTOOL_CMD --baud 1200 --port $selectedComPort chip_id"
	$b = run_cmd "$ESPTOOL_CMD --baud 1200 --port $selectedComPort chip_id"
	Start-Sleep -Seconds 1
	Write-Host "Flashing $OTA_FILENAME at $OTA_OFFSET. Write Bluetooth Over The Air Update firmware."
	Write-Host "$ESPTOOL_CMD --baud 115200 --port $selectedComPortPart2 $WriteFlashCommand $OTA_OFFSET $OTA_FILENAME"
	Write-Host ""
	run_cmd "$ESPTOOL_CMD --baud 115200 --port $selectedComPortPart2 $WriteFlashCommand $OTA_OFFSET $OTA_FILENAME" -Stream


	Write-Host ""
	Write-Host ""
	Write-Host ""
	Write-Host "Waiting 12 seconds"
	Start-Sleep -Seconds 12
	Write-Host "Setting baud to 1200 for firmware update mode. $ESPTOOL_CMD --baud 1200 --port $selectedComPort chip_id"
	$c = run_cmd "$ESPTOOL_CMD --baud 1200 --port $selectedComPort chip_id"
	Start-Sleep -Seconds 1
	Write-Host "Flashing $SPIFFS_FILENAME at $SPIFFS_OFFSET. Write Filesystem firmware."
	Write-Host "$ESPTOOL_CMD" "--baud" "115200" "--port" "$selectedComPortPart2" $WriteFlashCommand "$SPIFFS_OFFSET" "$SPIFFS_FILENAME"
	Write-Host ""
	run_cmd "$ESPTOOL_CMD --baud 115200 --port $selectedComPortPart2 $WriteFlashCommand $SPIFFS_OFFSET $SPIFFS_FILENAME" -Stream
	
	
	Write-Host ""
	Pop-Location
	return $true
}


function flashNotESP32mt {
	param(
		[string] $SelectedFirmwareFile,
		[string] $selectedComPort
    )
	
	if ($selectedComPort -ne "NA") {
		Read-Host "Press Enter to put node into Device Firmware Update (DFU) mode via $pythonCommand -m meshtastic --port $selectedComPort --enter-dfu"
		
		$before = Get-PSDrive -PSProvider FileSystem | Select-Object -ExpandProperty Name
		
		$result = runMeshtasticCommand $selectedComPort "--enter-dfu"
		Write-Progress -Activity " " -Status " " -Completed
		$meshtasticOutput = $result[0]
		$meshtasticError  = $result[1]
		Write-Host $meshtasticOutput
		Write-Host $meshtasticError
		
		$endTime = (Get-Date).AddSeconds(15)
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
		if (-not $newDrive.ToString().EndsWith(':')) {
			$newDrive += ':'
		}
		Write-Host "DFU mount is drive `"$newDrive`""
		$dest = Join-Path -Path $newDrive -ChildPath (Split-Path $SelectedFirmwareFile -Leaf)
		# Read-Host "Press Enter Copy the Firmware to $dest"
		Copy-Item -Path $SelectedFirmwareFile -Destination $dest -Force -ErrorAction Stop

		Write-Host "Done." -ForegroundColor Green
	} else {
		Write-Warning "Timed out waiting for DFU drive (no new PSDrive after $timeout seconds)"
	}
}

function Get-NrfutilExecutable {
	$cmd = Get-Command adafruit-nrfutil -ErrorAction SilentlyContinue
	if ($cmd) {
		return $cmd.Source
	}

	try {
		$scriptsDir = (& $pythonCommand -c "import sysconfig; print(sysconfig.get_path('scripts'))" 2>$null | Out-String).Trim()
		if (-not [string]::IsNullOrWhiteSpace($scriptsDir)) {
			foreach ($candidate in @("adafruit-nrfutil.exe", "adafruit-nrfutil")) {
				$fullPath = Join-Path $scriptsDir $candidate
				if (Test-Path $fullPath) {
					return $fullPath
				}
			}
		}
	}
	catch {
	}

	throw "adafruit-nrfutil was not found. Install it with $pythonCommand -m pip install adafruit-nrfutil"
}

function Get-MeshCoreNrf52FlashAction {
	param(
		[Parameter(Mandatory)][pscustomobject]$hw
	)

	$fwType = ([string]$hw.FWType).Trim().ToLowerInvariant()
	switch ($fwType) {
		'flash-wipe'   { return 'flash-wipe' }
		'flash-update' { return 'flash-update' }
	}

	$baseName = Split-Path -Path $hw.FirmwareFile -Leaf
	$lower = $baseName.ToLowerInvariant()
	if ($lower -match '(?:^|[-_.])(freshinstall|factory|wipe)(?:[-_.]|$)') {
		return 'flash-wipe'
	}
	if ($lower -match '(?:^|[-_.])(upgrade|update)(?:[-_.]|$)') {
		return 'flash-update'
	}

	$sel = Prompt-Menu `
		-Title "Choose firmware action for $($hw.HWNameFile) on $($hw.ComPort):" `
		-Options @("flash-update       (write only)", "flash-wipe + flash (erase, then write)") `
		-Prompt "Choice"

	if ($sel.Index -eq 2) {
		return 'flash-wipe'
	}
	return 'flash-update'
}

function Select-MeshCoreEraseUrl {
	param(
		[Parameter(Mandatory)][pscustomobject]$hw
	)

	if (-not [string]::IsNullOrWhiteSpace([string]$hw.EraseUrl)) {
		return [string]$hw.EraseUrl
	}

	$config = Load-JsonFile $CONFIG_FILE
	if (-not $config) {
		throw "ERROR: could not load config: $CONFIG_FILE"
	}

	$pairs = @()
	foreach ($dev in @($config.device)) {
		$erase = [string]$dev.erase
		$name = [string]$dev.name
		if ([string]::IsNullOrWhiteSpace($erase) -or [string]::IsNullOrWhiteSpace($name)) { continue }
		$pairs += [pscustomobject]@{
			Device = $name
			Erase  = $erase
		}
	}
	$pairs = @($pairs | Sort-Object Device, Erase -Unique)
	if ($pairs.Count -eq 0) {
		throw "No erase packages were found in $CONFIG_FILE"
	}

	$options = @($pairs | ForEach-Object { "{0}    {1}" -f $_.Device, $_.Erase })
	$sel = Prompt-Menu -Title "Select erase package:" -Options $options -Prompt "Choice"
	$eraseValue = [string]$pairs[$sel.Index - 1].Erase
	if ($eraseValue -match '^\s*https?://') {
		return $eraseValue
	}
	return "https://flasher.meshcore.dev/firmware/$eraseValue"
}

function Get-AvailableComPorts {
	$ports = [System.IO.Ports.SerialPort]::GetPortNames()
	return @($ports | Sort-Object { [int](($_ -replace '^[^\d]*','')) })
}

function Touch-ComPort1200 {
	param(
		[Parameter(Mandatory)][string]$ComPort
	)

	try {
		$sp = New-Object System.IO.Ports.SerialPort $ComPort, 1200, "None", 8, "One"
		$sp.ReadTimeout = 300
		$sp.WriteTimeout = 300
		$sp.Handshake = [System.IO.Ports.Handshake]::None
		$sp.DtrEnable = $false
		$sp.RtsEnable = $false
		try {
			$sp.Open()
			Start-Sleep -Milliseconds 150
		}
		finally {
			if ($sp -and $sp.IsOpen) {
				$sp.Close()
			}
			if ($sp) {
				$sp.Dispose()
			}
		}
	}
	catch {
		$fallbackScript = Join-Path $ScriptPath "nrf52.py"
		if (Test-Path $fallbackScript) {
			Write-Warning "Direct 1200-baud touch on $ComPort failed; trying python fallback."
			$proc = Start-Process -FilePath $pythonCommand -ArgumentList @($fallbackScript, $ComPort) -NoNewWindow -Wait -PassThru
			if ($proc.ExitCode -ne 0) {
				Write-Warning "Python fallback touch failed on $ComPort with exit code $($proc.ExitCode)."
			}
		}
		else {
			Write-Warning "1200-baud touch on $ComPort failed: $($_.Exception.Message)"
		}
	}

	Start-Sleep -Milliseconds 1500
}

function Resolve-Nrf52DfuComPort {
	param(
		[string]$PreferredComPort,
		[string]$TouchComPort = "",
		[int]$TimeoutSec = 15
	)

	$before = Get-AvailableComPorts
	$requestedTouch = -not [string]::IsNullOrWhiteSpace($TouchComPort)
	$sawTouchPortDisappear = $false
	$lastObservedPorts = $before
	if ($requestedTouch -and ($before -contains $TouchComPort)) {
		Write-Host "Putting device into DFU mode via 1200 baud touch on $TouchComPort"
		Touch-ComPort1200 -ComPort $TouchComPort
	}
	elseif ($requestedTouch) {
		Write-Warning "Runtime COM port $TouchComPort was not present before DFU touch; watching for DFU port anyway."
	}

	$deadline = (Get-Date).AddSeconds($TimeoutSec)
	while ((Get-Date) -lt $deadline) {
		$current = Get-AvailableComPorts
		$lastObservedPorts = $current
		$newPorts = @($current | Where-Object { $_ -notin $before })
		if ($requestedTouch -and ($current -notcontains $TouchComPort)) {
			$sawTouchPortDisappear = $true
		}

		if ($newPorts.Count -eq 1) {
			return $newPorts[0]
		}
		if ($newPorts.Count -gt 1) {
			return ($newPorts | Sort-Object { [int](($_ -replace '^[^\d]*','')) } | Select-Object -Last 1)
		}

		if ($requestedTouch) {
			if ($sawTouchPortDisappear -and ($current -contains $TouchComPort)) {
				return $TouchComPort
			}
			if ($current.Count -eq 1 -and $current[0] -ne $TouchComPort) {
				return $current[0]
			}
		}
		else {
			if (-not [string]::IsNullOrWhiteSpace($PreferredComPort) -and ($current -contains $PreferredComPort)) {
				return $PreferredComPort
			}
			if ([string]::IsNullOrWhiteSpace($PreferredComPort) -and $current.Count -eq 1) {
				return $current[0]
			}
		}

		Start-Sleep -Milliseconds 300
	}

	if ($requestedTouch) {
		$current = Get-AvailableComPorts
		$lastObservedPorts = $current
		if ($sawTouchPortDisappear -and ($current -contains $TouchComPort)) {
			return $TouchComPort
		}
		if ($current -contains $TouchComPort) {
			Write-Warning "DFU port did not enumerate on a new COM number; retrying on the original COM port $TouchComPort."
			return $TouchComPort
		}
		if ($current.Count -eq 1) {
			return $current[0]
		}
	}

	$observed = if ($lastObservedPorts.Count -gt 0) { $lastObservedPorts -join ', ' } else { '<none>' }
	Write-Warning "Observed COM ports while waiting for DFU: $observed"
	return ""
}

function Get-NrfutilUploadSteps {
	param(
		[Parameter(Mandatory)][string]$PackageFile
	)

	try {
		Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
		$archive = [System.IO.Compression.ZipFile]::OpenRead($PackageFile)
		try {
			$totalSteps = 0
			foreach ($entry in $archive.Entries) {
				if ($entry.FullName -match '(?i)\.bin$') {
					$totalSteps += [int][Math]::Ceiling([double]$entry.Length / 512.0)
				}
			}
			return $totalSteps
		}
		finally {
			$archive.Dispose()
		}
	}
	catch {
		return 0
	}
}

function Invoke-NrfutilSerialDfu {
	param(
		[Parameter(Mandatory)][string]$PackageFile,
		[Parameter(Mandatory)][string]$ComPort,
		[string]$TouchComPort = "",
		[int]$TimeoutSec = 15,
		[string]$ProgressActivity = "nRF52 DFU"
	)

	if (-not (Test-Path $PackageFile)) {
		throw "Package file does not exist: $PackageFile"
	}

	$nrfutilExe = Get-NrfutilExecutable
	$dfuComPort = Resolve-Nrf52DfuComPort -PreferredComPort $ComPort -TouchComPort $TouchComPort -TimeoutSec $TimeoutSec
	if ([string]::IsNullOrWhiteSpace($dfuComPort)) {
		throw "Could not find a DFU serial port after requesting bootloader mode. Last known runtime port: $TouchComPort"
	}

	$args = @(
		'dfu', 'serial',
		'--package', $PackageFile,
		'-p', $dfuComPort,
		'-b', '115200'
	)

	Write-Host "$nrfutilExe $($args -join ' ')"
	$totalSteps = Get-NrfutilUploadSteps -PackageFile $PackageFile
	$progressId = 44
	$progressStatus = "Opening DFU transport on $dfuComPort"
	$hashCount = 0
	$outputBuffer = New-Object System.Text.StringBuilder
	$lineBuffer = New-Object System.Text.StringBuilder

	function ConvertTo-ProcessArgumentString {
		param([string[]]$Values)

		$quoted = foreach ($value in $Values) {
			if ($null -eq $value) { continue }

			$text = [string]$value
			if ($text -notmatch '[\s"]') {
				$text
				continue
			}

			$escaped = $text -replace '(\\*)"', '$1$1\"'
			$escaped = $escaped -replace '(\\+)$', '$1$1'
			'"{0}"' -f $escaped
		}

		return ($quoted -join ' ')
	}

	function Flush-NrfutilLine {
		param([string]$Line)

		if ($null -eq $Line) { return }
		$trimmed = $Line.Trim()
		if (-not $trimmed) { return }
		if ($trimmed -match '^[#\s]+$') { return }

		if ($trimmed -match '^Upgrading target on ') {
			Set-Variable -Name progressStatus -Scope 1 -Value $trimmed
			if ($totalSteps -gt 0) {
				Write-Progress -Id $progressId -Activity $progressActivity -Status $progressStatus -PercentComplete 0
			}
			else {
				Write-Progress -Id $progressId -Activity $progressActivity -Status $progressStatus
			}
			return
		}

		if ($trimmed -match '^Activating new firmware') {
			Set-Variable -Name progressStatus -Scope 1 -Value $trimmed
			if ($totalSteps -gt 0) {
				Write-Progress -Id $progressId -Activity $progressActivity -Status $progressStatus -PercentComplete 99
			}
			else {
				Write-Progress -Id $progressId -Activity $progressActivity -Status $progressStatus
			}
			Write-Host $trimmed
			return
		}

		if ($trimmed -match '^Device programmed\.') {
			Set-Variable -Name progressStatus -Scope 1 -Value $trimmed
			if ($totalSteps -gt 0) {
				Write-Progress -Id $progressId -Activity $progressActivity -Status $progressStatus -PercentComplete 100
			}
			else {
				Write-Progress -Id $progressId -Activity $progressActivity -Status $progressStatus
			}
			Write-Host $trimmed
			return
		}

		Write-Host $trimmed
	}

	function Add-NrfutilChars {
		param([string]$Chunk)

		if ([string]::IsNullOrEmpty($Chunk)) { return }
		[void]$outputBuffer.Append($Chunk)

		foreach ($ch in $Chunk.ToCharArray()) {
			switch ($ch) {
				"#" {
					$hashCount++
					if ($totalSteps -gt 0) {
						$pct = [Math]::Min(99, [int](($hashCount * 100) / [Math]::Max(1, $totalSteps)))
						Write-Progress -Id $progressId -Activity $progressActivity -Status "$progressStatus ($hashCount/$totalSteps)" -PercentComplete $pct
					}
				}
				"`r" { }
				"`n" {
					$line = $lineBuffer.ToString()
					$lineBuffer.Clear() | Out-Null
					Flush-NrfutilLine $line
				}
				default {
					[void]$lineBuffer.Append($ch)
				}
			}
		}
	}

	$psi = New-Object System.Diagnostics.ProcessStartInfo
	$psi.FileName = $nrfutilExe
	$psi.UseShellExecute = $false
	$psi.RedirectStandardOutput = $true
	$psi.RedirectStandardError = $true
	$psi.CreateNoWindow = $true
	if ($psi.PSObject.Properties.Name -contains 'ArgumentList' -and $null -ne $psi.ArgumentList) {
		foreach ($arg in $args) {
			[void]$psi.ArgumentList.Add($arg)
		}
	}
	else {
		$psi.Arguments = ConvertTo-ProcessArgumentString -Values $args
	}

	$proc = New-Object System.Diagnostics.Process
	$proc.StartInfo = $psi

	Write-Progress -Id $progressId -Activity $progressActivity -Status $progressStatus -PercentComplete 0
	$null = $proc.Start()
	try {
		while (-not $proc.HasExited -or $proc.StandardOutput.Peek() -ge 0 -or $proc.StandardError.Peek() -ge 0) {
			$hadData = $false

			while ($proc.StandardOutput.Peek() -ge 0) {
				$chunk = [string][char]$proc.StandardOutput.Read()
				$hadData = $true
				Add-NrfutilChars $chunk
			}

			while ($proc.StandardError.Peek() -ge 0) {
				$chunk = [string][char]$proc.StandardError.Read()
				$hadData = $true
				Add-NrfutilChars $chunk
			}

			if (-not $hadData) {
				Start-Sleep -Milliseconds 25
			}
		}

		$proc.WaitForExit()
	}
	finally {
		Write-Progress -Id $progressId -Activity $progressActivity -Completed
	}

	if ($lineBuffer.Length -gt 0) {
		Flush-NrfutilLine $lineBuffer.ToString()
		$lineBuffer.Clear() | Out-Null
	}

	$outputText = $outputBuffer.ToString()
	$exitCode = $proc.ExitCode
	if ($exitCode -ne 0 -or
		$outputText -match '(?im)^Failed to upgrade target\.' -or
		$outputText -match '(?im)NordicSemiException' -or
		$outputText -match '(?im)^Traceback ') {
		throw "adafruit-nrfutil failed on $dfuComPort. ExitCode=$exitCode"
	}

	return [pscustomobject]@{
		Success = $true
		ComPort = $dfuComPort
	}
}

function flashMeshCoreNrf52 {
	param(
		[Parameter(Mandatory)][pscustomobject]$hw
	)

	$selectedFirmwareFile = $hw.FirmwareFile
	$selectedComPort = $hw.ComPort
	if (-not (Test-Path $selectedFirmwareFile)) {
		throw "Firmware file does not exist: $selectedFirmwareFile"
	}

	if ((Split-Path -Path $selectedFirmwareFile -Leaf).ToLowerInvariant().EndsWith('.zip') -eq $false) {
		throw "MeshCore nRF52 flashing expects a .zip package: $selectedFirmwareFile"
	}

	$action = Get-MeshCoreNrf52FlashAction -hw $hw
	Write-Host "Running $action..."
	$runtimeComPort = $selectedComPort
	$dfuComPort = $selectedComPort

	if ($action -eq 'flash-wipe') {
		$eraseUrl = Select-MeshCoreEraseUrl -hw $hw
		$eraseFile = Resolve-MeshCoreFirmwareFile -SelectedReference $eraseUrl -CacheFile $ERASE_FILE_FILE
		Write-Host "Erasing UF2 area using $eraseFile"
		Start-Sleep -Seconds 1
		$eraseResult = Invoke-NrfutilSerialDfu -PackageFile $eraseFile -ComPort $dfuComPort -TouchComPort $runtimeComPort -ProgressActivity "nRF52 Erase"
		$dfuComPort = $eraseResult.ComPort
		Write-Host "Erase done."
		Write-Host ""
	}

	Write-Host "Flashing firmware file $selectedFirmwareFile"
	Start-Sleep -Seconds 1
	$flashResult = Invoke-NrfutilSerialDfu -PackageFile $selectedFirmwareFile -ComPort $dfuComPort -TouchComPort $(if ($action -eq 'flash-update') { $runtimeComPort } else { "" }) -ProgressActivity "nRF52 Flash"
	if ($flashResult.ComPort) {
		$hw.ComPort = $flashResult.ComPort
	}
	return $true
}


function InvokeFlash {
    param(
        [Parameter(Mandatory)][pscustomobject]$hw      # must expose Architecture, SelectedFirmwareFile, selectedComPort/Drive
    )
	Write-Progress -Activity " " -Status " " -Completed

	try {
		$result = $null
		if ($hw.Architecture -like '*esp32*') {
			$result = flashESP32 -hw $hw
		}
		elseif ($hw.Project -eq "MeshCore" -and $hw.Architecture -like '*nrf52*') {
			$result = flashMeshCoreNrf52 -hw $hw
		}
		else {
			$result = flashNotESP32mt -SelectedFirmwareFile $hw.FirmwareFile -selectedComPort $hw.ComPort
		}

		if ($false -eq $result) {
			return $false
		}

		Write-Host "Flash completed."
	}
	catch {
		Write-Warning "Flash failed: $_"
		return $false
	}
	Write-Host ""
	return ""
}


# Get release info
check_requirements
$hw = GetHW

$again = $true
while ($again) {
	$x = InvokeFlash $hw
	
	if ($hw.Architecture -like 'esp32*' -or ($hw.Project -eq "MeshCore" -and $hw.Architecture -like 'nrf52*')) {
		$choice = Read-Host "`nEverything OK?  [Y]es / [R]etry / change [C]OM port / [E]xit"
		switch ($choice.ToUpper()) {
			'Y' { $again = $false }
			'R' { }                             # loop again with same port
			'C' { 
				getallUSBCom | Write-Host
			
				$hw.ComPort = Read-Host 'Enter new COM port (e.g. COM7)'; 
			}
			default { $again = $false }
		}
	}
	else {
		$choice = Read-Host "`nEverything OK?  [Y]es / [R]etry / change drive [D]letter / [E]xit"
		switch ($choice.ToUpper()) {
			'Y' { $again = $false }
			'R' { }                             # loop again with same drive
			'D' { 
				GetModelFromNode | Write-Host
						
				$hw.ComPort = Read-Host 'Enter new drive letter (e.g. E:)\'; 
			}
			default { $again = $false }
		}
	}
}

   
# When the user finally hits Enter, the script will exit naturally.
$scriptOver = $true
Read-Host 'Press Enter to exit (via end of script)'
