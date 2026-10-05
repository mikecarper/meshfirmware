# Inventory orchestration tests: every USB device and probe result is a fixture.
$ErrorActionPreference = 'Stop'
$tokens = $null
$parseErrors = $null
$firmwareAst = [System.Management.Automation.Language.Parser]::ParseFile(
    (Join-Path (Split-Path $PSScriptRoot -Parent) 'firmware.cmd'),
    [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw "firmware.cmd parse failed: $parseErrors" }
function Assert-True { param([bool]$Condition, [string]$Message); if (-not $Condition) { throw $Message } }
function Assert-Equal {
    param($Expected, $Actual, [string]$Message)
    if ($Expected -ne $Actual) { throw "$Message Expected '$Expected', got '$Actual'." }
}
foreach ($name in @('getUsbComDevices', 'getUSBComPort', 'Get-UsbIdentityInterfaceNumber', 'Test-UsbComPortIdentityMatch')) {
    $definition = $firmwareAst.Find({ param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
    }, $true)
    if ($null -eq $definition) { throw "Missing function under test: $name" }
    Invoke-Expression $definition.Extent.Text
}
function New-Identity {
    param([string]$Serial, [string]$Interface = '00')
    return [pscustomobject]@{
        SerialNumber = $Serial; LocationPath = "ROOT#USB($Serial)"
        ParentInstanceId = "USB\VID_239A&PID_8029\$Serial"
        BusReportedDescription = 'MeshCore Full Companion'; InterfaceNumber = $Interface
    }
}
function New-Device {
    param([string]$Port)
    return [pscustomobject]@{
        drive_letter = $Port; device_name = "fixture $Port"
        friendly_name = "USB Serial Device ($Port)"; firmware_revision = '--'
    }
}
function New-NodeInfo {
    param([string]$Port, [string]$Project = 'MeshCore', [string]$State = 'identified')
    return [pscustomobject]@{
        Success = ($State -eq 'identified'); ComPort = $Port; Project = $Project; ProbeState = $State
        HWName = "board $Port"; FWVersion = 'v1.18.0.1'; ExtraInfo = ''
    }
}
function Reset-InventoryFixture {
    $script:fixtureDevices = @()
    $script:fixtureIdentities = @{}
    $script:fixtureResults = @{}
    $script:fixtureBatches = New-Object 'System.Collections.Generic.List[object]'
    $script:fixtureHintSaves = New-Object 'System.Collections.Generic.List[string]'
    $script:fixtureLegacyPorts = New-Object 'System.Collections.Generic.List[string]'
    $script:fixtureWaits = 0
    $script:fixtureIdentityReads = 0
    $script:fixtureHintLoads = 0
    $script:fixtureSelectedPort = 'COM7'
}
function Test-IsWindowsHost { return $true }
function Wait-FirmwareToolUpdates { $script:fixtureWaits++ }
function Exit-FirmwareToolUse { }
function getallUSBCom { return $script:fixtureDevices }
function Get-UsbComPortIdentity {
    param($ComPort, $PnpDevice)
    $script:fixtureIdentityReads++
    return $script:fixtureIdentities[$ComPort]
}
function Get-FirmwareProbeOrder {
    param($UsbIdentity)
    Assert-True ($null -eq $UsbIdentity) 'Inventory did not initialize cached hints before launching workers.'
    $script:fixtureHintLoads++
    return @('MeshCore', 'Meshtastic')
}
function Save-FirmwareProbeHint {
    param($UsbIdentity, $Project)
    $script:fixtureHintSaves.Add([string]$UsbIdentity.SerialNumber)
}
function Invoke-UsbNodeProbes {
    param([psobject[]]$Devices, [switch]$QuickOnly)
    Assert-True ([bool]$QuickOnly) 'Initial inventory allowed slow compatibility probes on every device.'
    $script:fixtureBatches.Add([object]@($Devices))
    $results = @{}
    foreach ($device in $Devices) { $results[$device.ComPort] = $script:fixtureResults[$device.ComPort] }
    return $results
}
function selectUSBCom {
    param($availableComPorts)
    Assert-True ($script:fixtureSelectedPort -in $availableComPorts) 'Selection fixture requested an absent COM.'
    return $script:fixtureSelectedPort
}
function Get-UsbNodeInfo {
    param($ComPort, $UsbIdentity, [switch]$QuickOnly)
    Assert-True (-not $QuickOnly) 'Selected legacy fallback was still restricted to quick detection.'
    $script:fixtureLegacyPorts.Add($ComPort)
    return New-NodeInfo -Port $ComPort
}

Reset-InventoryFixture
$script:fixtureDevices = @((New-Device COM9), (New-Device COM7))
$script:fixtureIdentities = @{ COM9 = (New-Identity radioA); COM7 = (New-Identity radioB) }
$script:fixtureResults = @{ COM9 = (New-NodeInfo COM9); COM7 = (New-NodeInfo COM7 Meshtastic) }
$rows = @(getUsbComDevices)
Assert-Equal 2 $rows.Count 'Independent radios were lost from inventory.'
Assert-Equal 1 $script:fixtureBatches.Count 'Independent radios were split into sequential probe batches.'
Assert-Equal 2 $script:fixtureBatches[0].Count 'Independent radios were not submitted together.'
Assert-Equal 1 $script:fixtureHintLoads 'Protocol-order cache was loaded more than once per inventory.'

Reset-InventoryFixture
$script:fixtureDevices = @((New-Device COM9), (New-Device COM11), (New-Device COM7))
$script:fixtureIdentities = @{
    COM9 = (New-Identity radioA '00'); COM11 = (New-Identity radioA '01'); COM7 = (New-Identity radioB)
}
$script:fixtureResults = @{ COM9 = (New-NodeInfo COM9); COM11 = (New-NodeInfo COM11); COM7 = (New-NodeInfo COM7) }
$rows = @(getUsbComDevices)
Assert-Equal 2 $script:fixtureBatches.Count 'Same-radio interfaces were not separated into sequential batches.'
foreach ($batch in $script:fixtureBatches) {
    $serials = @($batch | ForEach-Object { $_.UsbIdentity.SerialNumber })
    Assert-Equal $serials.Count (@($serials | Select-Object -Unique)).Count `
        'Two interfaces of the same physical radio were probed concurrently.'
}
Assert-Equal 3 $rows.Count 'Separating sibling interfaces removed an inventory row.'

# The logging COM is deliberately lower and first in enumeration. Only a
# confirmed MeshCore primary can justify omitting the output-only sibling.
Reset-InventoryFixture
$script:fixtureDevices = @((New-Device COM3), (New-Device COM9))
$script:fixtureIdentities = @{ COM3 = (New-Identity radioA '02'); COM9 = (New-Identity radioA '00') }
$script:fixtureResults = @{ COM9 = (New-NodeInfo COM9) }
$rows = @(getUsbComDevices)
$probedPorts = @($script:fixtureBatches | ForEach-Object { $_ | ForEach-Object { $_.ComPort } })
Assert-Equal 1 $probedPorts.Count 'Confirmed logging interface received a protocol probe.'
Assert-Equal 'COM9' $probedPorts[0] 'Lower logging COM was probed before the primary.'
$loggingRow = $rows | Where-Object ComPort -eq COM3
Assert-Equal 'MeshCore' $loggingRow.Project 'Logging interface did not inherit the primary firmware identity.'
Assert-Equal 'board COM9' $loggingRow.DeviceName 'Logging interface lost the primary board name.'
Assert-True ($loggingRow.ExtraInfo -match 'COM9' -and $loggingRow.ExtraInfo -match 'interface 02') `
    'Logging row did not explain which primary interface handles flashing.'

Reset-InventoryFixture
$script:fixtureDevices = @((New-Device COM3), (New-Device COM9))
$script:fixtureIdentities = @{ COM3 = (New-Identity radioC '02'); COM9 = (New-Identity radioA '00') }
$script:fixtureResults = @{ COM3 = (New-NodeInfo COM3 Meshtastic); COM9 = (New-NodeInfo COM9) }
$rows = @(getUsbComDevices)
$probedPorts = @($script:fixtureBatches | ForEach-Object { $_ | ForEach-Object { $_.ComPort } })
Assert-True ('COM3' -in $probedPorts) 'Unmatched interface 02 was incorrectly assumed to be a MeshCore logging port.'
Assert-Equal 'Meshtastic' ($rows | Where-Object ComPort -eq COM3).Project 'Unmatched secondary lost its actual detected firmware.'

Reset-InventoryFixture
$script:fixtureDevices = @((New-Device COM3), (New-Device COM9))
$script:fixtureIdentities = @{ COM3 = (New-Identity radioA '02'); COM9 = (New-Identity radioA '00') }
$script:fixtureResults = @{ COM3 = (New-NodeInfo COM3 '' unknown); COM9 = (New-NodeInfo COM9 '' unknown) }
$rows = @(getUsbComDevices)
$probedPorts = @($script:fixtureBatches | ForEach-Object { $_ | ForEach-Object { $_.ComPort } })
Assert-Equal 2 $probedPorts.Count 'Unknown primary caused its secondary to be skipped from descriptors alone.'
Assert-Equal 0 $script:fixtureHintSaves.Count 'Unconfirmed firmware identity was saved as a cached hint.'

Reset-InventoryFixture
$script:fixtureDevices = @((New-Device COM9), (New-Device COM7))
$rows = @(getUsbComDevices -SkipInfo)
Assert-Equal 2 $rows.Count 'Presence-only inventory lost serial ports.'
Assert-Equal 0 $script:fixtureBatches.Count 'Presence-only inventory attempted a serial handshake.'
Assert-Equal 0 $script:fixtureIdentityReads 'Presence-only inventory did costly USB descriptor queries.'
Assert-Equal 0 $script:fixtureHintLoads 'Presence-only inventory loaded protocol-order cache.'
Assert-Equal 0 $script:fixtureWaits 'Presence-only inventory waited for package updates.'

# Compatibility probing applies only to the user's chosen silent radio.
Reset-InventoryFixture
$script:fixtureDevices = @((New-Device COM9), (New-Device COM7))
$script:fixtureIdentities = @{ COM9 = (New-Identity radioA); COM7 = (New-Identity radioB) }
$script:fixtureResults = @{ COM9 = (New-NodeInfo COM9 '' unknown); COM7 = (New-NodeInfo COM7 '' unknown) }
$selection = getUSBComPort
Assert-Equal 1 $script:fixtureLegacyPorts.Count 'Selecting one unknown radio probed unrelated radios with the legacy detector.'
Assert-Equal COM7 $script:fixtureLegacyPorts[0] 'Legacy detector targeted the wrong selected port.'
Assert-Equal MeshCore $selection[4] 'Selected legacy firmware identity did not reach the firmware menu.'
Assert-Equal Unknown ($selection[3] | Where-Object ComPort -eq COM9).Project 'Selected fallback changed the unselected radio identity.'

foreach ($state in @('busy', 'unavailable', 'dfu')) {
    Reset-InventoryFixture
    $script:fixtureDevices = @((New-Device COM7))
    $script:fixtureIdentities = @{ COM7 = (New-Identity radioB) }
    $script:fixtureResults = @{ COM7 = (New-NodeInfo COM7 '' $state) }
    $null = getUSBComPort
    Assert-Equal 0 $script:fixtureLegacyPorts.Count "Selecting a $state radio caused a futile legacy probe."
}
Write-Host 'PASS: concurrent physical radios, serialized sibling interfaces, logging skip, fast inventory, and selected-port fallback.'
