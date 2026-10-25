# Exercise the real firmware selection functions without USB, network or cache writes.
$ErrorActionPreference = 'Stop'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    (Join-Path (Split-Path $PSScriptRoot -Parent) 'firmware.cmd'),
    [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw "firmware.cmd parse failed: $parseErrors" }
foreach ($name in @('Normalize-Id', 'Contains-Word', 'Is-GoodTail', 'Pick-MatchingDevice', 'ChooseMeshCoreFirmware')) {
    $definition = $ast.Find({ param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
    }, $true)
    if ($null -eq $definition) { throw "Missing function: $name" }
    Invoke-Expression $definition.Extent.Text
}

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

$devices = @('Heltec v4', 'UnitEng Station G2', 'UnitEng Station G3 ESP32')
# Match defaults must work even when the caller has no vendor/radio variables.
$g3 = Pick-MatchingDevice -UsbString 'Station G3 ESP32' -Devices $devices
Assert-True ($g3.Match -eq $devices[2] -and $g3.MatchIdx -eq 3) 'Default matching did not select the G3.'
$g2 = Pick-MatchingDevice -UsbString 'Station G2' -Devices $devices
Assert-True ($g2.Match -eq $devices[1] -and $g2.MatchIdx -eq 2) 'G2 matching changed.'
foreach ($lists in @(
    @{ VENDORLIST = ''; RADIOLIST = '' },
    @{ VENDORLIST = 'uniteng'; RADIOLIST = 'sx1262' }
)) {
    $matched = Pick-MatchingDevice -UsbString 'Station G3 ESP32' -Devices $devices @lists
    Assert-True ($matched.Match -eq $devices[2] -and $matched.MatchIdx -eq 3) 'Empty or explicit matching lists lost the G3.'
}
$unknown = Pick-MatchingDevice -UsbString 'USB Serial Device' -Devices $devices
Assert-True ($null -eq $unknown) 'A generic serial label selected a board.'

# Stop at the real firmware menu before role selection, downloads or flashing.
$DEFAULT_CONFIG_FILE = 'fixture-config'
$CONFIG_SOURCE_FILE = 'fixture-source'
$SELECTED_DEVICE_FILE = 'fixture-device'
$ARCHITECTURE_FILE = 'fixture-architecture'
$ERASE_URL_FILE = 'fixture-erase'
$SELECTED_ROLE_FILE = 'fixture-role'
$SELECTED_TITLE_FILE = 'fixture-title'
$SELECTED_SUBTITLE_FILE = 'fixture-subtitle'
$SELECTED_VERSION_FILE = 'fixture-version'
$SELECTED_TYPE_FILE = 'fixture-type'
$AUTODETECT_DEVICE_FILE = 'fixture-auto'
function Test-Path { param($Path) return $false }
function Remove-Item { param($Path, [switch]$Force, $ErrorAction) }
function UpdateMTAllCaches { return $true }
function Load-JsonFile {
    param($Path)
    return [pscustomobject]@{ device = @($devices | ForEach-Object { [pscustomobject]@{ name = $_ } }) }
}
function Read-TextFileIfExists {
    param($Path)
    if ($Path -eq $AUTODETECT_DEVICE_FILE) { return 'Station G3 ESP32' }
    return ''
}
function Write-DetectedMeshCoreIdentity {}
function Read-Host {
    param($Prompt)
    $script:MatchingPrompts += [string]$Prompt
    if ($script:RetryAuto -and $script:MatchingPrompts.Count -eq 1) { return '0' }
    throw 'fixture-menu-reached'
}
foreach ($retry in @($false, $true)) {
    $script:RetryAuto = $retry
    $script:MatchingPrompts = @()
    # Reproduce the previously undefined values even if the test's caller sets them.
    $VENDORLIST = ''
    $RADIOLIST = ''
    try {
        ChooseMeshCoreFirmware ([pscustomobject]@{
            ComPort = 'COM8'; DetectedBoard = 'Station G3 ESP32'
            DetectedVersion = 'v1.17.1.9-halo-keymind-cascade-dev-88c85108'
        })
        throw 'Firmware selection unexpectedly passed the test menu.'
    } catch {
        if ($_.Exception.Message -ne 'fixture-menu-reached') { throw }
    }
    Assert-True ($script:MatchingPrompts.Count -eq $(if ($retry) { 2 } else { 1 })) 'Auto-detect retry did not reach the menu.'
    foreach ($prompt in $script:MatchingPrompts) {
        Assert-True ($prompt -match 'Detected UnitEng Station G3 ESP32 on COM8, Enter will pick 3') 'The menu did not offer the detected G3.'
    }
}
Write-Host 'PASS Windows device matching defaults, G3 firmware menu, and auto-detect retry'
