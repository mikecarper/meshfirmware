# Hardware-free notices only: all serial, package, prompt and sleep calls mocked.
$ErrorActionPreference = 'Stop'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    (Join-Path (Split-Path $PSScriptRoot -Parent) 'firmware.cmd'), [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw "firmware.cmd parse failed: $parseErrors" }
foreach ($name in @('Get-MeshCoreBluetoothUsbNotice', 'flashMeshCoreNrf52')) {
    $definition = $ast.Find({ param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
    }, $true)
    if (-not $definition) { throw "Missing $name" }
    Invoke-Expression $definition.Extent.Text
}
function Assert-True($Condition, $Message) { if (-not $Condition) { throw $Message } }
$device = 'Seeed Studio SenseCAP T1000-E'
$file = 't1000e_companion_radio_full-v1.18.0.1-halo-keymind-cascade-dev-12345678.zip'
foreach ($alias in @($device, 'Seeed Tracker T1000-E', 'T1000-E')) {
    foreach ($role in @('companionFull', 'companionBle', 'companion')) {
        $notice = Get-MeshCoreBluetoothUsbNotice -Device $alias -Role $role -FirmwareFile $file
        Assert-True ($notice -match 'Bluetooth \(BLE\).*paused.*computer by USB') 'Affected companion missing BLE reminder.'
        Assert-True ($notice -match 'Finish any USB verification first, then unplug USB') 'Notice risks early USB disconnect.'
        Assert-True ($notice -match 'enabled in the radio') 'Notice implies manually disabled BLE will turn on.'
    }
}
foreach ($role in @('repeater', 'roomServer', 'sensor', 'companionUsb', '', 'auto')) {
    Assert-True (-not (Get-MeshCoreBluetoothUsbNotice -Device $device -Role $role -FirmwareFile $file)) "Wrong notice for role $role."
}
foreach ($other in @('RAK 4631', 'Seeed Studio Wio WM1110', 'Seeed Studio Xiao nRF52 WIO', 'Heltec v4', '', 'T1000-E Plus')) {
    Assert-True (-not (Get-MeshCoreBluetoothUsbNotice -Device $other -Role companionFull -FirmwareFile $file)) "Wrong board notice for $other."
}
foreach ($other in @(
    't1000e_companion_radio_full-v1.18.0.1.zip',
    't1000e_companion_radio_usb-v1.18.0.1-keymind.zip',
    't1000e_repeater-v1.18.0.1-keymind.zip',
    't1000e_companion_radio_full-bootloader-keymind.zip',
    't1000e_companion_radio_full-with-bootloader-unknown-keymind.zip',
    't1000e_companion_radio_full-with-bootloader-2.4.12.1.99-keymind.zip',
    't1000e_companion_radio_full-with-bootloader-2.4.12-bootloader-keymind.zip',
    't1000e_companion_radio_full-softdevice-keymind.zip',
    't1000e_companion_radio_full-erase-keymind.zip',
    't1000e_companion_radio_full-recovery-keymind.zip',
    'R_t1000e_companion_radio_full-keymind.zip',
    'unknown-keymind.zip',
    't1000e_companion_radio_full-keymind.uf2'
)) {
    Assert-True (-not (Get-MeshCoreBluetoothUsbNotice -Device $device -Role companionFull -FirmwareFile $other)) "Wrong package notice for $other."
}
Assert-True ([bool](Get-MeshCoreBluetoothUsbNotice -Device $device -Role companionBle -FirmwareFile ($file -replace '_full-', '_ble-'))) 'Legacy BLE build missing notice.'
foreach ($version in @('0.4', '2.4.12', '2.4.12.1')) {
    $wrapper = $file -replace '_full-', "_full-with-bootloader-$version-"
    Assert-True ([bool](Get-MeshCoreBluetoothUsbNotice -Device $device -Role companionFull -FirmwareFile $wrapper)) 'Embedded bootloader application missing notice.'
}

$identity = [pscustomobject]@{ SerialNumber = 'mock' }
function Get-SelectedUsbIdentityForFlash { param($Hardware) return $identity }
function Resolve-Nrf52PrimaryUsbSelection { param($SelectedComPort, $UsbIdentity) return [pscustomobject]@{ ComPort = 'COM9'; UsbIdentity = $identity } }
function Resolve-LiveUsbComPort { param($PreferredComPort, $Purpose, $UsbIdentity, $IdentityTimeoutSec) return 'COM9' }
function Test-Path { param($Path) return $true }
function Get-MeshCoreBootloaderHintText { param($hw) return '' }
function Request-MeshCoreUsbBackupBeforeFlash { param($Hardware, $ComPort, $UsbIdentity, $Action) return [pscustomobject]@{ Verified = $true } }
function Get-MeshCoreNrf52FlashAction { param($hw) return $script:action }
function Confirm-MeshCoreUsbBackupForAction { param($BackupResult, $Action) return $true }
function Confirm-MeshCoreFlash { param($Hardware, $Action) return $script:consent }
function Select-MeshCoreEraseUrl { param($hw) return 'erase.zip' }
function Resolve-MeshCoreFirmwareFile { param($SelectedReference, $CacheFile) return 'erase.zip' }
function Start-Sleep { param($Seconds) }
function Write-Host {
    param($Object, $ForegroundColor)
    if ([string]$Object -match '^Bluetooth \(BLE\)') { $script:events.Add('notice') }
}
function Write-Warning { param($Message) }
function Invoke-NrfutilSerialDfu {
    param($PackageFile, $ComPort, $NrfutilTouchBaud, $ProgressActivity, $UsbIdentity)
    $script:events.Add('write')
    if ($script:failWrite) { throw 'mock transfer failure' }
    return [pscustomobject]@{ ComPort = 'COM9' }
}
foreach ($scenario in @('update', 'wipe', 'cancel', 'backup', 'failure')) {
    $script:events = New-Object 'System.Collections.Generic.List[string]'
    $script:action = switch ($scenario) { wipe { 'flash-wipe' }; backup { 'backup-only' }; default { 'flash-update' } }
    $script:consent = $scenario -ne 'cancel'
    $script:failWrite = $scenario -eq 'failure'
    $hw = [pscustomobject]@{ HWNameFile = $device; Role = 'companionFull'; FirmwareFile = $file; ComPort = 'COM9' }
    try { $result = flashMeshCoreNrf52 -hw $hw } catch { if ($scenario -ne 'failure' -or $_.Exception.Message -ne 'mock transfer failure') { throw } }
    if ($scenario -in @('update', 'wipe')) {
        Assert-True ($result -eq $true) 'Completed flash did not succeed.'
        Assert-True ($script:events[$script:events.Count - 1] -eq 'notice') 'Notice was not after the final write.'
        Assert-True (@($script:events | Where-Object { $_ -eq 'notice' }).Count -eq 1) 'Notice appeared during intermediate erase.'
        Assert-True (@($script:events | Where-Object { $_ -eq 'write' }).Count -eq $(if ($scenario -eq 'wipe') { 2 } else { 1 })) 'Unexpected number of writes.'
    } else { Assert-True (-not $script:events.Contains('notice')) "Notice appeared after $scenario." }
}
[Console]::WriteLine('PASS: Keymind T1000-E BLE/Full completion reminders, exclusions, and successful-final-write ordering')
