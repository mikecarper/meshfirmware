$ErrorActionPreference = 'Stop'
$WarningPreference = 'SilentlyContinue'
$firmwarePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'firmware.cmd'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($firmwarePath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw "firmware.cmd parse failed: $parseErrors" }

function Find-FirmwareFunction ($name) {
    $node = $ast.Find({ param($candidate)
        $candidate -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $candidate.Name -eq $name
    }, $true)
    if (-not $node) { throw "Missing function: $name" }
    return $node
}
foreach ($name in @('Get-Nrf52ApplicationSoftDeviceWarning', 'Confirm-Nrf52ApplicationLayout')) {
    . ([scriptblock]::Create((Find-FirmwareFunction $name).Extent.Text))
}

function Assert-True ([bool]$condition, [string]$message) {
    if (-not $condition) { throw $message }
}

function New-DfuFixture ([string]$path, [uint16[]]$ids) {
    $archive = [System.IO.Compression.ZipFile]::Open($path, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        $writer = [System.IO.StreamWriter]::new($archive.CreateEntry('manifest.json').Open())
        try { $writer.Write('{"manifest":{"application":{"dat_file":"app.dat","init_packet_data":{"softdevice_req":[182]}}}}') }
        finally { $writer.Dispose() }
        # Deliberately make the manifest hint disagree: the DAT is what is sent.
        $writer = [System.IO.BinaryWriter]::new($archive.CreateEntry('app.dat').Open())
        try {
            $writer.Write([byte[]]::new(8))
            $writer.Write([uint16]$ids.Length)
            foreach ($id in $ids) { $writer.Write($id) }
            $writer.Write([uint16]0)
        }
        finally { $writer.Dispose() }
    }
    finally { $archive.Dispose() }
}

function Get-Nrf52BootloaderInfoForUsbParent ([string]$UsbParent) {
    Assert-True ($UsbParent -ceq 'selected-radio') 'Expected the selected USB parent instance ID.'
    if ($script:simulateError) { throw 'CIM unavailable' }
    return $script:detectedInfo
}
function Read-Host ([string]$Prompt) {
    $script:prompts++
    return $script:answer
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
$directory = Join-Path ([System.IO.Path]::GetTempPath()) ('dfu-softdevice-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $directory
try {
    $app = Join-Path $directory 'firmware.zip'
    New-DfuFixture $app @(0x0123)
    $any = Join-Path $directory 'firmware-any.zip'
    New-DfuFixture $any @(0xFFFE, 0x0123)
    foreach ($installed in @('6.1.1', '0x00B6', '182')) {
        $warning = Get-Nrf52ApplicationSoftDeviceWarning $app "UF2 Bootloader 1.0`r`nSoftDevice: S140 $installed`r`n"
        Assert-True ($warning -match 'FWID 0x00B6.*lists 0x0123') "Wrong DAT comparison for S140 $installed."
    }
    foreach ($info in @('SoftDevice: S140 7.3.0', 'SoftDevice: S140 0x0123', 'SoftDevice: not found', 'Unknown firmware', "SoftDevice: S140 6.1.1`nSoftDevice: S140 7.3.0")) {
        Assert-True (-not (Get-Nrf52ApplicationSoftDeviceWarning $app $info)) "Unexpected mismatch with $info."
    }
    Assert-True (-not (Get-Nrf52ApplicationSoftDeviceWarning $any 'SoftDevice: S140 6.1.1')) 'Wildcard must not prompt.'

    $script:prompts = 0
    $script:simulateError = $false
    $script:detectedInfo = 'SoftDevice: S140 6.1.1'
    $script:answer = ''
    Assert-True (-not (Confirm-Nrf52ApplicationLayout $app 'selected-radio')) 'A mismatch defaults to cancel.'
    $script:answer = 'yes'
    Assert-True (Confirm-Nrf52ApplicationLayout $app 'selected-radio') 'A mismatch can be overridden.'
    $script:detectedInfo = ''
    Assert-True (Confirm-Nrf52ApplicationLayout $app 'selected-radio') 'An absent drive cannot block the transfer.'
    $script:simulateError = $true
    Assert-True (Confirm-Nrf52ApplicationLayout $app 'selected-radio') 'An unavailable device-property query cannot block the transfer.'
    Assert-True ($script:prompts -eq 2) 'Prompt only for a known mismatch.'
}
finally { Remove-Item -LiteralPath $directory -Recurse -Force }

$upload = (Find-FirmwareFunction 'Invoke-NrfutilSerialDfu').Extent.Text
$checkIndex = $upload.IndexOf('Confirm-Nrf52ApplicationLayout')
Assert-True ($checkIndex -ge 0 -and $checkIndex -lt $upload.IndexOf('$dfuArgs =') -and $upload.IndexOf('Get-UsbComPortIdentity', $checkIndex) -gt $checkIndex) 'Warn before upload and recheck the COM identity afterwards.'
foreach ($name in @('flashMeshCoreNrf52', 'flashMeshtasticNrf52')) {
    $flash = (Find-FirmwareFunction $name).Extent.Text
    $match = $flash -match '(?m)-ProgressActivity "nRF52 Erase"[^\r\n]*-CheckApplicationLayout \$selectedFirmwareFile'
    Assert-True ($match -eq ($name -eq 'flashMeshCoreNrf52')) 'Check the final MeshCore application before erase, and leave Meshtastic unchanged.'
}
Write-Host 'PASS: nRF52 SoftDevice warnings are advisory and only apply to MeshCore on Windows.'
