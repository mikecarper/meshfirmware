$ErrorActionPreference = 'Stop'

function Assert-True {
    param([Parameter(Mandatory)][bool]$Condition, [Parameter(Mandatory)][string]$Message)
    if (-not $Condition) { throw $Message }
}

$firmwarePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'firmware.cmd'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $firmwarePath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -ne 0) { throw "firmware.cmd parse failed: $($parseErrors -join '; ')" }

function Get-FunctionSource {
    param([Parameter(Mandatory)][string]$Name)
    $definition = $ast.Find({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $Name
    }, $true)
    if ($null -eq $definition) { throw "Missing function $Name" }
    return $definition.Extent.Text
}

$meshCorePathSource = Get-FunctionSource 'Get-MeshCoreBackupOutputPath'
Invoke-Expression $meshCorePathSource
$ScriptPath = 'C:\git\meshfirmware'
$meshCorePath = Get-MeshCoreBackupOutputPath -DeviceHint 'T1000-E Companion' -ComPort 'COM4'
Assert-True ($meshCorePath -match '^C:\\git\\meshfirmware\\mc\.config_backup\.T1000-E Companion\.COM4\.\d{8}T\d{6}\.\d{7}Z\.json$') `
    "MeshCore backup path did not use the requested name/location: $meshCorePath"

$meshtasticSource = Get-FunctionSource 'MakeConfigBackup'
Assert-True ($meshtasticSource -match 'mt\.config_backup\.\$\{HWNameShort\}\.\$\{selectedComPort\}') `
    'Meshtastic config backups do not use the mt.config_backup prefix.'

$meshCoreInvokeSource = Get-FunctionSource 'Invoke-MeshCoreUsbBackup'
Assert-True ($meshCoreInvokeSource.Contains('Get-MeshCoreBackupOutputPath') -and
    $meshCoreInvokeSource.Contains("'--output', `$backupOutputPath")) `
    'MeshCore logical backup does not pass its mc.config_backup path to the helper.'

Write-Host 'PASS firmware backup paths'
