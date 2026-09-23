# 2>NUL & @set "MESH_RESTORE_SCRIPT=%~f0" & @powershell -NoProfile -ExecutionPolicy Bypass "(Get-Content -LiteralPath '%~f0' -Raw) | Invoke-Expression" & @call exit /b %%errorlevel%%

# This .cmd is PowerShell after the launcher line, so it works by double-click
# and from either Command Prompt or PowerShell.

$ErrorActionPreference = 'Stop'
$project = Split-Path -Parent $env:MESH_RESTORE_SCRIPT
$BackupPath = $env:MESH_RESTORE_BACKUP
$TargetSerial = $env:MESH_RESTORE_TARGET_SERIAL
$MoveToNewHardware = $env:MESH_RESTORE_NEW_HARDWARE -eq '1'
$helper = Join-Path $project 'tools\meshcore_restore.py'
if (-not (Test-Path -LiteralPath $helper)) {
    Write-Host 'Restore helper is missing. Run this file from the full meshfirmware checkout.' -ForegroundColor Red
    exit 1
}

if (-not $BackupPath) {
    $legacyDir = Join-Path $env:USERPROFILE '.meshfirmware\backups'
    $candidates = @(
        Get-ChildItem -LiteralPath $project -File -Filter 'mc.config_backup.*.json' -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $legacyDir) {
            Get-ChildItem -LiteralPath $legacyDir -File -Filter '*.json'
        }
    ) | Sort-Object LastWriteTime -Descending
    if ($candidates.Count -gt 0) {
        Write-Host 'Most recent MeshCore backup:'
        Write-Host $candidates[0].FullName
        $choice = Read-Host 'Use it? [Y/n]'
        if (-not $choice -or $choice -match '^(?i:y|yes)$') { $BackupPath = $candidates[0].FullName }
    }
    if (-not $BackupPath) { $BackupPath = Read-Host 'Full path of MeshCore backup JSON' }
}
$BackupPath = ([string]$BackupPath).Trim().Trim('"')
if (-not (Test-Path -LiteralPath $BackupPath -PathType Leaf)) {
    Write-Host 'Backup file not found.' -ForegroundColor Red
    exit 1
}
$BackupPath = (Resolve-Path -LiteralPath $BackupPath).Path

$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    Write-Host 'Python is not on PATH. Install Python and the MeshCore USB backup dependencies first.' -ForegroundColor Red
    exit 1
}

$targetArgs = @()
if (-not $MoveToNewHardware -and -not $TargetSerial) {
    $choice = Read-Host 'Target: 1. original USB device  2. different hardware [1/2, Enter=1]'
    if ($choice -eq '2') { $MoveToNewHardware = $true }
}
if ($MoveToNewHardware) {
    if (-not $TargetSerial) {
        Write-Host 'Connected serial devices:'
        & $python.Source $helper ports
        $TargetSerial = Read-Host 'Enter the exact USB serial of the new target'
    }
    if (-not $TargetSerial) { Write-Host 'Cancelled.'; exit 1 }
    $targetArgs += @('--target-serial', $TargetSerial, '--new-hardware')
} elseif ($TargetSerial) {
    Write-Host 'A different USB serial requires MESH_RESTORE_NEW_HARDWARE=1.' -ForegroundColor Red
    exit 1
}

Write-Host 'Checking backup integrity, target USB serial, and companion identity...'
$modeChoice = Read-Host 'If needed, temporarily switch USB logging off to enter Binary Companion mode? [Y/n]'
if (-not $modeChoice -or $modeChoice -match '^(?i:y|yes)$') {
    $targetArgs += '--allow-mode-switch'
}
& $python.Source $helper probe --input $BackupPath @targetArgs
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host ''
Write-Host 'Restores the captured identity (if needed), channels, contacts, and supported companion settings.'
Write-Host 'It does not restore firmware, unread messages, or optional CLI-only settings.'
$answer = Read-Host 'Restore this backup to the matched USB device? [y/N]'
if ($answer -notmatch '^(?i:y|yes)$') { Write-Host 'Cancelled.'; exit 0 }

# A differing public identity is a separate, explicit choice. The helper will
# refuse replacement unless this switch is supplied.
$replace = Read-Host 'If the target identity differs, replace it with the backup identity? [y/N]'
if ($replace -match '^(?i:y|yes)$') {
    & $python.Source $helper restore --input $BackupPath @targetArgs --confirmed --replace-identity
} else {
    & $python.Source $helper restore --input $BackupPath @targetArgs --confirmed
}
$result = $LASTEXITCODE
if ($result -ne 0) { Write-Host 'Restore did not complete. The backup file was not changed.' -ForegroundColor Red }
if ($result -eq 0) {
    & $python.Source $helper resync --input $BackupPath @targetArgs --confirmed
    if ($LASTEXITCODE -ne 0) {
        Write-Host 'Restore succeeded, but Bluetooth resync did not complete.' -ForegroundColor Yellow
        $result = $LASTEXITCODE
    }
}
exit $result
