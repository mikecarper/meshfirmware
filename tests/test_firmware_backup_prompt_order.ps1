# Hermetic orchestration tests: no radio, external commands, or package installs.
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $repoRoot 'firmware.cmd'), [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw "Parse errors: $parseErrors" }
foreach ($name in @('Request-MeshCoreUsbBackupBeforeFlash', 'Confirm-MeshCoreUsbBackupForAction',
    'Confirm-MeshCoreFlash', 'Test-CachedMeshCoreUsbBackup', 'flashMeshCoreNrf52', 'flashESP32')) {
    $definition = $ast.Find({ param($n)
        $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name
    }, $true)
    if ($null -eq $definition) { throw "Missing function $name" }
    Invoke-Expression $definition.Extent.Text
}
function Assert-True($Condition, $Message) { if (-not $Condition) { throw $Message } }

$archive = [System.IO.Path]::GetTempFileName()
$firmware = $archive + '.zip'
$null = New-Item -Path $firmware -ItemType File
$identity = [pscustomobject]@{ SerialNumber = 'selected-radio'; InterfaceNumber = '00' }
function Get-SelectedUsbIdentityForFlash { param($Hardware) return $identity }
function Resolve-Nrf52PrimaryUsbSelection {
    param($SelectedComPort, $UsbIdentity)
    return [pscustomobject]@{ ComPort = 'COM9'; UsbIdentity = $identity }
}
function Resolve-LiveUsbComPort { param($PreferredComPort, $Purpose, $UsbIdentity, $IdentityTimeoutSec) return 'COM9' }
function Resolve-EspUsbComPort { param($PreferredComPort, $Purpose, $UsbIdentity) return 'COM9' }
function Get-MeshCoreBootloaderHintText { param($hw) return '' }
function Test-UsbComPortIdentityMatch { param($Expected, $Actual) return $Expected.SerialNumber -eq $Actual.SerialNumber }
function Start-Sleep { param($Seconds) }
function Get-MeshCoreNrf52FlashAction { param($hw) $script:events.Add('action'); return $script:action }
function Get-EspFlashStrategy {
    param($Path)
    $mode = if ($script:action -eq 'flash-wipe') { 'install' } else { 'update' }
    return [pscustomobject]@{ SelectedMode = $mode; ClassifiedMode = $mode; FileNameMode = $mode }
}
function Select-MeshCoreEraseUrl { param($hw) return 'erase.zip' }
function Resolve-MeshCoreFirmwareFile { param($SelectedReference, $CacheFile) return $firmware }
function Invoke-NrfutilSerialDfu {
    param($PackageFile, $ComPort, $NrfutilTouchBaud, $ProgressActivity, $UsbIdentity)
    $script:events.Add('write')
    return [pscustomobject]@{ ComPort = 'COM9' }
}
function installFlashViaEspTool { param($hw) $script:events.Add('write'); return $true }
function updateFlashViaEspTool { param($hw) $script:events.Add('write'); return $true }
function Invoke-MeshCoreUsbBackup {
    param($ComPort, $UsbIdentity, $DeviceHint, $RoleHint)
    Assert-True ($ComPort -eq 'COM9') 'Backup did not use the live primary port.'
    $script:events.Add('backup')
    if ($script:backupMode -eq 'failed') { throw 'Simulated API unavailable (including ROM/DFU).' }
    $exitCode = if ($script:backupMode -eq 'partial') { 31 } else { 0 }
    return [pscustomobject]@{ ExitCode = $exitCode; Summary = [pscustomobject]@{
        ok = $true; exit_code = $exitCode; path = $archive
    } }
}
function Invoke-MeshCoreBackupHelper {
    param($Arguments, [switch]$Quiet)
    $script:events.Add('verify')
    $safe = $Arguments -notcontains '--require-safe-for-wipe' -or $script:backupMode -eq 'safe'
    return [pscustomobject]@{ ExitCode = $(if ($safe) { 0 } else { 40 }); Summary = [pscustomobject]@{ ok = $safe } }
}
function Read-Host {
    param($Prompt)
    $kind = switch -Regex ($Prompt) {
        '^Create and verify' { 'backup-prompt'; break }
        '^Type WIPE WITHOUT BACKUP' { 'wipe-consent'; break }
        '^Continue the write-only' { 'update-consent'; break }
        '^Run flash-' { 'flash-confirm'; break }
        default { throw "Unexpected prompt: $Prompt" }
    }
    $script:events.Add($kind)
    if ($script:answers.Count -eq 0) { throw "Unexpected extra prompt: $Prompt" }
    return $script:answers.Dequeue()
}
function Reset-Case($Mode, $Action, [string[]]$Replies) {
    $script:backupMode = $Mode
    $script:action = $Action
    $script:events = New-Object 'System.Collections.Generic.List[string]'
    $script:answers = New-Object 'System.Collections.Generic.Queue[string]'
    foreach ($reply in $Replies) { $script:answers.Enqueue($reply) }
}
function New-Hardware {
    return [pscustomobject]@{ Project = 'MeshCore'; HWNameFile = 'Test radio'; ComPort = 'COM21'; FirmwareFile = $firmware }
}
function Assert-Order($First, $Second) {
    Assert-True ($script:events.IndexOf($First) -ge 0 -and
        $script:events.IndexOf($Second) -gt $script:events.IndexOf($First)) "Wrong order: $First / $Second ($script:events)"
}
try {
    foreach ($entry in @('flashMeshCoreNrf52', 'flashESP32')) {
        foreach ($action in @('flash-update', 'flash-wipe')) {
            Reset-Case safe $action @('y', 'n')
            $hw = New-Hardware
            $result = & $entry -hw $hw
            Assert-True ($result -eq $false) "$entry did not cancel."
            Assert-Order backup-prompt flash-confirm
            Assert-Order verify flash-confirm
            if ($entry -eq 'flashMeshCoreNrf52') { Assert-Order backup action; Assert-Order action flash-confirm }
            Assert-True (-not $script:events.Contains('write')) "$entry wrote after cancellation."
            Assert-True (Test-Path -LiteralPath $hw.MeshCoreBackupPath) 'Cancelling removed the backup.'
            Assert-True ($script:answers.Count -eq 0) 'Expected prompts were not consumed.'

            # A retry may reuse a verified archive for this same USB identity.
            Reset-Case safe $action @('yes')
            $result = & $entry -hw $hw
            Assert-True ($result -eq $true) "$entry did not run after explicit confirmation."
            Assert-True (-not $script:events.Contains('backup-prompt')) 'Same-node retry duplicated the backup prompt.'
            Assert-Order verify flash-confirm
            Assert-Order flash-confirm write

            Reset-Case partial $action @('y', '')
            $blocked = $false
            try { $result = & $entry -hw (New-Hardware) } catch {
                if ($_.Exception.Message -notmatch 'no complete verified backup') { throw }
                $blocked = $true
            }
            Assert-True (-not $script:events.Contains('write')) 'Partial backup authorized an unconfirmed write.'
            if ($action -eq 'flash-wipe') {
                Assert-True $blocked 'Partial backup silently authorized a wipe.'
                Assert-Order backup wipe-consent
            } else { Assert-Order backup flash-confirm }

            # Skipping does not mean "flash yes"; it only skips the snapshot.
            $replies = if ($action -eq 'flash-wipe') { @('n', 'WIPE WITHOUT BACKUP', 'n') } else { @('n', 'n') }
            Reset-Case failed $action $replies
            $result = & $entry -hw (New-Hardware)
            Assert-True (-not $script:events.Contains('backup') -and -not $script:events.Contains('write')) 'Skip/cancel touched firmware.'
            Assert-Order backup-prompt flash-confirm
        }

        Reset-Case failed flash-update @('y', '')
        $blocked = $false
        try { & $entry -hw (New-Hardware) | Out-Null } catch {
            if ($_.Exception.Message -notmatch 'requested backup did not complete') { throw }
            $blocked = $true
        }
        Assert-True $blocked 'Failed backup allowed an update without explicit consent.'
        Assert-True (-not $script:events.Contains('write')) 'Failed backup reached firmware write.'
        Assert-Order backup update-consent

        Reset-Case failed flash-update @('y', 'yes', 'yes')
        $result = & $entry -hw (New-Hardware)
        Assert-True ($result -eq $true) 'Explicitly authorized update was blocked.'
        Assert-Order update-consent flash-confirm
        Assert-Order flash-confirm write
        Write-Host "PASS $entry backup-before-confirmation, cancellation, retry, skip, partial, and failure cases"
    }
}
finally {
    Remove-Item -LiteralPath $archive, $firmware -Force -ErrorAction SilentlyContinue
}
