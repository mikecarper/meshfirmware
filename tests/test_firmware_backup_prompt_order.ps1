# Hermetic orchestration tests: no radio, external commands, or package installs.
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $repoRoot 'firmware.cmd'), [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw "Parse errors: $parseErrors" }
foreach ($name in @('Request-MeshCoreUsbBackupBeforeFlash', 'Confirm-MeshCoreUsbBackupForAction',
    'Confirm-MeshCoreFlash', 'Test-CachedMeshCoreUsbBackup', 'flashMeshCoreNrf52',
    'Invoke-MeshCoreBackupOnly', 'InvokeFlash', 'flashESP32',
    'Wait-FirmwareToolUpdates', 'Enter-FirmwareToolUse')) {
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
function Get-EspRuntimeStorageLayout {
    param($ComPort)
    $script:events.Add('partition')
    return 'int:esp32=16384K ext:none; app0*@0x10000+6400K,app1@0x650000+6400K'
}
function Get-MeshCoreBootloaderHintText { param($hw) return '' }
function Test-UsbComPortIdentityMatch { param($Expected, $Actual) return $Expected.SerialNumber -eq $Actual.SerialNumber }
function Get-UsbComPortIdentity { param($ComPort) return $identity }
function Test-UsbIdentityIsNrf52Dfu { param($Identity) return $script:dfuMode }
function Start-Sleep { param($Seconds) }
function Cleanup-ScriptTempArtifacts { param([switch]$Quiet) }
function Start-FirmwareToolUpdates { }
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
function Complete-Esp32FlashSession {
    param($ComPort, $UsbIdentity)
    Assert-True ($UsbIdentity.SerialNumber -eq 'selected-radio') 'Reboot check lost USB identity.'
    $script:events.Add('reboot-verified')
    return 'COM9'
}
function Invoke-MeshCoreUsbBackup {
    param($ComPort, $UsbIdentity, $DeviceHint, $RoleHint)
    Assert-True ($ComPort -eq 'COM9') 'Backup did not use the live primary port.'
    Assert-True ($RoleHint -eq 'repeater') 'The selected repeater role was not passed as a probe-order hint.'
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
    $script:dfuMode = $false
    $script:events = New-Object 'System.Collections.Generic.List[string]'
    $script:answers = New-Object 'System.Collections.Generic.Queue[string]'
    foreach ($reply in $Replies) { $script:answers.Enqueue($reply) }
}
function New-Hardware {
    return [pscustomobject]@{ Project = 'MeshCore'; Role = 'repeater'; HWNameFile = 'Test radio'; ComPort = 'COM21'; FirmwareFile = $firmware }
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
            if ($entry -eq 'flashESP32') { Assert-Order partition backup }
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
            if ($entry -eq 'flashESP32') { Assert-Order write reboot-verified }

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
        if ($entry -eq 'flashESP32') { Assert-Order write reboot-verified }
        Write-Host "PASS $entry backup-before-confirmation, cancellation, retry, skip, partial, and failure cases"
    }

    # A known DFU port cannot answer the MeshCore backup API. Skip that prompt
    # and helper, but still require explicit unbacked-update or wipe consent.
    Reset-Case failed flash-update @('yes', 'n')
    $script:dfuMode = $true
    $hw = New-Hardware
    $hw | Add-Member -NotePropertyName Architecture -NotePropertyValue 'nrf52'
    $result = flashMeshCoreNrf52 -hw $hw
    Assert-True ($result -eq $false) 'DFU update cancellation did not stop.'
    Assert-True (-not $script:events.Contains('backup-prompt') -and -not $script:events.Contains('backup') -and
        -not $script:events.Contains('write')) 'DFU mode attempted backup or wrote after cancellation.'
    Assert-Order update-consent flash-confirm
    Assert-True ($script:answers.Count -eq 0) 'DFU update prompts did not consume the expected answers.'

    Reset-Case failed flash-wipe @('')
    $script:dfuMode = $true
    $hw = New-Hardware
    $hw | Add-Member -NotePropertyName Architecture -NotePropertyValue 'nrf52'
    $blocked = $false
    try { flashMeshCoreNrf52 -hw $hw | Out-Null } catch {
        if ($_.Exception.Message -notmatch 'no complete verified backup') { throw }
        $blocked = $true
    }
    Assert-True $blocked 'DFU mode silently authorized an unbacked wipe.'
    Assert-True (-not $script:events.Contains('backup-prompt') -and -not $script:events.Contains('backup') -and
        -not $script:events.Contains('write')) 'DFU wipe attempted backup or wrote without consent.'
    Assert-True ($script:events.Contains('wipe-consent')) 'DFU wipe did not request explicit override.'
    Write-Host 'PASS nRF52 DFU backup skip and unbacked-flash consent'

    Reset-Case safe backup-only @('y')
    $hw = New-Hardware
    $result = flashMeshCoreNrf52 -hw $hw
    Assert-True ($result -eq 'backup-only') 'Backup-only choice did not exit without flashing.'
    Assert-True (Test-Path -LiteralPath $hw.MeshCoreBackupPath) 'Backup-only choice lost the verified archive.'
    Assert-True (-not $script:events.Contains('flash-confirm') -and -not $script:events.Contains('write')) `
        'Backup-only choice reached firmware confirmation or write.'
    Assert-True ($script:answers.Count -eq 0) 'Backup-only choice prompted for an unexpected flash action.'

    Reset-Case failed backup-only @('y')
    $hw = New-Hardware
    $result = flashMeshCoreNrf52 -hw $hw
    Assert-True ($result -eq 'backup-only') 'Failed backup-only choice did not exit.'
    Assert-True (-not $script:events.Contains('flash-confirm') -and -not $script:events.Contains('write')) `
        'Failed backup-only choice reached firmware confirmation or write.'
    Write-Host 'PASS nRF52 backup-only exit after successful and failed backups'

    Reset-Case safe backup-only @('y')
    $hw = New-Hardware
    $hw | Add-Member -NotePropertyName BackupOnly -NotePropertyValue $true
    $hw | Add-Member -NotePropertyName UsbIdentity -NotePropertyValue $identity
    $hw | Add-Member -NotePropertyName Architecture -NotePropertyValue ''
    $result = InvokeFlash -hw $hw
    Assert-True ($result -eq 'backup-only') 'Early backup-only path did not exit the flash wrapper.'
    Assert-True (Test-Path -LiteralPath $hw.MeshCoreBackupPath) 'Early backup-only path lost the archive.'
    Assert-True (-not $script:events.Contains('action') -and -not $script:events.Contains('flash-confirm') -and
        -not $script:events.Contains('write')) 'Early backup-only path reached a firmware action.'

    Reset-Case safe backup-only @()
    $hw = New-Hardware
    $hw | Add-Member -NotePropertyName BackupOnly -NotePropertyValue $true
    $hw | Add-Member -NotePropertyName Architecture -NotePropertyValue ''
    $result = InvokeFlash -hw $hw
    Assert-True ($result -eq $false) 'Backup-only path accepted a missing physical USB identity.'
    Assert-True (-not $script:events.Contains('backup') -and -not $script:events.Contains('write')) `
        'Backup-only path touched the device without its selected USB identity.'
    Write-Host 'PASS early backup-only path skips firmware selection and refuses missing identity'

    $actionDefinition = $ast.Find({ param($n)
        $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $n.Name -eq 'Get-MeshCoreNrf52FlashAction'
    }, $true)
    if ($null -eq $actionDefinition) { throw 'Missing nRF52 action menu.' }
    Invoke-Expression $actionDefinition.Extent.Text
    function Prompt-Menu {
        param($Title, $Options, $Prompt)
        Assert-True ($Options.Count -eq 3 -and $Options[2] -match 'backup only') `
            'The nRF52 action menu does not offer backup only.'
        return [pscustomobject]@{ Index = 3 }
    }
    $hw = New-Hardware
    $hw | Add-Member -NotePropertyName FWType -NotePropertyValue 'flash'
    Assert-True ((Get-MeshCoreNrf52FlashAction -hw $hw) -eq 'backup-only') `
        'Selecting menu option 3 did not choose backup only.'
    Write-Host 'PASS nRF52 action menu offers backup only'

    $getHwDefinition = $ast.Find({ param($n)
        $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'GetHW'
    }, $true)
    if ($null -eq $getHwDefinition) { throw 'Missing hardware-selection flow.' }
    $getHwText = $getHwDefinition.Extent.Text
    Assert-True ($getHwText.IndexOf('Back up this MeshCore node only') -gt 0 -and
        $getHwText.IndexOf('Back up this MeshCore node only') -lt $getHwText.IndexOf('ChooseMeshCoreFirmware')) `
        'Early backup-only prompt must precede firmware selection and download.'
    Invoke-Expression $getHwDefinition.Extent.Text
    function Test-IsWindowsHost { return $true }
    function GetModelFromNode { return @($null, $null) }
    function getUSBComPort { return @('COM11', 'Ikoka Stick', 'Repeater', @(), 'MeshCore') }
    function Select-FlashTarget { param($MonitorComPort, $CheckIntervalMs) return 'MeshCore' }
    function SetProjectVars { param($Project) }
    function Read-Host {
        param($Prompt)
        Assert-True ($Prompt -match 'Back up this MeshCore node only') `
            "Backup-only selection unexpectedly asked: $Prompt"
        return 'y'
    }
    function ChooseMeshCoreFirmware { throw 'Backup-only path entered firmware selection.' }
    function Resolve-MeshCoreFirmwareFile { throw 'Backup-only path downloaded firmware.' }
    $selected = GetHW
    Assert-True ($selected.BackupOnly -and $selected.Project -eq 'MeshCore' -and
        $selected.ComPort -eq 'COM11' -and $selected.UsbIdentity.SerialNumber -eq 'selected-radio') `
        'Early backup-only selection did not preserve the selected USB radio.'
    Write-Host 'PASS early backup-only selection requires no firmware download'
}
finally {
    Remove-Item -LiteralPath $archive, $firmware -Force -ErrorAction SilentlyContinue
}
