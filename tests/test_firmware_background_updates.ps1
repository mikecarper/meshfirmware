# Hermetic startup/update tests: no network, packages, or serial devices.
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $repoRoot 'firmware.cmd'), [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw "firmware.cmd parse failed: $parseErrors" }

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

foreach ($name in @('Enter-FirmwareToolUse', 'Exit-FirmwareToolUse',
    'Invoke-FirmwareToolUpdates', 'Start-FirmwareToolUpdates', 'Wait-FirmwareToolUpdates',
    'check_requirements', 'InvokeFlash')) {
    $definition = $ast.Find({ param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
    }, $true)
    if ($null -eq $definition) { throw "Missing function $name" }
    Invoke-Expression $definition.Extent.Text
}
$productionUpdateWorker = ${function:Invoke-FirmwareToolUpdates}

$scratch = Join-Path ([IO.Path]::GetTempPath()) ('firmware updates test ' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $scratch
$ScriptPath = $scratch
$global:pythonCommand = $scratch
$script:FirmwareToolUpdateUsePipx = $false
$script:FirmwareToolUpdatePipxPath = ''
$script:FirmwareToolUpdateUpdatePipx = $false
$script:FirmwareToolUseMutex = $null
$script:FirmwareToolUpdatesStarted = $false
$script:FirmwareToolUpdateJob = $null
$ownedJobs = New-Object System.Collections.Generic.List[object]
$previousArgsLog = $env:MESHFIRMWARE_TEST_UPDATE_ARGS
$previousNativeExit = $env:MESHFIRMWARE_TEST_UPDATE_EXIT
$workerMutex = $null
$workerMutexHeld = $false

# The real launcher serializes this worker into a real background process.
# Hold it until released to make launch/wait ordering observable.
function Invoke-FirmwareToolUpdates {
    param([string]$PythonCommand, [bool]$UsePipx, [string]$PipxPath,
        [bool]$UpdatePipx, [string]$LogPath, [string]$MutexName)
    $ErrorActionPreference = 'Stop'
    Set-Content -LiteralPath (Join-Path $PythonCommand 'started') -Value 'started'
    while (-not (Test-Path -LiteralPath (Join-Path $PythonCommand 'release'))) {
        Start-Sleep -Milliseconds 25
    }
    Set-Content -LiteralPath (Join-Path $PythonCommand 'finished') -Value 'finished'
    [pscustomobject]@{ Tool = 'fixture'; Success = $true }
}

function Cleanup-ScriptTempArtifacts { param([switch]$Quiet) }
function Invoke-MeshCoreBackupOnly {
    param($hw)
    Assert-True (Test-Path -LiteralPath (Join-Path $scratch 'finished')) `
        'Backup started while its dependencies were still being updated.'
    Set-Content -LiteralPath (Join-Path $scratch 'backup-entered') -Value 'backup'
    return 'backup-only'
}

try {
    $noJobOutput = @(Wait-FirmwareToolUpdates)
    Assert-True ($noJobOutput.Count -eq 0) 'Waiting without an update leaked output.'

    $startOutput = @(Start-FirmwareToolUpdates)
    Assert-True ($startOutput.Count -eq 0) 'Background launch leaked the job into caller output.'
    Assert-True ($null -ne $script:FirmwareToolUpdateJob) 'Background launch did not retain its job.'
    $firstJob = $script:FirmwareToolUpdateJob
    $ownedJobs.Add($firstJob)
    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    while (-not (Test-Path -LiteralPath (Join-Path $scratch 'started'))) {
        if ([DateTime]::UtcNow -ge $deadline) { throw 'The fixture update worker did not start.' }
        if ($firstJob.State -eq 'Failed') {
            Receive-Job -Job $firstJob -ErrorAction Continue
            throw 'Background update worker failed before reaching the fixture.'
        }
        Start-Sleep -Milliseconds 25
    }
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $scratch 'finished'))) `
        'Launch waited for the updater instead of allowing menus to continue.'
    $duplicateOutput = @(Start-FirmwareToolUpdates)
    Assert-True ($duplicateOutput.Count -eq 0 -and $script:FirmwareToolUpdateJob.Id -eq $firstJob.Id) `
        'A second launch created another updater or leaked output.'

    $releaser = Start-Job -ScriptBlock {
        param($Path)
        while (-not (Test-Path -LiteralPath (Join-Path $Path 'wait-entered'))) {
            Start-Sleep -Milliseconds 25
        }
        Start-Sleep -Milliseconds 350
        Set-Content -LiteralPath (Join-Path $Path 'release') -Value 'release'
    } -ArgumentList $scratch
    $ownedJobs.Add($releaser)
    Set-Content -LiteralPath (Join-Path $scratch 'wait-entered') -Value 'wait'
    $operationOutput = @(InvokeFlash -hw ([pscustomobject]@{
        Project = 'MeshCore'; BackupOnly = $true; Architecture = ''; ComPort = 'TEST'
    }))
    Assert-True (Test-Path -LiteralPath (Join-Path $scratch 'finished')) `
        'A tool operation resumed before the updater completed.'
    Assert-True (Test-Path -LiteralPath (Join-Path $scratch 'backup-entered')) `
        'The backup-only operation did not run after the updater completed.'
    Assert-True ($operationOutput.Count -eq 1 -and $operationOutput[0] -eq 'backup-only') `
        'Updater results leaked into the firmware operation output.'
    Assert-True ($null -eq $script:FirmwareToolUpdateJob) 'Completed update job was not cleared.'
    Assert-True ($null -eq (Get-Job -Id $firstJob.Id -ErrorAction SilentlyContinue)) `
        'Completed update job was not removed.'
    $repeatOutput = @(Start-FirmwareToolUpdates)
    Assert-True ($repeatOutput.Count -eq 0 -and $null -eq $script:FirmwareToolUpdateJob) `
        'The updater restarted after completing in the same session.'

    # An upgrade failure must be visible while preserving installed tools.
    function Invoke-FirmwareToolUpdates {
        param([string]$PythonCommand, [bool]$UsePipx, [string]$PipxPath,
            [bool]$UpdatePipx, [string]$LogPath, [string]$MutexName)
        [pscustomobject]@{ Tool = 'fixture-failure'; Success = $false }
    }
    $script:FirmwareToolUpdatesStarted = $false
    $null = Start-FirmwareToolUpdates
    Assert-True ($null -ne $script:FirmwareToolUpdateJob) 'Failure fixture did not launch.'
    $ownedJobs.Add($script:FirmwareToolUpdateJob)
    $failureRecords = @(Wait-FirmwareToolUpdates 3>&1)
    $updateWarnings = @($failureRecords | Where-Object { $_ -is [System.Management.Automation.WarningRecord] })
    $failureOutput = @($failureRecords | Where-Object { $_ -isnot [System.Management.Automation.WarningRecord] })
    Assert-True ($failureOutput.Count -eq 0) 'Failed-upgrade diagnostics leaked into caller output.'
    Assert-True ($updateWarnings.Count -gt 0) 'A failed upgrade was silently ignored.'
    Assert-True ($null -eq $script:FirmwareToolUpdateJob) 'Failed update job was not cleared.'
    Write-Host 'PASS background updates (launch returns, one worker, operation waits, cleanup, failure)'

    # Run the production updater against a fake native executable. This checks
    # native exit codes and stderr handling on both Windows PowerShell and PS7.
    $nativeFixture = @'
@echo off
echo %*>>"%MESHFIRMWARE_TEST_UPDATE_ARGS%"
echo fixture stdout
echo fixture stderr 1>&2
exit /b %MESHFIRMWARE_TEST_UPDATE_EXIT%
'@
    $fakePython = Join-Path $scratch 'fake python.cmd'
    $fakePipx = Join-Path $scratch 'fake pipx.cmd'
    Set-Content -LiteralPath $fakePython -Value $nativeFixture -Encoding Ascii
    Set-Content -LiteralPath $fakePipx -Value $nativeFixture -Encoding Ascii
    $env:MESHFIRMWARE_TEST_UPDATE_ARGS = Join-Path $scratch 'native arguments.log'
    $env:MESHFIRMWARE_TEST_UPDATE_EXIT = '0'
    $directLog = Join-Path $scratch 'direct updater.log'
    $directResults = @(& $productionUpdateWorker -PythonCommand $fakePython -UsePipx $false `
        -PipxPath '' -UpdatePipx $false -LogPath $directLog -MutexName '')
    Assert-True ($directResults.Count -eq 4) 'Native updater output leaked into its four tool results.'
    foreach ($result in $directResults) {
        Assert-True ($result.Success -eq $true) "A successful native upgrade failed for $($result.Tool)."
    }
    $directCommands = @(Get-Content -LiteralPath $env:MESHFIRMWARE_TEST_UPDATE_ARGS)
    Assert-True ($directCommands.Count -eq 4) 'Direct-pip worker did not invoke four upgrades.'
    foreach ($command in $directCommands) {
        Assert-True ($command -match '^-m pip install --upgrade\b') 'Direct backend invoked a different installer.'
    }
    Assert-True ($directCommands[-1] -match 'adafruit-nrfutil\s*$') 'Direct backend omitted nrfutil.'
    $nativeLog = Get-Content -LiteralPath $directLog -Raw
    Assert-True ($nativeLog.Contains('fixture stdout') -and $nativeLog.Contains('fixture stderr')) `
        'Native stdout/stderr did not reach the updater log.'

    Set-Content -LiteralPath $env:MESHFIRMWARE_TEST_UPDATE_ARGS -Value ''
    $env:MESHFIRMWARE_TEST_UPDATE_EXIT = '7'
    $pipxLog = Join-Path $scratch 'pipx updater.log'
    $pipxResults = @(& $productionUpdateWorker -PythonCommand $fakePython -UsePipx $true `
        -PipxPath $fakePipx -UpdatePipx $true -LogPath $pipxLog -MutexName '')
    Assert-True ($pipxResults.Count -eq 5) 'Pipx updater returned native text instead of its five tool results.'
    foreach ($result in $pipxResults) {
        Assert-True ($result.Success -eq $false) "Native exit 7 was not reported for $($result.Tool)."
    }
    $pipxCommands = @(Get-Content -LiteralPath $env:MESHFIRMWARE_TEST_UPDATE_ARGS | Where-Object { $_.Trim() })
    Assert-True ($pipxCommands.Count -eq 5) 'Pipx backend invoked the wrong number of upgrades.'
    Assert-True ($pipxCommands[3] -match '^-m pip install --upgrade\b.*\bpipx\s*$') `
        'Existing pipx did not receive its own background upgrade.'
    Assert-True ($pipxCommands[4] -match '^upgrade adafruit-nrfutil --pip-args\b') `
        'Pipx backend did not use the isolated nrfutil updater.'
    Assert-True ((Get-Content -LiteralPath $pipxLog -Raw).Contains('exit 7')) `
        'Native failure exit codes were absent from the updater log.'
    Write-Host 'PASS native updater (pip/pipx commands, native failures, stdout/stderr logs, clean results)'

    # Another firmware window can hold this environment while probing or
    # flashing. Its updater must wait rather than altering packages in use.
    Set-Content -LiteralPath $env:MESHFIRMWARE_TEST_UPDATE_ARGS -Value ''
    $env:MESHFIRMWARE_TEST_UPDATE_EXIT = '0'
    $mutexName = 'Local\MeshFirmwareFixture-' + [guid]::NewGuid().ToString('N')
    $workerMutex = New-Object System.Threading.Mutex($false, $mutexName)
    $workerMutexHeld = $workerMutex.WaitOne()
    $mutexReady = Join-Path $scratch 'mutex worker ready'
    $mutexLog = Join-Path $scratch 'mutex updater.log'
    $workerArguments = @{
        PythonCommand = $fakePython; UsePipx = $false; PipxPath = ''
        UpdatePipx = $false; LogPath = $mutexLog; MutexName = $mutexName
    }
    $mutexJob = Start-Job -ScriptBlock {
        param($Source, $WorkerArguments, $ReadyPath)
        Set-Content -LiteralPath $ReadyPath -Value 'ready'
        & ([scriptblock]::Create($Source)) @WorkerArguments
    } -ArgumentList $productionUpdateWorker.ToString(), $workerArguments, $mutexReady
    $ownedJobs.Add($mutexJob)
    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    while (-not (Test-Path -LiteralPath $mutexReady)) {
        if ([DateTime]::UtcNow -ge $deadline) { throw 'Mutex fixture did not start.' }
        Start-Sleep -Milliseconds 25
    }
    $heldCommands = @(Get-Content -LiteralPath $env:MESHFIRMWARE_TEST_UPDATE_ARGS | Where-Object { $_.Trim() })
    Assert-True ($heldCommands.Count -eq 0) 'The worker invoked an installer while another window held the mutex.'
    $workerMutex.ReleaseMutex()
    $workerMutexHeld = $false
    $null = Wait-Job -Job $mutexJob -Timeout 15
    Assert-True ($mutexJob.State -eq 'Completed') 'The worker did not complete after the environment was released.'
    $mutexResults = @(Receive-Job -Job $mutexJob)
    Assert-True ($mutexResults.Count -eq 4) 'The worker did not resume its upgrades after acquiring the mutex.'
    $workerMutex.Dispose()
    $workerMutex = $null
    Write-Host 'PASS environment lock (worker waits for another window and resumes after release)'

    # A complete installation should get one read-only package probe at startup.
    $script:StartupPythonCalls = New-Object System.Collections.Generic.List[object]
    $script:StartupToolProbeJson = '{"pip":true,"meshtastic":true,"esptool":true,"pipx":true,"nordicsemi":true}'
    $script:AllowMissingToolInstalls = $false
    function python {
        $script:StartupPythonCalls.Add(@($args))
        $global:LASTEXITCODE = 0
        if ($args.Count -eq 1 -and $args[0] -eq '--version') {
            'Python 3.13.5'
            return
        }
        if ($args.Count -eq 2 -and $args[0] -eq '-c') {
            $script:StartupToolProbeJson
            return
        }
        if ($script:AllowMissingToolInstalls -and $args.Count -ge 4 -and
            $args[0] -eq '-m' -and $args[1] -eq 'pip' -and $args[2] -eq 'install') {
            "Fixture installed $($args[-1])"
            return
        }
        throw "Startup attempted an installer or unexpected command: $($args -join ' ')"
    }
    $global:pythonCommand = ''
    $script:FirmwareToolUpdateJob = $null
    $PORTABLE_PYTHON_DIR = Join-Path $scratch 'missing portable Python'
    $startupOutput = @(check_requirements)
    Assert-True ($startupOutput.Count -eq 0) 'Startup readiness diagnostics leaked into caller output.'
    $probeCalls = @($script:StartupPythonCalls | Where-Object { $_.Count -eq 2 -and $_[0] -eq '-c' })
    Assert-True ($probeCalls.Count -eq 1) 'Startup did not use exactly one package readiness probe.'
    Assert-True ($script:StartupPythonCalls.Count -eq 2) 'Startup ran more than Python version and package readiness checks.'
    Write-Host 'PASS installed tools startup (one read-only probe, no installs or upgrades)'

    # First-time installations stay synchronous, but only the missing tools
    # are installed. Existing pip/nrfutil/pipx must not be upgraded here.
    Exit-FirmwareToolUse
    if ($script:FirmwareToolUseMutex) { $script:FirmwareToolUseMutex.Dispose() }
    $script:FirmwareToolUseMutex = $null
    $script:FirmwareToolUseLocked = $false
    $script:StartupPythonCalls.Clear()
    $script:StartupToolProbeJson = '{"pip":true,"meshtastic":false,"esptool":false,"pipx":true,"nordicsemi":true}'
    $script:AllowMissingToolInstalls = $true
    $missingOutput = @(check_requirements)
    Assert-True ($missingOutput.Count -eq 0) 'Missing-tool installation leaked into caller output.'
    $installCalls = @($script:StartupPythonCalls | Where-Object {
        $_.Count -ge 4 -and $_[0] -eq '-m' -and $_[1] -eq 'pip' -and $_[2] -eq 'install'
    })
    Assert-True ($installCalls.Count -eq 2) 'Startup did not install exactly its two missing tools.'
    $installedSpecs = @($installCalls | ForEach-Object { $_[-1] })
    Assert-True ($installedSpecs -contains 'meshtastic[cli]' -and $installedSpecs -contains 'esptool') `
        'Startup installed an unrelated package or omitted a required tool.'
    foreach ($call in $script:StartupPythonCalls) {
        Assert-True ($call -notcontains '--upgrade') 'Startup upgraded tools before the menus.'
    }
    Assert-True ($script:StartupPythonCalls.Count -eq 4) 'Missing-tool startup ran additional package commands.'
    Write-Host 'PASS missing tools startup (install only absent packages, no upgrades)'
}
finally {
    # These jobs only touch the fixture directory; release before cleanup.
    if ($workerMutexHeld) { $workerMutex.ReleaseMutex() }
    if ($workerMutex) { $workerMutex.Dispose() }
    Set-Content -LiteralPath (Join-Path $scratch 'release') -Value 'release'
    Set-Content -LiteralPath (Join-Path $scratch 'wait-entered') -Value 'wait'
    foreach ($job in $ownedJobs) {
        $existing = Get-Job -Id $job.Id -ErrorAction SilentlyContinue
        if ($null -ne $existing) {
            $null = Wait-Job -Job $existing -Timeout 15
            if ($existing.State -in @('Running', 'NotStarted')) { Stop-Job -Job $existing }
            Remove-Job -Job $existing -Force -ErrorAction SilentlyContinue
        }
    }
    Exit-FirmwareToolUse
    if ($script:FirmwareToolUseMutex) { $script:FirmwareToolUseMutex.Dispose() }
    $env:MESHFIRMWARE_TEST_UPDATE_ARGS = $previousArgsLog
    $env:MESHFIRMWARE_TEST_UPDATE_EXIT = $previousNativeExit
    Remove-Item -LiteralPath Function:\python -ErrorAction SilentlyContinue
    $resolvedScratch = [IO.Path]::GetFullPath($scratch)
    $temporaryRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    if (-not $resolvedScratch.StartsWith($temporaryRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Fixture cleanup target left the temporary directory.'
    }
    Remove-Item -LiteralPath $resolvedScratch -Recurse -Force
}
