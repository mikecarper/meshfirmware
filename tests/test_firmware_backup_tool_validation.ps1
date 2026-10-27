# Real native Python children; no network, dependencies, or connected radio.
param([string]$Python = 'python')
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$repoRoot = Split-Path $PSScriptRoot -Parent
$tokens = $null; $parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $repoRoot 'firmware.cmd'), [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw $parseErrors }
foreach ($definition in $ast.EndBlock.Statements) {
    if ($definition -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $definition.Name -in @('Test-MeshCoreBackupToolVersion', 'Resolve-MeshCoreBackupTool')) {
        Invoke-Expression $definition.Extent.Text
    }
}
function Assert-True { param([bool]$Condition, [string]$Message); if (-not $Condition) { throw $Message } }
function Expect-Failure {
    param([scriptblock]$Action, [string]$Pattern)
    try { $null = & $Action } catch {
        if ($_.Exception.Message -notmatch ('(?s)' + $Pattern)) { throw }
        Assert-True ($ErrorActionPreference -eq 'Stop') 'Error preference leaked from a failed query.'
        return $_.Exception.Message
    }
    throw "Expected a failure matching '$Pattern'."
}
function Wait-FirmwareToolUpdates { }
$scratch = Join-Path ([IO.Path]::GetTempPath()) ('meshcore helper validation ' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $scratch
$oldMode = $env:MESHFIRMWARE_TEST_VERSION_MODE
$oldMarker = $env:MESHFIRMWARE_TEST_VERSION_MARKER
$pythonCommand = (Get-Command $Python -ErrorAction Stop).Source
$realPython = $pythonCommand
$MESHCORE_BACKUP_TOOL_VERSION = '0.2.4'
$MESHCORE_BACKUP_TOOL_URL = 'https://invalid.example/fixture-only'
$script:DownloadCalls = 0
# Intercept downloads with a copy of the local fixture. Nothing reaches a server.
function Invoke-WebRequest {
    param($Uri, $OutFile, [switch]$UseBasicParsing, $Headers)
    Assert-True ($Uri -eq $MESHCORE_BACKUP_TOOL_URL) 'Unexpected download URL.'
    Assert-True ($Headers['Cache-Control'] -eq 'no-cache') 'Download did not bypass stale caches.'
    $script:DownloadCalls++
    Copy-Item -LiteralPath $fixture -Destination $OutFile
}
try {
    $fixture = Join-Path $scratch 'version probe.py'
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'fixtures\meshcore_backup_version_probe.py') -Destination $fixture
    $MESHCORE_BACKUP_TOOL_SHA256 = (Get-FileHash -LiteralPath $fixture -Algorithm SHA256).Hash.ToLowerInvariant()
    $fixtureHash = $MESHCORE_BACKUP_TOOL_SHA256
    $env:MESHFIRMWARE_TEST_VERSION_MARKER = Join-Path $scratch 'executed'
    foreach ($mode in @('ok', 'stderr')) {
        $env:MESHFIRMWARE_TEST_VERSION_MODE = $mode
        $result = @(Test-MeshCoreBackupToolVersion -Path $fixture -ThrowOnFailure)
        Assert-True ($result.Count -eq 1 -and $result[0] -eq $true) 'Successful version query leaked output or rejected stderr.'
        Assert-True ($ErrorActionPreference -eq 'Stop') 'Successful query changed ErrorActionPreference.'
    }
    foreach ($case in @(
        @('failed', 'version query failed.*exit 7.*SyntaxError'),
        @('empty', 'no single JSON version report'),
        @('invalid', 'invalid JSON'),
        @('ambiguous', 'no single JSON version report'),
        @('not-ok', 'did not report success'),
        @('version', 'version mismatch.*expected 0.2.4.*found .0.0.0'),
        @('schema', 'schema mismatch.*wrong/schema')
    )) {
        $env:MESHFIRMWARE_TEST_VERSION_MODE = $case[0]
        $null = Expect-Failure { Test-MeshCoreBackupToolVersion -Path $fixture -ThrowOnFailure } $case[1]
        $result = @(Test-MeshCoreBackupToolVersion -Path $fixture)
        Assert-True ($result.Count -eq 1 -and $result[0] -eq $false) 'Boolean cache probe threw or leaked native output.'
    }
    $env:MESHFIRMWARE_TEST_VERSION_MODE = 'ok'
    Remove-Item -LiteralPath $env:MESHFIRMWARE_TEST_VERSION_MARKER
    $MESHCORE_BACKUP_TOOL_SHA256 = '0' * 64
    $message = Expect-Failure { Test-MeshCoreBackupToolVersion -Path $fixture -ThrowOnFailure } 'SHA-256 mismatch.*Expected.*found'
    Assert-True ($message.Contains($fixtureHash)) 'Checksum diagnostic omitted the actual hash.'
    Assert-True (-not (Test-Path -LiteralPath $env:MESHFIRMWARE_TEST_VERSION_MARKER)) 'Untrusted helper executed before its hash was checked.'
    $MESHCORE_BACKUP_TOOL_SHA256 = $fixtureHash
    $null = Expect-Failure { Test-MeshCoreBackupToolVersion -Path (Join-Path $scratch 'absent.py') -ThrowOnFailure } 'file not found'
    $pythonCommand = Join-Path $scratch 'missing python.exe'
    $null = Expect-Failure { Test-MeshCoreBackupToolVersion -Path $fixture -ThrowOnFailure } 'Cannot launch backup Python'
    $pythonCommand = ''
    $null = Expect-Failure { Test-MeshCoreBackupToolVersion -Path $fixture -ThrowOnFailure } 'Python is not configured'
    $pythonCommand = $realPython

    $ScriptPath = Join-Path $scratch 'bundled'
    $null = New-Item -ItemType Directory -Path (Join-Path $ScriptPath 'tools') -Force
    $bundled = Join-Path $ScriptPath 'tools\meshcore_backup.py'
    Copy-Item -LiteralPath $fixture -Destination $bundled
    Assert-True ((Resolve-MeshCoreBackupTool) -eq $bundled) 'Valid bundled helper was not selected.'
    $env:MESHFIRMWARE_TEST_VERSION_MODE = 'failed'
    $null = Expect-Failure { Resolve-MeshCoreBackupTool } 'Bundled.*version query failed.*exit 7.*SyntaxError'
    $env:MESHFIRMWARE_TEST_VERSION_MODE = 'ok'
    $MESHCORE_BACKUP_TOOL_SHA256 = '0' * 64
    $null = Expect-Failure { Resolve-MeshCoreBackupTool } 'Bundled.*SHA-256 mismatch'
    Assert-True ($script:DownloadCalls -eq 0) 'A bundled validation failure silently switched to a downloaded helper.'
    $MESHCORE_BACKUP_TOOL_SHA256 = $fixtureHash

    # Single-script distribution, then cached reuse and rejected-cache refresh.
    $ScriptPath = Join-Path $scratch 'standalone'
    $FIRMWARE_ROOT = Join-Path $scratch 'cache'
    $cached = Join-Path $FIRMWARE_ROOT 'tools\meshcore_backup.py'
    Assert-True ((Resolve-MeshCoreBackupTool) -eq $cached) 'Verified download did not become the cache.'
    Assert-True ($script:DownloadCalls -eq 1) 'Download path was not exercised.'
    $null = Resolve-MeshCoreBackupTool
    Assert-True ($script:DownloadCalls -eq 1) 'Valid cached helper was downloaded again.'
    Remove-Item -LiteralPath $cached
    $env:MESHFIRMWARE_TEST_VERSION_MODE = 'failed'
    $null = Expect-Failure { Resolve-MeshCoreBackupTool } 'Downloaded.*version query failed.*exit 7.*SyntaxError'
    Assert-True (-not (Test-Path -LiteralPath "$cached.partial")) 'Failed download validation left a partial helper behind.'
    Assert-True (-not (Test-Path -LiteralPath $cached)) 'Failed version query published a cached helper.'
    $env:MESHFIRMWARE_TEST_VERSION_MODE = 'ok'
    $MESHCORE_BACKUP_TOOL_SHA256 = '0' * 64
    $null = Expect-Failure { Resolve-MeshCoreBackupTool } 'Downloaded.*SHA-256 mismatch'
    Assert-True (-not (Test-Path -LiteralPath "$cached.partial")) 'Checksum failure left a partial helper behind.'
    $MESHCORE_BACKUP_TOOL_SHA256 = $fixtureHash
    $null = New-Item -ItemType File -Path $cached
    $records = @(Resolve-MeshCoreBackupTool 3>&1)
    $warnings = @($records | Where-Object { $_ -is [System.Management.Automation.WarningRecord] })
    $result = @($records | Where-Object { $_ -isnot [System.Management.Automation.WarningRecord] })
    Assert-True ($result.Count -eq 1 -and $result[0] -eq $cached) 'Rejected cache was not replaced by a valid download.'
    Assert-True (($warnings -join ' ') -match 'Cached.*SHA-256 mismatch') 'Rejected cache reason was hidden.'
    Write-Host 'PASS backup helper validation (hash before execution, native stderr/exit, JSON/version/schema, bundled/cache/download diagnostics)'
} finally {
    $env:MESHFIRMWARE_TEST_VERSION_MODE = $oldMode
    $env:MESHFIRMWARE_TEST_VERSION_MARKER = $oldMarker
    $resolved = [IO.Path]::GetFullPath($scratch)
    $temporary = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    if (-not $resolved.StartsWith($temporary, [StringComparison]::OrdinalIgnoreCase)) { throw 'Cleanup left the temporary directory.' }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
