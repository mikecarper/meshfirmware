param([string]$Python = 'python', [switch]$CheckInstalled)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
$tokens = $null; $parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $repoRoot 'firmware.cmd'), [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw $parseErrors }
foreach ($definition in $ast.EndBlock.Statements) {
    if ($definition -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $definition.Name -in @('Ensure-MeshCoreBackupDependencies', 'Test-MeshCoreBackupToolVersion', 'Resolve-MeshCoreBackupTool')) {
        Invoke-Expression $definition.Extent.Text
    }
    if ($definition -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $definition.Left.Extent.Text -in @('$MESHCORE_BACKUP_TOOL_VERSION', '$MESHCORE_BACKUP_TOOL_SHA256')) {
        Invoke-Expression $definition.Extent.Text
    }
}
$pythonCommand = (Get-Command $Python -ErrorAction Stop).Source
$ScriptPath = $repoRoot
$helper = Join-Path $repoRoot 'tools\meshcore_backup.py'
if ((Resolve-MeshCoreBackupTool) -ne $helper) { throw 'Bundled helper version/hash mismatch.' }

$scratch = Join-Path ([IO.Path]::GetTempPath()) ('meshcore dependency test ' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $scratch
$fakeHelper = Join-Path $scratch 'dependency helper.py'
$previousExit = $env:MESHFIRMWARE_TEST_DEPENDENCY_EXIT
try {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'fixtures\meshcore_backup_dependency_probe.py') -Destination $fakeHelper
    $env:MESHFIRMWARE_TEST_DEPENDENCY_EXIT = '0'
    $result = @(Ensure-MeshCoreBackupDependencies -ToolPath $fakeHelper)
    if ($result.Count -ne 0) { throw 'Dependency diagnostics leaked into the helper result.' }
    if ($ErrorActionPreference -ne 'Stop') { throw 'Dependency check changed ErrorActionPreference.' }
    $env:MESHFIRMWARE_TEST_DEPENDENCY_EXIT = '10'
    $failed = $false
    try { Ensure-MeshCoreBackupDependencies -ToolPath $fakeHelper } catch {
        $failed = $_.Exception.Message -match 'exit 10' -and $_.Exception.Message -match 'versions'
    }
    if (-not $failed) { throw 'A failed dependency repair did not stop the backup.' }
    if ($ErrorActionPreference -ne 'Stop') { throw 'Failed dependency check changed ErrorActionPreference.' }
    if ($CheckInstalled) {
        # Opt-in smoke check of the real file-based version/API probe. Never
        # install packages just to run tests; no USB transport is constructed.
        & $pythonCommand $helper dependencies --text
        if ($LASTEXITCODE -ne 0) { throw 'Installed MeshCore API smoke check failed.' }
    }
} finally {
    $env:MESHFIRMWARE_TEST_DEPENDENCY_EXIT = $previousExit
    Remove-Item -LiteralPath $fakeHelper -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $scratch -Force
}
Write-Host 'PASS MeshCore dependency launcher (native stderr, spaces, versions, failure, helper pin)'
