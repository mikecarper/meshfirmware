# Exercise the Windows menu launcher without a network connection or radio.
$ErrorActionPreference = 'Stop'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    (Join-Path (Split-Path $PSScriptRoot -Parent) 'firmware.cmd'), [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw "firmware.cmd parse failed: $parseErrors" }
$definition = $ast.Find({ param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Invoke-StationRecovery'
}, $true)
if (-not $definition) { throw 'Missing recovery entry' }
Invoke-Expression $definition.Extent.Text
function Get-Command { return [pscustomobject]@{ Source = 'Invoke-RecoveryPythonFixture' } }
function GetPortablePython { throw 'Unexpected Python download' }
function GetHW { throw 'Recovery must not query a crashing application' }
function check_requirements { throw 'Recovery must not install unrelated tools' }
function Invoke-RecoveryPythonFixture {
    if ($args[0] -eq '--version') { $global:LASTEXITCODE = 0; return }
    $script:launcherPath = $args[0]
    $program = [IO.File]::ReadAllText($script:launcherPath)
    if ($program -notmatch 'SHA256 = "[0-9a-f]{64}"') { throw 'Package pin missing' }
    if ($args[1] -ne '--guided') { throw 'Recovery wizard not selected' }
    # This output must reach the user, not contaminate the return code.
    Write-Output 'Recovery fixture output'
    $global:LASTEXITCODE = $script:backendStatus
}
foreach ($script:backendStatus in @(0, 1, 2, 7)) {
    $result = Invoke-StationRecovery
    if ($result -ne $script:backendStatus) { throw "Lost backend exit code: $result" }
    if (Test-Path -LiteralPath $script:launcherPath) { throw 'Temporary launcher leaked' }
}
Write-Host 'PASS: Windows recovery entry preserves failures, cleans up, and bypasses normal flasher setup'
exit 0
