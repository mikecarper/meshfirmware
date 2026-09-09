$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$tokens = $null; $parseErrors = $null
$path = Join-Path (Split-Path $PSScriptRoot -Parent) 'firmware.cmd'
$ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw $parseErrors }
foreach ($definition in $ast.EndBlock.Statements) {
    if ($definition -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $definition.Name -in @('run_cmd', 'Split-CommandLine')) {
        Invoke-Expression $definition.Extent.Text
    }
    if ($definition -is [System.Management.Automation.Language.IfStatementAst] -and
        $definition.Extent.Text -match 'CommandLineToArgvW') {
        Invoke-Expression $definition.Extent.Text
    }
}
# Run a real native child, not a mocked PowerShell function: Windows PS5
# treats its stderr differently from PS7 even when the exit status is zero.
$child = (Get-Command powershell.exe -ErrorAction Stop).Source
$command = '"' + $child + '" -NoProfile -Command "[Console]::Error.WriteLine(''harmless warning''); [Console]::WriteLine(''finished''); exit 0"'
$result = run_cmd $command
if ($result -notmatch 'harmless warning' -or $result -notmatch 'finished') {
    throw 'Successful native stderr/stdout was not preserved.'
}
if ($ErrorActionPreference -ne 'Stop') { throw 'Error preference leaked out of run_cmd.' }
$command = $command.Replace('exit 0', 'exit 7')
$failed = $false
try { $null = run_cmd $command } catch {
    $failed = $_.Exception.Message -match 'exit 7' -and $_.Exception.Message -match 'harmless warning'
}
if (-not $failed) { throw 'A native failure was not reported with its exit code/output.' }
$failed = $false
try { $null = run_cmd 'meshfirmware-nonexistent-executable-394205 --version' } catch { $failed = $true }
if (-not $failed) { throw 'A missing executable was silently accepted.' }
Write-Host 'PASS native stderr/exit-code regression tests'
