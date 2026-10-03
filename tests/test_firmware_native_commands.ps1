$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$tokens = $null; $parseErrors = $null
$path = Join-Path (Split-Path $PSScriptRoot -Parent) 'firmware.cmd'
$ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw $parseErrors }
foreach ($definition in $ast.EndBlock.Statements) {
    if ($definition -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $definition.Name -in @('run_cmd', 'Split-CommandLine', 'Get-EspRomMac')) {
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

# A read-mac child can print a valid MAC before a later fatal failure. Exercise
# the actual capture/exit-code helper and ROM parser together, not a fake exit
# status. The child only prints fixtures; COM999 is never opened.
$script:ESPTOOL_NO_RESET = 'no-reset'
$script:ESPTOOL_READ_MAC = 'read-mac'
$fakeEspTool = '"' + $child + '" -NoProfile -Command "& { [Console]::WriteLine(''MAC: 44:1b:f6:69:c9:c0''); [Console]::Error.WriteLine(''A fatal error occurred: simulated failure''); exit 9 }"'
$failed = $false
try {
    $null = Get-EspRomMac -ComPort 'COM999' -EspToolCommand $fakeEspTool -Before 'no-reset'
} catch {
    $failed = $_.Exception.Message -match 'exit 9' -and
        $_.Exception.Message -match 'MAC: 44:1b:f6:69:c9:c0' -and
        $_.Exception.Message -match 'simulated failure'
}
if (-not $failed) { throw 'An early valid MAC bypassed a later native command failure.' }
Write-Host 'PASS native stderr/exit-code regression tests'
