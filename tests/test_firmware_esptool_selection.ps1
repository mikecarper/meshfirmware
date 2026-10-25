# Real native fixtures; no Python packages, network, or serial-port activity.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$tokens = $null; $parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    (Join-Path (Split-Path $PSScriptRoot -Parent) 'firmware.cmd'), [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw $parseErrors }
foreach ($definition in $ast.EndBlock.Statements) {
    if ($definition -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $definition.Name -in @('get_esptool_cmd', 'Assert-Esp32FinishCapability', 'Split-CommandLine', 'run_cmd')) {
        Invoke-Expression $definition.Extent.Text
    }
    if ($definition -is [System.Management.Automation.Language.IfStatementAst] -and
        $definition.Extent.Text -match 'CommandLineToArgvW') {
        Invoke-Expression $definition.Extent.Text
    }
}
function Assert-True { param([bool]$Condition, [string]$Message); if (-not $Condition) { throw $Message } }
function Expect-Failure {
    param([scriptblock]$Action, [string]$Pattern)
    try { $null = & $Action } catch {
        if ($_.Exception.Message -notmatch ('(?s)' + $Pattern)) { throw }
        Assert-True ($ErrorActionPreference -eq 'Stop') 'Failure changed the caller error preference.'
        return $_.Exception.Message
    }
    throw "Expected a failure matching '$Pattern'."
}
function Wait-FirmwareToolUpdates { $script:Waits++ }
# Reproduces an older global esptool shadowing the selected Python environment.
function esptool { throw 'The unrelated PATH esptool must never be launched.' }
$scratch = Join-Path ([IO.Path]::GetTempPath()) ('esptool selection ' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $scratch
$oldVersion = $env:MESHFIRMWARE_TEST_ESP_VERSION
$oldExit = $env:MESHFIRMWARE_TEST_ESP_EXIT
$oldLog = $env:MESHFIRMWARE_TEST_ESP_ARGS
$oldPythonVersion = $env:MESHFIRMWARE_TEST_ESP_PYTHON_VERSION
$oldPythonExit = $env:MESHFIRMWARE_TEST_ESP_PYTHON_EXIT
try {
    $pythonCommand = Join-Path $scratch 'selected python.cmd'
    $fixture = @'
@echo off
echo %*>>"%MESHFIRMWARE_TEST_ESP_ARGS%"
if "%~1"=="--version" (
    echo harmless Python stderr warning 1>&2
    echo %MESHFIRMWARE_TEST_ESP_PYTHON_VERSION%
    exit /b %MESHFIRMWARE_TEST_ESP_PYTHON_EXIT%
)
echo harmless esptool stderr warning 1>&2
echo %MESHFIRMWARE_TEST_ESP_VERSION%
exit /b %MESHFIRMWARE_TEST_ESP_EXIT%
'@
    Set-Content -LiteralPath $pythonCommand -Value $fixture -Encoding Ascii
    $env:MESHFIRMWARE_TEST_ESP_VERSION = 'esptool v5.5.0'
    $env:MESHFIRMWARE_TEST_ESP_EXIT = '0'
    $env:MESHFIRMWARE_TEST_ESP_ARGS = Join-Path $scratch 'arguments.log'
    $env:MESHFIRMWARE_TEST_ESP_PYTHON_VERSION = 'Python 3.13.5'
    $env:MESHFIRMWARE_TEST_ESP_PYTHON_EXIT = '0'
    $script:Waits = 0
    $output = @(get_esptool_cmd)
    Assert-True ($script:Waits -eq 1) 'Tool selection did not wait for its package updater.'
    $expectedCommand = '"' + $pythonCommand + '" -m esptool'
    Assert-True ($output.Count -eq 1 -and $output[0] -eq $expectedCommand) 'Selected command changed interpreter, lost quoting, or leaked diagnostics.'
    Assert-True ($script:ESPTOOL_PYTHON_COMMAND -eq $pythonCommand) 'Diagnostic interpreter does not match the returned command.'
    Assert-True ($script:ESPTOOL_VERSION -match '5.5.0') 'Selected esptool version was not retained.'
    Assert-True ($script:ESPTOOL_WATCHDOG_RESET -eq 'watchdog-reset') 'Modern capability was lost behind the stale PATH copy.'
    Assert-True ($ErrorActionPreference -eq 'Stop') 'Harmless native stderr changed the error preference.'
    $parts = @(Split-CommandLine $output[0])
    Assert-True ($parts.Count -eq 3 -and $parts[0] -eq $pythonCommand -and $parts[2] -eq 'esptool') 'run_cmd cannot parse the quoted interpreter path.'
    $null = run_cmd "$($output[0]) version"
    $commands = @(Get-Content -LiteralPath $env:MESHFIRMWARE_TEST_ESP_ARGS)
    Assert-True ($commands.Count -eq 2) 'Probe and real command did not both execute the selected interpreter.'
    foreach ($command in $commands) { Assert-True ($command -eq '-m esptool version') 'Probe/flash command prefix diverged.' }
    $identity = [pscustomobject]@{ Esp32ChipType = 'ESP32-S3'; Esp32RomTransport = 'usb-jtag' }
    Assert-Esp32FinishCapability -UsbIdentity $identity
    Assert-True (@(Get-Content -LiteralPath $env:MESHFIRMWARE_TEST_ESP_ARGS).Count -eq 2) 'Supported esptool launched an unnecessary Python version diagnostic.'
    $env:MESHFIRMWARE_TEST_ESP_EXIT = '7'
    $message = Expect-Failure { get_esptool_cmd } 'version check failed.*exit 7.*esptool v5.5.0'
    Assert-True ($message.Contains($pythonCommand)) 'Failed probe did not identify its Python environment.'
    $env:MESHFIRMWARE_TEST_ESP_EXIT = '0'
    $env:MESHFIRMWARE_TEST_ESP_VERSION = 'not a version'
    $null = Expect-Failure { get_esptool_cmd } 'no recognizable version'
    $env:MESHFIRMWARE_TEST_ESP_VERSION = 'esptool.py v4.8.1'
    $null = get_esptool_cmd
    $message = Expect-Failure { Assert-Esp32FinishCapability -UsbIdentity $identity } 'esptool 5 or newer.*4.8.1.*Python 3.13.5.*pip install --upgrade'
    Assert-True ($message.Contains($pythonCommand)) 'Upgrade advice targets a different Python environment.'
    Assert-True ($message -notmatch 'is too old') 'A compatible Python was told to upgrade itself.'
    foreach ($runtime in @('3.7.17', '3.9.21', '3.9.21+')) {
        $env:MESHFIRMWARE_TEST_ESP_PYTHON_VERSION = "Python $runtime"
        $message = Expect-Failure { Assert-Esp32FinishCapability -UsbIdentity $identity } 'Python .* is too old.*Upgrade Python to 3.10 or newer.*PATH.*restart firmware.cmd'
        Assert-True ($message.Contains($runtime) -and $message.Contains($pythonCommand)) 'Old-Python guidance omitted the detected version or interpreter.'
        Assert-True ($message -notmatch 'pip install --upgrade') 'Old Python was sent into an impossible esptool-only repair loop.'
    }
    foreach ($runtime in @('3.10.16', '3.14.0rc2')) {
        $env:MESHFIRMWARE_TEST_ESP_PYTHON_VERSION = "Python $runtime"
        $message = Expect-Failure { Assert-Esp32FinishCapability -UsbIdentity $identity } 'pip install --upgrade'
        Assert-True ($message.Contains("Python $runtime") -and $message -notmatch 'is too old') 'Python minimum-version boundary or prerelease parsing was incorrect.'
    }
    $env:MESHFIRMWARE_TEST_ESP_PYTHON_VERSION = 'Python 3.9.21'
    $env:MESHFIRMWARE_TEST_ESP_PYTHON_EXIT = '7'
    $message = Expect-Failure { Assert-Esp32FinishCapability -UsbIdentity $identity } 'Python unknown.*Could not detect.*Python 3.10 or newer'
    Assert-True ($message -notmatch 'is too old') 'A failed runtime probe was treated as a verified Python version.'
    $env:MESHFIRMWARE_TEST_ESP_PYTHON_EXIT = '0'
    $env:MESHFIRMWARE_TEST_ESP_PYTHON_VERSION = 'unrecognized runtime banner'
    $null = Expect-Failure { Assert-Esp32FinishCapability -UsbIdentity $identity } 'Python unknown.*Could not detect'
    $beforeLegacyCheck = @(Get-Content -LiteralPath $env:MESHFIRMWARE_TEST_ESP_ARGS).Count
    Assert-Esp32FinishCapability -UsbIdentity ([pscustomobject]@{ Esp32ChipType = 'ESP32-S3'; Esp32RomTransport = 'uart' })
    Assert-Esp32FinishCapability -UsbIdentity ([pscustomobject]@{ Esp32ChipType = 'ESP32'; Esp32RomTransport = 'uart' })
    Assert-True (@(Get-Content -LiteralPath $env:MESHFIRMWARE_TEST_ESP_ARGS).Count -eq $beforeLegacyCheck) 'Legacy UART unexpectedly probed or rejected Python/esptool.'
    $pythonCommand = Join-Path $scratch 'absent.exe'
    $null = Expect-Failure { get_esptool_cmd } 'Cannot launch the selected esptool Python'
    $pythonCommand = ''
    $null = Expect-Failure { get_esptool_cmd } 'Python is not configured'
    Write-Host 'PASS esptool selection (same Python as updater, stale PATH ignored, quoted paths, native stderr/exit, version/capability diagnostics)'
} finally {
    $env:MESHFIRMWARE_TEST_ESP_VERSION = $oldVersion
    $env:MESHFIRMWARE_TEST_ESP_EXIT = $oldExit
    $env:MESHFIRMWARE_TEST_ESP_ARGS = $oldLog
    $env:MESHFIRMWARE_TEST_ESP_PYTHON_VERSION = $oldPythonVersion
    $env:MESHFIRMWARE_TEST_ESP_PYTHON_EXIT = $oldPythonExit
    $resolved = [IO.Path]::GetFullPath($scratch)
    $temporary = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    if (-not $resolved.StartsWith($temporary, [StringComparison]::OrdinalIgnoreCase)) { throw 'Cleanup left the temporary directory.' }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
