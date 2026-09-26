$ErrorActionPreference = 'Stop'
$firmwarePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'firmware.cmd'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $firmwarePath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw "firmware.cmd parse failed: $parseErrors" }
$definition = $ast.Find({ param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -eq 'Complete-Esp32FlashSession'
}, $true)
if ($null -eq $definition) { throw 'Missing ESP32 finish function.' }
Invoke-Expression $definition.Extent.Text

$identity = [pscustomobject]@{ SerialNumber = 'CC8DA2E96F34' }
$script:ESPTOOL_NO_RESET = 'no-reset'
$script:ESPTOOL_HARD_RESET = 'hard-reset'
$script:state = 'runtime'
$script:resetCommands = @()
$script:resolvedIdentity = @()
function Resolve-EspUsbComPort {
    param($PreferredComPort, $UsbIdentity, $TimeoutMs, $Purpose)
    $script:resolvedIdentity += $UsbIdentity.SerialNumber
    if ($UsbIdentity.SerialNumber -ne 'CC8DA2E96F34') { throw 'Wrong USB identity.' }
    if ($script:state -eq 'runtime') { return 'COM12' }
    return 'COM11'
}
function Get-EspRuntimeStorageLayout {
    param($ComPort)
    if ($script:state -eq 'runtime' -and $ComPort -eq 'COM12') {
        return 'int:esp32=16384K ext:none; app0*@0x10000+6400K,app1@0x650000+6400K'
    }
    return ''
}
function get_esptool_cmd { return 'esptool' }
function run_cmd {
    param($CommandLine, [switch]$Stream)
    $script:resetCommands += $CommandLine
    if ($script:resetSucceeds) { $script:state = 'runtime'; return 0 }
    return 1
}
function Start-Sleep { param($Milliseconds) }

$port = Complete-Esp32FlashSession -ComPort 'COM11' -UsbIdentity $identity
if ($port -ne 'COM12' -or $script:resetCommands.Count -ne 0) {
    throw 'Already running application was reset or not recognized.'
}

$script:state = 'rom'
$script:resetSucceeds = $true
$port = Complete-Esp32FlashSession -ComPort 'COM11' -UsbIdentity $identity
if ($port -ne 'COM12' -or $script:resetCommands.Count -ne 1 -or
    $script:resetCommands[0] -notmatch '--before no-reset --after hard-reset run$') {
    throw 'ROM did not receive a hard reset and return as the application.'
}
if (@($script:resolvedIdentity | Where-Object { $_ -ne $identity.SerialNumber }).Count) {
    throw 'ESP32 reboot lookup lost selected USB identity.'
}

$script:state = 'rom'
$script:resetSucceeds = $false
$failed = $false
try { $null = Complete-Esp32FlashSession -ComPort 'COM11' -UsbIdentity $identity }
catch {
    if ($_.Exception.Message -notmatch 'did not answer') { throw }
    $failed = $true
}
if (-not $failed) { throw 'Flash was reported successful while application stayed in ROM.' }
Write-Host 'PASS ESP32 runtime recognition, hard-reset recovery, and failure reporting'
