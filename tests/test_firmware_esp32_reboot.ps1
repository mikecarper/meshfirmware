$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$firmwarePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'firmware.cmd'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $firmwarePath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw "firmware.cmd parse failed: $parseErrors" }
foreach ($name in @(
    'Complete-Esp32FlashSession', 'New-Esp32ApplicationVerificationTimer',
    'Get-EspUsbBootloaderStrategy', 'Get-Esp32RomBeforeMode',
    'Get-Esp32RomSessionStamp', 'Assert-Esp32FinishCapability', 'Get-Esp32WriteAfterMode',
    'Get-EspRomMac', 'Set-Esp32VerifiedChipMac', 'Assert-Esp32RomChipIdentity',
    'Test-UsbComPortIdentityMatch', 'Get-UsbIdentityInterfaceNumber', 'Install-SimpleMergedEspImage'
)) {
    $definition = $ast.Find({ param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq $name
    }, $true)
    if ($null -eq $definition) { throw "Missing function: $name" }
    Invoke-Expression $definition.Extent.Text
}

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}
function Expect-Failure {
    param([scriptblock]$Action, [string]$Pattern)
    $failed = $false
    try { & $Action } catch {
        if ($_.Exception.Message -notmatch $Pattern) { throw }
        $failed = $true
    }
    if (-not $failed) { throw "Expected failure matching '$Pattern'." }
}

$realTimer = New-Esp32ApplicationVerificationTimer
Assert-True ($realTimer -is [System.Diagnostics.Stopwatch] -and $realTimer.IsRunning) `
    'Production first-boot verification does not use a running monotonic timer.'
$realTimer.Stop()

function New-Identity {
    param([string]$Description = 'Espressif USB JTAG/serial debug unit', [string]$Serial = 'CC8DA2E96F34')
    return [pscustomobject]@{
        SerialNumber = $Serial
        ParentInstanceId = "USB\VID_303A&PID_1001\$Serial"
        LocationPath = 'PCIROOT(0)#USBROOT(0)#USB(3)'
        InterfaceNumber = '00'
        BusReportedDescription = $Description
    }
}
function Reset-Fixture {
    param([string]$Description = 'Espressif USB JTAG/serial debug unit')
    $script:expected = New-Identity $Description
    $script:actual = New-Identity $Description
    $script:state = 'rom'
    $script:port = 'COM11'
    $script:chipType = 'ESP32-S3'
    $script:mac = 'cc:8d:a2:e9:6f:34'
    $script:commands = @()
    $script:resetSucceeds = $true
    $script:resetThrows = $false
    $script:resetStartsApp = $true
    $script:runtimeAnswers = $true
    $script:sameEndpoint = $false
    $script:swapAfterReset = $false
    $script:missingAfterReset = $false
    $script:swapDuringMac = $false
    $script:writeFails = $false
    $script:verificationTimeMs = 0
    $script:runtimeProbeCount = 0
    $script:runtimeReadyAtMs = 0
    $script:runtimeUsbReadyAtMs = 0
    $script:swapDuringRuntimeReply = $false
    $script:sleepCount = 0
    $script:hostMessages = @()
    $script:ESPTOOL_NO_RESET = 'no-reset'
    $script:ESPTOOL_HARD_RESET = 'hard-reset'
    $script:ESPTOOL_WATCHDOG_RESET = 'watchdog-reset'
    $script:ESPTOOL_DEFAULT_RESET = 'default-reset'
    $script:ESPTOOL_READ_MAC = 'read-mac'
    $script:ESPTOOL_WRITE_MEM = 'write-mem'
    $script:ESPTOOL_WRITE_FLASH = 'write-flash'
    $script:ESPTOOL_ERASE_FLASH = 'erase-flash'
}
function Resolve-EspUsbComPort {
    param($PreferredComPort, $UsbIdentity, $TimeoutMs, $Purpose)
    if ($script:missingAfterReset -and $script:state -eq 'runtime') { throw 'Selected USB device missing.' }
    if ($script:state -eq 'runtime' -and $script:verificationTimeMs -lt $script:runtimeUsbReadyAtMs) {
        throw 'Selected USB device is re-enumerating.'
    }
    if (-not (Test-UsbComPortIdentityMatch -Expected $UsbIdentity -Actual $script:actual)) {
        throw 'Selected USB identity changed.'
    }
    return $script:port
}
function Get-UsbComPortIdentity {
    param($ComPort)
    if ($ComPort -ne $script:port) { return $null }
    return $script:actual
}
function Get-EspRuntimeStorageLayout {
    param($ComPort)
    $script:runtimeProbeCount++
    $script:verificationTimeMs += 3000
    Assert-True (Test-UsbComPortIdentityMatch -Expected $script:expected -Actual $script:actual) `
        'A runtime query was sent to a different physical radio.'
    if ($script:state -eq 'runtime' -and $script:runtimeAnswers -and $ComPort -eq $script:port -and
        $script:verificationTimeMs -ge $script:runtimeReadyAtMs) {
        if ($script:swapDuringRuntimeReply) { $script:actual = New-Identity -Serial '441BF669CF98' }
        return 'int:esp32=16384K ext:none; app0*@0x10000+6400K,app1@0x650000+6400K'
    }
    return ''
}
function get_esptool_cmd { return 'esptool' }
function run_cmd {
    param($CommandLine, [switch]$Stream)
    $script:commands += $CommandLine
    if ($CommandLine -match '(?:read-mac|read_mac)$') {
        if ($script:state -ne 'rom') { throw 'A bootloader query was sent to the application.' }
        if ($script:swapDuringMac) { $script:actual = New-Identity -Serial '441BF669CF98' }
        return "Chip type: $script:chipType`nMAC: $script:mac`nStaying in bootloader."
    }
    if ($CommandLine -match '(?:write-flash|write_flash) ') {
        if ($script:writeFails) { throw 'Simulated image write failure.' }
        return 0
    }
    if ($CommandLine -match '(?:erase-flash|erase_flash)$') { return 0 }
    if ($script:resetThrows) {
        $script:state = 'runtime'
        throw 'Reset may have succeeded before disconnect.'
    }
    if (-not $script:resetSucceeds) { return 7 }
    if ($script:resetStartsApp) {
        $script:state = 'runtime'
        if (-not $script:sameEndpoint) { $script:port = 'COM12' }
        if ($script:swapAfterReset) { $script:actual = New-Identity -Serial '441BF669CF98' }
    }
    return 0
}
function New-Esp32ApplicationVerificationTimer {
    # Model a new monotonic stopwatch per call; no real waits or device access.
    $timer = [pscustomobject]@{ StartedAtMs = $script:verificationTimeMs }
    $timer | Add-Member -MemberType ScriptProperty -Name ElapsedMilliseconds -Value {
        $script:verificationTimeMs - $this.StartedAtMs
    }
    return $timer
}
function Start-Sleep {
    param($Milliseconds)
    $script:sleepCount++
    $script:verificationTimeMs += $Milliseconds
}
function Write-Host {
    param($Object)
    $script:hostMessages += [string]$Object
}
function Bind-RomSession {
    $null = Assert-Esp32RomChipIdentity -ComPort $script:port -UsbIdentity $script:expected `
        -EspToolCommand 'esptool'
    $script:commands = @()
}
function Enter-Esp32Bootloader {
    param($ComPort, $UsbIdentity, $EspToolCommand)
    $livePort = Assert-Esp32RomChipIdentity -ComPort $ComPort -UsbIdentity $UsbIdentity `
        -EspToolCommand $EspToolCommand
    Assert-Esp32FinishCapability -UsbIdentity $UsbIdentity
    return $livePort
}

# Hardware JTAG descriptors can remain identical to ROM. Missing CLI alone
# must never authorize SLIP commands, even when the USB serial still matches.
Reset-Fixture
$script:state = 'runtime'
$script:port = 'COM12'
$port = Complete-Esp32FlashSession -ComPort 'COM11' -UsbIdentity $script:expected
Assert-True ($port -eq 'COM12' -and $script:commands.Count -eq 0) 'Running app was probed/reset.'
Assert-True ($script:runtimeProbeCount -eq 1 -and $script:sleepCount -eq 0) `
    'A ready application waited through the first-boot budget instead of returning immediately.'
Assert-True (@($script:hostMessages | Where-Object { $_ -like 'Waiting for*' }).Count -eq 0) `
    'A ready application printed a slow-boot warning.'

# A healthy first boot may not serve the CLI until storage/identity work is
# done, well beyond the previous eight short probes. Keep waiting, never reset.
Reset-Fixture
Bind-RomSession
$script:runtimeReadyAtMs = 80000
$port = Complete-Esp32FlashSession -ComPort 'COM11' -UsbIdentity $script:expected
Assert-True ($port -eq 'COM12' -and $script:runtimeProbeCount -gt 8 -and
    $script:verificationTimeMs -ge 80000 -and $script:verificationTimeMs -lt 120000) `
    'Slow first boot was not verified within the longer startup allowance.'
Assert-True ($script:commands.Count -eq 2 -and -not $script:expected.Esp32RomSessionActive) `
    'Slow application startup triggered an additional ROM query or reset.'
$waitingMessages = @($script:hostMessages | Where-Object { $_ -like 'Waiting for*' })
Assert-True ($waitingMessages.Count -gt 0 -and $waitingMessages.Count -le 6) `
    'Slow-boot waiting notices were missing or printed on every retry.'

# A selected radio may temporarily disappear, then return under a new COM
# number before its slow first boot completes. Only that identity is queried.
Reset-Fixture
Bind-RomSession
$script:runtimeUsbReadyAtMs = 20000
$script:runtimeReadyAtMs = 60000
$port = Complete-Esp32FlashSession -ComPort 'COM11' -UsbIdentity $script:expected
Assert-True ($port -eq 'COM12' -and $script:verificationTimeMs -ge 60000 -and
    $script:commands.Count -eq 2) 'Delayed same-device USB return was rejected or reset again.'

# A reply racing a device swap cannot count as application boot proof.
Reset-Fixture
$script:state = 'runtime'
$script:port = 'COM12'
$script:swapDuringRuntimeReply = $true
Expect-Failure { Complete-Esp32FlashSession -ComPort 'COM11' -UsbIdentity $script:expected } `
    'Application boot is unverified'
Assert-True ($script:commands.Count -eq 0 -and $script:runtimeProbeCount -eq 1) `
    'USB identity was not rechecked after reading an application reply.'

Reset-Fixture
Expect-Failure { Complete-Esp32FlashSession -ComPort 'COM11' -UsbIdentity $script:expected } 'Application boot is unverified'
Assert-True ($script:commands.Count -eq 0) 'Identical JTAG descriptors or absent CLI triggered blind SLIP.'
Assert-True ($script:verificationTimeMs -ge 120000 -and $script:verificationTimeMs -le 123000) `
    'Default application verification did not honor its bounded two-minute budget.'

Reset-Fixture
Expect-Failure { Complete-Esp32FlashSession -ComPort 'COM11' -UsbIdentity $script:expected `
    -ApplicationVerificationTimeoutSec 1 } 'within 1 seconds'
Assert-True ($script:runtimeProbeCount -eq 1 -and $script:commands.Count -eq 0) `
    'An explicit short verification budget caused a reset or unbounded retry loop.'
Reset-Fixture
Expect-Failure { Complete-Esp32FlashSession -ComPort 'COM11' -UsbIdentity $script:expected `
    -ApplicationVerificationTimeoutSec 0 } 'range|greater than or equal'
Assert-True ($script:runtimeProbeCount -eq 0 -and $script:commands.Count -eq 0) `
    'An invalid verification timeout reached a device operation.'

# Skip/bridge paths must never consume the normal application wait, and must
# not claim that a descriptor match proves startup.
Reset-Fixture
Bind-RomSession
$port = Complete-Esp32FlashSession -ComPort 'COM11' -UsbIdentity $script:expected -SkipApplicationVerification
Assert-True ($port -eq 'COM12' -and $script:runtimeProbeCount -eq 0 -and
    $script:verificationTimeMs -eq 0 -and $script:commands.Count -eq 2) `
    'Skip verification entered the startup wait or repeated the final reset.'
Reset-Fixture
Bind-RomSession
$null = Complete-Esp32FlashSession -ComPort 'COM11' -UsbIdentity $script:expected `
    -SkipApplicationVerification -PartitionBridgeBoot
Assert-True ($script:runtimeProbeCount -eq 0 -and $script:verificationTimeMs -eq 0 -and
    $script:commands.Count -eq 2) 'Partition bridge used the ordinary application startup loop.'

Reset-Fixture
Bind-RomSession
$port = Complete-Esp32FlashSession -ComPort 'COM11' -UsbIdentity $script:expected
Assert-True ($port -eq 'COM12' -and $script:commands.Count -eq 2) 'Native finish lost its selected identity.'
Assert-True ($script:commands[0] -match '--before no-reset --after no-reset read-mac$') 'Final reset omitted immediate MAC verification.'
Assert-True ($script:commands[1] -match '--before no-reset --after watchdog-reset write-mem 0x6000812c 0x0 0x1$') 'Native S3 reset did not clear only OPTION1 bit0 before watchdog reset.'
Assert-True (-not $script:expected.Esp32RomSessionActive) 'Reset left the ROM session reusable.'

# Same tty is acceptable physical identity, never application-boot proof.
Reset-Fixture
Bind-RomSession
$script:sameEndpoint = $true
$port = Complete-Esp32FlashSession -ComPort 'COM11' -UsbIdentity $script:expected
Assert-True ($port -eq 'COM11' -and $script:commands.Count -eq 2) 'Same endpoint prevented valid application handoff.'
Reset-Fixture
Bind-RomSession
$script:resetStartsApp = $false
Expect-Failure { Complete-Esp32FlashSession -ComPort 'COM11' -UsbIdentity $script:expected } 'Application boot is unverified'
Assert-True ($script:commands.Count -eq 2) 'Silent endpoint triggered bootloader retry after reset.'
$script:commands = @()
Expect-Failure { Complete-Esp32FlashSession -ComPort 'COM11' -UsbIdentity $script:expected } 'no bootloader retry'
Assert-True ($script:commands.Count -eq 0) 'Failed handoff kept a stale ROM session.'

foreach ($failure in @('resetSucceeds', 'resetThrows')) {
    Reset-Fixture
    Bind-RomSession
    if ($failure -eq 'resetSucceeds') { $script:resetSucceeds = $false } else { $script:resetThrows = $true }
    Expect-Failure { Complete-Esp32FlashSession -ComPort 'COM11' -UsbIdentity $script:expected } '(?:final reset failed|disconnect)'
    Assert-True ($script:commands.Count -eq 2 -and -not $script:expected.Esp32RomSessionActive) 'Failed reset retried or retained ROM trust.'
}

# Identity/MAC/stamp conflicts fail before the masked register write.
Reset-Fixture
Bind-RomSession
$script:actual = New-Identity -Serial '441BF669CF98'
Expect-Failure { Complete-Esp32FlashSession -ComPort 'COM11' -UsbIdentity $script:expected } 'identity changed'
Assert-True ($script:commands.Count -eq 0) 'Different USB radio received bootloader commands.'
Reset-Fixture
Bind-RomSession
$script:actual.LocationPath = 'PCIROOT(0)#USBROOT(0)#USB(9)'
Expect-Failure { Complete-Esp32FlashSession -ComPort 'COM11' -UsbIdentity $script:expected } 'ROM session changed'
Assert-True ($script:commands.Count -eq 0) 'Changed ROM endpoint received SLIP based solely on serial.'
Reset-Fixture
Bind-RomSession
$script:mac = '44:1b:f6:69:cf:98'
Expect-Failure { Complete-Esp32FlashSession -ComPort 'COM11' -UsbIdentity $script:expected } 'chip MAC changed'
Assert-True ($script:commands.Count -eq 1) 'Changed chip MAC received a register write.'
Reset-Fixture
Bind-RomSession
$script:swapDuringMac = $true
Expect-Failure { Complete-Esp32FlashSession -ComPort 'COM11' -UsbIdentity $script:expected } 'endpoint changed'
Assert-True ($script:commands.Count -eq 1) 'USB swap after final MAC query received a register write.'
Reset-Fixture
Bind-RomSession
$script:expected.Esp32ChipMac = ''
Expect-Failure { Complete-Esp32FlashSession -ComPort 'COM11' -UsbIdentity $script:expected } 'previously verified ESP32 chip MAC'
Assert-True ($script:commands.Count -eq 0) 'Missing bound MAC was silently learned at finish.'
Reset-Fixture
Bind-RomSession
$script:chipType = 'ESP32-C3'
Expect-Failure { Complete-Esp32FlashSession -ComPort 'COM11' -UsbIdentity $script:expected } 'No qualified final reset'
Assert-True ($script:commands.Count -eq 1) 'A non-S3 chip received the S3-specific register write.'
foreach ($failure in @('swapAfterReset', 'missingAfterReset')) {
    Reset-Fixture
    Bind-RomSession
    Set-Variable -Name $failure -Scope Script -Value $true
    Expect-Failure { Complete-Esp32FlashSession -ComPort 'COM11' -UsbIdentity $script:expected } 'Application boot is unverified'
    Assert-True ($script:commands.Count -eq 2) 'Lost post-reset identity triggered bootloader retries.'
}

# External UART retains qualified reset and legacy spellings.
Reset-Fixture 'Silicon Labs CP2102 USB to UART Bridge Controller'
$script:expected.SerialNumber = 'BRIDGE-001'
$script:actual.SerialNumber = 'BRIDGE-001'
$script:ESPTOOL_NO_RESET = 'no_reset'
$script:ESPTOOL_DEFAULT_RESET = 'default_reset'
$script:ESPTOOL_HARD_RESET = 'hard_reset'
$script:ESPTOOL_READ_MAC = 'read_mac'
$script:ESPTOOL_WRITE_MEM = 'write_mem'
$script:ESPTOOL_WATCHDOG_RESET = ''
Bind-RomSession
Assert-True ((Get-Esp32WriteAfterMode -UsbIdentity $script:expected) -eq 'hard_reset') 'UART S3 reset policy changed.'
$null = Complete-Esp32FlashSession -ComPort 'COM11' -UsbIdentity $script:expected
Assert-True ($script:commands[1] -match '--before default_reset --after hard_reset run$') 'UART S3 received native watchdog reset.'

# Native S3 refuses unsupported esptool4 before the first erase/write.
Reset-Fixture
$script:ESPTOOL_WRITE_MEM = 'write_mem'
$script:ESPTOOL_WATCHDOG_RESET = ''
Expect-Failure { Install-SimpleMergedEspImage -ImagePath $firmwarePath -ComPort 'COM11' -UsbIdentity $script:expected } 'esptool 5 or newer'
Assert-True (@($script:commands | Where-Object { $_ -match 'erase-flash|write-flash|write-mem' }).Count -eq 0) 'Unsupported native reset was discovered only after erase/write.'

# Direct merged-image callers finish once without falsely claiming app boot.
Reset-Fixture
$null = Install-SimpleMergedEspImage -ImagePath $firmwarePath -ComPort 'COM11' -UsbIdentity $script:expected
$writes = @($script:commands | Where-Object { $_ -match 'write-flash ' })
$resets = @($script:commands | Where-Object { $_ -match 'watchdog-reset' })
Assert-True ($writes.Count -eq 1 -and $writes[0] -match '--after no-reset write-flash' -and $resets.Count -eq 1) 'Merged install reset before native finish or omitted reset.'
Assert-True (-not $script:expected.Esp32RomSessionActive) 'Merged install left stale ROM session after reset.'
Reset-Fixture
$script:writeFails = $true
Expect-Failure { Install-SimpleMergedEspImage -ImagePath $firmwarePath -ComPort 'COM11' -UsbIdentity $script:expected } 'image write failure'
Assert-True (-not $script:expected.Esp32RomSessionActive -and @($script:commands | Where-Object { $_ -match 'watchdog-reset' }).Count -eq 0) 'Failed image write retained trust or issued final reset.'

Microsoft.PowerShell.Utility\Write-Host 'PASS ESP32 bounded slow-first-boot verification, masked watchdog finish, ROM/MAC gates, UART legacy reset, and no blind bootloader retries'
