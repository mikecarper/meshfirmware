$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$firmwarePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'firmware.cmd'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $firmwarePath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw "firmware.cmd parse failed: $parseErrors" }

function Load-FirmwareFunction {
    param([string]$Name)
    $definition = $ast.Find({ param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq $Name
    }, $true)
    if ($null -eq $definition) { throw "Missing function: $Name" }
    # Function definitions must remain in the script test scope.
    return $definition.Extent.Text
}
foreach ($name in @(
    'Wait-FirmwareToolUpdates', 'Enter-FirmwareToolUse',
    'Get-EspUsbBootloaderStrategy', 'Get-Esp32RomBeforeMode', 'New-EspUsbTouchSerialPort',
    'Invoke-EspTinyUsbTouch1200', 'Get-EspRomMac', 'Set-Esp32VerifiedChipMac',
    'Assert-Esp32RomChipIdentity', 'Enter-Esp32Bootloader',
    'Assert-UsbComPortIdentityFor1200Touch', 'Test-UsbComPortIdentityMatch',
    'Get-UsbIdentityInterfaceNumber', 'Get-UsbIdentityDisplayText', 'get_esptool_cmd',
    'Get-Esp32RomSessionStamp', 'Assert-Esp32FinishCapability', 'Get-Esp32WriteAfterMode'
)) { Invoke-Expression (Load-FirmwareFunction $name) }

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
function New-Identity {
    param([string]$Description, [string]$Serial = '441BF669C9C0')
    return [pscustomobject]@{
        SerialNumber = $Serial
        LocationPath = 'PCIROOT(0)#USBROOT(0)#USB(3)'
        ParentInstanceId = "USB\VID_303A&PID_1001\$Serial"
        BusReportedDescription = $Description
        InterfaceNumber = '00'
    }
}

# Matching VID/PID alone cannot select a protocol or a physical radio. Product
# strings determine the reset mode only after the selected identity is checked.
foreach ($case in @(
    @('heltec_wifi_lora_32 v4 (16 MB FLASH, 2 MB PSRAM) - TinyUSB CDC', 'tinyusb'),
    @('TinyUSB CDC USB JTAG/serial', 'tinyusb'),
    @('Espressif USB JTAG/serial debug unit', 'usb-jtag'),
    @('USB Serial/JTAG', 'usb-jtag'),
    @('Silicon Labs CP2102 USB to UART Bridge Controller', 'uart'),
    @('USB-SERIAL CH340', 'uart'),
    @('FT232R USB UART', 'uart'),
    @('USB Serial Device', 'unknown'),
    @('', 'unknown')
)) {
    $actual = Get-EspUsbBootloaderStrategy -UsbIdentity (New-Identity $case[0])
    Assert-True ($actual -eq $case[1]) "Wrong reset protocol for '$($case[0])': $actual"
}
$interfaceHint = New-Identity 'Heltec WiFi LoRa32 V4'
$interfaceHint | Add-Member -NotePropertyName InterfaceReportedDescription -NotePropertyValue 'TinyUSB CDC'
Assert-True ((Get-EspUsbBootloaderStrategy -UsbIdentity $interfaceHint) -eq 'tinyusb') `
    'TinyUSB interface descriptor was lost behind the board product name.'

# Constructing this object does not open COM999 or access any USB device.
$touchPort = New-EspUsbTouchSerialPort -ComPort 'COM999'
try {
    Assert-True (-not $touchPort.IsOpen -and $touchPort.BaudRate -eq 1200 -and
        -not $touchPort.DtrEnable -and -not $touchPort.RtsEnable -and
        $touchPort.Handshake -eq [System.IO.Ports.Handshake]::None) `
        'TinyUSB touch starts with active control lines or opens a device in its factory.'
} finally { $touchPort.Dispose() }

# Test command spelling with the banner and bare version output used by
# esptool4/5. This mocked executable does not launch esptool or open a port.
function esptool { param($Verb) return $script:versionOutput }
foreach ($version in @('esptool.py v4.8.1', "esptool v5.1.0`n5.1.0", '5.1.0')) {
    $script:versionOutput = $version
    $null = get_esptool_cmd
    $newSyntax = $version -match '(?:^|v)5\.'
    Assert-True ($script:ESPTOOL_READ_MAC -eq $(if ($newSyntax) { 'read-mac' } else { 'read_mac' })) `
        'MAC command spelling does not follow the esptool version.'
    Assert-True ($script:ESPTOOL_USB_RESET -eq $(if ($newSyntax) { 'usb-reset' } else { 'usb_reset' })) `
        'USB/JTAG reset spelling does not follow the esptool version.'
    Assert-True ($script:ESPTOOL_WRITE_MEM -eq $(if ($newSyntax) { 'write-mem' } else { 'write_mem' })) `
        'Masked register-write spelling does not follow the esptool version.'
    Assert-True ($script:ESPTOOL_WATCHDOG_RESET -eq $(if ($newSyntax) { 'watchdog-reset' } else { '' })) `
        'Unsupported legacy watchdog-reset was advertised as usable.'
}
$script:ESPTOOL_READ_MAC = 'read-mac'
$script:ESPTOOL_NO_RESET = 'no-reset'
$script:ESPTOOL_USB_RESET = 'usb-reset'
$script:ESPTOOL_DEFAULT_RESET = 'default-reset'

function Start-Sleep { param($Milliseconds) }
function Reset-Fixture {
    param([string]$Description, [string]$Serial = '441BF669C9C0')
    $script:expected = New-Identity $Description $Serial
    $script:actual = New-Identity $Description $Serial
    $script:state = 'runtime'
    $script:mac = '44:1b:f6:69:c9:c0'
    $script:events = @()
    $script:touchThrows = $false
    $script:touchReboots = $true
    $script:swapAfterTouch = $false
    $script:missingMac = $false
    $script:ambiguousMac = $false
    $script:changeMacAfterReset = $false
    $script:romInterface = '00'
    $script:resetTransportThrows = $false
    $script:macThenFatal = $false
}
function Resolve-EspUsbComPort {
    param($PreferredComPort, $UsbIdentity, $TimeoutMs, $Purpose)
    $script:events += "resolve:$Purpose"
    if (-not (Test-UsbComPortIdentityMatch -Expected $script:expected -Actual $UsbIdentity)) {
        throw 'Resolver lost the selected physical identity.'
    }
    if ($script:state -eq 'rom') { return 'COM22' }
    return 'COM7'
}
function Get-UsbComPortIdentity {
    param($ComPort)
    $script:events += "identity:$ComPort"
    return $script:actual
}
function New-EspUsbTouchSerialPort {
    param($ComPort)
    $script:events += "touch-factory:$ComPort"
    $port = [pscustomobject]@{ IsOpen = $false; DtrEnable = $false; RtsEnable = $false }
    $port | Add-Member -MemberType ScriptMethod -Name Open -Value {
        $script:events += 'touch-open'
        if ($script:touchReboots) {
            $script:state = 'rom'
            $serial = if ($script:swapAfterTouch) { '441BF669CF98' } else { $script:actual.SerialNumber }
            $script:actual = New-Identity 'Espressif USB JTAG/serial debug unit' $serial
            $script:actual.InterfaceNumber = $script:romInterface
        }
        if ($script:touchThrows) { throw 'Device disconnected during open.' }
        $this.IsOpen = $true
    }
    $port | Add-Member -MemberType ScriptMethod -Name Close -Value {
        $script:events += 'touch-close'; $this.IsOpen = $false
    }
    $port | Add-Member -MemberType ScriptMethod -Name Dispose -Value {
        $script:events += 'touch-dispose'
    }
    return $port
}
function run_cmd {
    param($CommandLine)
    $script:events += "rom:$CommandLine"
    if ($CommandLine -match '--before (usb-reset|default-reset)') { $script:state = 'rom' }
    if ($script:resetTransportThrows -and $CommandLine -match '--before usb-reset') {
        throw 'Native command failed (exit2): Could not open port after reset.'
    }
    if ($script:state -ne 'rom') { throw 'No serial data received from ROM.' }
    if ($script:missingMac) { return 'Chip is ESP32-S3; no MAC in response.' }
    if ($script:ambiguousMac) { return "MAC: $script:mac`nMAC: 44:1b:f6:69:cf:98" }
    if ($script:macThenFatal) { return "MAC: $script:mac`nA fatal error occurred: Flash ID read failed." }
    $reply = "Chip type: ESP32-S3`nMAC: $script:mac`nStaying in bootloader."
    if ($script:changeMacAfterReset -and $CommandLine -match '--before default-reset') {
        $script:mac = '44:1b:f6:69:cf:98'
    }
    return $reply
}

Reset-Fixture 'heltec_wifi_lora_32 v4 - TinyUSB CDC'
$port = Enter-Esp32Bootloader -ComPort 'COM7' -UsbIdentity $script:expected -EspToolCommand 'esptool'
Assert-True ($port -eq 'COM22' -and $script:expected.Esp32ChipMac -eq '441BF669C9C0') `
    'TinyUSB handoff lost COM renumbering or chip MAC.'
Assert-True (@($script:events | Where-Object { $_ -eq 'touch-open' }).Count -eq 1) `
    'TinyUSB did not receive exactly one software handoff.'
Assert-True (@($script:events | Where-Object { $_ -match 'rom:.*(?:usb-reset|--baud 1200)' }).Count -eq 0) `
    'TinyUSB was sent the hardware USB/JTAG reset or an implicit esptool1200 reset.'
Assert-True (@($script:events | Where-Object { $_ -match 'rom:.*--before no-reset --after no-reset read-mac$' }).Count -eq 1) `
    'TinyUSB success was not proven by a no-reset ROM MAC query.'

Reset-Fixture 'TinyUSB CDC'
$script:romInterface = ''
$null = Enter-Esp32Bootloader -ComPort 'COM7' -UsbIdentity $script:expected -EspToolCommand 'esptool'
Assert-True ($script:expected.Esp32ChipMac -eq '441BF669C9C0') `
    'ROM interface change was mistaken for a different physical radio.'

Reset-Fixture 'TinyUSB CDC'
$script:touchThrows = $true
$null = Enter-Esp32Bootloader -ComPort 'COM7' -UsbIdentity $script:expected -EspToolCommand 'esptool'
Assert-True ($script:expected.Esp32ChipMac -eq '441BF669C9C0') `
    'A successful reset/disconnect exception prevented ROM verification.'

Reset-Fixture 'TinyUSB CDC'
$script:touchThrows = $true; $script:touchReboots = $false
Expect-Failure { Enter-Esp32Bootloader -ComPort 'COM7' -UsbIdentity $script:expected -EspToolCommand 'esptool' } `
    'No serial data received'

Reset-Fixture 'Espressif USB JTAG/serial debug unit'
$null = Enter-Esp32Bootloader -ComPort 'COM7' -UsbIdentity $script:expected -EspToolCommand 'esptool'
Assert-True (@($script:events | Where-Object { $_ -match 'rom:.*--before usb-reset' }).Count -eq 1 -and
    @($script:events | Where-Object { $_ -like 'touch-*' }).Count -eq 0) `
    'Hardware USB/JTAG reset was confused with TinyUSB.'

Reset-Fixture 'Espressif USB JTAG/serial debug unit'
$script:resetTransportThrows = $true
$port = Enter-Esp32Bootloader -ComPort 'COM7' -UsbIdentity $script:expected -EspToolCommand 'esptool'
Assert-True ($port -eq 'COM22' -and $script:expected.Esp32ChipMac -eq '441BF669C9C0') `
    'USB/JTAG reset succeeded but its COM-number transition prevented ROM verification.'

Reset-Fixture 'Silicon Labs CP2102 USB to UART Bridge Controller' 'BRIDGE-001'
$null = Enter-Esp32Bootloader -ComPort 'COM7' -UsbIdentity $script:expected -EspToolCommand 'esptool'
Assert-True (@($script:events | Where-Object { $_ -match 'rom:.*--before default-reset' }).Count -eq 2 -and
    @($script:events | Where-Object { $_ -match 'rom:.*--before no-reset' }).Count -eq 0 -and
    @($script:events | Where-Object { $_ -like 'touch-*' }).Count -eq 0) `
    'UART bridge was sent a native USB touch or its reopen omitted the qualified default reset.'
$script:mac = '44:1b:f6:69:cf:98'
Expect-Failure { Assert-Esp32RomChipIdentity -ComPort 'COM22' -UsbIdentity $script:expected -EspToolCommand 'esptool' } `
    'chip MAC changed'

Reset-Fixture 'Silicon Labs CP2102 USB to UART Bridge Controller' 'BRIDGE-001'
$script:changeMacAfterReset = $true
Expect-Failure { Enter-Esp32Bootloader -ComPort 'COM7' -UsbIdentity $script:expected -EspToolCommand 'esptool' } `
    'chip MAC changed'

Reset-Fixture 'USB Serial Device'
$script:state = 'rom'
Expect-Failure { Enter-Esp32Bootloader -ComPort 'COM7' -UsbIdentity $script:expected -EspToolCommand 'esptool' } `
    'protocol is unknown'
Assert-True (@($script:events | Where-Object { $_ -like 'touch-*' -or $_ -like 'rom:*' }).Count -eq 0) `
    'Unknown USB descriptor received a reset or SLIP probe based on VID/PID.'
Reset-Fixture 'USB Serial Device'
Expect-Failure { Enter-Esp32Bootloader -ComPort 'COM7' -UsbIdentity $script:expected -EspToolCommand 'esptool' } `
    'protocol is unknown'
Expect-Failure { Assert-Esp32RomChipIdentity -ComPort 'COM7' -UsbIdentity $script:expected -EspToolCommand 'esptool' } `
    'protocol is unknown'
Assert-True (@($script:events | Where-Object { $_ -like 'rom:*' }).Count -eq 0) `
    'Direct ROM verifier sent SLIP bytes to an unqualified application port.'

Reset-Fixture 'TinyUSB CDC'
$script:actual = New-Identity 'TinyUSB CDC' '441BF669CF98'
Expect-Failure { Enter-Esp32Bootloader -ComPort 'COM7' -UsbIdentity $script:expected -EspToolCommand 'esptool' } `
    'Refusing ESP32 bootloader handoff'
Assert-True (@($script:events | Where-Object { $_ -like 'touch-*' -or $_ -like 'rom:*' }).Count -eq 0) `
    'COM reuse was discovered only after touching the wrong radio.'

Reset-Fixture 'TinyUSB CDC'
$script:swapAfterTouch = $true
Expect-Failure { Enter-Esp32Bootloader -ComPort 'COM7' -UsbIdentity $script:expected -EspToolCommand 'esptool' } `
    'Refusing ESP32 ROM verification after handoff'
Assert-True (@($script:events | Where-Object { $_ -like 'rom:*' }).Count -eq 0) `
    'Post-handoff USB identity conflict was not rejected before ROM access.'

Reset-Fixture 'TinyUSB CDC'
$script:mac = '44:1b:f6:69:cf:98'
Expect-Failure { Enter-Esp32Bootloader -ComPort 'COM7' -UsbIdentity $script:expected -EspToolCommand 'esptool' } `
    'chip MAC changed'

foreach ($badReply in @('missingMac', 'ambiguousMac')) {
    Reset-Fixture 'Espressif USB JTAG/serial debug unit'
    Set-Variable -Name $badReply -Scope Script -Value $true
    Expect-Failure { Enter-Esp32Bootloader -ComPort 'COM7' -UsbIdentity $script:expected -EspToolCommand 'esptool' } `
        'exactly one chip MAC'
}
Reset-Fixture 'Espressif USB JTAG/serial debug unit'
$script:state = 'rom'; $script:macThenFatal = $true
Expect-Failure { Get-EspRomMac -ComPort 'COM22' -EspToolCommand 'esptool' -Before 'no-reset' } `
    'reported a fatal error'

foreach ($case in @(@('TinyUSB CDC', 'no-reset'), @('USB JTAG/serial debug unit', 'no-reset'),
    @('Silicon Labs CP2102 USB to UART Bridge Controller', 'default-reset'))) {
    Assert-True ((Get-Esp32RomBeforeMode -UsbIdentity (New-Identity $case[0])) -eq $case[1]) `
        'Per-process ESP32 reset strategy does not match the qualified transport.'
}

# All destructive call paths must use the handoff, revalidate chip/USB identity,
# and preserve ROM across erase/write. No mocked command launches real tools.
foreach ($name in @('updateFlashViaEspTool', 'Install-SimpleMergedEspImage', 'installFlashViaEspTool')) {
    $body = Load-FirmwareFunction $name
    Assert-True ($body -match 'Enter-Esp32Bootloader' -and $body -match 'Assert-Esp32RomChipIdentity' -and
        $body -notmatch '--baud 1200') "ESP32 path $name still has an unchecked/implicit1200 handoff."
    Assert-True ($body -match 'Get-Esp32RomBeforeMode -UsbIdentity' -and
        $body -match 'Get-Esp32WriteAfterMode -UsbIdentity' -and
        $body -match '--before \$beforeMode --after \$afterMode' -and
        $body -match 'Complete-Esp32FlashSession' -and $body -match '-SkipApplicationVerification') `
        "ESP32 path $name ignores the qualified per-process reset strategy."
    if ($name -ne 'updateFlashViaEspTool') {
        Assert-True ($body -match '--before \$beforeMode --after \$script:ESPTOOL_NO_RESET \$EraseFlashCommand') `
            "ESP32 path $name leaves ROM after erase."
    }
}
Write-Host 'PASS ESP32 USB protocol classification, safe TinyUSB handoff, ROM/MAC gates, and flash integration'
