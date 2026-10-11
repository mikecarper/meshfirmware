# Hermetic Windows partition-expansion tests. No native process or USB access.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$tokens = $null
$parseErrors = $null
$firmwareAst = [System.Management.Automation.Language.Parser]::ParseFile(
    (Join-Path (Split-Path $PSScriptRoot -Parent) 'firmware.cmd'), [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw "firmware.cmd parse failed: $parseErrors" }
foreach ($name in @('Resolve-PartitionExpansionTool', 'Read-EspPartitionSnapshot',
    'Get-EspOtadataSnapshot', 'Get-EspNvsSnapshot', 'Wait-EspPartitionBridgeRom',
    'Invoke-EspPartitionExpansion', 'flashESP32', 'updateFlashViaEspTool',
    'Assert-Esp32RomChipIdentity', 'Set-Esp32VerifiedChipMac', 'Get-EspUsbBootloaderStrategy',
    'Get-Esp32RomBeforeMode', 'Get-Esp32RomSessionStamp', 'Get-UsbIdentityInterfaceNumber',
    'Test-UsbComPortIdentityMatch')) {
    $definition = $firmwareAst.Find({ param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
    }, $true)
    if ($null -eq $definition) { throw "Missing function under test: $name" }
    Invoke-Expression $definition.Extent.Text
}
$productionExpansion = ${function:Invoke-EspPartitionExpansion}
$productionUpdate = ${function:updateFlashViaEspTool}
$productionWait = ${function:Wait-EspPartitionBridgeRom}
function Assert-True { param([bool]$Condition, [string]$Message); if (-not $Condition) { throw $Message } }
function Assert-Equal {
    param($Expected, $Actual, [string]$Message)
    if ($Expected -ne $Actual) { throw "$Message Expected '$Expected', got '$Actual'." }
}
function Expect-Failure {
    param([scriptblock]$Action, [string]$Pattern)
    $failed = $false
    try { $null = & $Action } catch {
        if ($_.Exception.Message -notmatch $Pattern) { throw }
        $failed = $true
    }
    Assert-True $failed "Expected failure matching '$Pattern'."
}
function Parse-Number { param([string]$Number); if ($Number.StartsWith('0x')) { return [Convert]::ToInt64($Number.Substring(2), 16) }; return [int64]$Number }
function Hash-File { param([string]$Path); return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function New-PartitionTable {
    param([switch]$Factory, [switch]$DuplicateOta, [int]$OtaSize = 8192,
        [switch]$NoNvs, [switch]$DuplicateNvs, [uint32]$NvsOffset = 0x9000, [uint32]$NvsSize = 0x5000)
    [byte[]]$table = @(0xff) * 4096
    $nextEntry = 0
    if (-not $Factory) {
        foreach ($entryOffset in $(if ($DuplicateOta) { @(0, 32) } else { @(0) })) {
            $table[$entryOffset] = 0xaa; $table[$entryOffset + 1] = 0x50
            $table[$entryOffset + 2] = 1; $table[$entryOffset + 3] = 0
            [Array]::Copy([BitConverter]::GetBytes([uint32]0xe000), 0, $table, $entryOffset + 4, 4)
            [Array]::Copy([BitConverter]::GetBytes([uint32]$OtaSize), 0, $table, $entryOffset + 8, 4)
            $nextEntry = $entryOffset + 32
        }
    }
    if (-not $NoNvs) {
        $nvsEntries = if ($DuplicateNvs) { @($nextEntry, ($nextEntry + 32)) } else { @($nextEntry) }
        foreach ($entryOffset in $nvsEntries) {
            $table[$entryOffset] = 0xaa; $table[$entryOffset + 1] = 0x50
            $table[$entryOffset + 2] = 1; $table[$entryOffset + 3] = 2
            [Array]::Copy([BitConverter]::GetBytes($NvsOffset), 0, $table, $entryOffset + 4, 4)
            [Array]::Copy([BitConverter]::GetBytes($NvsSize), 0, $table, $entryOffset + 8, 4)
        }
    }
    return ,$table
}
$scratch = (New-Item -ItemType Directory -Path (Join-Path ([IO.Path]::GetTempPath()) `
    ('meshfirmware-expansion-test-' + [guid]::NewGuid().ToString('N')))).FullName
$ScriptPath = $scratch
$firmwarePath = Join-Path $scratch 'selected.bin'
$bridgePath = Join-Path $scratch 'bridge.bin'
$planPath = Join-Path $scratch 'plan.json'
$script:ESPTOOL_NO_RESET = 'no-reset'
$script:ESPTOOL_DEFAULT_RESET = 'default-reset'
$script:ESPTOOL_HARD_RESET = 'hard-reset'
$script:ESPTOOL_READ_FLASH = 'read-flash'
$script:ESPTOOL_FLASH_ID = 'flash-id'
$script:ESPTOOL_WRITE_FLASH = 'write-flash'

function Reset-Fixture {
    [IO.File]::WriteAllBytes($firmwarePath, [byte[]]@(1, 2, 3, 4))
    [IO.File]::WriteAllBytes($bridgePath, [byte[]]@(5, 6, 7, 8))
    $script:identity = [pscustomobject]@{
        SerialNumber = 'CC8DA2E96F34'; LocationPath = 'ROOT#USB(3)'
        ParentInstanceId = 'USB\VID_303A&PID_1001\CC8DA2E96F34'
        BusReportedDescription = 'Espressif USB JTAG/serial debug unit'; InterfaceNumber = '00'
        Esp32RomSessionActive = $false; Esp32RomTransport = 'usb-jtag'; Esp32ChipType = 'ESP32-S3'
    }
    $script:actualIdentity = $script:identity
    $script:mac = 'CC8DA2E96F34'
    $script:hardware = [pscustomobject]@{
        FirmwareFile = $firmwarePath; ComPort = 'COM9'; UsbIdentity = $script:identity
        Project = 'MeshCore'; Architecture = 'esp32-s3'; FlashSize = '16MB'
    }
    $script:events = New-Object 'System.Collections.Generic.List[string]'
    $script:nativeWrites = New-Object 'System.Collections.Generic.List[string]'
    $script:readPaths = New-Object 'System.Collections.Generic.List[string]'
    $script:helperCalls = New-Object 'System.Collections.Generic.List[object]'
    $script:needed = $true; $script:resume = $false; $script:consent = 'y'
    $script:readShort = $false; $script:readThrows = $false; $script:writeFails = $false
    $script:proofFails = $false; $script:planFails = $false; $script:waitThrows = $false
    $script:changeFinalAtConsent = $false; $script:changeBridgeAtConsent = $false
    $script:changeMacAfterBridge = $false; $script:enterCount = 0; $script:flashConsent = $true
    $script:resetThrows = $false; $script:swapUsbAfterBridge = $false
    $script:wrapperFails = $false; $script:backupFails = $false; $script:uartWaitFails = $false
    $script:missingPySerial = $false
    $script:unknownTransportAfterBridge = $false
    $script:romSilent = $false
    $script:partitionTable = New-PartitionTable
    $script:plan = [pscustomobject]@{
        ok = $true; needed = $true; resume = $false
        chip = 9; usb_safe = $true; automatic_rom_return = $true; uart_completion_status = $false
        bridge_file = $bridgePath; bridge_sha256 = (Hash-File $bridgePath)
        target_table_file = (Join-Path $scratch 'target.bin'); target_table_sha256 = ('0' * 64)
        nvs_offset = 0x9000; nvs_size = 0x5000; ota_offset = 0xe000; ota_size = 0x2000
        plan_file = $planPath; firmware_sha256 = (Hash-File $firmwarePath)
        app_offsets = @(0x210000, 0x10000)
    }
}
function Set-ClassicFixture {
    $script:identity.BusReportedDescription = 'Silicon Labs CP2102 USB to UART Bridge'
    $script:identity.Esp32RomTransport = 'uart'; $script:identity.Esp32ChipType = 'ESP32'
    $script:hardware.Architecture = 'esp32'
    $script:plan.chip = 0; $script:plan.automatic_rom_return = $false
    $script:plan.uart_completion_status = $true
}
function Wait-FirmwareToolUpdates { }
function Write-Host { param($Object, $ForegroundColor, [switch]$NoNewline) }
function Invoke-WebRequest { throw 'No downloads are permitted in this test.' }
function get_esptool_cmd { return 'fixture-esptool' }
function Get-SelectedUsbIdentityForFlash { param($Hardware); return $script:identity }
function Resolve-EspUsbComPort {
    param($PreferredComPort, $UsbIdentity, $TimeoutMs, $Purpose)
    if (-not (Test-UsbComPortIdentityMatch -Expected $UsbIdentity -Actual $script:actualIdentity)) { throw 'Selected USB device changed.' }
    return 'COM11'
}
function Get-UsbComPortIdentity { param($ComPort); return $script:actualIdentity }
function Get-EspRomMac {
    param($ComPort, $EspToolCommand, $Before, $UsbIdentity)
    Assert-Equal (Get-Esp32RomBeforeMode -UsbIdentity $UsbIdentity) $Before 'ROM identification used an unqualified reset mode.'
    $script:events.Add('mac')
    if ($script:romSilent) { return $null }
    return $script:mac
}
function Enter-Esp32Bootloader {
    param($ComPort, $UsbIdentity, $EspToolCommand)
    $script:enterCount++
    $script:events.Add('enter-rom')
    if ($script:enterCount -gt 1 -and $script:changeMacAfterBridge) { $script:mac = 'AABBCCDDEEFF' }
    Set-Esp32VerifiedChipMac -Mac $script:mac -ComPort COM11 -UsbIdentity $UsbIdentity
    $UsbIdentity.Esp32RomSessionActive = $true
    return 'COM11'
}
function Get-Esp32WriteAfterMode { param($UsbIdentity); return 'no-reset' }
function Complete-Esp32FlashSession {
    param($ComPort, $UsbIdentity, [switch]$SkipApplicationVerification, [switch]$PartitionBridgeBoot)
    if ($PartitionBridgeBoot) {
        Assert-True ([bool]$SkipApplicationVerification) 'Bridge reset attempted normal firmware verification.'
        Assert-True ($UsbIdentity -eq $script:identity) 'Bridge reset lost the selected physical identity.'
        $script:events.Add('bridge-reset')
        if ($script:resetThrows) { throw 'Guarded bridge reset failed.' }
        if ($script:swapUsbAfterBridge) { $script:actualIdentity = [pscustomobject]@{ SerialNumber = 'another-radio' } }
        if ($script:unknownTransportAfterBridge) { $script:identity.BusReportedDescription = 'Unknown transport' }
    } else { $script:events.Add('final-reset') }
    return 'COM11'
}
function Start-Sleep {
    param($Seconds, $Milliseconds)
    if ($Seconds) { Assert-Equal 2 $Seconds 'Passive ROM wait used the wrong polling interval.'; $script:events.Add('passive-sleep') }
}
function Wait-EspPartitionBridgeRom {
    param($ComPort, $UsbIdentity, $EspToolCommand, $TimeoutSeconds)
    $script:events.Add('wait-rom')
    if ($script:waitThrows) { throw 'The USB migration bridge did not return a verified ROM response in time.' }
    if ($script:changeMacAfterBridge) { $script:mac = 'AABBCCDDEEFF' }
    return (Assert-Esp32RomChipIdentity -ComPort $ComPort -UsbIdentity $UsbIdentity `
        -EspToolCommand $EspToolCommand -Purpose 'Fixture passive migration ROM return')
}
function Read-Host {
    param($Prompt)
    if ($Prompt -match '^Run the verified') {
        $script:events.Add('expansion-consent')
        if ($script:changeFinalAtConsent) { [IO.File]::WriteAllBytes($firmwarePath, [byte[]]@(9, 9, 9, 9)) }
        if ($script:changeBridgeAtConsent) { [IO.File]::WriteAllBytes($bridgePath, [byte[]]@(9, 9, 9, 9)) }
        return $script:consent
    }
    throw "Unexpected prompt in test: $Prompt"
}
function run_cmd {
    param($CommandLine, [switch]$Stream)
    if ($CommandLine -match '(?:erase-flash|erase_flash)') { throw 'Partition migration attempted a full erase.' }
    if ($CommandLine -match 'read-flash\s+(0x[0-9a-f]+|\d+)\s+(\d+)\s+"([^"]+)"') {
        $offset = Parse-Number $matches[1]; $length = [int]$matches[2]; $path = $matches[3]
        Assert-True ($script:events.Count -gt 0 -and $script:events[$script:events.Count - 1] -eq 'mac') 'Physical snapshot was read without an immediate ROM/MAC guard.'
        Assert-True ($CommandLine -match '--after no-reset') 'A proof read reset the board out of its checked ROM session.'
        $script:events.Add(('read:{0:x}' -f $offset)); $script:readPaths.Add($path)
        if ($script:readThrows) { throw 'Native read-flash failed.' }
        $bytes = if ($offset -eq 0x8000) { $script:partitionTable } else { New-Object byte[] $length }
        if ($offset -eq 0x9000) { $bytes[0] = 0x63 }
        if ($script:readShort) { $bytes = $bytes[0..($length - 2)] }
        [IO.File]::WriteAllBytes($path, [byte[]]$bytes)
        return 'Read successful'
    }
    if ($CommandLine -match 'flash-id$') { $script:events.Add('flash-id'); return 'Detected flash size: 16MB' }
    if ($CommandLine -match 'write-flash') {
        Assert-True ([bool]$Stream) 'Firmware write did not use the checked native exit code.'
        $script:nativeWrites.Add($CommandLine)
        $script:events.Add('bridge-write')
        if ($script:writeFails) { return 2 }
        return 0
    }
    throw "Unexpected native command in fixture: $CommandLine"
}
function Invoke-PartitionExpansionTool {
    param([string[]]$Arguments)
    $script:helperCalls.Add([object]$Arguments)
    $verb = $Arguments[0]; $script:events.Add($verb)
    if ($verb -eq 'plan') {
        if ($script:planFails) { throw 'No matching verified partition-expansion artifact is available.' }
        $script:plan.needed = $script:needed; $script:plan.resume = $script:resume
        Assert-True ($Arguments -contains '--device-mac') 'Planner lost the verified physical chip MAC.'
        Assert-True ($Arguments -contains '--otadata') 'Planner did not receive physical OTA selection metadata.'
        Assert-True ($Arguments -contains '--nvs') 'Planner did not receive physical primary NVS.'
        $nvsPath = $Arguments[[Array]::IndexOf($Arguments, '--nvs') + 1]
        Assert-Equal 0x5000 (Get-Item -LiteralPath $nvsPath).Length 'Planner NVS was not the complete physical partition.'
        Assert-Equal 0x63 ([IO.File]::ReadAllBytes($nvsPath)[0]) 'Planner NVS did not contain the actual read-flash bytes.'
        return $script:plan
    }
    if ($verb -eq 'begin') { return [pscustomobject]@{ ok = $true } }
    if ($verb -eq 'preflight-uart') {
        Assert-Equal 1 $Arguments.Count 'UART dependency preflight unexpectedly received a live port.'
        if ($script:missingPySerial) { throw 'PySerial is required for classic UART migration completion.' }
        return [pscustomobject]@{ ok = $true }
    }
    if ($verb -eq 'wait-uart') {
        Assert-Equal COM11 $Arguments[[Array]::IndexOf($Arguments, '--port') + 1] 'UART completion wait used another port.'
        Assert-Equal CC8DA2E96F34 $Arguments[[Array]::IndexOf($Arguments, '--device-mac') + 1] 'UART completion wait was not bound to the original physical MAC.'
        Assert-Equal 1 $script:enterCount 'UART bridge was reset before its settled completion signal.'
        if ($script:uartWaitFails) { throw 'UART migration completion signal did not arrive in time.' }
        return [pscustomobject]@{ ok = $true; settled = $true; device_mac = $script:mac }
    }
    if ($verb -eq 'verify') {
        if ($script:proofFails) { throw 'Partition expansion stopped: restoration proof failed.' }
        return [pscustomobject]@{ ok = $true; app_offsets = @(0x650000, 0x10000); active_offset = 0x10000; firmware_sha256 = $script:plan.firmware_sha256 }
    }
    throw "Unexpected helper command: $verb"
}

try {
    # Local helper checksum mismatch must stop before attempting any download.
    $toolDir = New-Item -ItemType Directory -Path (Join-Path $scratch 'tools')
    $toolPath = Join-Path $toolDir.FullName 'meshcore_partition_expansion.py'
    [IO.File]::WriteAllBytes($toolPath, [byte[]]@(1, 2, 3))
    $MESHCORE_PARTITION_TOOL_SHA256 = Hash-File $toolPath
    Assert-Equal $toolPath (Resolve-PartitionExpansionTool) 'Pinned bundled helper was not reused.'
    $MESHCORE_PARTITION_TOOL_SHA256 = '0' * 64
    Expect-Failure { Resolve-PartitionExpansionTool } 'does not match'

    Reset-Fixture
    $script:needed = $false
    Assert-True (-not (Invoke-EspPartitionExpansion -Hardware $script:hardware)) 'Fitting app unexpectedly used an intermediate firmware.'
    Assert-Equal '0x210000,0x10000' ($script:hardware.EspUpdateOffsets -join ',') 'Fitting update lost its checked active-last offsets.'
    Assert-Equal 0 $script:nativeWrites.Count 'Fitting app wrote a bridge.'
    Assert-Equal 0 (@($script:events | Where-Object { $_ -eq 'expansion-consent' })).Count 'Fitting app prompted for expansion.'

    Reset-Fixture
    Assert-True (Invoke-EspPartitionExpansion -Hardware $script:hardware) 'Verified expansion did not complete.'
    Assert-Equal '0x650000,0x10000' ($script:hardware.EspUpdateOffsets -join ',') 'Final offsets did not come from physical restoration proof.'
    Assert-Equal 1 $script:nativeWrites.Count 'Expansion issued the wrong number of bridge write commands.'
    Assert-True ($script:nativeWrites[0] -match 'write-flash 0x210000 .+ 0x10000 ') 'Bridge write did not put the inactive app first and active app last.'
    Assert-True ($script:events.IndexOf('begin') -lt $script:events.IndexOf('bridge-write')) 'Bridge began before recording resumable state.'
    Assert-True ($script:events.IndexOf('bridge-write') -lt $script:events.IndexOf('bridge-reset') -and
        $script:events.IndexOf('bridge-reset') -lt $script:events.IndexOf('wait-rom') -and
        $script:events.IndexOf('wait-rom') -lt $script:events.IndexOf('verify')) 'Expansion did not preserve write/reset/passive-ROM/proof ordering.'
    Assert-Equal 1 $script:enterCount 'Migration re-entered ROM by resetting an executing bridge.'
    foreach ($path in $script:readPaths) { Assert-True (-not (Test-Path -LiteralPath $path)) 'Private proof snapshot remained after completion.' }

    Reset-Fixture; $script:resume = $true
    Assert-True (Invoke-EspPartitionExpansion -Hardware $script:hardware) 'Interrupted expansion did not take its verification path.'
    Assert-Equal 0 $script:nativeWrites.Count 'Resuming a migrated table rewrote the bridge.'
    Assert-Equal 1 (@($script:events | Where-Object { $_ -eq 'verify' })).Count 'Resume bypassed restoration proof.'
    Assert-Equal 0 (@($script:events | Where-Object { $_ -eq 'begin' -or $_ -eq 'wait-rom' -or $_ -eq 'expansion-consent' })).Count 'Verification-only resume reran expansion actions.'

    foreach ($unsafeProperty in @('usb_safe', 'automatic_rom_return')) {
        Reset-Fixture; $script:plan.$unsafeProperty = $false
        Expect-Failure { Invoke-EspPartitionExpansion -Hardware $script:hardware } 'USB-safe|automatic-return'
        Assert-Equal 0 $script:nativeWrites.Count 'An unsafe USB bridge reached a native write.'
        Assert-True (-not ($script:events -contains 'begin' -or $script:events -contains 'expansion-consent')) 'An unsafe USB bridge was offered or started.'
    }

    Reset-Fixture; Set-ClassicFixture
    Assert-True (Invoke-EspPartitionExpansion -Hardware $script:hardware) 'Classic USB-UART completion path did not complete.'
    Assert-True ($script:events.IndexOf('preflight-uart') -lt $script:events.IndexOf('expansion-consent') -and
        $script:events.IndexOf('preflight-uart') -lt $script:events.IndexOf('begin')) 'UART dependency preflight happened after consent or bridge start.'
    Assert-Equal 2 $script:enterCount 'Classic USB-UART did not enter ROM after its settled signal.'
    $secondEnter = $script:events.LastIndexOf('enter-rom')
    Assert-True ($script:events.IndexOf('bridge-reset') -lt $script:events.IndexOf('wait-uart') -and
        $script:events.IndexOf('wait-uart') -lt $secondEnter -and
        $secondEnter -lt $script:events.IndexOf('verify')) 'Classic UART reset/proof happened before completion was confirmed.'
    Assert-True (-not ($script:events -contains 'wait-rom')) 'Classic UART incorrectly waited for native automatic ROM return.'
    Reset-Fixture; Set-ClassicFixture; $script:missingPySerial = $true
    Expect-Failure { Invoke-EspPartitionExpansion -Hardware $script:hardware } 'PySerial is required'
    Assert-Equal 0 $script:nativeWrites.Count 'Missing PySerial allowed an intermediate firmware write.'
    Assert-True (-not ($script:events -contains 'begin' -or $script:events -contains 'expansion-consent' -or
        $script:events -contains 'bridge-reset')) 'Missing PySerial reached consent, bridge start, or execution.'
    Reset-Fixture; Set-ClassicFixture; $script:resume = $true; $script:missingPySerial = $true
    Assert-True (Invoke-EspPartitionExpansion -Hardware $script:hardware) 'Classic verification-only resume unnecessarily required PySerial.'
    Assert-True (-not ($script:events -contains 'preflight-uart' -or $script:events -contains 'wait-uart')) 'Classic resume ran bridge-only dependency or completion workflow.'
    Assert-Equal 0 $script:nativeWrites.Count 'Classic verification-only resume rewrote the bridge.'
    Reset-Fixture; Set-ClassicFixture; $script:uartWaitFails = $true
    Expect-Failure { Invoke-EspPartitionExpansion -Hardware $script:hardware } 'completion signal did not arrive'
    Assert-Equal 1 $script:enterCount 'Timed-out UART bridge was forcibly reset.'
    Assert-True (-not ($script:events -contains 'verify')) 'Timed-out UART completion reached final physical proof.'
    Assert-True (-not $script:hardware.PSObject.Properties['EspUpdateOffsets']) 'Timed-out UART bridge authorized final app writes.'
    Reset-Fixture; Set-ClassicFixture; $script:unknownTransportAfterBridge = $true
    Expect-Failure { Invoke-EspPartitionExpansion -Hardware $script:hardware } 'verified USB-UART transport'
    Assert-Equal 1 $script:enterCount 'An unknown UART transport was reset after bridge execution.'
    Assert-True (-not ($script:events -contains 'wait-uart' -or $script:events -contains 'verify')) 'Unknown classic transport reached completion wait or final proof.'
    Reset-Fixture; Set-ClassicFixture; $script:plan.uart_completion_status = $false
    Expect-Failure { Invoke-EspPartitionExpansion -Hardware $script:hardware } 'USB-safe|automatic-return'
    Assert-Equal 0 $script:nativeWrites.Count 'Classic bridge without settled completion support was written.'

    foreach ($answer in @('', 'n', 'maybe')) {
        Reset-Fixture; $script:consent = $answer
        Expect-Failure { Invoke-EspPartitionExpansion -Hardware $script:hardware } 'cancelled'
        Assert-Equal 0 $script:nativeWrites.Count 'Denied expansion wrote the bridge.'
    }
    foreach ($mutation in @('final', 'bridge')) {
        Reset-Fixture
        if ($mutation -eq 'final') { $script:changeFinalAtConsent = $true } else { $script:changeBridgeAtConsent = $true }
        Expect-Failure { Invoke-EspPartitionExpansion -Hardware $script:hardware } 'changed after verification'
        Assert-Equal 0 $script:nativeWrites.Count 'Changed artifact reached a native bridge write.'
    }
    Reset-Fixture; $script:planFails = $true
    Expect-Failure { Invoke-EspPartitionExpansion -Hardware $script:hardware } 'No matching verified'
    Assert-Equal 0 $script:nativeWrites.Count 'Unsupported expansion artifact reached a write.'
    Reset-Fixture; $script:writeFails = $true
    Expect-Failure { Invoke-EspPartitionExpansion -Hardware $script:hardware } 'write failed'
    Assert-True (-not ($script:events -contains 'bridge-reset' -or $script:events -contains 'verify')) 'Failed bridge write was rebooted or accepted.'
    Reset-Fixture; $script:proofFails = $true
    Expect-Failure { Invoke-EspPartitionExpansion -Hardware $script:hardware } 'restoration proof failed'
    Assert-True (-not $script:hardware.PSObject.Properties['EspUpdateOffsets']) 'Failed restoration proof authorized final app offsets.'
    foreach ($path in $script:readPaths) { Assert-True (-not (Test-Path -LiteralPath $path)) 'Failed proof left private snapshots behind.' }
    Reset-Fixture; $script:resetThrows = $true
    Expect-Failure { Invoke-EspPartitionExpansion -Hardware $script:hardware } 'Guarded bridge reset failed'
    Assert-True (-not ($script:events -contains 'verify' -or $script:events -contains 'wait-rom')) 'Failed reset was accepted as bridge execution.'
    Reset-Fixture; $script:changeMacAfterBridge = $true
    Expect-Failure { Invoke-EspPartitionExpansion -Hardware $script:hardware } 'chip MAC changed|chip changed'
    Assert-True (-not ($script:events -contains 'verify')) 'A substituted chip reached restoration verification.'
    Reset-Fixture; $script:swapUsbAfterBridge = $true
    Expect-Failure { Invoke-EspPartitionExpansion -Hardware $script:hardware } 'USB device changed'
    Assert-True (-not ($script:events -contains 'verify')) 'A substituted USB device reached restoration verification.'
    Reset-Fixture; $script:waitThrows = $true
    Expect-Failure { Invoke-EspPartitionExpansion -Hardware $script:hardware } 'verified ROM response in time'
    Assert-True (-not ($script:events -contains 'verify')) 'Timed-out automatic ROM return reached final proof.'
    Assert-True (-not $script:hardware.PSObject.Properties['EspUpdateOffsets']) 'Timed-out bridge authorized final app writes.'

    # A passive ROM return only interrogates the selected physical endpoint.
    # It must never use Enter-Esp32Bootloader or reset an executing bridge.
    Reset-Fixture
    Set-Esp32VerifiedChipMac -Mac $script:mac -ComPort COM11 -UsbIdentity $script:identity
    Assert-Equal COM11 (& $productionWait -ComPort COM11 -UsbIdentity $script:identity -EspToolCommand fixture-esptool -TimeoutSeconds 0) 'An immediate checked ROM return was not accepted.'
    Assert-Equal 0 $script:enterCount 'Passive ROM return called the resetting bootloader entry workflow.'
    Assert-True (-not ($script:events -contains 'bridge-reset' -or $script:events -contains 'final-reset')) 'Passive ROM return issued a reset.'
    Reset-Fixture; $script:romSilent = $true
    Set-Esp32VerifiedChipMac -Mac $script:mac -ComPort COM11 -UsbIdentity $script:identity
    Expect-Failure { & $productionWait -ComPort COM11 -UsbIdentity $script:identity -EspToolCommand fixture-esptool -TimeoutSeconds 0 } 'verified ROM response in time'
    Assert-Equal 0 $script:enterCount 'A silent bridge was forcibly reset.'
    Assert-True (-not ($script:events -contains 'bridge-reset' -or $script:events -contains 'final-reset')) 'A timed-out bridge was reset.'

    Reset-Fixture; $script:readShort = $true
    Expect-Failure { Read-EspPartitionSnapshot -ComPort COM11 -UsbIdentity $script:identity -EspToolCommand fixture-esptool -Offset 0x8000 -Length 4096 -Path (Join-Path $scratch 'short.bin') } 'exactly 4096 bytes'
    Reset-Fixture; $script:readThrows = $true
    Expect-Failure { Read-EspPartitionSnapshot -ComPort COM11 -UsbIdentity $script:identity -EspToolCommand fixture-esptool -Offset 0x8000 -Length 4096 -Path (Join-Path $scratch 'failed.bin') } 'Native read-flash failed'
    Reset-Fixture; $script:actualIdentity = [pscustomobject]@{ SerialNumber = 'another-radio' }
    Expect-Failure { Read-EspPartitionSnapshot -ComPort COM11 -UsbIdentity $script:identity -EspToolCommand fixture-esptool -Offset 0x8000 -Length 4096 -Path (Join-Path $scratch 'other.bin') } 'USB device changed'
    Assert-Equal 0 $script:readPaths.Count 'A substituted USB device reached a flash snapshot read.'

    $tablePath = Join-Path $scratch 'table.bin'
    Reset-Fixture
    [IO.File]::WriteAllBytes($tablePath, (New-PartitionTable -Factory))
    Assert-True ($null -eq (Get-EspOtadataSnapshot -PartitionTable $tablePath -ComPort COM11 -UsbIdentity $script:identity -EspToolCommand fixture-esptool -Path (Join-Path $scratch 'factory-ota.bin'))) 'Factory table fabricated an OTA data snapshot.'
    [IO.File]::WriteAllBytes($tablePath, (New-PartitionTable -DuplicateOta))
    Expect-Failure { Get-EspOtadataSnapshot -PartitionTable $tablePath -ComPort COM11 -UsbIdentity $script:identity -EspToolCommand fixture-esptool -Path (Join-Path $scratch 'ambiguous-ota.bin') } 'ambiguous'
    [IO.File]::WriteAllBytes($tablePath, (New-PartitionTable -OtaSize 4096))
    Expect-Failure { Get-EspOtadataSnapshot -PartitionTable $tablePath -ComPort COM11 -UsbIdentity $script:identity -EspToolCommand fixture-esptool -Path (Join-Path $scratch 'short-ota.bin') } 'incomplete'

    Reset-Fixture
    [IO.File]::WriteAllBytes($tablePath, (New-PartitionTable))
    $nvsPath = Join-Path $scratch 'complete-nvs.bin'
    Assert-Equal $nvsPath (Get-EspNvsSnapshot -PartitionTable $tablePath -ComPort COM11 -UsbIdentity $script:identity -EspToolCommand fixture-esptool -Path $nvsPath) 'Primary NVS snapshot path was not returned.'
    Assert-Equal 0x5000 (Get-Item -LiteralPath $nvsPath).Length 'Primary NVS snapshot was incomplete.'
    Assert-True ($script:events -contains 'read:9000') 'Primary NVS read used an unverified or incorrect offset.'
    [IO.File]::WriteAllBytes($tablePath, (New-PartitionTable -NoNvs))
    Assert-True ($null -eq (Get-EspNvsSnapshot -PartitionTable $tablePath -ComPort COM11 -UsbIdentity $script:identity -EspToolCommand fixture-esptool -Path $nvsPath)) 'Absent NVS fabricated a snapshot.'
    foreach ($badTable in @((New-PartitionTable -DuplicateNvs), (New-PartitionTable -NvsOffset 0x9001),
            (New-PartitionTable -NvsSize 0x5001), (New-PartitionTable -NvsSize 0x101000))) {
        [IO.File]::WriteAllBytes($tablePath, $badTable)
        Expect-Failure { Get-EspNvsSnapshot -PartitionTable $tablePath -ComPort COM11 -UsbIdentity $script:identity -EspToolCommand fixture-esptool -Path $nvsPath } 'ambiguous or invalid'
    }

    # Changing the selected file after its checked fit/proof must not allow an
    # app write at offsets planned for the earlier bytes.
    Reset-Fixture; $script:needed = $false
    $null = & $productionExpansion -Hardware $script:hardware
    [IO.File]::WriteAllBytes($firmwarePath, [byte[]]@(9, 9, 9, 9))
    $locationBefore = Get-Location
    try { Expect-Failure { & $productionUpdate -hw $script:hardware } 'changed|hash|verified' }
    finally { Set-Location $locationBefore }
    Assert-Equal 0 $script:nativeWrites.Count 'Final firmware changed after planning but reached a native app write.'

    # Verify the entry point requests a logical backup and final write consent
    # before handing control to the ROM/bridge workflow, even with no CLI layout.
    function Get-EspFlashStrategy { param($Path); return [pscustomobject]@{ ClassifiedMode = 'update'; SelectedMode = 'update'; FileNameMode = 'update' } }
    function Get-EspRuntimeStorageLayout { param($ComPort); return '' }
    function Request-MeshCoreUsbBackupBeforeFlash { param($Hardware, $ComPort, $UsbIdentity, $Action); $script:events.Add('backup'); if ($script:backupFails) { throw 'Requested backup failed.' } }
    function Confirm-MeshCoreFlash { param($Hardware, $Action); $script:events.Add('flash-consent'); return $script:flashConsent }
    function Invoke-EspPartitionExpansion { param($Hardware); $script:events.Add('expansion-wrapper'); if ($script:wrapperFails) { throw 'Restoration proof failed.' }; $Hardware | Add-Member -Force NoteProperty EspUpdateOffsets @('0x650000', '0x10000'); return $true }
    function updateFlashViaEspTool { param($hw); $script:events.Add('final-write'); return $true }
    Reset-Fixture
    Assert-True (flashESP32 -hw $script:hardware) 'MeshCore app-only entry point did not complete.'
    Assert-True ($script:events.IndexOf('backup') -lt $script:events.IndexOf('flash-consent') -and
        $script:events.IndexOf('flash-consent') -lt $script:events.IndexOf('expansion-wrapper') -and
        $script:events.IndexOf('expansion-wrapper') -lt $script:events.IndexOf('final-write')) 'Backup/write consent/expansion/final write order was not preserved.'
    Reset-Fixture; $script:flashConsent = $false
    Assert-True (-not (flashESP32 -hw $script:hardware)) 'Denied flash continued.'
    Assert-True (-not ($script:events -contains 'expansion-wrapper' -or $script:events -contains 'final-write')) 'Denied flash entered the bridge or final write workflow.'
    Reset-Fixture; $script:wrapperFails = $true
    Expect-Failure { flashESP32 -hw $script:hardware } 'Restoration proof failed'
    Assert-True (-not ($script:events -contains 'final-write')) 'Failed expansion proof allowed the selected firmware to be written.'
    Reset-Fixture; $script:backupFails = $true
    Expect-Failure { flashESP32 -hw $script:hardware } 'Requested backup failed'
    Assert-True (-not ($script:events -contains 'expansion-wrapper' -or $script:events -contains 'final-write')) 'Failed required backup entered the destructive migration workflow.'

    Microsoft.PowerShell.Utility\Write-Host 'PASS: Windows partition planning, fit/expansion/resume, consent, artifact hashes, ROM identity, proof reads, cleanup, and backup ordering.'
}
finally {
    $resolvedScratch = [IO.Path]::GetFullPath($scratch)
    Assert-True ($resolvedScratch.StartsWith([IO.Path]::GetFullPath([IO.Path]::GetTempPath()), [StringComparison]::OrdinalIgnoreCase) -and
        (Split-Path $resolvedScratch -Leaf) -like 'meshfirmware-expansion-test-*') 'Refusing cleanup outside the test temporary directory.'
    Remove-Item -LiteralPath $resolvedScratch -Recurse -Force
}
