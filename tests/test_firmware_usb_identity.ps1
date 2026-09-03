$ErrorActionPreference = 'Stop'

function Assert-Equal {
	param(
		[Parameter(Mandatory)]$Expected,
		[Parameter(Mandatory)]$Actual,
		[Parameter(Mandatory)][string]$Message
	)

	if ($Expected -ne $Actual) {
		throw "$Message Expected '$Expected', got '$Actual'."
	}
}

function Assert-True {
	param(
		[Parameter(Mandatory)][bool]$Condition,
		[Parameter(Mandatory)][string]$Message
	)

	if (-not $Condition) { throw $Message }
}

$firmwarePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'firmware.cmd'
$tokens = $null
$parseErrors = $null
$firmwareAst = [System.Management.Automation.Language.Parser]::ParseFile(
	$firmwarePath,
	[ref]$tokens,
	[ref]$parseErrors
)
if ($parseErrors.Count -ne 0) {
	throw "firmware.cmd parse failed: $($parseErrors -join '; ')"
}

foreach ($functionName in @(
	'Test-IsWindowsHost',
	'Enter-MeshCoreTerminalForProbe',
	'Exit-MeshCoreTerminalAfterProbe',
	'getMeshCore',
	'getUsbComDevices',
	'Resolve-UsbParentInstanceId',
	'Get-UsbInterfaceNumberFromInstanceId',
	'Get-UsbIdentityInterfaceNumber',
	'Get-UsbComPortIdentity',
	'Test-UsbComPortIdentityMatch',
	'Test-UsbIdentityIsNrf52Dfu',
	'Assert-UsbIdentityIsNrf52Dfu',
	'Get-SelectedUsbIdentityForFlash',
	'Set-HardwareUsbComPortSelection',
	'Test-ShouldRetryNrfutilSerialPort',
	'Get-UsbIdentityDisplayText',
	'Resolve-UsbComPortForIdentity',
	'Resolve-EspUsbComPort',
	'Install-SimpleMergedEspImage',
	'Resolve-Nrf52PrimaryUsbSelection',
	'Resolve-LiveUsbComPort',
	'Wait-Nrf52DfuTransitionAfterFailedTouch',
	'Assert-UsbComPortIdentityFor1200Touch',
	'Touch-ComPort1200',
	'Resolve-Nrf52DfuComPort',
	'Test-CachedMeshCoreUsbBackup',
	'Request-MeshCoreUsbBackupBeforeFlash',
	'flashMeshtasticNrf52',
	'flashMeshCoreNrf52'
)) {
	$definition = $firmwareAst.Find({
		param($node)
		$node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
		$node.Name -eq $functionName
	}, $true)
	if ($null -eq $definition) { throw "Missing function under test: $functionName" }
	Invoke-Expression $definition.Extent.Text
}

# These fixtures exercise the Windows-only USB identity path even when the
# test runner itself is PowerShell Core on Linux.
function Test-IsWindowsHost { return $true }

$pocketRuntime = [pscustomobject]@{
	SerialNumber = '93DA83ADF7B2092B'
	LocationPath = 'PCIROOT(0)#USBROOT(0)#USB(8)'
	ParentInstanceId = 'USB\VID_239A&PID_4405\93DA83ADF7B2092B'
	InterfaceNumber = '00'
}
$pocketLogging = [pscustomobject]@{
	SerialNumber = '93DA83ADF7B2092B'
	LocationPath = 'PCIROOT(0)#USBROOT(0)#USB(8)'
	ParentInstanceId = 'USB\VID_239A&PID_4405\93DA83ADF7B2092B'
	BusReportedDescription = 'MeshCore Full Companion'
	InterfaceNumber = '02'
}
$pocketDfu = [pscustomobject]@{
	SerialNumber = '93DA83ADF7B2092B'
	LocationPath = 'PCIROOT(0)#USBROOT(0)#USB(8)'
	ParentInstanceId = 'USB\VID_239A&PID_0071\93DA83ADF7B2092B'
	BusReportedDescription = 'MeshPocket_DFU'
	InterfaceNumber = ''
}
$pocketDfuChangedSerial = [pscustomobject]@{
	SerialNumber = 'BOOTLOADER-SERIAL'
	LocationPath = 'PCIROOT(0)#USBROOT(0)#USB(8)'
	ParentInstanceId = 'USB\VID_239A&PID_0071\BOOTLOADER-SERIAL'
	BusReportedDescription = 'MeshPocket_DFU'
	InterfaceNumber = ''
}
$t1000eDfu = [pscustomobject]@{
	SerialNumber = '34A9141999729D5D'
	LocationPath = 'PCIROOT(0)#USBROOT(0)#USB(8)'
	ParentInstanceId = 'USB\VID_2886&PID_0057\34A9141999729D5D'
	BusReportedDescription = 'T1000-E'
	InterfaceNumber = ''
}
$t1000eWrongPid = [pscustomobject]@{
	SerialNumber = '34A9141999729D5D'
	LocationPath = 'PCIROOT(0)#USBROOT(0)#USB(8)'
	ParentInstanceId = 'USB\VID_2886&PID_0058\34A9141999729D5D'
	BusReportedDescription = 'T1000-E'
	InterfaceNumber = ''
}
$t1000eRuntime = [pscustomobject]@{
	SerialNumber = '34A9141999729D5D'
	LocationPath = 'PCIROOT(0)#USBROOT(0)#USB(8)'
	ParentInstanceId = 'USB\VID_239A&PID_8029\34A9141999729D5D'
	BusReportedDescription = 'MeshCore T1000-E'
	InterfaceNumber = '00'
}
$t096Runtime = [pscustomobject]@{
	SerialNumber = '651F8E496197F882'
	LocationPath = 'PCIROOT(0)#USBROOT(0)#USB(13)#USB(3)'
	ParentInstanceId = 'USB\VID_239A&PID_8029\651F8E496197F882'
	BusReportedDescription = 'T096_OTA'
	InterfaceNumber = '00'
}
$t096Logging = [pscustomobject]@{
	SerialNumber = '651F8E496197F882'
	LocationPath = 'PCIROOT(0)#USBROOT(0)#USB(13)#USB(3)'
	ParentInstanceId = 'USB\VID_239A&PID_8029\651F8E496197F882'
	BusReportedDescription = 'T096_OTA'
	InterfaceNumber = '02'
}
$v4Runtime = [pscustomobject]@{
	SerialNumber = '44:1B:F6:6A:E8:44'
	LocationPath = 'PCIROOT(0)#USBROOT(0)#USB(8)'
	ParentInstanceId = 'USB\VID_303A&PID_1001\44:1B:F6:6A:E8:44'
	BusReportedDescription = 'USB JTAG/serial debug unit'
	InterfaceNumber = '00'
}
$v4Bootloader = [pscustomobject]@{
	SerialNumber = '44:1B:F6:6A:E8:44'
	LocationPath = 'PCIROOT(0)#USBROOT(0)#USB(8)'
	ParentInstanceId = 'USB\VID_303A&PID_1001\44:1B:F6:6A:E8:44'
	BusReportedDescription = 'USB JTAG/serial debug unit'
	InterfaceNumber = '00'
}

# A non-composite CDC device may itself be the stable USB parent. The traversal
# must inspect that devnode before walking upward to a hub.
$script:parentLookupCount = 0
$nonCompositeParent = Resolve-UsbParentInstanceId `
	-InitialInstanceId 'USB\VID_1234&PID_5678\SERIAL7' `
	-ParentResolver {
		param($instanceId)
		$script:parentLookupCount++
		throw 'The non-composite USB devnode must not be skipped.'
	}
Assert-Equal -Expected 'USB\VID_1234&PID_5678\SERIAL7' -Actual $nonCompositeParent -Message 'Non-composite USB identity was not captured.'
Assert-Equal -Expected 0 -Actual $script:parentLookupCount -Message 'The resolver walked past a valid non-composite USB devnode.'

$compositeParent = Resolve-UsbParentInstanceId `
	-InitialInstanceId 'USB\VID_1234&PID_5678&MI_00\7&ABC&0&0000' `
	-ParentResolver {
		param($instanceId)
		if ($instanceId -match '&MI_00\\') { return 'USB\VID_1234&PID_5678\SERIAL7' }
		return ''
	}
Assert-Equal -Expected 'USB\VID_1234&PID_5678\SERIAL7' -Actual $compositeParent -Message 'Composite USB child did not resolve to its stable parent.'
Assert-Equal `
	-Expected '00' `
	-Actual (Get-UsbInterfaceNumberFromInstanceId -InstanceId 'USB\VID_239A&PID_8029&MI_00\7&ABC&0&0000') `
	-Message 'Primary Full Companion CDC interface number was not captured.'
Assert-Equal `
	-Expected '02' `
	-Actual (Get-UsbInterfaceNumberFromInstanceId -InstanceId 'USB\VID_239A&PID_8029&MI_02\7&ABC&0&0002') `
	-Message 'Dedicated Full Companion logging interface number was not captured.'
Assert-Equal `
	-Expected '' `
	-Actual (Get-UsbInterfaceNumberFromInstanceId -InstanceId 'USB\VID_239A&PID_0071\93DA83ADF7B2092B') `
	-Message 'A non-composite DFU port was assigned a fabricated interface number.'

Assert-True `
	-Condition (Test-UsbComPortIdentityMatch -Expected $pocketRuntime -Actual $pocketDfu) `
	-Message 'The same physical device must match after its VID/PID and COM port change.'
Assert-True `
	-Condition (Test-UsbComPortIdentityMatch -Expected $t1000eRuntime -Actual $t1000eDfu) `
	-Message 'The same T1000-E must match across its 239A:8029 runtime and 2886:0057 DFU identities.'
Assert-True `
	-Condition (-not (Test-UsbComPortIdentityMatch -Expected $pocketRuntime -Actual $t096Runtime)) `
	-Message 'A second radio must never match the selected device.'
# Explicit policy: when both modes report a serial, a mismatch is a hard
# identity conflict even at the same USB location. This prevents a swapped-in
# radio from inheriting the selected device merely by using the same socket.
Assert-True `
	-Condition (-not (Test-UsbComPortIdentityMatch -Expected $pocketRuntime -Actual $pocketDfuChangedSerial)) `
	-Message 'Different explicit serials incorrectly matched by USB location.'
Assert-True -Condition (Test-UsbIdentityIsNrf52Dfu -Identity $pocketDfu) -Message 'DFU mode was not recognized.'
Assert-True -Condition (Test-UsbIdentityIsNrf52Dfu -Identity $t1000eDfu) -Message 'T1000-E 2886:0057 DFU mode was not recognized.'
Assert-True -Condition (-not (Test-UsbIdentityIsNrf52Dfu -Identity $t1000eWrongPid)) -Message 'An unlisted Seeed USB PID was misidentified as T1000-E DFU mode.'
Assert-True -Condition (-not (Test-UsbIdentityIsNrf52Dfu -Identity $t1000eRuntime)) -Message 'T1000-E runtime firmware was misidentified as DFU mode.'
Assert-True -Condition (-not (Test-UsbIdentityIsNrf52Dfu -Identity $t096Runtime)) -Message 'Runtime firmware was misidentified as DFU mode.'

$noTouchRuntimeRejected = $false
try {
	Assert-UsbIdentityIsNrf52Dfu -Identity $t096Runtime -ComPort 'COM9'
}
catch {
	$noTouchRuntimeRejected = $_.Exception.Message -match 'Refusing a no-touch DFU upload'
}
Assert-True -Condition $noTouchRuntimeRejected -Message 'A no-touch upload did not reject runtime mode.'
Assert-UsbIdentityIsNrf52Dfu -Identity $pocketDfu -ComPort 'COM18'
Assert-UsbIdentityIsNrf52Dfu -Identity $t1000eDfu -ComPort 'COM24'

Assert-True `
	-Condition (Test-ShouldRetryNrfutilSerialPort -TouchWasRequested $true -SerialOpenFailure $true) `
	-Message 'A port-open failure lost the fact that a 1200-baud touch was requested.'
Assert-True `
	-Condition (-not (Test-ShouldRetryNrfutilSerialPort -TouchWasRequested $false -SerialOpenFailure $true)) `
	-Message 'A no-touch upload unexpectedly enabled the one-shot touch retry.'

$script:usbIdentities = @{
	'COM7' = $v4Runtime
	'COM9' = $t096Runtime
	'COM10' = $pocketRuntime
	'COM18' = $pocketDfu
	'COM22' = $v4Bootloader
}
function Get-UsbComPortIdentity {
	param([string]$ComPort)
	return $script:usbIdentities[$ComPort]
}

# The post-flash retry menu may intentionally select a different radio. Replace
# its COM number and identity together; if the new port is absent, retain the
# old pair and abort rather than silently relocating back to radio A.
$retryHardware = [pscustomobject]@{
	ComPort = 'COM7'
	UsbIdentity = $v4Runtime
}
$null = Set-HardwareUsbComPortSelection -Hardware $retryHardware -ComPort 'com9'
Assert-Equal -Expected 'COM9' -Actual $retryHardware.ComPort -Message 'Retry selection did not normalize and store the new COM port.'
Assert-True `
	-Condition (Test-UsbComPortIdentityMatch -Expected $t096Runtime -Actual $retryHardware.UsbIdentity) `
	-Message 'Retry selection retained radio A identity after selecting radio B.'

$missingRetrySelectionRejected = $false
try {
	$null = Set-HardwareUsbComPortSelection -Hardware $retryHardware -ComPort 'COM99'
}
catch {
	$missingRetrySelectionRejected = $_.Exception.Message -match 'existing radio selection was not changed'
}
Assert-True -Condition $missingRetrySelectionRejected -Message 'Retry selection accepted an unidentifiable COM port.'
Assert-Equal -Expected 'COM9' -Actual $retryHardware.ComPort -Message 'Failed retry selection changed the prior COM port.'
Assert-True `
	-Condition (Test-UsbComPortIdentityMatch -Expected $t096Runtime -Actual $retryHardware.UsbIdentity) `
	-Message 'Failed retry selection restored or retained radio A identity.'

$firmwareSource = Get-Content -LiteralPath $firmwarePath -Raw
Assert-True `
	-Condition ($firmwareSource -match 'Set-HardwareUsbComPortSelection\s+-Hardware\s+\$hw\s+-ComPort\s+\$newComPort') `
	-Message 'The change-COM menu path does not replace the hardware USB identity.'
Assert-True `
	-Condition ($firmwareSource -match 'Aborting this retry so the previously selected radio is not flashed by mistake') `
	-Message 'The change-COM menu path can retry the old radio after new identity capture fails.'

function Get-AvailableComPorts { return @('COM9', 'COM18') }
$resolved = Resolve-UsbComPortForIdentity -Identity $pocketRuntime -PreferredComPort 'COM10'
Assert-Equal -Expected 'COM18' -Actual $resolved -Message 'Identity resolution selected the wrong post-transition COM port.'

# ESP32 reset can renumber the selected V4 while other radios remain attached,
# or Windows can reuse its old COM number for one of them. Follow only the
# captured V4 identity and never accept the stale preferred number.
$script:usbIdentities['COM7'] = $t096Runtime
function Get-AvailableComPorts { return @('COM7', 'COM9', 'COM21', 'COM22') }
$espRenumbered = Resolve-EspUsbComPort `
	-PreferredComPort 'COM7' `
	-UsbIdentity $v4Runtime `
	-TimeoutMs 0 `
	-Purpose 'ESP32 reset regression test'
Assert-Equal -Expected 'COM22' -Actual $espRenumbered -Message 'ESP32 resolution accepted a stale COM number or another attached radio.'

$missingEspIdentityRejected = $false
try {
	$null = Resolve-EspUsbComPort `
		-PreferredComPort 'COM7' `
		-UsbIdentity $null `
		-TimeoutMs 0 `
		-Purpose 'missing-identity regression test'
}
catch {
	$missingEspIdentityRejected = $_.Exception.Message -match 'physical USB identity' -and
		$_.Exception.Message -match 'Refusing to use an unbound COM port'
}
Assert-True -Condition $missingEspIdentityRejected -Message 'ESP32 flashing did not fail closed when selected identity was missing.'

# Two live ports claiming the selected physical identity are ambiguous once the
# old preferred COM is gone. Do not guess between them.
$script:usbIdentities['COM23'] = $v4Bootloader
function Get-AvailableComPorts { return @('COM9', 'COM21', 'COM22', 'COM23') }
$ambiguousEspIdentityRejected = $false
try {
	$null = Resolve-EspUsbComPort `
		-PreferredComPort 'COM7' `
		-UsbIdentity $v4Runtime `
		-TimeoutMs 0 `
		-Purpose 'ambiguous ESP32 regression test'
}
catch {
	$ambiguousEspIdentityRejected = $_.Exception.Message -match 'Multiple COM ports matched'
}
Assert-True -Condition $ambiguousEspIdentityRejected -Message 'ESP32 flashing guessed between ambiguous identity-matched COM ports.'
$script:usbIdentities.Remove('COM23')

# The optional nRF52 logging endpoint shares the exact physical serial and USB
# parent. When a stale COM cannot be preferred, retain interface 00 instead of
# treating the two Full Companion CDC ports as an ambiguous pair.
$script:usbIdentities['COM10'] = $pocketRuntime
$script:usbIdentities['COM20'] = $pocketLogging
function Get-AvailableComPorts { return @('COM10', 'COM20') }
$dualCdcPrimary = Resolve-UsbComPortForIdentity -Identity $pocketRuntime -PreferredComPort 'COM18'
Assert-Equal -Expected 'COM10' -Actual $dualCdcPrimary -Message 'Dual-CDC resolution did not prefer Full Companion interface 00.'

$dfuIdentityReturningToDualCdc = Resolve-UsbComPortForIdentity -Identity $pocketDfu -PreferredComPort 'COM18'
Assert-Equal -Expected 'COM10' -Actual $dfuIdentityReturningToDualCdc -Message 'A DFU identity returning to dual CDC did not select interface 00.'

$script:usbIdentities['COM9'] = $t096Runtime
$script:usbIdentities['COM21'] = $t096Logging
function Get-AvailableComPorts { return @('COM9', 'COM21') }
$canonicalT096Selection = Resolve-Nrf52PrimaryUsbSelection `
	-SelectedComPort 'COM21' `
	-UsbIdentity $t096Logging `
	-TimeoutSec 0
Assert-Equal -Expected 'COM9' -Actual $canonicalT096Selection.ComPort -Message 'Selected logging interface 02 was not canonicalized to sibling interface 00.'
Assert-Equal `
	-Expected '00' `
	-Actual (Get-UsbIdentityInterfaceNumber -Identity $canonicalT096Selection.UsbIdentity) `
	-Message 'Canonical nRF52 selection retained the logging-port identity.'

function Get-AvailableComPorts { return @('COM10', 'COM21') }
$missingPrimaryRejected = $false
try {
	$null = Resolve-Nrf52PrimaryUsbSelection `
		-SelectedComPort 'COM21' `
		-UsbIdentity $t096Logging `
		-TimeoutSec 0
}
catch {
	$missingPrimaryRejected = $_.Exception.Message -match 'logging interface 02' -and
		$_.Exception.Message -match 'primary interface 00 did not enumerate' -and
		$_.Exception.Message -match 'Refusing to issue a 1200-baud touch'
}
Assert-True -Condition $missingPrimaryRejected -Message 'Missing same-radio interface 00 did not fail clearly before touch.'

function Get-AvailableComPorts { return @('COM9', 'COM18') }
$liveResolved = Resolve-LiveUsbComPort `
	-PreferredComPort 'COM10' `
	-Purpose 'regression test' `
	-UsbIdentity $pocketRuntime
Assert-Equal -Expected 'COM18' -Actual $liveResolved -Message 'Live-port resolution fell back to the unrelated T096.'

function Get-AvailableComPorts { return @('COM9') }
$failedClosed = $false
try {
	$null = Resolve-LiveUsbComPort `
		-PreferredComPort 'COM10' `
		-Purpose 'fail-closed regression test' `
		-UsbIdentity $pocketRuntime
}
catch {
	$failedClosed = $_.Exception.Message -match 'Refusing to use a different USB radio'
}
Assert-True -Condition $failedClosed -Message 'A missing selected device did not fail closed.'

# The selected device may be absent for several snapshots after erase. Keep
# waiting for its identity; the unrelated radio is never an acceptable fallback.
$pocketLater = [pscustomobject]@{
	SerialNumber = '93DA83ADF7B2092B'
	LocationPath = 'PCIROOT(0)#USBROOT(0)#USB(8)'
	ParentInstanceId = 'USB\VID_239A&PID_0071\93DA83ADF7B2092B'
}
$script:usbIdentities['COM21'] = $pocketLater
$script:postEraseSnapshotCall = 0
function Get-AvailableComPorts {
	$script:postEraseSnapshotCall++
	if ($script:postEraseSnapshotCall -le 3) { return @('COM9') }
	return @('COM9', 'COM21')
}
$postEraseResolved = Resolve-LiveUsbComPort `
	-PreferredComPort 'COM18' `
	-Purpose 'post-erase regression test' `
	-UsbIdentity $pocketRuntime `
	-IdentityTimeoutSec 2
Assert-Equal -Expected 'COM21' -Actual $postEraseResolved -Message 'Post-erase wait selected the unrelated live radio.'

$script:portSnapshotCall = 0
function Get-AvailableComPorts {
	$script:portSnapshotCall++
	if ($script:portSnapshotCall -eq 1) { return @('COM9', 'COM10') }
	return @('COM9', 'COM18')
}
function Touch-ComPort1200 { param([string]$ComPort, [psobject]$UsbIdentity) }

$dfuResolved = Resolve-Nrf52DfuComPort `
	-PreferredComPort 'COM10' `
	-TouchComPort 'COM10' `
	-TimeoutSec 1 `
	-UsbIdentity $pocketRuntime
Assert-Equal -Expected 'COM18' -Actual $dfuResolved -Message 'DFU transition followed the unrelated radio.'

# With nRF52 logging enabled, interface 02 is already present before the touch
# and matches the selected physical serial. It must never be returned as DFU
# while Windows is still enumerating the real bootloader interface.
$script:dualCdcDfuSnapshotCall = 0
$script:usbIdentities['COM10'] = $pocketRuntime
$script:usbIdentities['COM20'] = $pocketLogging
function Get-AvailableComPorts {
	$script:dualCdcDfuSnapshotCall++
	if ($script:dualCdcDfuSnapshotCall -le 2) { return @('COM9', 'COM10', 'COM20') }
	return @('COM9', 'COM18')
}
$dualCdcDfuResolved = Resolve-Nrf52DfuComPort `
	-PreferredComPort 'COM10' `
	-TouchComPort 'COM10' `
	-TimeoutSec 1 `
	-UsbIdentity $pocketRuntime
Assert-Equal -Expected 'COM18' -Actual $dualCdcDfuResolved -Message 'Pre-existing Full Companion logging interface 02 was mistaken for DFU.'

# At the timeout boundary, the old COM number may already have been reused by
# another device. Identity-aware resolution must not fall through to the legacy
# raw-COM retry merely because COM10 exists again.
$script:usbIdentities['COM10'] = $t096Runtime
function Get-AvailableComPorts { return @('COM10') }
$staleReuseResolved = Resolve-Nrf52DfuComPort `
	-PreferredComPort 'COM10' `
	-TouchComPort 'COM10' `
	-TimeoutSec 0 `
	-UsbIdentity $pocketRuntime
Assert-Equal -Expected '' -Actual $staleReuseResolved -Message 'DFU timeout accepted a stale COM number owned by another radio.'

# Identity captured at selection time wins over later COM-number reuse. If the
# original number is simply absent, the captured identity remains usable so the
# live resolver can find the device on its new COM number.
function Get-UsbComPortIdentity {
	param([string]$ComPort)
	if ($ComPort -eq 'COM10') { return $t096Runtime }
	return $null
}
$capturedHw = [pscustomobject]@{ ComPort = 'COM10'; UsbIdentity = $pocketRuntime }
$selectionReuseRejected = $false
try {
	$null = Get-SelectedUsbIdentityForFlash -Hardware $capturedHw
}
catch {
	$selectionReuseRejected = $_.Exception.Message -match 'was reused by'
}
Assert-True -Condition $selectionReuseRejected -Message 'A COM number reused after selection replaced the captured radio identity.'

function Get-UsbComPortIdentity { param([string]$ComPort) return $null }
$capturedWhileAbsent = Get-SelectedUsbIdentityForFlash -Hardware $capturedHw
Assert-True `
	-Condition (Test-UsbComPortIdentityMatch -Expected $pocketRuntime -Actual $capturedWhileAbsent) `
	-Message 'A captured identity was lost merely because its old COM number disappeared.'

# Capture identity from the exact user-selected COM before any generic live-port
# resolution. If that identity cannot be read, flashing must stop immediately.
$script:liveResolverCalled = $false
function Get-UsbComPortIdentity { param([string]$ComPort) return $null }
function Resolve-LiveUsbComPort {
	param($PreferredComPort, $Purpose, $UsbIdentity, $IdentityTimeoutSec)
	$script:liveResolverCalled = $true
	return 'COM9'
}
$fakeHw = [pscustomobject]@{
	ComPort = 'COM10'
	FirmwareFile = 'C:\firmware.zip'
}
$identityCaptureFailedClosed = $false
try {
	$null = flashMeshCoreNrf52 -hw $fakeHw
}
catch {
	$identityCaptureFailedClosed = $_.Exception.Message -match 'Refusing to substitute a different radio'
}
Assert-True -Condition $identityCaptureFailedClosed -Message 'Missing selected-port identity did not stop flashing.'
Assert-True -Condition (-not $script:liveResolverCalled) -Message 'Live-port fallback ran before the selected USB identity was captured.'

# A bootloader-version rejection can occur after the first erase attempt has
# already moved the node from runtime COM10 to DFU COM18. The alternate erase
# package and final app upload must follow the captured identity to COM18.
function Get-UsbComPortIdentity {
	param([string]$ComPort)
	if ($ComPort -eq 'COM10') { return $pocketRuntime }
	if ($ComPort -eq 'COM18') { return $pocketDfu }
	return $null
}
$script:alternateResolveCalls = @()
function Resolve-LiveUsbComPort {
	param($PreferredComPort, $Purpose, $UsbIdentity, $IdentityTimeoutSec)
	$script:alternateResolveCalls += [pscustomobject]@{
		PreferredComPort = $PreferredComPort
		Purpose = $Purpose
	}
	if ($Purpose -match 'alternate') { return 'COM18' }
	if ($PreferredComPort -eq 'COM18') { return 'COM18' }
	return 'COM10'
}
function Resolve-MeshtasticNrf52FirmwareFile { param($hw) return 'C:\firmware.zip' }
function Get-MeshtasticNrf52FlashAction { param($hw) return 'flash-wipe' }
function Get-MeshtasticNrf52EraseUf2Candidates {
	param($FolderPath)
	return @(
		[pscustomobject]@{ FilePath = 'C:\erase-a.uf2' },
		[pscustomobject]@{ FilePath = 'C:\erase-b.uf2' }
	)
}
function Resolve-MeshtasticNrf52ErasePackage {
	param($EraseUf2Path, $ReferenceFile)
	return "$EraseUf2Path.zip"
}
function Resolve-MeshtasticNrf52AppPackage { param($FirmwareFile) return 'C:\application.zip' }
function Test-Path { param($Path) return $true }
function Start-Sleep { param($Seconds, $Milliseconds) }
$script:dfuCalls = @()
function Invoke-NrfutilSerialDfu {
	param($PackageFile, $ComPort, $NrfutilTouchBaud, $ProgressActivity, $UsbIdentity, $TimeoutSec)
	$script:dfuCalls += [pscustomobject]@{
		PackageFile = $PackageFile
		ComPort = $ComPort
		TouchBaud = $NrfutilTouchBaud
	}
	if ($PackageFile -eq 'C:\erase-a.uf2.zip') {
		throw 'Selected Bootloader version does not match'
	}
	return [pscustomobject]@{ Success = $true; ComPort = 'COM18'; UsbIdentity = $UsbIdentity }
}
$alternateHw = [pscustomobject]@{
	ComPort = 'COM10'
	FirmwareFile = 'C:\firmware.zip'
	HWNameFile = 'pocket'
	UsbIdentity = $pocketRuntime
}
$null = flashMeshtasticNrf52 -hw $alternateHw
Assert-Equal -Expected 3 -Actual $script:dfuCalls.Count -Message 'Unexpected number of alternate-erase/app DFU calls.'
Assert-Equal -Expected 'COM10' -Actual $script:dfuCalls[0].ComPort -Message 'First erase did not start on selected runtime port.'
Assert-Equal -Expected 'COM18' -Actual $script:dfuCalls[1].ComPort -Message 'Alternate erase did not follow the device into DFU.'
Assert-Equal -Expected 'COM18' -Actual $script:dfuCalls[2].ComPort -Message 'App upload did not remain bound to the DFU device.'
Assert-Equal -Expected 1200 -Actual $script:dfuCalls[2].TouchBaud -Message 'App upload did not request mode-aware touch handling after wipe.'
Assert-True `
	-Condition (@($script:alternateResolveCalls | Where-Object { $_.Purpose -match 'alternate' }).Count -eq 1) `
	-Message 'Retryable erase failure did not re-resolve the selected physical identity.'

# Confirm that the production nrfutil orchestration uses the preserved touch
# intent for its one-shot COM retry and wires no-touch mode through the DFU
# assertion. This is an AST/source wiring assertion around the tested helpers.
$invokeDefinition = $firmwareAst.Find({
	param($node)
	$node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
	$node.Name -eq 'Invoke-NrfutilSerialDfu'
}, $true)
$invokeText = $invokeDefinition.Extent.Text
Assert-True -Condition ($invokeText -match '\$touchWasRequested\s*=') -Message 'Invoke-NrfutilSerialDfu does not preserve the original touch intent.'
Assert-True -Condition ($invokeText -match 'Test-ShouldRetryNrfutilSerialPort\s+-TouchWasRequested\s+\$touchWasRequested') -Message 'Retry path is still coupled to the cleared NrfutilTouchBaud value.'
Assert-True -Condition ($invokeText -match 'Assert-UsbIdentityIsNrf52Dfu') -Message 'No-touch upload is not wired to a DFU-mode assertion.'
Assert-True `
	-Condition ($invokeText -match 'Get-UsbIdentityInterfaceNumber\s+-Identity\s+\$currentPortIdentity' -and
		$invokeText -match 'Resolve-Nrf52PrimaryUsbSelection') `
	-Message 'Direct nrfutil orchestration can still issue a touch on logging interface 02.'

$meshtasticFlashDefinition = $firmwareAst.Find({
	param($node)
	$node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
	$node.Name -eq 'flashMeshtasticNrf52'
}, $true)
Assert-True `
	-Condition ($meshtasticFlashDefinition.Extent.Text -match 'Resolve-Nrf52PrimaryUsbSelection') `
	-Message 'Meshtastic nRF52 flashing does not canonicalize a selected logging interface.'

$getHwDefinition = $firmwareAst.Find({
	param($node)
	$node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
	$node.Name -eq 'GetHW'
}, $true)
$getHwText = $getHwDefinition.Extent.Text
Assert-True `
	-Condition ($getHwText -match '\$selectedUsbIdentity\s*=\s*Get-UsbComPortIdentity\s+-ComPort\s+\$selectedComPort') `
	-Message 'GetHW does not capture USB identity when the COM port is selected.'
Assert-True `
	-Condition ($getHwText -match 'UsbIdentity') `
	-Message 'GetHW does not carry selected USB identity into the hardware object.'

# The duplicated ESP32 update/install paths must all use the same selected USB
# identity. Source-wiring assertions prevent a later path from bypassing the
# behavior exercised above with a raw COM list or stale-port fallback.
$espFunctionTexts = @{}
foreach ($functionName in @('updateFlashViaEspTool', 'Install-SimpleMergedEspImage', 'installFlashViaEspTool')) {
	$definition = $firmwareAst.Find({
		param($node)
		$node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
		$node.Name -eq $functionName
	}, $true)
	if ($null -eq $definition) { throw "Missing ESP32 function under test: $functionName" }
	$espFunctionTexts[$functionName] = $definition.Extent.Text

	$resolverCalls = @($definition.FindAll({
		param($node)
		$node -is [System.Management.Automation.Language.CommandAst] -and
		$node.GetCommandName() -eq 'Resolve-EspUsbComPort'
	}, $true))
	Assert-True `
		-Condition ($resolverCalls.Count -ge 2) `
		-Message "$functionName does not re-resolve the selected ESP32 across reset boundaries."
	foreach ($resolverCall in $resolverCalls) {
		Assert-True `
			-Condition ($resolverCall.Extent.Text -match '-UsbIdentity\s+\$UsbIdentity') `
			-Message "$functionName has an ESP32 COM resolver call that is not bound to the selected USB identity."
	}
}

foreach ($functionName in @('updateFlashViaEspTool', 'installFlashViaEspTool')) {
	Assert-True `
		-Condition ($espFunctionTexts[$functionName] -match 'Get-SelectedUsbIdentityForFlash\s+-Hardware\s+\$hw') `
		-Message "$functionName does not capture and validate the selected USB identity before reset."
}

$simpleInstallInvocation = $firmwareAst.Find({
	param($node)
	$node -is [System.Management.Automation.Language.CommandAst] -and
	$node.GetCommandName() -eq 'Install-SimpleMergedEspImage'
}, $true)
Assert-True `
	-Condition ($null -ne $simpleInstallInvocation -and
		$simpleInstallInvocation.Extent.Text -match '-UsbIdentity\s+\$usbIdentity') `
	-Message 'The simple merged-image path loses the selected ESP32 USB identity.'

$allEspFlashText = $espFunctionTexts.Values -join "`n"
Assert-True `
	-Condition ($allEspFlashText -notmatch 'getUSBComPort\s+-SkipInfo' -and
		$allEspFlashText -notmatch '\$devicesAfter\s*\[\s*0\s*\]') `
	-Message 'An ESP32 flash path still selects an unbound USB COM port by list position.'
Assert-True `
	-Condition ($allEspFlashText -notmatch '\$selectedComPortPart2\s*=\s*\$selectedComPort') `
	-Message 'An ESP32 flash path still falls back to a stale preferred COM port.'
Assert-True `
	-Condition ($allEspFlashText -notmatch '(?m)^\s*run_cmd\b.*-Stream\s*$') `
	-Message 'An ESP32 flash path still ignores a destructive esptool exit code.'
foreach ($functionName in @('updateFlashViaEspTool', 'Install-SimpleMergedEspImage', 'installFlashViaEspTool')) {
	Assert-True `
		-Condition ($espFunctionTexts[$functionName] -match '\$\w+ExitCode\s*=\s*run_cmd' -and
			$espFunctionTexts[$functionName] -match '\$\w+ExitCode\s+-ne\s+0') `
		-Message "$functionName does not fail when esptool reports an error."
}

# Exercise the destructive full-install orchestration with all commands mocked.
# The selected identity must be carried into every resolution, and a second COM
# renumber after erase must be honored before the merged image write begins.
$script:espResolveCalls = @()
function Resolve-EspUsbComPort {
	param($PreferredComPort, $UsbIdentity, $TimeoutMs, $Purpose)
	$index = $script:espResolveCalls.Count
	$script:espResolveCalls += [pscustomobject]@{
		PreferredComPort = $PreferredComPort
		UsbIdentity = $UsbIdentity
		Purpose = $Purpose
	}
	return @('COM7', 'COM22', 'COM24')[$index]
}
function get_esptool_cmd {
	$script:ESPTOOL_ERASE_FLASH = 'erase_flash'
	$script:ESPTOOL_WRITE_FLASH = 'write_flash'
	return 'esptool'
}
$script:espCommands = @()
function run_cmd {
	param([string]$CommandLine, [switch]$Stream)
	$script:espCommands += $CommandLine
	if ($Stream) { return 0 }
	return ''
}
$null = Install-SimpleMergedEspImage `
	-ImagePath $firmwarePath `
	-ComPort 'COM7' `
	-UsbIdentity $v4Runtime
Assert-Equal -Expected 3 -Actual $script:espResolveCalls.Count -Message 'Merged ESP32 install did not resolve around both reset boundaries.'
foreach ($resolverCall in $script:espResolveCalls) {
	Assert-True `
		-Condition (Test-UsbComPortIdentityMatch -Expected $v4Runtime -Actual $resolverCall.UsbIdentity) `
		-Message 'Merged ESP32 install lost the selected V4 identity during COM resolution.'
}
Assert-Equal -Expected 3 -Actual $script:espCommands.Count -Message 'Merged ESP32 install issued an unexpected command count.'
Assert-True -Condition ($script:espCommands[0] -match '--port COM7 chip_id') -Message 'ESP32 reset did not start on the selected live V4 port.'
Assert-True -Condition ($script:espCommands[1] -match '--port COM22 erase_flash') -Message 'ESP32 erase did not follow the selected V4 after its first COM change.'
Assert-True -Condition ($script:espCommands[2] -match '--port COM24 write_flash 0x00') -Message 'ESP32 merged write did not follow the selected V4 after erase.'

# A failed erase is terminal: do not re-resolve or write an image after esptool
# says the destructive prerequisite did not complete.
$script:espResolveCalls = @()
function Resolve-EspUsbComPort {
	param($PreferredComPort, $UsbIdentity, $TimeoutMs, $Purpose)
	$script:espResolveCalls += $Purpose
	return @('COM7', 'COM22')[$script:espResolveCalls.Count - 1]
}
$script:espCommands = @()
function run_cmd {
	param([string]$CommandLine, [switch]$Stream)
	$script:espCommands += $CommandLine
	if ($Stream -and $CommandLine -match 'erase_flash') { return 17 }
	if ($Stream) { return 0 }
	return ''
}
$eraseFailureRejected = $false
try {
	$null = Install-SimpleMergedEspImage `
		-ImagePath $firmwarePath `
		-ComPort 'COM7' `
		-UsbIdentity $v4Runtime
}
catch {
	$eraseFailureRejected = $_.Exception.Message -match 'erase failed' -and
		$_.Exception.Message -match 'exit code 17' -and
		$_.Exception.Message -match 'Firmware was not written'
}
Assert-True -Condition $eraseFailureRejected -Message 'Merged ESP32 install reported success after erase failure.'
Assert-Equal -Expected 2 -Actual $script:espCommands.Count -Message 'Merged ESP32 install continued after erase failure.'
Assert-True `
	-Condition (@($script:espCommands | Where-Object { $_ -match 'write_flash' }).Count -eq 0) `
	-Message 'Merged ESP32 install wrote firmware after erase failure.'
Assert-Equal -Expected 2 -Actual $script:espResolveCalls.Count -Message 'Merged ESP32 install resolved a write port after erase failure.'

# A failed write must propagate as failure rather than returning true.
$script:espResolveCalls = @()
function Resolve-EspUsbComPort {
	param($PreferredComPort, $UsbIdentity, $TimeoutMs, $Purpose)
	$script:espResolveCalls += $Purpose
	return @('COM7', 'COM22', 'COM24')[$script:espResolveCalls.Count - 1]
}
$script:espCommands = @()
function run_cmd {
	param([string]$CommandLine, [switch]$Stream)
	$script:espCommands += $CommandLine
	if ($Stream -and $CommandLine -match 'write_flash') { return 23 }
	if ($Stream) { return 0 }
	return ''
}
$writeFailureRejected = $false
try {
	$null = Install-SimpleMergedEspImage `
		-ImagePath $firmwarePath `
		-ComPort 'COM7' `
		-UsbIdentity $v4Runtime
}
catch {
	$writeFailureRejected = $_.Exception.Message -match 'write failed' -and
		$_.Exception.Message -match 'exit code 23'
}
Assert-True -Condition $writeFailureRejected -Message 'Merged ESP32 install reported success after write failure.'
Assert-Equal -Expected 3 -Actual $script:espCommands.Count -Message 'Merged ESP32 write-failure orchestration issued an unexpected command count.'

# If the selected identity disappears after the 1200-baud command, abort before
# erase rather than substituting one of the other attached radios.
$script:espResolveCalls = @()
function Resolve-EspUsbComPort {
	param($PreferredComPort, $UsbIdentity, $TimeoutMs, $Purpose)
	$script:espResolveCalls += [pscustomobject]@{
		PreferredComPort = $PreferredComPort
		UsbIdentity = $UsbIdentity
		Purpose = $Purpose
	}
	if ($script:espResolveCalls.Count -eq 1) { return 'COM7' }
	throw 'USB serial 44:1B:F6:6A:E8:44 did not enumerate a COM port. Refusing to use a different USB radio.'
}
$script:espCommands = @()
$missingAfterTouchRejected = $false
try {
	$null = Install-SimpleMergedEspImage `
		-ImagePath $firmwarePath `
		-ComPort 'COM7' `
		-UsbIdentity $v4Runtime
}
catch {
	$missingAfterTouchRejected = $_.Exception.Message -match 'did not enumerate a COM port' -and
		$_.Exception.Message -match 'Refusing to use a different USB radio'
}
Assert-True -Condition $missingAfterTouchRejected -Message 'Merged ESP32 install did not fail closed when the selected V4 disappeared after touch.'
Assert-Equal -Expected 1 -Actual $script:espCommands.Count -Message 'Merged ESP32 install issued erase/write after losing the selected identity.'
Assert-True -Condition ($script:espCommands[0] -match 'chip_id') -Message 'Unexpected command ran before the missing post-touch identity was rejected.'

# Full Companion interface 00 can already be in framed Binary mode when the
# inventory probe opens it. Verify the bounded control-line handoff recognizes
# the terminal banner, and that the matching STOP token is sent afterward.
$probePort = [pscustomobject]@{
	IsOpen = $true
	ReadChunks = [System.Collections.ArrayList]@(
		"`r`n===== MeshCore Full ",
		"Companion Terminal =====`r`n"
	)
	Writes = [System.Collections.ArrayList]@()
}
$probePort | Add-Member -MemberType ScriptMethod -Name DiscardInBuffer -Value { }
$probePort | Add-Member -MemberType ScriptMethod -Name WriteLine -Value {
	param($line)
	[void]$this.Writes.Add([string]$line)
}
$probePort | Add-Member -MemberType ScriptMethod -Name ReadExisting -Value {
	if ($this.ReadChunks.Count -eq 0) { return '' }
	$chunk = [string]$this.ReadChunks[0]
	$this.ReadChunks.RemoveAt(0)
	return $chunk
}
$enteredForProbe = Enter-MeshCoreTerminalForProbe -SerialPort $probePort -TotalMs 100
Assert-True -Condition $enteredForProbe -Message 'Full Companion Binary mode was not handed to the inventory terminal probe.'
Exit-MeshCoreTerminalAfterProbe -SerialPort $probePort
Assert-Equal `
	-Expected '+++MESHCORE-TERM-START' `
	-Actual $probePort.Writes[0] `
	-Message 'Inventory did not send the Full Companion terminal start token.'
Assert-Equal `
	-Expected '+++MESHCORE-TERM-STOP' `
	-Actual $probePort.Writes[1] `
	-Message 'Inventory did not restore Full Companion Binary mode after probing.'

$unknownProbePort = [pscustomobject]@{
	IsOpen = $true
	Writes = [System.Collections.ArrayList]@()
}
$unknownProbePort | Add-Member -MemberType ScriptMethod -Name DiscardInBuffer -Value { }
$unknownProbePort | Add-Member -MemberType ScriptMethod -Name WriteLine -Value {
	param($line)
	[void]$this.Writes.Add([string]$line)
}
$unknownProbePort | Add-Member -MemberType ScriptMethod -Name ReadExisting -Value { return '' }
Assert-True `
	-Condition (-not (Enter-MeshCoreTerminalForProbe -SerialPort $unknownProbePort -TotalMs 0)) `
	-Message 'An arbitrary silent serial device was mistaken for a MeshCore terminal.'
Assert-Equal `
	-Expected '+++MESHCORE-TERM-START,+++MESHCORE-TERM-STOP' `
	-Actual ($unknownProbePort.Writes -join ',') `
	-Message 'A silent probe was not balanced with STOP after START was written.'

$readFailureProbePort = [pscustomobject]@{
	IsOpen = $true
	Writes = [System.Collections.ArrayList]@()
}
$readFailureProbePort | Add-Member -MemberType ScriptMethod -Name DiscardInBuffer -Value { }
$readFailureProbePort | Add-Member -MemberType ScriptMethod -Name WriteLine -Value {
	param($line)
	[void]$this.Writes.Add([string]$line)
}
$readFailureProbePort | Add-Member -MemberType ScriptMethod -Name ReadExisting -Value { throw 'synthetic read failure' }
Assert-True `
	-Condition (-not (Enter-MeshCoreTerminalForProbe -SerialPort $readFailureProbePort -TotalMs 1)) `
	-Message 'A read failure was mistaken for a MeshCore terminal banner.'
Assert-Equal `
	-Expected '+++MESHCORE-TERM-START,+++MESHCORE-TERM-STOP' `
	-Actual ($readFailureProbePort.Writes -join ',') `
	-Message 'A probe read failure left terminal mode active after START was written.'

# Exercise getMeshCore's state-dependent retry: ordinary board commands are
# silent until the terminal handoff, after which inventory obtains the real
# hardware/name/version and finally restores Binary mode.
$meshProbePort = [pscustomobject]@{ IsOpen = $true }
$meshProbePort | Add-Member -MemberType ScriptMethod -Name Close -Value { $this.IsOpen = $false }
function Open-SerialPort { param($ComPort, $Baud, $ReadTimeoutMs, $WriteTimeoutMs, $Dtr, $Rts) return $meshProbePort }
function Get-UsableSerialResponse { param($Text, $Kind, $MaxLength) return [string]$Text }
$script:meshProbeInTerminal = $false
$script:meshProbeEnterCalls = 0
$script:meshProbeExitCalls = 0
function Enter-MeshCoreTerminalForProbe {
	param($SerialPort, $TotalMs)
	$script:meshProbeEnterCalls++
	$script:meshProbeInTerminal = $true
	return $true
}
function Exit-MeshCoreTerminalAfterProbe {
	param($SerialPort)
	$script:meshProbeExitCalls++
	$script:meshProbeInTerminal = $false
}
function Invoke-SerialCommandWithRetry {
	param($SerialPort, $Command, $MaxAttempts, $TotalMs, $ProgressId, $Activity)
	if (-not $script:meshProbeInTerminal) { return '' }
	switch ($Command) {
		'board' { return 'Heltec T096' }
		'get name' { return 'T096 Full Companion' }
		'ver' { return 'v1.17.1' }
		default { return '' }
	}
}
function Get-MeshCoreCompanionInfo { return $null }
$meshProbeResult = getMeshCore -ComPort 'COM9' -CmdTimeoutMs 1
Assert-True -Condition $meshProbeResult.Success -Message 'Binary-mode Full Companion remained a generic USB inventory row.'
Assert-Equal -Expected 'Heltec T096' -Actual $meshProbeResult.HWName -Message 'Inventory lost the Full Companion hardware name.'
Assert-Equal -Expected 'MeshCore' -Actual $meshProbeResult.Project -Message 'Inventory did not identify the Full Companion as MeshCore.'
Assert-Equal -Expected 'v1.17.1' -Actual $meshProbeResult.FWVersion -Message 'Inventory lost the Full Companion firmware version.'
Assert-Equal -Expected 1 -Actual $script:meshProbeEnterCalls -Message 'Inventory used an unexpected number of Binary-to-terminal handoffs.'
Assert-Equal -Expected 1 -Actual $script:meshProbeExitCalls -Message 'Inventory did not restore Binary mode exactly once.'

# Interface 02 is output-only and cannot answer the same probe. Keep it visible
# for log readers, but inherit the same-radio interface 00 board/version and
# explicitly tell the user which sibling will be used for flashing.
function getallUSBCom {
	return @(
		[pscustomobject]@{ drive_letter = 'COM9'; device_name = 'VID_239A&PID_8029&MI_00'; friendly_name = 'USB Serial Device (COM9)'; firmware_revision = '--' },
		[pscustomobject]@{ drive_letter = 'COM21'; device_name = 'VID_239A&PID_8029&MI_02'; friendly_name = 'USB Serial Device (COM21)'; firmware_revision = '--' }
	)
}
function getMeshtasticNodeInfo {
	param($ComPort)
	return [pscustomobject]@{ Success = $false }
}
function getMeshCore {
	param($ComPort)
	if ($ComPort -eq 'COM9') {
		return [pscustomobject]@{
			Success = $true
			HWName = 'Heltec T096'
			Project = 'MeshCore'
			FWVersion = 'v1.17.1'
			ExtraInfo = 'T096 Full Companion Baud: 115200'
		}
	}
	return [pscustomobject]@{ Success = $false }
}
function Get-UsbComPortIdentity {
	param($ComPort)
	if ($ComPort -eq 'COM9') { return $t096Runtime }
	if ($ComPort -eq 'COM21') { return $t096Logging }
	return $null
}
$dualCdcInventory = @(getUsbComDevices)
$loggingInventoryRow = $dualCdcInventory | Where-Object { $_.ComPort -eq 'COM21' }
Assert-Equal -Expected 'Heltec T096' -Actual $loggingInventoryRow.DeviceName -Message 'Logging interface 02 remained a generic VID/PID inventory row.'
Assert-Equal -Expected 'MeshCore' -Actual $loggingInventoryRow.Project -Message 'Logging interface 02 was not associated with its MeshCore primary.'
Assert-Equal -Expected 'v1.17.1' -Actual $loggingInventoryRow.FirmwareVersion -Message 'Logging interface 02 did not inherit its primary firmware version.'
Assert-True `
	-Condition ($loggingInventoryRow.ExtraInfo -match 'interface 02' -and $loggingInventoryRow.ExtraInfo -match 'COM9') `
	-Message 'Logging inventory row did not explain its primary flashing port.'

# A failed direct SerialPort close/open can race Windows PnP: the old COM may
# still be listed when the selected identity already exists on a new DFU COM.
# A pre-existing second CDC logging port from that same radio must not count.
function Get-AvailableComPorts { return @('COM6', 'COM9', 'COM20') }
function Get-UsbComPortIdentity {
	param([string]$ComPort)
	if ($ComPort -eq 'COM6') { return $pocketDfu }
	if ($ComPort -eq 'COM9') { return $pocketRuntime }
	if ($ComPort -eq 'COM20') { return $pocketLogging }
	return $null
}
$transitionSeen = Wait-Nrf52DfuTransitionAfterFailedTouch `
	-ComPort 'COM9' `
	-BeforePorts @('COM9', 'COM20') `
	-UsbIdentity $pocketRuntime `
	-TimeoutMs 0
Assert-True -Condition $transitionSeen -Message 'A new identity-matched DFU COM was missed while the old COM devnode lingered.'

function Get-AvailableComPorts { return @('COM9', 'COM20') }
$loggingPortIsNotTransition = Wait-Nrf52DfuTransitionAfterFailedTouch `
	-ComPort 'COM9' `
	-BeforePorts @('COM9', 'COM20') `
	-UsbIdentity $pocketRuntime `
	-TimeoutMs 0
Assert-True `
	-Condition (-not $loggingPortIsNotTransition) `
	-Message 'A pre-existing second CDC logging port was mistaken for a new DFU transition.'

function Get-AvailableComPorts { return @('COM20') }
Assert-True `
	-Condition (Wait-Nrf52DfuTransitionAfterFailedTouch -ComPort 'COM9' -BeforePorts @('COM9', 'COM20') -UsbIdentity $pocketRuntime -TimeoutMs 0) `
	-Message 'Disappearance of the touched COM port was not recognized as a reset.'

# Re-load the production touch function after the earlier DFU resolver mock,
# then prove an observed reset suppresses the doomed Python retry.
$touchDefinition = $firmwareAst.Find({
	param($node)
	$node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
	$node.Name -eq 'Touch-ComPort1200'
}, $true)
Invoke-Expression $touchDefinition.Extent.Text
function Get-AvailableComPorts { return @('COM999') }
$script:failedTouchWaitCalls = 0
$script:pythonTouchCalls = 0
$script:failedTouchIdentity = $null
$script:touchIdentityChecks = 0
function Get-UsbComPortIdentity {
	param([string]$ComPort)
	$script:touchIdentityChecks++
	return $pocketRuntime
}
function Wait-Nrf52DfuTransitionAfterFailedTouch {
	param($ComPort, $BeforePorts, $UsbIdentity, $TimeoutMs, $PollIntervalMs)
	$script:failedTouchWaitCalls++
	$script:failedTouchIdentity = $UsbIdentity
	return $true
}
function Invoke-PythonSerialTouch1200 {
	param($ComPort)
	$script:pythonTouchCalls++
	return 0
}
Touch-ComPort1200 -ComPort 'COM999' -UsbIdentity $pocketRuntime
Assert-Equal -Expected 1 -Actual $script:failedTouchWaitCalls -Message 'A direct touch exception did not check for an in-progress DFU transition.'
Assert-Equal -Expected 0 -Actual $script:pythonTouchCalls -Message 'Python retried a stale runtime COM after its DFU transition was observed.'
Assert-Equal -Expected 1 -Actual $script:touchIdentityChecks -Message 'The selected identity was not revalidated immediately before direct touch.'
Assert-True `
	-Condition (Test-UsbComPortIdentityMatch -Expected $pocketRuntime -Actual $script:failedTouchIdentity) `
	-Message 'The selected physical identity was not passed into failed-touch transition detection.'

function Wait-Nrf52DfuTransitionAfterFailedTouch {
	param($ComPort, $BeforePorts, $UsbIdentity, $TimeoutMs, $PollIntervalMs)
	return $false
}
$script:pythonTouchCalls = 0
$script:touchIdentityChecks = 0
Touch-ComPort1200 -ComPort 'COM999' -UsbIdentity $pocketRuntime
Assert-Equal -Expected 1 -Actual $script:pythonTouchCalls -Message 'Python fallback was not retained for a genuine direct-touch failure with no transition.'
Assert-Equal -Expected 2 -Actual $script:touchIdentityChecks -Message 'Identity was not revalidated before both direct touch and Python fallback.'

# If the same COM number disappears or is reused after the direct open fails,
# Python must never receive that stale name. This is the last point at which an
# unrelated radio can race into the selected COM number.
$script:fallbackReuseCheck = 0
$script:pythonTouchCalls = 0
function Get-UsbComPortIdentity {
	param([string]$ComPort)
	$script:fallbackReuseCheck++
	if ($script:fallbackReuseCheck -eq 1) { return $pocketRuntime }
	return $t096Runtime
}
$fallbackReuseRejected = $false
try {
	Touch-ComPort1200 -ComPort 'COM999' -UsbIdentity $pocketRuntime
}
catch {
	$fallbackReuseRejected = $_.Exception.Message -match 'now belongs to' -and
		$_.Exception.Message -match 'Refusing Python 1200-baud fallback'
}
Assert-True -Condition $fallbackReuseRejected -Message 'Same-COM reuse before Python fallback did not fail closed.'
Assert-Equal -Expected 0 -Actual $script:pythonTouchCalls -Message 'Python touched a COM number reused by another radio.'

$script:fallbackMissingCheck = 0
$script:pythonTouchCalls = 0
function Get-UsbComPortIdentity {
	param([string]$ComPort)
	$script:fallbackMissingCheck++
	if ($script:fallbackMissingCheck -eq 1) { return $pocketRuntime }
	return $null
}
$fallbackMissingRejected = $false
try {
	Touch-ComPort1200 -ComPort 'COM999' -UsbIdentity $pocketRuntime
}
catch {
	$fallbackMissingRejected = $_.Exception.Message -match 'Could not revalidate' -and
		$_.Exception.Message -match 'Python 1200-baud fallback'
}
Assert-True -Condition $fallbackMissingRejected -Message 'Missing identity before Python fallback did not fail closed.'
Assert-Equal -Expected 0 -Actual $script:pythonTouchCalls -Message 'Python touched a COM port whose identity disappeared.'

$script:initialIdentityChecks = 0
$script:pythonTouchCalls = 0
function Get-UsbComPortIdentity {
	param([string]$ComPort)
	$script:initialIdentityChecks++
	return $null
}
$missingInitialIdentityRejected = $false
try {
	Touch-ComPort1200 -ComPort 'COM999' -UsbIdentity $pocketRuntime
}
catch {
	$missingInitialIdentityRejected = $_.Exception.Message -match 'Could not revalidate' -and
		$_.Exception.Message -match 'Refusing to touch an unverified COM port'
}
Assert-True -Condition $missingInitialIdentityRejected -Message 'Missing identity immediately before direct touch did not fail closed.'
Assert-Equal -Expected 1 -Actual $script:initialIdentityChecks -Message 'Direct touch identity was checked an unexpected number of times.'
Assert-Equal -Expected 0 -Actual $script:pythonTouchCalls -Message 'Missing direct-touch identity still reached Python fallback.'

function Get-UsbComPortIdentity { param([string]$ComPort) return $pocketLogging }
$wrongInterfaceRejected = $false
try {
	Touch-ComPort1200 -ComPort 'COM999' -UsbIdentity $pocketRuntime
}
catch {
	$wrongInterfaceRejected = $_.Exception.Message -match 'interface 02' -and
		$_.Exception.Message -match 'interface 00' -and
		$_.Exception.Message -match 'Refusing direct 1200-baud touch'
}
Assert-True -Condition $wrongInterfaceRejected -Message 'Logging interface 02 passed the final direct-touch identity check.'
Assert-Equal -Expected 0 -Actual $script:pythonTouchCalls -Message 'Wrong-interface identity still reached Python fallback.'

# The backup gate must validate the archive independently, re-prompt invalid
# answers, and never let an API-limited snapshot silently authorize a wipe.
$gateArchive = [System.IO.Path]::GetTempFileName()
try {
	$script:gateMode = 'unsafe'
	$script:gateAnswers = @()
	$script:gateAnswerIndex = 0
	$script:gateBackupCalls = 0
	function Read-Host {
		param([string]$Prompt)
		if ($script:gateAnswerIndex -ge $script:gateAnswers.Count) { return '' }
		$answer = $script:gateAnswers[$script:gateAnswerIndex]
		$script:gateAnswerIndex++
		return $answer
	}
	function Test-CachedMeshCoreUsbBackup {
		param($Hardware, $UsbIdentity, [switch]$RequireSafeForWipe)
		return $false
	}
	function Invoke-MeshCoreUsbBackup {
		param($ComPort, $UsbIdentity, $DeviceHint, $RoleHint)
		$script:gateBackupCalls++
		$exitCode = if ($script:gateMode -eq 'partial') { 31 } else { 0 }
		return [pscustomobject]@{
			ExitCode = $exitCode
			Summary = [pscustomobject]@{
				ok = $true
				exit_code = $exitCode
				path = $gateArchive
				safe_for_wipe = $false
			}
		}
	}
	function Invoke-MeshCoreBackupHelper {
		param([string[]]$Arguments, [switch]$Quiet)
		if ($Arguments -contains '--require-safe-for-wipe') {
			return [pscustomobject]@{ ExitCode = 40; Summary = [pscustomobject]@{ ok = $false } }
		}
		return [pscustomobject]@{ ExitCode = 0; Summary = [pscustomobject]@{ ok = $true } }
	}

	$gateHw = [pscustomobject]@{ HWNameFile = 'Test nRF52' }
	$script:gateAnswers = @('Y', '')
	$unsafeWipeBlocked = $false
	try {
		Request-MeshCoreUsbBackupBeforeFlash -Hardware $gateHw -ComPort 'COM9' -UsbIdentity $t096Runtime -Action 'flash-wipe'
	}
	catch {
		$unsafeWipeBlocked = $_.Exception.Message -match 'no complete verified backup'
	}
	Assert-True -Condition $unsafeWipeBlocked -Message 'A verified but API-limited logical backup silently authorized a wipe.'

	$script:gateMode = 'partial'
	$script:gateAnswers = @('Y')
	$script:gateAnswerIndex = 0
	$partialUpdateAccepted = Request-MeshCoreUsbBackupBeforeFlash `
		-Hardware ([pscustomobject]@{ HWNameFile = 'Test nRF52' }) `
		-ComPort 'COM9' `
		-UsbIdentity $t096Runtime `
		-Action 'flash-update'
	Assert-True -Condition $partialUpdateAccepted -Message 'A verified logical snapshot did not satisfy the non-destructive update backup gate.'

	$script:gateMode = 'unsafe'
	$script:gateAnswers = @('not-an-answer', 'N')
	$script:gateAnswerIndex = 0
	$script:gateBackupCalls = 0
	$skippedUpdate = Request-MeshCoreUsbBackupBeforeFlash `
		-Hardware ([pscustomobject]@{ HWNameFile = 'Test nRF52' }) `
		-ComPort 'COM9' `
		-UsbIdentity $t096Runtime `
		-Action 'flash-update'
	Assert-True -Condition (-not $skippedUpdate) -Message 'An explicit N response unexpectedly reported a completed backup.'
	Assert-Equal -Expected 2 -Actual $script:gateAnswerIndex -Message 'Invalid Y/N input did not cause a re-prompt.'
	Assert-Equal -Expected 0 -Actual $script:gateBackupCalls -Message 'Explicitly declining a backup still invoked the helper.'
}
finally {
	Remove-Item -LiteralPath $gateArchive -Force -ErrorAction SilentlyContinue
}

# End-to-end orchestration guard: even when GetHW carries COM21/MI_02, the
# MeshCore nRF52 path must hand COM9/MI_00 to the first and only 1200-touch
# uploader call.
function Get-SelectedUsbIdentityForFlash { param($Hardware) return $t096Logging }
$script:primarySelectionInputs = @()
function Resolve-Nrf52PrimaryUsbSelection {
	param($SelectedComPort, $UsbIdentity, $TimeoutSec, $PollIntervalMs)
	$script:primarySelectionInputs += [pscustomobject]@{
		ComPort = $SelectedComPort
		UsbIdentity = $UsbIdentity
	}
	return [pscustomobject]@{ ComPort = 'COM9'; UsbIdentity = $t096Runtime }
}
$script:meshFlashLivePorts = @()
function Resolve-LiveUsbComPort {
	param($PreferredComPort, $Purpose, $UsbIdentity, $IdentityTimeoutSec)
	$script:meshFlashLivePorts += [pscustomobject]@{
		PreferredComPort = $PreferredComPort
		Purpose = $Purpose
		UsbIdentity = $UsbIdentity
	}
	return 'COM9'
}
function Get-MeshCoreNrf52FlashAction { param($hw) return 'flash-update' }
function Get-MeshCoreBootloaderHintText { param($hw) return '' }
$script:meshFlashOrder = @()
$script:meshBackupCalls = @()
function Request-MeshCoreUsbBackupBeforeFlash {
	param($Hardware, $ComPort, $UsbIdentity, $Action)
	$script:meshFlashOrder += 'backup'
	$script:meshBackupCalls += [pscustomobject]@{
		ComPort = $ComPort
		UsbIdentity = $UsbIdentity
		Action = $Action
	}
	return $true
}
$script:meshFlashDfuCalls = @()
function Invoke-NrfutilSerialDfu {
	param($PackageFile, $ComPort, $NrfutilTouchBaud, $TouchComPort, $TimeoutSec, $ProgressActivity, $UsbIdentity)
	$script:meshFlashOrder += 'dfu'
	$script:meshFlashDfuCalls += [pscustomobject]@{
		ComPort = $ComPort
		TouchBaud = $NrfutilTouchBaud
		UsbIdentity = $UsbIdentity
	}
	return [pscustomobject]@{ Success = $true; ComPort = 'COM9'; UsbIdentity = $UsbIdentity }
}
$loggingSelectedHw = [pscustomobject]@{
	ComPort = 'COM21'
	FirmwareFile = 'C:\firmware.zip'
	UsbIdentity = $t096Logging
}
$null = flashMeshCoreNrf52 -hw $loggingSelectedHw
Assert-Equal -Expected 1 -Actual $script:primarySelectionInputs.Count -Message 'MeshCore flash did not canonicalize the selected logging interface exactly once.'
Assert-Equal -Expected 'COM21' -Actual $script:primarySelectionInputs[0].ComPort -Message 'MeshCore flash lost the originally selected logging COM.'
Assert-Equal -Expected 1 -Actual $script:meshBackupCalls.Count -Message 'MeshCore flash did not request exactly one USB backup.'
Assert-Equal -Expected 'COM9' -Actual $script:meshBackupCalls[0].ComPort -Message 'MeshCore backup did not use the canonical primary interface.'
Assert-Equal -Expected 'flash-update' -Actual $script:meshBackupCalls[0].Action -Message 'MeshCore backup did not receive the selected flash action.'
Assert-Equal -Expected 'backup' -Actual $script:meshFlashOrder[0] -Message 'MeshCore entered DFU before requesting its USB backup.'
Assert-Equal -Expected 'dfu' -Actual $script:meshFlashOrder[1] -Message 'MeshCore DFU did not follow its USB backup.'
Assert-Equal -Expected 1 -Actual $script:meshFlashDfuCalls.Count -Message 'Unexpected MeshCore DFU call count for flash-update.'
Assert-Equal -Expected 'COM9' -Actual $script:meshFlashDfuCalls[0].ComPort -Message 'MeshCore attempted its 1200 touch on logging interface 02.'
Assert-Equal -Expected 1200 -Actual $script:meshFlashDfuCalls[0].TouchBaud -Message 'MeshCore flash-update lost its expected touch request.'
Assert-Equal `
	-Expected '00' `
	-Actual (Get-UsbIdentityInterfaceNumber -Identity $script:meshFlashDfuCalls[0].UsbIdentity) `
	-Message 'MeshCore handed the logging identity to the nRF52 uploader.'

Write-Host 'PASS firmware USB identity regression tests'
