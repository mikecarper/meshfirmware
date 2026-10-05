$ErrorActionPreference = 'Stop'

function Assert-Equal {
	param($Expected, $Actual, [string]$Message)
	if ($Expected -ne $Actual) { throw "$Message Expected '$Expected', got '$Actual'." }
}

function Assert-True {
	param([bool]$Condition, [string]$Message)
	if (-not $Condition) { throw $Message }
}

$firmwarePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'firmware.cmd'
$tokens = $null
$parseErrors = $null
$firmwareAst = [System.Management.Automation.Language.Parser]::ParseFile($firmwarePath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -ne 0) { throw "firmware.cmd parse failed: $($parseErrors -join '; ')" }
foreach ($functionName in @('Get-UsbPnpProperties', 'Get-UsbComPortIdentity', 'Get-UsbInterfaceNumberFromInstanceId', 'Resolve-UsbParentInstanceId')) {
	$definition = $firmwareAst.Find({
		param($node)
		$node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $functionName
	}, $true)
	if ($null -eq $definition) { throw "Missing function under test: $functionName" }
	Invoke-Expression $definition.Extent.Text
}

# These fixtures call only mocked read-only getters. Constructing a client-side
# CIM instance does not contact a provider or enumerate a physical device.
function New-FixtureCimDevice {
	param([string]$InstanceId, [string]$Name = 'USB Serial Device (COM4)', [bool]$Present = $true, [uint32]$ErrorCode = 0)
	$device = [Microsoft.Management.Infrastructure.CimInstance]::new('Win32_PnPEntity', 'root/cimv2')
	foreach ($property in @(
		@('DeviceID', $InstanceId, [Microsoft.Management.Infrastructure.CimType]::String, [Microsoft.Management.Infrastructure.CimFlags]::Key),
		@('PNPDeviceID', $InstanceId, [Microsoft.Management.Infrastructure.CimType]::String, [Microsoft.Management.Infrastructure.CimFlags]::None),
		@('Name', $Name, [Microsoft.Management.Infrastructure.CimType]::String, [Microsoft.Management.Infrastructure.CimFlags]::None),
		@('Present', $Present, [Microsoft.Management.Infrastructure.CimType]::Boolean, [Microsoft.Management.Infrastructure.CimFlags]::None),
		@('ConfigManagerErrorCode', $ErrorCode, [Microsoft.Management.Infrastructure.CimType]::UInt32, [Microsoft.Management.Infrastructure.CimFlags]::None)
	)) {
		$device.CimInstanceProperties.Add([Microsoft.Management.Infrastructure.CimProperty]::Create($property[0], $property[1], $property[2], $property[3]))
	}
	return $device
}

function Reset-Fixtures {
	$script:CimMethodCalls = @()
	$script:CimConstructorCalls = @()
	$script:PnpPropertyCalls = @()
	$script:DeviceQueryCalls = 0
	$script:CimFailure = ''
	$script:PropertyValues = @{}
	$script:EnumeratedDevice = $null
}

function Test-IsWindowsHost { return $true }

function New-CimInstance {
	[CmdletBinding()]
	param([string]$ClassName, [hashtable]$Property, [string[]]$Key, [switch]$ClientOnly)
	$script:CimConstructorCalls += [pscustomobject]@{ ClassName = $ClassName; Property = $Property; Key = $Key; ClientOnly = $ClientOnly.IsPresent }
	return [pscustomobject]@{ DeviceID = [string]$Property.DeviceID }
}

function Invoke-CimMethod {
	[CmdletBinding()]
	param($InputObject, [string]$MethodName, [hashtable]$Arguments)
	$script:CimMethodCalls += [pscustomobject]@{ InputObject = $InputObject; MethodName = $MethodName; Keys = @($Arguments.devicePropertyKeys) }
	if ($script:CimFailure -eq 'unsupported') { throw 'The provider does not support GetDeviceProperties.' }
	if ($script:CimFailure -eq 'return-code') { return [pscustomobject]@{ ReturnValue = 1; deviceProperties = @() } }
	$values = $script:PropertyValues[[string]$InputObject.DeviceID]
	$properties = @()
	foreach ($key in $Arguments.devicePropertyKeys) {
		if ($null -ne $values -and $values.ContainsKey($key)) {
			$properties += [pscustomobject]@{ KeyName = $key; Data = $values[$key] }
		}
	}
	return [pscustomobject]@{ ReturnValue = 0; deviceProperties = $properties }
}

function Get-PnpDeviceProperty {
	[CmdletBinding()]
	param([string]$InstanceId, [string]$KeyName)
	$script:PnpPropertyCalls += [pscustomobject]@{ InstanceId = $InstanceId; KeyName = $KeyName }
	$values = $script:PropertyValues[$InstanceId]
	if ($null -eq $values -or -not $values.ContainsKey($KeyName)) { throw "Property unavailable: $KeyName" }
	return [pscustomobject]@{ Data = $values[$KeyName] }
}

function Get-CimInstance {
	[CmdletBinding()]
	param([string]$ClassName)
	$script:DeviceQueryCalls++
	return $script:EnumeratedDevice
}

$portId = 'USB\VID_239A&PID_8029&MI_00\7&65CC297&2&0000'
$parentId = 'USB\VID_239A&PID_8029\25B8546F36809E2C'
$location = 'PCIROOT(0)#PCI(1400)#USBROOT(0)#USB(8)'
$parentKey = 'DEVPKEY_Device_Parent'
$descriptionKey = 'DEVPKEY_Device_BusReportedDeviceDesc'
$locationKey = 'DEVPKEY_Device_LocationPaths'
$portDevice = New-FixtureCimDevice -InstanceId $portId

Reset-Fixtures
$script:PropertyValues[$portId] = @{ $parentKey = $parentId; $descriptionKey = 'TinyUSB Serial' }
$properties = Get-UsbPnpProperties -InstanceId $portId -KeyNames @($parentKey, $descriptionKey) -CimDevice $portDevice
Assert-Equal $parentId $properties[$parentKey] 'The batched getter must preserve the parent property.'
Assert-Equal 'TinyUSB Serial' $properties[$descriptionKey] 'The batched getter must preserve the description property.'
Assert-Equal 1 $script:CimMethodCalls.Count 'Both port keys must use one CIM method call.'
Assert-Equal 'GetDeviceProperties' $script:CimMethodCalls[0].MethodName 'Only the read-only getter may be called.'
Assert-Equal "$parentKey,$descriptionKey" ($script:CimMethodCalls[0].Keys -join ',') 'The getter must pass both exact property keys.'
Assert-True ([object]::ReferenceEquals($portDevice, $script:CimMethodCalls[0].InputObject)) 'An existing CIM instance must be reused unchanged.'
Assert-Equal 0 $script:CimConstructorCalls.Count 'An existing CIM instance must not be reconstructed.'
Assert-Equal 0 $script:PnpPropertyCalls.Count 'The normal path must not call the slower wrapper.'

Reset-Fixtures
$script:PropertyValues[$parentId] = @{ $locationKey = @($location, 'ACPI(_SB_)#USB'); $descriptionKey = 'MeshCore T1000-E' }
$properties = Get-UsbPnpProperties -InstanceId $parentId -KeyNames @($locationKey, $descriptionKey)
Assert-Equal 1 $script:CimConstructorCalls.Count 'A parent reference must be created once.'
Assert-Equal 'Win32_PnPEntity' $script:CimConstructorCalls[0].ClassName 'The reference must use the same Windows provider.'
Assert-Equal 'DeviceID' ($script:CimConstructorCalls[0].Key -join ',') 'The provider key is DeviceID, not PNPDeviceID.'
Assert-Equal $parentId $script:CimConstructorCalls[0].Property.DeviceID 'The client-only reference must target the exact parent.'
Assert-True $script:CimConstructorCalls[0].ClientOnly 'Reference construction must not query a provider.'
Assert-Equal 2 @($properties[$locationKey]).Count 'A location-path list must not be flattened or truncated.'
Assert-Equal $location $properties[$locationKey][0] 'The preferred location path must retain its order.'
Assert-Equal 0 $script:DeviceQueryCalls 'Resolving a parent must not enumerate the device tree.'

foreach ($failure in @('unsupported', 'return-code')) {
	Reset-Fixtures
	$script:CimFailure = $failure
	$script:PropertyValues[$portId] = @{ $parentKey = $parentId; $descriptionKey = 'TinyUSB Serial' }
	$properties = Get-UsbPnpProperties -InstanceId $portId -KeyNames @($parentKey, $descriptionKey) -CimDevice $portDevice
	Assert-Equal $parentId $properties[$parentKey] "The $failure fallback must preserve the parent."
	Assert-Equal 'TinyUSB Serial' $properties[$descriptionKey] "The $failure fallback must preserve the interface description."
	Assert-Equal 2 $script:PnpPropertyCalls.Count "The $failure fallback must query the existing property API."
	Assert-Equal "$parentKey,$descriptionKey" (($script:PnpPropertyCalls | ForEach-Object KeyName) -join ',') 'Fallback keys must match the requested batch.'
}

Reset-Fixtures
$script:PropertyValues[$portId] = @{ $parentKey = $parentId; $descriptionKey = 'TinyUSB Serial' }
$script:PropertyValues[$parentId] = @{ $locationKey = @($location, 'ACPI(_SB_)#USB'); $descriptionKey = 'MeshCore T1000-E' }
$identity = Get-UsbComPortIdentity -ComPort ' com4 ' -PnpDevice $portDevice
Assert-True ($null -ne $identity) 'A supplied present devnode must produce a physical identity.'
Assert-Equal '25B8546F36809E2C' $identity.SerialNumber 'The reported USB serial must be preserved.'
Assert-Equal $location $identity.LocationPath 'The first physical location path must be preserved.'
Assert-Equal $parentId $identity.ParentInstanceId 'The physical parent must not be replaced by an interface.'
Assert-Equal 'MeshCore T1000-E' $identity.BusReportedDescription 'The physical-device description must be preserved.'
Assert-Equal 'TinyUSB Serial' $identity.InterfaceReportedDescription 'The interface description must remain separate.'
Assert-Equal '00' $identity.InterfaceNumber 'The CDC interface number must be preserved.'
Assert-Equal 0 $script:DeviceQueryCalls 'Inventory-provided devnodes must avoid a second device-tree enumeration.'
Assert-Equal 2 $script:CimMethodCalls.Count 'Identity lookup must batch two port keys and two parent keys.'
Assert-Equal "$parentKey,$descriptionKey" ($script:CimMethodCalls[0].Keys -join ',') 'Port lookup must batch parent and interface description.'
Assert-Equal "$locationKey,$descriptionKey" ($script:CimMethodCalls[1].Keys -join ',') 'Parent lookup must batch location and physical description.'

# One unsupported optional property must not discard other usable properties,
# particularly the bootloader description needed to recognize DFU safely.
Reset-Fixtures
$script:CimFailure = 'unsupported'
$script:PropertyValues[$portId] = @{ $parentKey = $parentId }
$script:PropertyValues[$parentId] = @{ $descriptionKey = 'T1000-E UF2' }
$identity = Get-UsbComPortIdentity -ComPort COM4 -PnpDevice $portDevice
Assert-True ($null -ne $identity) 'A missing optional property must not discard a valid USB serial identity.'
Assert-Equal '25B8546F36809E2C' $identity.SerialNumber 'Fallback identity must retain the USB serial.'
Assert-Equal '' $identity.LocationPath 'A missing location property must remain empty.'
Assert-Equal 'T1000-E UF2' $identity.BusReportedDescription 'A missing location must not discard the available bootloader description.'
Assert-Equal '' $identity.InterfaceReportedDescription 'A missing interface description must remain empty.'

Reset-Fixtures
$script:PropertyValues[$portId] = @{ $parentKey = $parentId }
$script:PropertyValues[$parentId] = @{ $descriptionKey = 'T1000-E UF2' }
$identity = Get-UsbComPortIdentity -ComPort COM4 -PnpDevice $portDevice
Assert-True ($null -ne $identity) 'A partial successful batch must retain a valid USB serial identity.'
Assert-Equal 'T1000-E UF2' $identity.BusReportedDescription 'The normal path must retain available descriptions when optional keys are absent.'
Assert-Equal 0 $script:PnpPropertyCalls.Count 'Missing optional keys in a successful batch must not trigger extra wrapper queries.'

Reset-Fixtures
$script:PropertyValues[$portId] = @{ $descriptionKey = 'TinyUSB Serial' }
$identity = Get-UsbComPortIdentity -ComPort COM4 -PnpDevice $portDevice
Assert-True ($null -eq $identity) 'An interface description alone must not substitute for a missing physical parent.'
Assert-Equal 1 $script:CimMethodCalls.Count 'A missing physical parent must stop further identity queries.'

Reset-Fixtures
$unserializedParent = 'USB\VID_239A&PID_8029\7&FAKE&0&8'
$script:PropertyValues[$portId] = @{ $parentKey = $unserializedParent; $descriptionKey = 'TinyUSB Serial' }
$script:PropertyValues[$unserializedParent] = @{ $locationKey = @($location); $descriptionKey = 'MeshCore T1000-E' }
$identity = Get-UsbComPortIdentity -ComPort COM4 -PnpDevice $portDevice
Assert-True ($null -ne $identity) 'A serial-less device with a physical location must remain identifiable.'
Assert-Equal '' $identity.SerialNumber 'A Windows-generated instance suffix must not become a USB serial.'
Assert-Equal $location $identity.LocationPath 'A serial-less device must retain the physical-location identity.'
$script:PropertyValues[$unserializedParent] = @{ $descriptionKey = 'MeshCore T1000-E' }
$identity = Get-UsbComPortIdentity -ComPort COM4 -PnpDevice $portDevice
Assert-True ($null -eq $identity) 'A description without a real USB serial or location must not produce an identity.'

Reset-Fixtures
$script:EnumeratedDevice = $portDevice
$script:PropertyValues[$portId] = @{ $parentKey = $parentId; $descriptionKey = 'TinyUSB Serial' }
$script:PropertyValues[$parentId] = @{ $locationKey = @($location); $descriptionKey = 'MeshCore T1000-E' }
$identity = Get-UsbComPortIdentity -ComPort COM4
Assert-True ($null -ne $identity) 'Standalone identity lookup must retain its enumeration fallback.'
Assert-Equal 1 $script:DeviceQueryCalls 'Standalone lookup must enumerate only once.'

Reset-Fixtures
$identity = Get-UsbComPortIdentity -ComPort COM4 -PnpDevice (New-FixtureCimDevice -InstanceId $portId -Present $false)
Assert-True ($null -eq $identity) 'Disconnected devnodes must not produce a physical identity.'
Assert-Equal 0 $script:CimMethodCalls.Count 'Disconnected devnodes must not be queried.'
$identity = Get-UsbComPortIdentity -ComPort COM4 -PnpDevice (New-FixtureCimDevice -InstanceId $portId -ErrorCode 10)
Assert-True ($null -eq $identity) 'Failed devnodes must not produce a physical identity.'
Assert-Equal 0 $script:CimMethodCalls.Count 'Failed devnodes must not be queried.'

Write-Host 'USB property batching, fallback, and identity reuse tests passed.'
