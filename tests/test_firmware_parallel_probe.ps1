# Hermetic concurrency tests: no serial ports, native processes, or downloads.
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
$tokens = $null; $parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $repoRoot 'firmware.cmd'), [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw "firmware.cmd parse failed: $parseErrors" }
$definition = $ast.Find({ param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Invoke-UsbNodeProbes'
}, $true)
if (-not $definition) { throw 'Invoke-UsbNodeProbes is missing from firmware.cmd.' }
Invoke-Expression $definition.Extent.Text

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

Add-Type -TypeDefinition @'
using System;
using System.Collections.Concurrent;
using System.Threading;
public static class FirmwareParallelProbeFixture {
    public static CountdownEvent Started;
    public static ConcurrentDictionary<string, int> Calls;
    public static ConcurrentBag<object> Runspaces;
    public static int Finished;
    public static void Reset(int count) {
        if (Started != null) Started.Dispose();
        Started = new CountdownEvent(count);
        Calls = new ConcurrentDictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        Runspaces = new ConcurrentBag<object>();
        Finished = 0;
    }
    public static void Enter(string port) {
        Calls.AddOrUpdate(port, 1, (key, old) => old + 1);
        Started.Signal();
        // A serialized implementation times out; a real parallel scan reaches
        // zero before any worker can finish. This checks ordering, not speed.
        if (!Started.Wait(10000)) throw new Exception("Workers were serialized.");
        Interlocked.Increment(ref Finished);
    }
}
'@

$global:pythonCommand = 'parallel-fixture-python'
$ScriptPath = 'parallel-fixture-path'
$timeoutMeshtastic = 19
$script:FirmwareProtocolHints = @{ identity = 'MeshCore' }
$script:FirmwareToolUpdateJob = [pscustomobject]@{ MustNotBeCopied = $true }
$script:FirmwareToolUseMutex = [pscustomobject]@{ MustNotBeCopied = $true }
$script:DirectCalls = 0

function Get-UsbNodeInfo {
    param([string]$ComPort, [psobject]$UsbIdentity)
    $script:DirectCalls++
    return [pscustomobject]@{ Success = $true; ComPort = $ComPort; Project = 'MeshCore' }
}

$empty = Invoke-UsbNodeProbes -Devices @()
Assert-True ($empty -is [hashtable] -and $empty.Count -eq 0 -and $script:DirectCalls -eq 0) 'Empty inventory launched a probe or returned the wrong shape.'
$single = Invoke-UsbNodeProbes -Devices @([pscustomobject]@{ ComPort = 'TEST1'; UsbIdentity = $null })
Assert-True ($single.Count -eq 1 -and $single.TEST1.Success -and $script:DirectCalls -eq 1) 'Single-port scan did not call directly in its parent runspace.'

function Get-UsbNodeInfo {
    param([string]$ComPort, [psobject]$UsbIdentity, [switch]$QuickOnly)
    [FirmwareParallelProbeFixture]::Runspaces.Add([runspace]::DefaultRunspace)
    [FirmwareParallelProbeFixture]::Enter($ComPort)
    if ($global:pythonCommand -ne 'parallel-fixture-python' -or $ScriptPath -ne 'parallel-fixture-path' -or $timeoutMeshtastic -ne 19) {
        throw 'Worker lost the required probe environment.'
    }
    if ($script:FirmwareToolUpdateJob -or $script:FirmwareToolUseMutex) { throw 'Worker inherited parent updater state.' }
    if ($script:FirmwareProtocolHints.identity -ne 'MeshCore') { throw 'Worker lost cached protocol order.' }
    $script:FirmwareProtocolHints.identity = $ComPort
    if ($ProgressPreference -ne 'SilentlyContinue') { throw 'Worker progress was not suppressed.' }
    if (-not $QuickOnly) { throw 'Quick-only inventory flag was not forwarded.' }
    Wait-FirmwareToolUpdates
    if ($ComPort -eq 'FAIL') { throw 'Fixture port is inaccessible.' }
    return [pscustomobject]@{ Success = $true; ComPort = $ComPort; Project = 'MeshCore'; UsbSerial = $UsbIdentity.SerialNumber }
}

$devices = @('TEST2', 'TEST3', 'FAIL', 'TEST4') | ForEach-Object {
    [pscustomobject]@{ ComPort = $_; UsbIdentity = [pscustomobject]@{ SerialNumber = "identity-$_" } }
}
[FirmwareParallelProbeFixture]::Reset(4)
try {
    $results = Invoke-UsbNodeProbes -Devices (@($devices) + @($devices[0])) -QuickOnly
    Assert-True ($results -is [hashtable] -and $results.Count -eq 4) 'Parallel results are incomplete or duplicate ports were launched.'
    foreach ($port in @('TEST2', 'TEST3', 'TEST4')) {
        Assert-True ($results[$port].Success -and $results[$port].UsbSerial -eq "identity-$port") "Parallel worker failed or lost device identity on $port."
    }
    Assert-True (-not $results.FAIL.Success -and $results.FAIL.ProbeState -eq 'unavailable' -and $results.FAIL.ExtraInfo -match 'Fixture port is inaccessible') 'An inaccessible port did not return an isolated diagnostic.'
    Assert-True ([FirmwareParallelProbeFixture]::Finished -eq 4) 'Not all workers finished before the scan returned.'
    foreach ($port in @('TEST2', 'TEST3', 'FAIL', 'TEST4')) {
        Assert-True ([FirmwareParallelProbeFixture]::Calls[$port] -eq 1) "Port $port was scanned more than once."
    }
    Assert-True ($script:FirmwareProtocolHints.identity -eq 'MeshCore') 'A worker mutated the parent protocol cache.'
    foreach ($runspace in [FirmwareParallelProbeFixture]::Runspaces) {
        Assert-True ($runspace.RunspaceStateInfo.State -eq 'Closed') 'Parallel scan left a worker runspace alive.'
    }
    Write-Host 'PASS parallel USB probes (barrier, direct single, isolated failure, identity, cache snapshot, deduplication, cleanup)'
}
finally { [FirmwareParallelProbeFixture]::Started.Dispose() }

# Load the actual production probe dependency chain, then replace only serial
# port opening. Both protocols traverse their real frame and identity parsers
# in isolated runspaces; the fixture never opens hardware or starts Python.
foreach ($functionName in @(
    'Get-UsbNodeInfo', 'Get-QuickFirmwareNodeInfo', 'Get-FirmwareProbeOrder',
    'Invoke-MeshCoreBinaryCommand', 'Get-MeshCoreCompanionInfo',
    'Get-MeshCoreTextInfoProbe', 'Read-QuickSerialResponse',
    'Invoke-MeshtasticInfoProbe', 'Get-MeshtasticIdentityFromPayload',
    'ConvertFrom-ProtobufMessage', 'Read-ProtobufVarint', 'Get-MeshtasticHardwareName',
    'Get-UsableSerialResponse', 'Get-VersionTokenFromText',
    'Remove-Ansi', 'Strip-Prefix', 'Test-IsLogLine', 'Test-UsbIdentityIsNrf52Dfu'
)) {
    $definition = $ast.Find({ param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $functionName
    }, $true)
    if (-not $definition) { throw "Missing production probe dependency $functionName." }
    Invoke-Expression $definition.Extent.Text
}

Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Text;
public sealed class FirmwareParallelSerialFixture : IDisposable {
    public static ConcurrentDictionary<string, FirmwareParallelSerialFixture> Ports =
        new ConcurrentDictionary<string, FirmwareParallelSerialFixture>();
    private readonly string protocol;
    private readonly List<byte> incoming = new List<byte>();
    public readonly List<byte[]> Writes = new List<byte[]>();
    public bool IsOpen = true;
    public int Closed;
    public int Disposed;
    public int BytesToRead { get { return incoming.Count; } }
    public FirmwareParallelSerialFixture(string port) {
        protocol = port;
        Ports[port] = this;
    }
    private void AddFrame(byte first, byte second, byte[] payload) {
        if (first == 0x3e) incoming.AddRange(new byte[] { first, (byte)payload.Length, 0 });
        else incoming.AddRange(new byte[] { first, second, 0, (byte)payload.Length });
        incoming.AddRange(payload);
    }
    public void DiscardInBuffer() { incoming.Clear(); }
    public void Write(byte[] bytes, int offset, int count) {
        byte[] written = new byte[count];
        Array.Copy(bytes, offset, written, 0, count);
        Writes.Add(written);
        if (protocol == "MC" && count == 5 && written[0] == 0x3c && written[3] == 0x16) {
            byte[] reply = new byte[82];
            reply[0] = 0x0d; reply[1] = 14;
            Array.Copy(Encoding.ASCII.GetBytes("RAK4631"), 0, reply, 20, 7);
            Array.Copy(Encoding.ASCII.GetBytes("v1.18.0.1"), 0, reply, 60, 9);
            AddFrame(0x3e, 0, reply);
        } else if (protocol == "MC" && count > 4 && written[0] == 0x3c && written[3] == 0x42) {
            byte[] text = Encoding.ASCII.GetBytes("Companion v1.18.0.1 (protocol 14)");
            byte[] reply = new byte[text.Length + 1];
            reply[0] = 0x1d; Array.Copy(text, 0, reply, 1, text.Length);
            AddFrame(0x3e, 0, reply);
        } else if (protocol == "MT" && count == 8 && written[0] == 0x94 && written[4] == 0x18) {
            // Captured official SDK protobuf bytes, independent of our decoder.
            AddFrame(0x94, 0xc3, new byte[] {
                0x1a,0x1c,0x08,0xf8,0xac,0xd1,0x91,0x01,0x6a,0x14,
                0x73,0x65,0x65,0x65,0x64,0x5f,0x78,0x69,0x61,0x6f,
                0x5f,0x6e,0x72,0x66,0x35,0x32,0x5f,0x6b,0x69,0x74 });
            AddFrame(0x94, 0xc3, new byte[] {
                0x6a,0x10,0x0a,0x0c,0x32,0x2e,0x37,0x2e,0x34,0x2e,
                0x61,0x62,0x63,0x31,0x32,0x33,0x48,0x58 });
        }
    }
    public int Read(byte[] bytes, int offset, int count) {
        int take = Math.Min(7, Math.Min(count, incoming.Count));
        incoming.CopyTo(0, bytes, offset, take);
        incoming.RemoveRange(0, take);
        return take;
    }
    public void WriteLine(string text) { Write(Encoding.ASCII.GetBytes(text + "\r\n"), 0, text.Length + 2); }
    public string ReadExisting() {
        string text = Encoding.ASCII.GetString(incoming.ToArray()); incoming.Clear(); return text;
    }
    public void Close() { Closed++; IsOpen = false; }
    public void Dispose() { Disposed++; IsOpen = false; }
}
'@

function Open-SerialPort {
    param($ComPort, $Baud, $ReadTimeoutMs, $WriteTimeoutMs, $Dtr, $Rts)
    [FirmwareParallelProbeFixture]::Runspaces.Add([runspace]::DefaultRunspace)
    [FirmwareParallelProbeFixture]::Enter($ComPort)
    return (New-Object FirmwareParallelSerialFixture -ArgumentList $ComPort)
}
$productionDevices = @(
    [pscustomobject]@{ ComPort = 'MC'; UsbIdentity = [pscustomobject]@{
        ParentInstanceId = 'USB\VID_239A&PID_8029\fixture-MC'; SerialNumber = 'fixture-MC'
        BusReportedDescription = 'MeshCore Full Companion'; InterfaceNumber = '00'
    } },
    [pscustomobject]@{ ComPort = 'MT'; UsbIdentity = [pscustomobject]@{
        ParentInstanceId = 'USB\VID_239A&PID_8029\fixture-MT'; SerialNumber = 'fixture-MT'
        BusReportedDescription = 'Meshtastic'; InterfaceNumber = '00'
    } }
)
[FirmwareParallelProbeFixture]::Reset(2)
try {
    $results = Invoke-UsbNodeProbes -Devices $productionDevices -QuickOnly
    Assert-True ($results.Count -eq 2) 'Production parallel scan lost a port.'
    Assert-True ($results.MC.Success -and $results.MC.Project -eq 'MeshCore' -and $results.MC.HWName -eq 'RAK4631' -and $results.MC.FWVersion -eq 'v1.18.0.1') `
        "Production MeshCore worker failed: $($results.MC | ConvertTo-Json -Compress)"
    Assert-True ($results.MT.Success -and $results.MT.Project -eq 'Meshtastic' -and $results.MT.HWName -eq 'seeed_xiao_nrf52_kit' -and $results.MT.FWVersion -eq '2.7.4.abc123') `
        "Production Meshtastic worker failed: $($results.MT | ConvertTo-Json -Compress)"
    foreach ($port in @('MC', 'MT')) {
        $serial = [FirmwareParallelSerialFixture]::Ports[$port]
        Assert-True ($serial.Closed -eq 1 -and $serial.Disposed -eq 1 -and -not $serial.IsOpen) "Production $port worker leaked its serial handle."
    }
    $mtWrites = [FirmwareParallelSerialFixture]::Ports['MT'].Writes
    Assert-True ($mtWrites.Count -eq 3 -and $mtWrites[2][4] -eq 0x20 -and $mtWrites[2][5] -eq 1) 'Production parallel MT probe did not end its API session.'
    foreach ($runspace in [FirmwareParallelProbeFixture]::Runspaces) {
        Assert-True ($runspace.RunspaceStateInfo.State -eq 'Closed') 'Production protocol scan left a worker runspace alive.'
    }
    Write-Host 'PASS parallel production MT/MC probes (dependency closure, framed replies, protobuf identity, USB cleanup)'
}
finally { [FirmwareParallelProbeFixture]::Started.Dispose() }
