# Hardware-free helper-integrity contract tests. Never execute a Python helper.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$repo = Split-Path $PSScriptRoot -Parent
$tokens = $null; $parseErrors = $null
$firmwareAst = [System.Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $repo 'firmware.cmd'), [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw "firmware.cmd parse failed: $parseErrors" }
foreach ($name in @('MESHCORE_PARTITION_TOOL_URL', 'MESHCORE_PARTITION_TOOL_SHA256',
    'MESHCORE_PARTITION_TOOL_MANIFEST', 'MESHCORE_PARTITION_TOOL_API_VERSION',
    'MESHCORE_PARTITION_TOOL_PLAN_FORMAT', 'MESHCORE_PARTITION_TOOL_MAX_BYTES')) {
    $definition = $firmwareAst.Find({ param($node)
        $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
        $node.Left.VariablePath.UserPath -eq $name
    }, $true)
    if ($null -eq $definition) { throw "Missing production constant: $name" }
    Invoke-Expression $definition.Extent.Text
}
foreach ($name in @('Get-PartitionExpansionToolIdentity', 'Read-PartitionExpansionToolManifest',
    'Test-PartitionExpansionTool', 'Resolve-PartitionExpansionTool')) {
    $definition = $firmwareAst.Find({ param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
    }, $true)
    if ($null -eq $definition) { throw "Missing production function: $name" }
    Invoke-Expression $definition.Extent.Text
}
function Assert-True { param([bool]$Condition, [string]$Message); if (-not $Condition) { throw $Message } }
function Assert-Equal { param($Expected, $Actual, [string]$Message); if ($Expected -cne $Actual) { throw "$Message Expected '$Expected', got '$Actual'." } }
function Expect-Failure {
    param([scriptblock]$Action, [string]$Pattern)
    $failed = $false
    try { $null = & $Action } catch { if ($_.Exception.Message -notmatch $Pattern) { throw }; $failed = $true }
    Assert-True $failed "Expected failure matching '$Pattern'."
}
function Wait-FirmwareToolUpdates { }
function Invoke-WebRequest {
    param([string]$Uri, [string]$OutFile, [switch]$UseBasicParsing, [int]$TimeoutSec)
    $script:downloads++
    Assert-Equal $MESHCORE_PARTITION_TOOL_URL $Uri 'Fallback URL changed.'
    Assert-True ($Uri -match '/[0-9a-f]{40}/tools/meshcore_partition_expansion.py$') 'Fallback must use an immutable source commit.'
    Assert-Equal 30 $TimeoutSec 'Fallback download must be bounded.'
    [IO.File]::WriteAllBytes($OutFile, $script:downloadBytes)
    if ($script:downloadFailure) { throw 'simulated interrupted download' }
}
function Write-Text { param([string]$Path, [string]$Text); [IO.File]::WriteAllText($Path, $Text, (New-Object Text.UTF8Encoding($false))) }
function New-Manifest {
    param([string]$Helper)
    $identity = Get-PartitionExpansionToolIdentity -Path $Helper
    return [ordered]@{ schema = 'org.meshfirmware.partition-helper/v1'; helper = 'meshcore_partition_expansion.py';
        api_version = 1; plan_format = 'meshcore-usb-partition-expansion-v2'; sha256 = $identity.Sha256; bytes = $identity.Bytes }
}
$scratch = (New-Item -ItemType Directory -Path (Join-Path ([IO.Path]::GetTempPath()) `
    ('meshfirmware-partition-tool-test-' + [guid]::NewGuid().ToString('N')))).FullName
$script:downloads = 0; $script:downloadFailure = $false
try {
    # Real checked-in bytes, generated manifest and production constants must
    # agree. Do not replace the expected production hash to make this pass.
    Assert-Equal 'f91b2102865ef6a7378dd6a072d83895d972b17826cd5f1981bd98d2a13f2f64' $MESHCORE_PARTITION_TOOL_SHA256 'Historical fallback checksum changed.'
    Assert-Equal 'https://raw.githubusercontent.com/mikecarper/meshfirmware/e0c6ee2dce3ef5a80d3560577ab703a98900336d/tools/meshcore_partition_expansion.py' $MESHCORE_PARTITION_TOOL_URL 'Historical fallback URL changed.'
    $ScriptPath = $repo
    $productionHelper = Join-Path $repo 'tools\meshcore_partition_expansion.py'
    Assert-Equal $productionHelper (Resolve-PartitionExpansionTool) 'Real bundled helper/manifest contract failed.'
    Assert-Equal 0 $downloads 'Bundled resolution contacted the network.'

    $ScriptPath = Join-Path $scratch 'future-checkout'
    $tools = New-Item -ItemType Directory -Path (Join-Path $ScriptPath 'tools')
    $helper = Join-Path $tools.FullName 'meshcore_partition_expansion.py'
    $manifest = Join-Path $tools.FullName $MESHCORE_PARTITION_TOOL_MANIFEST
    $payload = "API_VERSION = 1`n# compatible future implementation; validation must not execute it`nraise RuntimeError('must never execute')`n"
    Write-Text $helper $payload
    $record = New-Manifest $helper
    Write-Text $manifest ($record | ConvertTo-Json -Compress)
    Assert-Equal $helper (Resolve-PartitionExpansionTool) 'Compatible future implementation requires no script checksum edit.'
    # Repository checkouts on Windows can use CRLF without changing integrity.
    Write-Text $helper ($payload.Replace("`n", "`r`n"))
    Assert-Equal $helper (Resolve-PartitionExpansionTool) 'CRLF normalization failed.'

    $valid = $record | ConvertTo-Json -Compress
    $mutations = @(
        @{ key = 'schema'; value = 'unknown' }, @{ key = 'schema'; value = $true },
        @{ key = 'helper'; value = '../other.py' }, @{ key = 'helper'; value = $true },
        @{ key = 'api_version'; value = 2 }, @{ key = 'api_version'; value = $true },
        @{ key = 'api_version'; value = '1' }, @{ key = 'api_version'; value = 1.5 },
        @{ key = 'plan_format'; value = 'unknown' }, @{ key = 'plan_format'; value = $true }, @{ key = 'bytes'; value = $true },
        @{ key = 'bytes'; value = '122' }, @{ key = 'bytes'; value = 0 },
        @{ key = 'bytes'; value = 262145 }, @{ key = 'bytes'; value = ($record.bytes + 1) },
        @{ key = 'sha256'; value = ('0' * 64) }, @{ key = 'sha256'; value = $record.sha256.ToUpperInvariant() }
    )
    foreach ($mutation in $mutations) {
        $changed = $valid | ConvertFrom-Json
        $changed.($mutation.key) = $mutation.value
        Write-Text $manifest ($changed | ConvertTo-Json -Compress)
        Expect-Failure { Resolve-PartitionExpansionTool } 'manifest|match'
    }
    foreach ($invalid in @('{}', '{bad json}', $valid.Replace('"schema":', '"extra":null,"schema":'),
        $valid.Replace('"schema":', '"api_version":1,"schema":'), $valid.Replace('"schema":', '"Schema":null,"schema":'),
        $valid.Replace('"schema":', '"sch\u0065ma":'), (' ' * 4097))) {
        Write-Text $manifest $invalid
        Expect-Failure { Resolve-PartitionExpansionTool } 'manifest'
    }
    Write-Text $manifest $valid
    Write-Text $helper ($payload + '# altered')
    Expect-Failure { Resolve-PartitionExpansionTool } 'does not match its manifest'
    Write-Text $helper ('x' * 262145)
    Expect-Failure { Resolve-PartitionExpansionTool } 'does not match its manifest'
    Write-Text $helper ''
    Expect-Failure { Resolve-PartitionExpansionTool } 'does not match its manifest'
    Remove-Item -LiteralPath $helper
    Expect-Failure { Resolve-PartitionExpansionTool } 'missing beside its manifest'
    Assert-Equal 0 $downloads 'Invalid or incomplete bundled data must not fall back to downloads.'
    Remove-Item -LiteralPath $manifest
    Write-Text $helper $payload
    Expect-Failure { Resolve-PartitionExpansionTool } 'no matching manifest'
    Assert-Equal 0 $downloads 'Unmanifested unknown bundled helper must not be replaced over the network.'

    # Synthetic immutable-fallback contents exercise cache/download control
    # flow independently of the real production bundle assertion above.
    $ScriptPath = Join-Path $scratch 'standalone'
    $null = New-Item -ItemType Directory -Path $ScriptPath
    $fixture = Join-Path $scratch 'fallback.py'
    Write-Text $fixture "# immutable fallback fixture`nraise RuntimeError('never execute')`n"
    $MESHCORE_PARTITION_TOOL_SHA256 = (Get-PartitionExpansionToolIdentity $fixture).Sha256
    $script:downloadBytes = [IO.File]::ReadAllBytes($fixture)
    $cache = Join-Path $ScriptPath '.tmp\meshcore_partition_expansion.py'
    Assert-Equal $cache (Resolve-PartitionExpansionTool) 'Verified fallback download failed.'
    Assert-Equal 1 $downloads 'Fallback was not downloaded exactly once.'
    Assert-Equal $cache (Resolve-PartitionExpansionTool) 'Verified fallback cache was not reused.'
    Assert-Equal 1 $downloads 'Verified cache caused another download.'
    $legacyTools = New-Item -ItemType Directory -Path (Join-Path $ScriptPath 'tools')
    $legacy = Join-Path $legacyTools.FullName 'meshcore_partition_expansion.py'
    Copy-Item -LiteralPath $fixture -Destination $legacy
    Assert-Equal $legacy (Resolve-PartitionExpansionTool) 'Exact pre-manifest historical helper was not accepted.'
    Remove-Item -LiteralPath $legacy
    Write-Text $cache '# invalid previous cache'
    $oldCache = [IO.File]::ReadAllText($cache)
    $script:downloadBytes = [Text.Encoding]::UTF8.GetBytes('# tampered download')
    Expect-Failure { Resolve-PartitionExpansionTool } 'checksum check'
    Assert-Equal $oldCache ([IO.File]::ReadAllText($cache)) 'Failed verification replaced an existing cache.'
    $script:downloadFailure = $true
    Expect-Failure { Resolve-PartitionExpansionTool } 'interrupted download'
    Assert-Equal $oldCache ([IO.File]::ReadAllText($cache)) 'Interrupted download replaced an existing cache.'
    Assert-Equal 0 @(Get-ChildItem -LiteralPath (Split-Path $cache -Parent) -Filter '*.partial').Count 'Partial downloads were not cleaned up.'
    Write-Output 'PASS: real manifest, API compatibility, LF/CRLF integrity, bundled rejection and immutable fallback resolution'
} finally {
    Remove-Item -LiteralPath $scratch -Recurse -Force
}
