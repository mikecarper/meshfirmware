$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$firmwarePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'firmware.cmd'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $firmwarePath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw "firmware.cmd parse failed: $parseErrors" }
$dfu = $ast.Find({ param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -eq 'Invoke-NrfutilSerialDfu'
}, $true)
if ($null -eq $dfu) { throw 'Missing Invoke-NrfutilSerialDfu.' }

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}
function Assert-Equal {
    param($Expected, $Actual, [string]$Message)
    if ($Expected -cne $Actual) { throw "$Message Expected '$Expected', got '$Actual'." }
}
function Expect-Failure {
    param([scriptblock]$Action, [string]$Pattern)
    $failed = $false
    try { & $Action } catch {
        if ($_.Exception.Message -notmatch $Pattern) { throw }
        $failed = $true
    }
    Assert-True $failed "Expected failure matching '$Pattern'."
}

# Capture rendering only: no serial ports, nrfutil executable, or child process
# is opened. Exercise the actual nested callbacks with their real call scopes.
$script:hostWrites = New-Object 'System.Collections.Generic.List[object]'
$script:progressWrites = New-Object 'System.Collections.Generic.List[object]'
function Write-Host {
    param([Parameter(ValueFromRemainingArguments = $true)][object[]]$Object,
          [switch]$NoNewline)
    [void]$script:hostWrites.Add([pscustomobject]@{
        Text = ($Object -join ' '); NoNewline = [bool]$NoNewline
    })
}
function Write-Progress {
    param([int]$Id, [string]$Activity, [string]$Status,
          [int]$PercentComplete = -1, [switch]$Completed)
    [void]$script:progressWrites.Add([pscustomobject]@{
        Id = $Id; Activity = $Activity; Status = $Status
        PercentComplete = $PercentComplete; Completed = [bool]$Completed
    })
}

$fixtureStatements = @($dfu.Body.EndBlock.Statements | Where-Object {
    ($_ -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $_.Left.Extent.Text -in @('$nrfProgress', '$outputBuffer', '$lineBuffer')) -or
    ($_ -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $_.Name -in @('Update-NrfutilInlineProgress', 'Clear-NrfutilInlineProgress',
                     'Flush-NrfutilLine', 'Add-NrfutilChars'))
})
Assert-Equal 7 $fixtureStatements.Count 'Progress callback fixture is incomplete.'
$fixtureSource = @'
function Invoke-ProgressFixture {
    param([int]$TotalSteps, [scriptblock]$Action)
    $dfuComPort = 'COM999'
    $progressActivity = 'nRF52 fixture'
    $progressId = 44
    $script:hostWrites.Clear()
    $script:progressWrites.Clear()
'@
$fixtureSource += "`n" + (($fixtureStatements | ForEach-Object { $_.Extent.Text }) -join "`n")
$fixtureSource += "`n& `$Action`n}"
Invoke-Expression $fixtureSource

# The real process reader calls Add-NrfutilChars once for each character. The
# former child-scope scalar increment restarted at 1 for every call here.
Invoke-ProgressFixture -TotalSteps 4 -Action {
    Add-NrfutilChars '#'
    Assert-Equal 1 $nrfProgress.HashCount 'First hash was not counted.'
    Add-NrfutilChars '#'
    Assert-Equal 2 $nrfProgress.HashCount 'Single-character calls lost the previous count.'
    Add-NrfutilChars '##'
    Assert-Equal 4 $nrfProgress.HashCount 'Chunked hashes were not accumulated.'
    Assert-Equal '25,50,75,99' (($script:progressWrites | ForEach-Object { $_.PercentComplete }) -join ',') `
        'Progress did not advance or reached 100 before activation finished.'
    Add-NrfutilChars '#'
    Assert-Equal 5 $nrfProgress.HashCount 'Extra hashes changed the persistent count.'
    Assert-Equal 99 $script:progressWrites[-1].PercentComplete 'Hash progress exceeded its pre-completion ceiling.'
    Assert-Equal '#####' $outputBuffer.ToString() 'The result-check transcript lost hashes.'
    Assert-True (-not ($script:progressWrites.PercentComplete -contains 100)) 'Hash progress claimed completed programming.'
}

# Line callbacks are one scope deeper still. Their status must reach later
# character callbacks as well as the initial transport/activation display.
Invoke-ProgressFixture -TotalSteps 4 -Action {
    foreach ($ch in "Upgrading target on COM999`r`n".ToCharArray()) { Add-NrfutilChars ([string]$ch) }
    Assert-Equal 'Upgrading target on COM999' $nrfProgress.Status 'Transport status was lost in a child scope.'
    Add-NrfutilChars '#'
    Add-NrfutilChars "##`nActivating new firm"
    Assert-Equal 'Upgrading target on COM999 (3/4)' $script:progressWrites[-1].Status `
        'Later hash progress did not reuse the transport status/count.'
    Assert-Equal 'Upgrading target on COM999' $nrfProgress.Status 'A partial line was flushed too early.'
    Add-NrfutilChars "ware`r`n"
    Assert-Equal 'Activating new firmware' $nrfProgress.Status 'Activation status was not persistent.'
    Assert-Equal 99 $script:progressWrites[-1].PercentComplete 'Activation was not held at 99%.'
    Assert-True (-not $nrfProgress.InlineVisible) 'Activation diagnostic did not clear the inline display.'
    Assert-True (-not ($script:progressWrites.PercentComplete -contains 100)) 'Activation alone claimed complete programming.'
    Assert-True ([bool]($script:hostWrites | Where-Object { $_.Text -eq 'Activating new firmware' -and -not $_.NoNewline })) `
        'Activation diagnostic disappeared from normal output.'
    Add-NrfutilChars "Device programmed.`n"
    Assert-Equal 'Device programmed.' $nrfProgress.Status 'Completion status was not persistent.'
    Assert-Equal 100 $script:progressWrites[-1].PercentComplete 'Confirmed programming did not reach 100%.'
    Assert-True (-not $nrfProgress.InlineVisible) 'Completion diagnostic left an inline display behind.'
    Assert-Equal "Upgrading target on COM999`r`n###`nActivating new firmware`r`nDevice programmed.`n" `
        $outputBuffer.ToString() 'Result-check transcript was altered by rendering.'
}

Invoke-ProgressFixture -TotalSteps 100 -Action {
    Update-NrfutilInlineProgress 'Long progress text'
    Update-NrfutilInlineProgress 'Long progress text'
    Assert-Equal 1 $script:hostWrites.Count 'Duplicate inline text was rendered again.'
    Assert-True $nrfProgress.InlineVisible 'Inline visibility was not persisted.'
    Update-NrfutilInlineProgress 'x'
    Assert-Equal ("`rx" + (' ' * 17)) $script:hostWrites[-1].Text 'Shorter inline update did not erase the old suffix.'
    Assert-Equal 1 $nrfProgress.LastInlineWidth 'Inline width was not updated.'
    Clear-NrfutilInlineProgress
    Assert-Equal "`r `r" $script:hostWrites[-1].Text 'Clear did not erase the actual last inline width.'
    Assert-True (-not $nrfProgress.InlineVisible) 'Clear did not persist invisible state.'
    Assert-Equal '' $nrfProgress.LastInlineText 'Clear did not reset the dedup cache.'
    Assert-Equal 0 $nrfProgress.LastInlineWidth 'Clear did not reset width.'
    $count = $script:hostWrites.Count
    Clear-NrfutilInlineProgress
    Assert-Equal $count $script:hostWrites.Count 'Clearing an already empty display emitted duplicate output.'
    Update-NrfutilInlineProgress 'x'
    Assert-Equal ($count + 1) $script:hostWrites.Count 'A cleared value could not be rendered again.'
}

Invoke-ProgressFixture -TotalSteps 0 -Action {
    Add-NrfutilChars "Upgrading target on COM999`n##`nActivating new firmware`nDevice programmed.`n"
    Assert-Equal 2 $nrfProgress.HashCount 'Unknown-length transfer lost the hash count.'
    Assert-True (-not [bool]($script:progressWrites | Where-Object { $_.PercentComplete -ne -1 })) `
        'Unknown-length transfer fabricated a percentage.'
    Assert-True (-not [bool]($script:hostWrites | Where-Object { $_.Text -match '(\d+%|\(\d+/0\))' })) `
        'Unknown-length transfer displayed a false denominator or percent.'
    Assert-True ([bool]($script:hostWrites | Where-Object { $_.Text -eq 'Device programmed.' })) `
        'Unknown-length completion diagnostic was not preserved.'
}

Invoke-ProgressFixture -TotalSteps 4 -Action {
    Assert-Equal 0 $nrfProgress.HashCount 'A later upload inherited an earlier count.'
    Assert-Equal '' $nrfProgress.LastInlineText 'A later upload inherited the display cache.'
    Add-NrfutilChars "#`nFailed to upgrade target.`n"
    Assert-True ([bool]($script:hostWrites | Where-Object { $_.Text -eq 'Failed to upgrade target.' })) `
        'Failure diagnostics were hidden behind the inline display.'
    Assert-True (-not ($script:progressWrites.PercentComplete -contains 100)) 'Failure diagnostics produced 100% progress.'
}

# Run the unchanged production result gate against fixture transcripts without
# launching a process. Progress rendering must never substitute for its exit
# status and explicit start/programmed evidence.
$resultStatements = @()
$inResult = $false
foreach ($statement in $dfu.Body.EndBlock.Statements) {
    if ($statement -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $statement.Left.Extent.Text -eq '$outputText') { $inResult = $true }
    if ($inResult) { $resultStatements += $statement.Extent.Text }
}
Assert-True ($resultStatements.Count -ge 7) 'Production DFU result gate fixture is incomplete.'
$resultSource = @'
function Invoke-ResultFixture {
    param([string]$Transcript, [int]$ExitCode = 0)
    $outputBuffer = New-Object System.Text.StringBuilder
    [void]$outputBuffer.Append($Transcript)
    $proc = [pscustomobject]@{ ExitCode = $ExitCode }
    $dfuComPort = 'COM999'
    $touchWasRequested = $false
    $UsbIdentity = [pscustomobject]@{ SerialNumber = 'fixture-no-device' }
    function Test-ShouldRetryNrfutilSerialPort { return $false }
'@
$resultSource += "`n" + ($resultStatements -join "`n") + "`n}"
Invoke-Expression $resultSource
$successTranscript = "Upgrading target on COM999`n####`nActivating new firmware`nDevice programmed.`n"
Assert-True (Invoke-ResultFixture $successTranscript).Success 'A confirmed successful transfer did not pass the result gate.'
Expect-Failure { Invoke-ResultFixture "Upgrading target on COM999`n####`nActivating new firmware`n" } 'adafruit-nrfutil failed'
Expect-Failure { Invoke-ResultFixture "Device programmed.`n" } 'adafruit-nrfutil failed'
Expect-Failure { Invoke-ResultFixture $successTranscript -ExitCode 1 } 'adafruit-nrfutil failed'
Expect-Failure { Invoke-ResultFixture ($successTranscript + "No data received on serial port.`n") } 'adafruit-nrfutil failed'

Remove-Item Function:Write-Host, Function:Write-Progress
Write-Host 'PASS: nRF52 DFU progress scopes, rendering, and result gates.'
