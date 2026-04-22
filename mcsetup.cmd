# 2>NUL & @powershell -nop -ep bypass "(gc '%~f0')-join[Environment]::NewLine|iex" & goto :eof

#Example execute:
# powershell -ExecutionPolicy ByPass -File c:\git\meshfirmware\mcsetup.ps1


[CmdletBinding()]
param(
    [string]$ComPort = "",
    [int]$Baud = 115200,
    [int]$BootWait = 2
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ScriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$script:RepoOwner = 'meshcore-dev'
$script:RepoName = 'MeshCore'
$script:ConfigUrl = 'https://api.meshcore.nz/api/v1/config'
$script:FirmwareRoot = Join-Path $script:ScriptRoot ("{0}_{1}" -f $script:RepoOwner, $script:RepoName)
$script:RadioConfigFile = Join-Path $script:FirmwareRoot 'meshcore_config.json'

$script:PreferredBaud = $Baud
$script:DefaultBauds = @(57600, 115200, 38400, 9600, 19200, 2400)
$script:SerialBaudCache = $Baud
$script:SerialIdleTimeoutMs = 2500
$script:SerialTotalTimeoutMs = 7500
$script:SerialRetryDelayMs = 80
$script:DeviceName = $ComPort
$script:DeviceEpoch = $null
$script:CanSendCommands = $false
$script:ActiveSerialPort = $null
$script:ActiveSerialBaud = 0

$script:Settings = [ordered]@{}
$script:Radio = [ordered]@{
    Freq = ''
    Bw   = ''
    Sf   = ''
    Cr   = ''
}
$script:RadioBaseline = [ordered]@{
    Freq = ''
    Bw   = ''
    Sf   = ''
    Cr   = ''
}

function Ensure-Directory {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Trim-Text {
    param([AllowNull()][string]$Text)

    if ($null -eq $Text) { return '' }
    return $Text.Trim()
}

function Remove-Ansi {
    param([string]$Text)

    if (-not $Text) { return '' }

    $clean = [regex]::Replace($Text, "`e\[[0-?]*[ -/]*[@-~]", '')
    $clean = [regex]::Replace($clean, '(?i)\[(?:\d{1,3}(?:;\d{1,3})*)m', '')
    $clean = [regex]::Replace($clean, "[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", '')
    return $clean
}

function Strip-Prefix {
    param([string]$Text)

    if (-not $Text) { return '' }
    $text = Remove-Ansi $Text
    return (($text -replace "`r", '') -replace '^[\s>]*(->|>)+\s*', '').Trim()
}

function Test-IsLogLine {
    param([string]$Text)

    if (-not $Text) { return $false }

    $value = Remove-Ansi $Text
    $value = ($value -replace "`r", '')
    $value = ($value -replace '^[\s>]*(->|>)+\s*', '').Trim()

    return (
        $value -match '^[\W_]*(DEBUG|TRACE|INFO|WARN|ERROR)\s*(?:\:|\|)\s*' -or
        $value -match '^[\W_]*\[[^\]]+\]\s*(DEBUG|TRACE|INFO|WARN|ERROR)\b' -or
        $value -match '^\s*\[[^\]]+\]\s*$' -or
        $value -match '\[SerialConsole\].*\bState\s*:\s*\w+\b' -or
        $value -match '^\d{1,2}:\d{2}(?::\d{2})?\s*-\s*\d{1,2}/\d{1,2}/\d{4}\s+[A-Z]+(?:\s+[A-Z]+)*:'
    )
}

function Get-VersionTokenFromText {
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }

    $patterns = @(
        '(?i)\b(?:powersaving|easyskymesh)[a-z0-9._\-+]*\d+(?:\.\d+)+(?:[A-Za-z0-9._\-+]*)\b',
        '(?i)\bv?\d+(?:\.\d+)+(?:[A-Za-z0-9._\-+]*)\b',
        '(?i)\b[a-z][a-z0-9_-]*\d+(?:\.\d+)+(?:[A-Za-z0-9._\-+]*)\b'
    )

    foreach ($pattern in $patterns) {
        $match = [regex]::Match($Text, $pattern)
        if ($match.Success) {
            return $match.Value
        }
    }

    return ''
}

function Get-UsableSerialResponse {
    param(
        [string]$Text,
        [ValidateSet('Generic', 'Board', 'Version', 'Name')]
        [string]$Kind = 'Generic',
        [int]$MaxLength = 64
    )

    if (-not $Text) { return '' }

    $value = Strip-Prefix $Text
    if (-not $value) { return '' }
    if (Test-IsLogLine $value) { return '' }

    if ($MaxLength -gt 0 -and $value.Length -gt $MaxLength) {
        $value = $value.Substring(0, $MaxLength).Trim()
    }

    $length = [Math]::Max(1, $value.Length)
    $cleanChars = [regex]::Matches($value, '[A-Za-z0-9 _\-\.\(\)\[\]/:+]').Count
    $questionChars = [regex]::Matches($value, '\?').Count

    if ($cleanChars -eq 0) { return '' }
    if (($cleanChars / $length) -lt 0.45) { return '' }

    switch ($Kind) {
        'Board' {
            if ($value -notmatch '[A-Za-z0-9]') { return '' }
            if ($questionChars -gt 0) { return '' }
        }
        'Version' {
            $versionToken = Get-VersionTokenFromText -Text $value
            if (-not $versionToken) { return '' }
            $value = $versionToken
            if ($value -match '(?i)\b(DEBUG|TRACE|INFO|WARN|ERROR)\b') { return '' }
            if ($questionChars -gt [Math]::Ceiling($length * 0.20)) { return '' }
        }
        'Name' {
            if ($questionChars -gt [Math]::Ceiling($length * 0.30)) { return '' }
        }
    }

    return $value
}

function Open-SerialPort {
    param(
        [Parameter(Mandatory)][string]$ComPort,
        [int]$BaudRate = 115200,
        [int]$ReadTimeoutMs = 500,
        [int]$WriteTimeoutMs = 500,
        [bool]$Dtr = $true,
        [bool]$Rts = $true
    )

    $port = New-Object System.IO.Ports.SerialPort $ComPort, $BaudRate, 'None', 8, 'One'
    $port.NewLine = "`r`n"
    $port.Encoding = [System.Text.Encoding]::ASCII
    $port.ReadTimeout = $ReadTimeoutMs
    $port.WriteTimeout = $WriteTimeoutMs
    $port.Handshake = [System.IO.Ports.Handshake]::None
    $port.DtrEnable = $Dtr
    $port.RtsEnable = $Rts
    $port.Open()
    Start-Sleep -Milliseconds 120
    return $port
}

function Close-ActiveSerialSession {
    if ($script:ActiveSerialPort) {
        try {
            if ($script:ActiveSerialPort.IsOpen) {
                $script:ActiveSerialPort.Close()
            }
        }
        catch {
        }
        finally {
            try {
                $script:ActiveSerialPort.Dispose()
            }
            catch {
            }
        }
    }

    $script:ActiveSerialPort = $null
    $script:ActiveSerialBaud = 0
}

function Clear-SerialStartupNoise {
    param(
        [Parameter(Mandatory)][System.IO.Ports.SerialPort]$Port,
        [int]$TotalMs = 1500,
        [int]$IdleMs = 250
    )

    if (-not $Port.IsOpen) { return }

    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $idle = [System.Diagnostics.Stopwatch]::StartNew()
    $sawData = $false

    while ($watch.ElapsedMilliseconds -lt $TotalMs) {
        try { $chunk = $Port.ReadExisting() } catch { $chunk = '' }

        if ($chunk) {
            $sawData = $true
            $idle.Restart()
        }
        else {
            Start-Sleep -Milliseconds 20
        }

        if ($sawData -and $idle.ElapsedMilliseconds -ge $IdleMs) {
            break
        }
    }

    try { $Port.DiscardInBuffer() } catch { }
}

function Get-ActiveSerialSession {
    param(
        [Parameter(Mandatory)][int]$BaudRate
    )

    if ($script:ActiveSerialPort -and
        $script:ActiveSerialPort.IsOpen -and
        $script:ActiveSerialBaud -eq $BaudRate -and
        $script:ActiveSerialPort.PortName -eq $script:DeviceName) {
        return $script:ActiveSerialPort
    }

    Close-ActiveSerialSession

    $port = Open-SerialPort -ComPort $script:DeviceName -BaudRate $BaudRate -ReadTimeoutMs 800 -WriteTimeoutMs 800 -Dtr $true -Rts $true
    Clear-SerialStartupNoise -Port $port
    $script:ActiveSerialPort = $port
    $script:ActiveSerialBaud = $BaudRate
    return $script:ActiveSerialPort
}

function Invoke-SerialCommand {
    param(
        [Parameter(Mandatory)][System.IO.Ports.SerialPort]$Port,
        [Parameter(Mandatory)][string]$Line,
        [int]$TotalMs = 1000,
        [int]$IdleMs = 250,
        [int]$Attempts = 1,
        [int]$RetryDelayMs = 80,
        [int]$ExtraReadMs = 300,
        [switch]$AllowBlankResponse,
        [int]$BlankIdleMs = 220
    )

    if (-not $Port.IsOpen) { return '' }

    $ignorePatterns = @(
        '^[\W_]*(DEBUG|TRACE|INFO|WARN|ERROR)\s*(?:\:|\|)\s*',
        '^[\W_]*\[[^\]]+\]\s*(DEBUG|TRACE|INFO|WARN|ERROR)\b',
        '.*\[SerialConsole\].*\bState\s*:\s*\w+\b',
        '^\s*#',
        '^\s*;',
        '^\s*$'
    )

    function Test-IgnoredLine {
        param([string]$Candidate)

        if (-not $Candidate) { return $true }
        $candidate = ($Candidate -replace '^[\s>]*(->|>)+\s*', '').Trim()
        if (-not $candidate) { return $true }
        foreach ($pattern in $ignorePatterns) {
            if ($candidate -match $pattern) { return $true }
        }
        return $false
    }

    function Read-UsefulLine {
        param(
            [int]$ReadMs,
            [string]$CommandEcho,
            [bool]$AllowBlank,
            [int]$BlankIdleTimeoutMs
        )

        $watch = [System.Diagnostics.Stopwatch]::StartNew()
        $idle = [System.Diagnostics.Stopwatch]::StartNew()
        $buffer = New-Object System.Text.StringBuilder
        $lastGood = ''
        $processed = 0

        while ($watch.ElapsedMilliseconds -lt $ReadMs) {
            try { $chunk = $Port.ReadExisting() } catch { $chunk = '' }

            if ($chunk) {
                [void]$buffer.Append($chunk)
                $idle.Restart()
            }
            else {
                Start-Sleep -Milliseconds 10
            }

            $text = ($buffer.ToString() -replace "`r", '')
            $endedWithNewLine = $text.EndsWith("`n")
            $parts = $text -split "`n", -1
            $maxIndex = $parts.Count - 1
            if (-not $endedWithNewLine) { $maxIndex-- }

            for ($i = $processed; $i -le $maxIndex; $i++) {
                $candidate = $parts[$i].Trim()
                if ($candidate -eq $CommandEcho) { continue }
                if (Test-IgnoredLine $candidate) { continue }
                if (Test-IsLogLine $candidate) { continue }
                $candidate = ($candidate -replace '^[\s>]*(->|>)+\s*', '').Trim()
                if (-not $candidate) { continue }
                $lastGood = $candidate
            }

            if ($maxIndex -ge $processed) {
                $processed = $maxIndex + 1
            }

            if ($lastGood -and $idle.ElapsedMilliseconds -ge $IdleMs) {
                break
            }

            if (-not $lastGood -and $AllowBlank -and $idle.ElapsedMilliseconds -ge $BlankIdleTimeoutMs) {
                break
            }
        }

        if (-not $lastGood -and $parts.Count -gt 0) {
            $tail = $parts[$parts.Count - 1].Trim()
            if ($tail -and $tail -ne $CommandEcho -and -not (Test-IgnoredLine $tail) -and -not (Test-IsLogLine $tail)) {
                $tail = ($tail -replace '^[\s>]*(->|>)+\s*', '').Trim()
                if ($tail) {
                    $lastGood = $tail
                }
            }
        }

        return $lastGood
    }

    for ($attempt = 1; $attempt -le $Attempts; $attempt++) {
        try { $Port.DiscardInBuffer() } catch { return '' }
        try { $Port.DiscardOutBuffer() } catch { }
        try { $Port.WriteLine($Line) } catch { return '' }

        $response = Read-UsefulLine -ReadMs $TotalMs -CommandEcho $Line -AllowBlank $AllowBlankResponse.IsPresent -BlankIdleTimeoutMs $BlankIdleMs
        if ($response -and -not (Test-IsLogLine $response)) {
            return $response
        }

        if ($AllowBlankResponse) {
            return ''
        }

        if ($ExtraReadMs -gt 0) {
            $lateResponse = Read-UsefulLine -ReadMs $ExtraReadMs -CommandEcho $Line -AllowBlank $false -BlankIdleTimeoutMs $BlankIdleMs
            if ($lateResponse -and -not (Test-IsLogLine $lateResponse)) {
                return $lateResponse
            }
        }

        if ($attempt -lt $Attempts) {
            Start-Sleep -Milliseconds $RetryDelayMs
        }
    }

    return ''
}

function Get-CandidateBauds {
    $values = New-Object System.Collections.Generic.List[int]
    foreach ($item in @($script:SerialBaudCache, $script:PreferredBaud) + $script:DefaultBauds) {
        if ($null -eq $item) { continue }
        $candidate = [int]$item
        if (-not $values.Contains($candidate)) {
            [void]$values.Add($candidate)
        }
    }
    return @($values)
}

function Invoke-MeshCoreSerialCommand {
    param(
        [Parameter(Mandatory)][string]$Command,
        [int]$MaxRetries = 3,
        [int]$TotalMs = $script:SerialTotalTimeoutMs,
        [switch]$UseKnownGoodBaudOnly,
        [switch]$AllowBlankResponse,
        [int]$BlankIdleMs = 220
    )

    if ([string]::IsNullOrWhiteSpace($script:DeviceName)) {
        throw 'No COM port has been selected.'
    }

    $lastOutput = ''

    $baudCandidates = @()
    if ($UseKnownGoodBaudOnly -and $script:SerialBaudCache) {
        $baudCandidates = @([int]$script:SerialBaudCache)
    }
    else {
        $baudCandidates = @(Get-CandidateBauds)
    }

    for ($baudIndex = 0; $baudIndex -lt $baudCandidates.Count; $baudIndex++) {
        $baudCandidate = $baudCandidates[$baudIndex]
        for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
            try {
                $port = Get-ActiveSerialSession -BaudRate $baudCandidate
                $response = Invoke-SerialCommand -Port $port -Line $Command -TotalMs $TotalMs -IdleMs $script:SerialIdleTimeoutMs -Attempts 1 -RetryDelayMs $script:SerialRetryDelayMs -ExtraReadMs 400 -AllowBlankResponse:$AllowBlankResponse -BlankIdleMs $BlankIdleMs
                $response = Strip-Prefix $response
                if (-not [string]::IsNullOrWhiteSpace($response) -and $response -ne 'Unknown command') {
                    $script:SerialBaudCache = $baudCandidate
                    $script:PreferredBaud = $baudCandidate
                    return $response
                }
                if ($AllowBlankResponse) {
                    return ''
                }
                $lastOutput = $response
            }
            catch {
                $lastOutput = ''
                Close-ActiveSerialSession
            }

            if ($attempt -lt $MaxRetries) {
                Start-Sleep -Milliseconds $script:SerialRetryDelayMs
            }
        }

        if ($baudIndex -lt ($baudCandidates.Count - 1)) {
            Close-ActiveSerialSession
        }
    }

    return $lastOutput
}

function Read-MeshCoreSettingValue {
    param(
        [Parameter(Mandatory)][string]$Command,
        [int]$TotalMs = 1200,
        [switch]$AllowBlankResponse,
        [int]$BlankIdleMs = 220
    )

    return Trim-Text (Invoke-MeshCoreSerialCommand -Command $Command -MaxRetries 1 -TotalMs $TotalMs -UseKnownGoodBaudOnly -AllowBlankResponse:$AllowBlankResponse -BlankIdleMs $BlankIdleMs)
}

function Get-SerialCommandPreview {
    param([Parameter(Mandatory)][string]$Command)

    return "Would send to $($script:DeviceName): $Command"
}

function Send-Or-EchoSerialCommand {
    param([Parameter(Mandatory)][string]$Command)

    if ($script:CanSendCommands) {
        return (Invoke-MeshCoreSerialCommand -Command $Command)
    }

    Write-Host (Get-SerialCommandPreview -Command $Command)
    return ''
}

function Send-OneWayOrEchoSerialCommand {
    param(
        [Parameter(Mandatory)][string]$Command,
        [int]$SettleMs = 120
    )

    if (-not $script:CanSendCommands) {
        Write-Host (Get-SerialCommandPreview -Command $Command)
        return
    }

    if ([string]::IsNullOrWhiteSpace($script:DeviceName)) {
        throw 'No COM port has been selected.'
    }

    $baudCandidates = @()
    if ($script:SerialBaudCache) {
        $baudCandidates = @([int]$script:SerialBaudCache)
    }
    else {
        $baudCandidates = @(Get-CandidateBauds)
    }

    foreach ($baudCandidate in $baudCandidates) {
        try {
            $port = Get-ActiveSerialSession -BaudRate $baudCandidate
            try { $port.DiscardInBuffer() } catch { }
            try { $port.DiscardOutBuffer() } catch { }
            $port.WriteLine($Command)
            Start-Sleep -Milliseconds $SettleMs
            $script:SerialBaudCache = $baudCandidate
            $script:PreferredBaud = $baudCandidate
            Close-ActiveSerialSession
            return
        }
        catch {
            Close-ActiveSerialSession
        }
    }

    throw "Failed to send one-way command '$Command' on $($script:DeviceName)"
}

function Ensure-MeshCoreConfig {
    Ensure-Directory -Path $script:FirmwareRoot

    $needsFetch = $true
    if (Test-Path -LiteralPath $script:RadioConfigFile) {
        $age = (Get-Date) - (Get-Item -LiteralPath $script:RadioConfigFile).LastWriteTime
        if ($age.TotalSeconds -le 21600) {
            $needsFetch = $false
        }
    }

    if ($needsFetch) {
        Write-Host "Downloading config from $($script:ConfigUrl)"
        Invoke-WebRequest -Uri $script:ConfigUrl -OutFile $script:RadioConfigFile -Headers @{ 'User-Agent' = 'mcsetup-powershell' } -UseBasicParsing
    }
}

function Get-MeshCoreConfigObject {
    Ensure-MeshCoreConfig
    $raw = Get-Content -Path $script:RadioConfigFile -Raw
    if ([string]::IsNullOrWhiteSpace($raw)) {
        throw "Config file is empty: $($script:RadioConfigFile)"
    }
    return ($raw | ConvertFrom-Json)
}

function Get-SystemTimezone {
    return [System.TimeZoneInfo]::Local.Id
}

function Guess-RadioTitleFromTimezone {
    param([string]$Timezone)

    $tz = Trim-Text $Timezone
    if (-not $tz) { return '' }

    switch -Wildcard ($tz) {
        'Australia/*' { return 'Australia' }
        'Pacific/Auckland' { return 'New Zealand' }
        'Pacific/Chatham' { return 'New Zealand' }
        'Europe/Prague' { return 'Czech Republic (Narrow)' }
        'Europe/Lisbon' { return 'Portugal 868' }
        'Europe/Zurich' { return 'Switzerland' }
        'Europe/*' { return 'EU/UK (Narrow)' }
        'America/*' { return 'USA/Canada (Recommended)' }
        'Canada/*' { return 'USA/Canada (Recommended)' }
        'US/*' { return 'USA/Canada (Recommended)' }
        'Asia/Ho_Chi_Minh' { return 'Vietnam' }
    }

    $tzLower = $tz.ToLowerInvariant()
    switch -Regex ($tzLower) {
        '^aus (central|eastern|western) standard time$' { return 'Australia' }
        '^tasmania standard time$' { return 'Australia' }
        '^cen\. australia standard time$' { return 'Australia' }
        '^e\. australia standard time$' { return 'Australia' }
        '^w\. australia standard time$' { return 'Australia' }

        '^new zealand standard time$' { return 'New Zealand' }
        '^chatham islands standard time$' { return 'New Zealand' }

        '^central europe standard time$' { return 'Czech Republic (Narrow)' }
        '^czech standard time$' { return 'Czech Republic (Narrow)' }

        '^gmt standard time$' { return 'Portugal 868' }
        '^greenwich standard time$' { return 'Portugal 868' }

        '^w\. europe standard time$' { return 'Switzerland' }
        '^romance standard time$' { return 'Switzerland' }
        '^central european standard time$' { return 'EU/UK (Narrow)' }

        '^(pacific|mountain|us mountain|central|eastern|atlantic|newfoundland|alaskan|hawaiian|yukon|canada central) standard time$' { return 'USA/Canada (Recommended)' }

        '^se asia standard time$' { return 'Vietnam' }
        default { return '' }
    }
}

function Snapshot-RadioBaseline {
    $script:RadioBaseline.Freq = $script:Radio.Freq
    $script:RadioBaseline.Bw = $script:Radio.Bw
    $script:RadioBaseline.Sf = $script:Radio.Sf
    $script:RadioBaseline.Cr = $script:Radio.Cr
}

function Get-SerialPortInventory {
    $ports = @()

    try {
        $entities = Get-WmiObject -Class Win32_PnPEntity | Where-Object {
            $_.DeviceID -like '*USB*' -and $_.Name -like '*(COM*'
        }

        foreach ($entity in $entities) {
            if ($entity.Name -match '(COM\d+)') {
                $comPort = $matches[1].ToUpperInvariant()
                $comNum = [int]($comPort -replace '^[^\d]*', '')
                $hardwareId = if ($entity.HardwareID) {
                    ($entity.HardwareID -split '\\')[-1]
                }
                else {
                    '--'
                }

                $ports += [pscustomobject]@{
                    ComPort    = $comPort
                    Label      = $entity.Name
                    DeviceName = $hardwareId
                    _Sort      = $comNum
                }
            }
        }
    }
    catch {
    }

    return @(
        $ports |
            Sort-Object _Sort, Label |
            Select-Object ComPort, Label, DeviceName
    )
}

function Choose-SerialPort {
    while ($true) {
        $ports = @(Get-SerialPortInventory)
        if ($ports.Count -eq 0) {
            Write-Host 'No USB serial devices found.'
            $retry = Read-Host 'Try again? [y/N]'
            if ($retry -match '^[Yy]$') { continue }
            return ''
        }

        if ($ports.Count -eq 1) {
            return $ports[0].ComPort
        }

        Write-Host 'Select a serial device:'
        for ($i = 0; $i -lt $ports.Count; $i++) {
            Write-Host (" {0,2}) {1}  ({2})" -f ($i + 1), $ports[$i].ComPort, $ports[$i].Label)
        }
        Write-Host '  0) Scan again'

        $choice = Read-Host 'Choice'
        $index = 0
        if (-not [int]::TryParse($choice, [ref]$index)) {
            Write-Host 'Invalid selection; please try again.'
            continue
        }

        if ($index -eq 0) { continue }
        if ($index -ge 1 -and $index -le $ports.Count) {
            return $ports[$index - 1].ComPort
        }

        Write-Host 'Invalid selection; please try again.'
    }
}

function Read-OnOffPrompt {
    param(
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][string]$Current
    )

    while ($true) {
        $value = Read-Host "$Label (on/off, current: $Current)"
        if ([string]::IsNullOrWhiteSpace($value)) {
            return $Current
        }

        switch ($value.Trim().ToLowerInvariant()) {
            'on' { return 'on' }
            'off' { return 'off' }
            default { Write-Host 'Please enter on or off.' }
        }
    }
}

function Test-IsNumeric {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $parsed = 0.0
    return [double]::TryParse($Value, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$parsed)
}

function Read-NumberPrompt {
    param(
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][string]$Current
    )

    while ($true) {
        $value = Read-Host "$Label (current: $Current)"
        if ([string]::IsNullOrWhiteSpace($value)) {
            return $Current
        }
        if (Test-IsNumeric $value) {
            return $value.Trim()
        }
        Write-Host 'Enter a number (for example 0.5, 1, or 2.0).'
    }
}

function Read-BoundedNumberPrompt {
    param(
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][string]$Current,
        [Parameter(Mandatory)][double]$Min,
        [Parameter(Mandatory)][double]$Max
    )

    while ($true) {
        $value = Read-Host "$Label ($Min-$Max, current: $Current)"
        if ([string]::IsNullOrWhiteSpace($value)) {
            return $Current
        }

        $parsed = 0.0
        if ([double]::TryParse($value, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$parsed) -and $parsed -ge $Min -and $parsed -le $Max) {
            return $value.Trim()
        }

        Write-Host "Enter a number between $Min and $Max."
    }
}

function Test-NumberEqual {
    param(
        [string]$Left,
        [string]$Right
    )

    if ([string]::IsNullOrWhiteSpace($Left) -or [string]::IsNullOrWhiteSpace($Right)) {
        return $false
    }

    $leftParsed = 0.0
    $rightParsed = 0.0
    if (-not [double]::TryParse($Left, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$leftParsed)) {
        return $false
    }
    if (-not [double]::TryParse($Right, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$rightParsed)) {
        return $false
    }

    return [Math]::Abs($leftParsed - $rightParsed) -le 1e-9
}

function Set-IfChanged {
    param(
        [Parameter(Mandatory)][string]$Key,
        [AllowNull()][string]$Current,
        [AllowNull()][string]$New,
        [ValidateSet('str', 'num')][string]$Mode = 'str',
        [switch]$NoSetPrefix
    )

    $newValue = Trim-Text $New
    $currentValue = Trim-Text $Current

    if ([string]::IsNullOrWhiteSpace($newValue)) {
        Write-Host "No change: $Key left as '$currentValue'"
        return
    }

    if ($Mode -eq 'num') {
        if (Test-NumberEqual -Left $currentValue -Right $newValue) {
            Write-Host "No change: $Key remains $currentValue"
            return
        }
    }
    else {
        if ($newValue -match '^(?i:on|off)$' -and $currentValue -match '^(?i:on|off)$') {
            if ($newValue.ToLowerInvariant() -eq $currentValue.ToLowerInvariant()) {
                Write-Host "No change: $Key remains $currentValue"
                return
            }
        }
        elseif ($newValue -eq $currentValue) {
            Write-Host "No change: $Key remains $currentValue"
            return
        }
    }

    Write-Host "Updating: $Key -> $newValue"
    $command = if ($NoSetPrefix) { "$Key $newValue" } else { "set $Key $newValue" }
    [void](Send-Or-EchoSerialCommand -Command $command)
}

function Initialize-EmptySettings {
    $script:Settings = [ordered]@{
        af                    = ''
        int_thresh            = ''
        agc_reset_interval    = ''
        multi_acks            = ''
        allow_read_only       = ''
        flood_advert_interval = ''
        advert_interval       = ''
        dutycycle             = ''
        guest_password        = ''
        password              = ''
        name                  = ''
        repeat                = ''
        lat                   = ''
        lon                   = ''
        private_key           = ''
        public_key            = ''
        owner_info            = ''
        path_hash_mode        = ''
        loop_detect           = ''
        rxdelay               = ''
        txdelay               = ''
        direct_txdelay        = ''
        flood_max             = ''
        tx                    = ''
        role                  = ''
        powersaving           = ''
    }

    $script:Radio.Freq = ''
    $script:Radio.Bw = ''
    $script:Radio.Sf = ''
    $script:Radio.Cr = ''
    Snapshot-RadioBaseline
}

function Select-CustomRadioSetting {
    Write-Host ''
    Write-Host 'Custom radio settings'

    while ($true) {
        $freq = Read-Host 'Center frequency (MHz, e.g. 915.000)'
        if (Test-IsNumeric $freq) { break }
        Write-Host 'Please enter a numeric MHz value (for example 915.000).'
    }

    Write-Host 'Spreading factor options: 5, 6, 7, 8, 9, 10, 11, 12'
    while ($true) {
        $sf = Read-Host 'SF (5-12)'
        $sfValue = 0
        if ([int]::TryParse($sf, [ref]$sfValue) -and $sfValue -ge 5 -and $sfValue -le 12) { break }
        Write-Host 'Please enter 5, 6, 7, 8, 9, 10, 11, or 12.'
    }

    $allowedBandwidths = @('7.81', '10.42', '15.63', '20.83', '31.25', '41.67', '62.5', '125', '250', '500')
    Write-Host ("Bandwidth options (kHz): {0}" -f ($allowedBandwidths -join ' '))
    while ($true) {
        $bw = Read-Host ("BW ({0})" -f ($allowedBandwidths -join ' '))
        if ($allowedBandwidths -contains $bw.Trim()) { break }
        Write-Host ("Please enter one of: {0}" -f ($allowedBandwidths -join ', '))
    }

    Write-Host 'Coding rate options: CR5, CR6, CR7, CR8'
    while ($true) {
        $cr = Read-Host 'CR (5-8)'
        $crValue = 0
        if ([int]::TryParse($cr, [ref]$crValue) -and $crValue -ge 5 -and $crValue -le 8) { break }
        Write-Host 'Please enter 5, 6, 7, or 8.'
    }

    $script:Radio.Freq = $freq.Trim()
    $script:Radio.Sf = $sf.Trim()
    $script:Radio.Bw = $bw.Trim()
    $script:Radio.Cr = $cr.Trim()
    return $true
}

function Select-SuggestedRadioSetting {
    $config = Get-MeshCoreConfigObject
    $entries = @($config.config.suggested_radio_settings.entries)
    if ($entries.Count -eq 0) {
        Write-Host 'No suggested radio settings were found in the config.'
        return $false
    }

    $timezone = Get-SystemTimezone
    $guessTitle = Guess-RadioTitleFromTimezone -Timezone $timezone

    $baseCounts = @{}
    foreach ($entry in $entries) {
        $base = ([string]$entry.title) -replace '\s+\(.*$', ''
        if (-not $baseCounts.ContainsKey($base)) {
            $baseCounts[$base] = 0
        }
        $baseCounts[$base]++
    }

    if ($guessTitle) {
        Write-Host "System timezone: $timezone. Guessed region: $guessTitle"
    }
    else {
        Write-Host "System timezone: $timezone"
    }
    Write-Host 'Select a suggested radio setting:'
    Write-Host ' 0) Custom (manual freq / SF / BW / CR)'

    for ($i = 0; $i -lt $entries.Count; $i++) {
        $entry = $entries[$i]
        $title = [string]$entry.title
        $base = $title -replace '\s+\(.*$', ''
        $lower = $title.ToLowerInvariant()
        $bandwidth = [string]$entry.bandwidth
        $mark = if ($guessTitle -and $title -like "*$guessTitle*") { '*' } else { '' }
        $color = $null

        if ($baseCounts[$base] -gt 1 -and $lower -notlike '*narrow*' -and $lower -notlike '*recommended*') {
            $color = 'Red'
        }
        if ($bandwidth -ne '62.5') {
            $color = 'DarkGray'
        }

        $line = "{0,2}) {1,-25} {2} {3}" -f ($i + 1), $title, ([string]$entry.description), $mark
        if ($color) {
            Write-Host $line -ForegroundColor $color
        }
        else {
            Write-Host $line
        }
    }

    while ($true) {
        $prompt = if ($guessTitle) {
            "Choice (0-$($entries.Count), Enter for $guessTitle, or q to quit)"
        }
        else {
            "Choice (0-$($entries.Count) or q to quit)"
        }

        $choice = Read-Host $prompt
        switch ($choice) {
            { $_ -match '^[Qq]$' } {
                Write-Host 'Aborted.'
                return $false
            }
            '' {
                if (-not $guessTitle) {
                    Write-Host 'No guessed region is available; please choose a number.'
                    continue
                }

                $selected = $entries | Where-Object { [string]$_.title -eq $guessTitle } | Select-Object -First 1
                if (-not $selected) {
                    $selected = $entries | Where-Object { [string]$_.title -like "*$guessTitle*" } | Select-Object -First 1
                }
                if (-not $selected) {
                    Write-Host 'Could not match the guessed region; please choose a number.'
                    continue
                }

                Write-Host "Using guessed region: $($selected.title)"
                $script:Radio.Freq = [string]$selected.frequency
                $script:Radio.Sf = [string]$selected.spreading_factor
                $script:Radio.Bw = [string]$selected.bandwidth
                $script:Radio.Cr = [string]$selected.coding_rate
                return $true
            }
            default {
                $index = 0
                if (-not [int]::TryParse($choice, [ref]$index)) {
                    Write-Host "Please enter a number, press Enter for $guessTitle, or q."
                    continue
                }

                if ($index -eq 0) {
                    return (Select-CustomRadioSetting)
                }

                if ($index -lt 1 -or $index -gt $entries.Count) {
                    Write-Host 'Out of range.'
                    continue
                }

                $selected = $entries[$index - 1]
                $script:Radio.Freq = [string]$selected.frequency
                $script:Radio.Sf = [string]$selected.spreading_factor
                $script:Radio.Bw = [string]$selected.bandwidth
                $script:Radio.Cr = [string]$selected.coding_rate
                return $true
            }
        }
    }
}

function Load-RepeaterSettings {
    Write-Host 'Reading all radio settings'

    $keyMap = @(
        @{ Remote = 'dutycycle';             Local = 'dutycycle' }
        @{ Remote = 'tx';                    Local = 'tx' }
        @{ Remote = 'repeat';                Local = 'repeat' }
        @{ Remote = 'role';                  Local = 'role' }
        @{ Remote = 'allow.read.only';       Local = 'allow_read_only' }
        @{ Remote = 'txdelay';               Local = 'txdelay' }
        @{ Remote = 'rxdelay';               Local = 'rxdelay' }
        @{ Remote = 'direct.txdelay';        Local = 'direct_txdelay' }
        @{ Remote = 'agc.reset.interval';    Local = 'agc_reset_interval' }
        @{ Remote = 'int.thresh';            Local = 'int_thresh' }
        @{ Remote = 'af';                    Local = 'af' }
        @{ Remote = 'multi.acks';            Local = 'multi_acks' }
        @{ Remote = 'advert.interval';       Local = 'advert_interval' }
        @{ Remote = 'flood.advert.interval'; Local = 'flood_advert_interval' }
        @{ Remote = 'flood.max';             Local = 'flood_max' }
        @{ Remote = 'guest.password';        Local = 'guest_password' }
        @{ Remote = 'password';              Local = 'password' }
        @{ Remote = 'name';                  Local = 'name' }
        @{ Remote = 'owner.info';            Local = 'owner_info' }
        @{ Remote = 'path.hash.mode';        Local = 'path_hash_mode' }
        @{ Remote = 'loop.detect';           Local = 'loop_detect' }
        @{ Remote = 'prv.key';               Local = 'private_key' }
        @{ Remote = 'public.key';            Local = 'public_key' }
        @{ Remote = 'lat';                   Local = 'lat' }
        @{ Remote = 'lon';                   Local = 'lon' }
    )

    $total = $keyMap.Count + 2
    $progressId = 51
    $step = 0

    foreach ($entry in $keyMap) {
        $step++
        $pct = [int](($step * 100) / $total)
        Write-Progress -Id $progressId -Activity 'Reading device settings' -Status "get $($entry.Remote)" -PercentComplete $pct
        $readTimeoutMs = switch ($entry.Remote) {
            'guest.password' { 700 }
            'password' { 700 }
            'public.key' { 900 }
            'owner.info' { 900 }
            default { 1200 }
        }
        $allowBlankResponse = $entry.Remote -in @('guest.password', 'password', 'owner.info')
        $blankIdleMs = switch ($entry.Remote) {
            'guest.password' { 180 }
            'owner.info' { 180 }
            default { 220 }
        }
        $script:Settings[$entry.Local] = Read-MeshCoreSettingValue -Command "get $($entry.Remote)" -TotalMs $readTimeoutMs -AllowBlankResponse:$allowBlankResponse -BlankIdleMs $blankIdleMs
        $displayValue = Format-ProgressSettingValue -Key $entry.Remote -Value $script:Settings[$entry.Local]
        Write-Progress -Id $progressId -Activity 'Reading device settings' -Status ("get {0} -> {1}" -f $entry.Remote, $displayValue) -PercentComplete $pct
        Start-Sleep -Milliseconds 40
    }

    $step++
    Write-Progress -Id $progressId -Activity 'Reading device settings' -Status 'powersaving' -PercentComplete ([int](($step * 100) / $total))
    $script:Settings.powersaving = Read-MeshCoreSettingValue -Command 'powersaving' -TotalMs 800
    Write-Progress -Id $progressId -Activity 'Reading device settings' -Status ("powersaving -> {0}" -f (Format-ProgressSettingValue -Key 'powersaving' -Value $script:Settings.powersaving)) -PercentComplete ([int](($step * 100) / $total))
    Start-Sleep -Milliseconds 40

    $step++
    Write-Progress -Id $progressId -Activity 'Reading device settings' -Status 'get radio' -PercentComplete ([int](($step * 100) / $total))
    $radioRaw = Read-MeshCoreSettingValue -Command 'get radio' -TotalMs 1200
    $radioRaw = $radioRaw -replace '\s*,\s*', ','
    $parts = $radioRaw -split ',', 4
    $script:Radio.Freq = if ($parts.Count -ge 1) { Trim-Text $parts[0] } else { '' }
    $script:Radio.Bw = if ($parts.Count -ge 2) { Trim-Text $parts[1] } else { '' }
    $script:Radio.Sf = if ($parts.Count -ge 3) { Trim-Text $parts[2] } else { '' }
    $script:Radio.Cr = if ($parts.Count -ge 4) { Trim-Text $parts[3] } else { '' }
    $radioDisplay = if ($radioRaw) { $radioRaw } else { '<empty>' }
    if ($radioDisplay.Length -gt 48) {
        $radioDisplay = $radioDisplay.Substring(0, 45) + '...'
    }
    Write-Progress -Id $progressId -Activity 'Reading device settings' -Status ("get radio -> {0}" -f $radioDisplay) -PercentComplete ([int](($step * 100) / $total))
    Start-Sleep -Milliseconds 40

    Write-Progress -Id $progressId -Activity 'Reading device settings' -Completed
}

function Format-PreviewText {
    param([AllowNull()][string]$Value)

    $text = Trim-Text $Value
    if (-not $text) { return '' }
    if ($text.Length -le 16) { return $text }
    return ('{0}...{1}' -f $text.Substring(0, 8), $text.Substring($text.Length - 8))
}

function Format-ProgressSettingValue {
    param(
        [Parameter(Mandatory)][string]$Key,
        [AllowNull()][string]$Value
    )

    $text = Trim-Text $Value
    if (-not $text) {
        return '<empty>'
    }

    switch ($Key) {
        'guest.password' { return '<hidden>' }
        'password' { return '<hidden>' }
        'prv.key' { return Format-PreviewText $text }
        'public.key' { return Format-PreviewText $text }
        default {
            if ($text.Length -le 48) { return $text }
            return ($text.Substring(0, 45) + '...')
        }
    }
}

function Edit-RepeaterSettingsMenu {
    while ($true) {
        Write-Host ''
        Write-Host 'Current settings:'
        Write-Host ' 0) Send Raw Command'
        Write-Host " 1) tx                    = $($script:Settings.tx)"
        Write-Host " 2) repeat                = $($script:Settings.repeat)"
        Write-Host " 3) allow.read.only       = $($script:Settings.allow_read_only)"
        Write-Host " 4) agc.reset.interval    = $($script:Settings.agc_reset_interval)"
        Write-Host " 5) advert.interval       = $($script:Settings.advert_interval)"
        Write-Host " 6) flood.advert.interval = $($script:Settings.flood_advert_interval)"
        Write-Host " 7) flood.max             = $($script:Settings.flood_max)"
        Write-Host " 8) guest.password        = $($script:Settings.guest_password)"
        Write-Host " 9) password              = $($script:Settings.password) (Reading is broken)"
        Write-Host "10) private key           = $(Format-PreviewText $script:Settings.private_key)"
        Write-Host "11) public key            = $(Format-PreviewText $script:Settings.public_key) (read-only)"
        Write-Host "12) name                  = $($script:Settings.name)"
        Write-Host "13) lat                   = $($script:Settings.lat)"
        Write-Host "14) lon                   = $($script:Settings.lon)"
        Write-Host "15) role                  = $($script:Settings.role) (read-only)"
        Write-Host "16) txdelay               = $($script:Settings.txdelay)"
        Write-Host "17) rxdelay               = $($script:Settings.rxdelay)"
        Write-Host "18) direct.txdelay        = $($script:Settings.direct_txdelay)"
        Write-Host "19) int.thresh            = $($script:Settings.int_thresh)"
        Write-Host "20) af                    = $($script:Settings.af)"
        Write-Host "21) multi.acks            = $($script:Settings.multi_acks)"
        Write-Host "22) radio                 = freq=$($script:Radio.Freq) bw=$($script:Radio.Bw) sf=$($script:Radio.Sf) cr=$($script:Radio.Cr)"
        Write-Host "23) powersaving           = $($script:Settings.powersaving)"
        Write-Host "24) dutycycle             = $($script:Settings.dutycycle)"
        Write-Host "25) owner.info            = $($script:Settings.owner_info)"
        Write-Host "26) path.hash.mode        = $($script:Settings.path_hash_mode)"
        Write-Host "27) loop.detect           = $($script:Settings.loop_detect)"
        Write-Host ' R) Refresh above settings from device'
        Write-Host ' Z) Send zero-hop advert now'
        Write-Host ' A) Send flood advert now'
        Write-Host ' L) Logs: start/stop/erase'
        Write-Host ' D) Dump log'
        Write-Host ' N) Show neighbors'
        Write-Host ' X) Remove neighbor by pubkey'
        Write-Host ' O) Start OTA'
        Write-Host ' K) Clock-reset reboot'
        Write-Host ' C) Clear stats'
        Write-Host ' Q) Quit'
        Write-Host ''

        $choice = Read-Host 'Choose an item to edit, an action, or q to finish'
        switch ($choice) {
            { $_ -match '^[Qq]$' } {
                Write-Host 'Done.'
                return
            }
            { $_ -match '^[Rr]$' } {
                Write-Host 'Reloading settings from device...'
                Load-RepeaterSettings
                Snapshot-RadioBaseline
            }
            '0' {
                $command = Read-Host 'Command to run'
                if (-not [string]::IsNullOrWhiteSpace($command)) {
                    Write-Host "Running: $command"
                    $result = Send-Or-EchoSerialCommand -Command $command
                    if ($result) { Write-Host $result }
                }
                else {
                    Write-Host 'No command entered.'
                }
            }
            '1' {
                $reply = Read-NumberPrompt -Label 'tx' -Current $script:Settings.tx
                Set-IfChanged -Key 'tx' -Current $script:Settings.tx -New $reply -Mode num
                $script:Settings.tx = $reply
            }
            '2' {
                $reply = Read-OnOffPrompt -Label 'repeat' -Current $script:Settings.repeat
                Set-IfChanged -Key 'repeat' -Current $script:Settings.repeat -New $reply
                $script:Settings.repeat = $reply
            }
            '3' {
                $reply = Read-OnOffPrompt -Label 'allow.read.only' -Current $script:Settings.allow_read_only
                Set-IfChanged -Key 'allow.read.only' -Current $script:Settings.allow_read_only -New $reply
                $script:Settings.allow_read_only = $reply
            }
            '4' {
                $reply = Read-NumberPrompt -Label 'agc.reset.interval' -Current $script:Settings.agc_reset_interval
                Set-IfChanged -Key 'agc.reset.interval' -Current $script:Settings.agc_reset_interval -New $reply -Mode num
                $script:Settings.agc_reset_interval = $reply
            }
            '5' {
                $reply = Read-NumberPrompt -Label 'advert.interval' -Current $script:Settings.advert_interval
                Set-IfChanged -Key 'advert.interval' -Current $script:Settings.advert_interval -New $reply -Mode num
                $script:Settings.advert_interval = $reply
            }
            '6' {
                $reply = Read-NumberPrompt -Label 'flood.advert.interval' -Current $script:Settings.flood_advert_interval
                Set-IfChanged -Key 'flood.advert.interval' -Current $script:Settings.flood_advert_interval -New $reply -Mode num
                $script:Settings.flood_advert_interval = $reply
            }
            '7' {
                $reply = Read-NumberPrompt -Label 'flood.max' -Current $script:Settings.flood_max
                Set-IfChanged -Key 'flood.max' -Current $script:Settings.flood_max -New $reply -Mode num
                $script:Settings.flood_max = $reply
            }
            '8' {
                $reply = Read-Host "guest.password (current: $($script:Settings.guest_password))"
                if ($reply -eq '-') { $reply = '' }
                if (-not [string]::IsNullOrWhiteSpace($reply) -and $reply -ne $script:Settings.guest_password) {
                    Write-Host 'Updating guest.password'
                    [void](Send-Or-EchoSerialCommand -Command "set guest.password $reply")
                    $script:Settings.guest_password = $reply
                }
                else {
                    Write-Host 'No change to guest.password'
                }
            }
            '9' {
                $reply = Read-Host "password (current: $($script:Settings.password))"
                if (-not [string]::IsNullOrWhiteSpace($reply) -and $reply -ne $script:Settings.password) {
                    Write-Host 'Updating password'
                    [void](Send-Or-EchoSerialCommand -Command "password $reply")
                    $script:Settings.password = $reply
                }
                else {
                    Write-Host 'No change to password'
                }
            }
            '10' {
                Write-Host "Existing key: $($script:Settings.private_key)"
                $reply = Trim-Text (Read-Host 'private key (blank to keep)')
                if (-not [string]::IsNullOrWhiteSpace($reply) -and $reply -ne $script:Settings.private_key) {
                    Write-Host 'Updating private key'
                    [void](Send-Or-EchoSerialCommand -Command "set prv.key $reply")
                    $script:Settings.private_key = $reply
                }
                else {
                    Write-Host 'Private key unchanged.'
                }
            }
            '11' {
                Write-Host 'public.key is read-only.'
            }
            '12' {
                $reply = Read-Host "name (current: $($script:Settings.name))"
                if (-not [string]::IsNullOrWhiteSpace($reply) -and $reply -ne $script:Settings.name) {
                    [void](Send-Or-EchoSerialCommand -Command "set name $reply")
                    $script:Settings.name = $reply
                }
                else {
                    Write-Host 'No change to name'
                }
            }
            '13' {
                $reply = Read-BoundedNumberPrompt -Label 'lat' -Current $script:Settings.lat -Min -90.0 -Max 90.0
                Set-IfChanged -Key 'lat' -Current $script:Settings.lat -New $reply -Mode num
                $script:Settings.lat = $reply
            }
            '14' {
                $reply = Read-BoundedNumberPrompt -Label 'lon' -Current $script:Settings.lon -Min -180.0 -Max 180.0
                Set-IfChanged -Key 'lon' -Current $script:Settings.lon -New $reply -Mode num
                $script:Settings.lon = $reply
            }
            '15' {
                Write-Host 'role is read-only.'
            }
            '16' {
                $reply = Read-BoundedNumberPrompt -Label 'txdelay' -Current $script:Settings.txdelay -Min 0.0 -Max 2.0
                Set-IfChanged -Key 'txdelay' -Current $script:Settings.txdelay -New $reply -Mode num
                $script:Settings.txdelay = $reply
            }
            '17' {
                $reply = Read-NumberPrompt -Label 'rxdelay' -Current $script:Settings.rxdelay
                Set-IfChanged -Key 'rxdelay' -Current $script:Settings.rxdelay -New $reply -Mode num
                $script:Settings.rxdelay = $reply
            }
            '18' {
                $reply = Read-BoundedNumberPrompt -Label 'direct.txdelay' -Current $script:Settings.direct_txdelay -Min 0.0 -Max 2.0
                Set-IfChanged -Key 'direct.txdelay' -Current $script:Settings.direct_txdelay -New $reply -Mode num
                $script:Settings.direct_txdelay = $reply
            }
            '19' {
                $reply = Read-NumberPrompt -Label 'int.thresh' -Current $script:Settings.int_thresh
                Set-IfChanged -Key 'int.thresh' -Current $script:Settings.int_thresh -New $reply -Mode num
                $script:Settings.int_thresh = $reply
            }
            '20' {
                $reply = Read-BoundedNumberPrompt -Label 'af' -Current $script:Settings.af -Min 0.0 -Max 1.0
                Set-IfChanged -Key 'af' -Current $script:Settings.af -New $reply -Mode num
                $script:Settings.af = $reply
            }
            '21' {
                $reply = Read-BoundedNumberPrompt -Label 'multi.acks' -Current $script:Settings.multi_acks -Min 0 -Max 1
                Set-IfChanged -Key 'multi.acks' -Current $script:Settings.multi_acks -New $reply -Mode num
                $script:Settings.multi_acks = $reply
            }
            '22' {
                if (Select-SuggestedRadioSetting) {
                    if ($script:Radio.Freq -ne $script:RadioBaseline.Freq -or
                        $script:Radio.Bw -ne $script:RadioBaseline.Bw -or
                        $script:Radio.Sf -ne $script:RadioBaseline.Sf -or
                        $script:Radio.Cr -ne $script:RadioBaseline.Cr) {
                        $radioValue = '{0},{1},{2},{3}' -f $script:Radio.Freq, $script:Radio.Bw, $script:Radio.Sf, $script:Radio.Cr
                        Write-Host "Setting radio: $radioValue"
                        [void](Send-Or-EchoSerialCommand -Command "set radio $radioValue")
                        Snapshot-RadioBaseline
                    }
                    else {
                        Write-Host 'Radio unchanged.'
                    }
                }
            }
            '23' {
                Write-Host 'Turning this ON will kill the USB connection right away'
                $reply = Read-OnOffPrompt -Label 'powersaving' -Current $script:Settings.powersaving
                Set-IfChanged -Key 'powersaving' -Current $script:Settings.powersaving -New $reply -NoSetPrefix
                $script:Settings.powersaving = $reply
            }
            '24' {
                $reply = Read-BoundedNumberPrompt -Label 'dutycycle' -Current $script:Settings.dutycycle -Min 1 -Max 100
                Set-IfChanged -Key 'dutycycle' -Current $script:Settings.dutycycle -New $reply -Mode num
                $script:Settings.dutycycle = $reply
            }
            '25' {
                $reply = Read-Host "owner.info (use | for line breaks, current: $($script:Settings.owner_info))"
                if (-not [string]::IsNullOrWhiteSpace($reply) -and $reply -ne $script:Settings.owner_info) {
                    Write-Host 'Updating owner.info'
                    [void](Send-Or-EchoSerialCommand -Command "set owner.info $reply")
                    $script:Settings.owner_info = $reply
                }
                else {
                    Write-Host 'No change to owner.info'
                }
            }
            '26' {
                $reply = Read-BoundedNumberPrompt -Label 'path.hash.mode' -Current $script:Settings.path_hash_mode -Min 0 -Max 2
                Set-IfChanged -Key 'path.hash.mode' -Current $script:Settings.path_hash_mode -New $reply -Mode num
                $script:Settings.path_hash_mode = $reply
            }
            '27' {
                while ($true) {
                    $reply = Trim-Text (Read-Host "loop.detect (off/minimal/moderate/strict, current: $($script:Settings.loop_detect))")
                    if ([string]::IsNullOrWhiteSpace($reply)) {
                        Write-Host 'No change to loop.detect'
                        break
                    }

                    switch ($reply.ToLowerInvariant()) {
                        'off' {
                            Set-IfChanged -Key 'loop.detect' -Current $script:Settings.loop_detect -New 'off'
                            $script:Settings.loop_detect = 'off'
                            break
                        }
                        'minimal' {
                            Set-IfChanged -Key 'loop.detect' -Current $script:Settings.loop_detect -New 'minimal'
                            $script:Settings.loop_detect = 'minimal'
                            break
                        }
                        'moderate' {
                            Set-IfChanged -Key 'loop.detect' -Current $script:Settings.loop_detect -New 'moderate'
                            $script:Settings.loop_detect = 'moderate'
                            break
                        }
                        'strict' {
                            Set-IfChanged -Key 'loop.detect' -Current $script:Settings.loop_detect -New 'strict'
                            $script:Settings.loop_detect = 'strict'
                            break
                        }
                        default {
                            Write-Host 'Enter one of: off, minimal, moderate, strict'
                        }
                    }

                    if ($script:Settings.loop_detect -eq $reply.ToLowerInvariant()) { break }
                }
            }
            { $_ -match '^[Zz]$' } {
                Write-Host 'Sending zero-hop advert...'
                $result = Send-Or-EchoSerialCommand -Command 'advert.zerohop'
                if ($result) { Write-Host $result }
            }
            { $_ -match '^[Aa]$' } {
                Write-Host 'Sending flood advert...'
                $result = Send-Or-EchoSerialCommand -Command 'advert'
                if ($result) { Write-Host $result }
            }
            { $_ -match '^[Ll]$' } {
                Write-Host 'Logs: (s)tart, s(t)op, (e)rase'
                $reply = Read-Host 'Choice [s/t/e]'
                switch ($reply) {
                    { $_ -match '^[Ss]$' } { $result = Send-Or-EchoSerialCommand -Command 'log start'; if ($result) { Write-Host $result } }
                    { $_ -match '^[Tt]$' } { $result = Send-Or-EchoSerialCommand -Command 'log stop'; if ($result) { Write-Host $result } }
                    { $_ -match '^[Ee]$' } { $result = Send-Or-EchoSerialCommand -Command 'log erase'; if ($result) { Write-Host $result } }
                    default { Write-Host 'Unknown choice.' }
                }
            }
            { $_ -match '^[Dd]$' } {
                Write-Host 'Dumping log...'
                $result = Send-Or-EchoSerialCommand -Command 'log'
                if ($result) { Write-Host $result }
            }
            { $_ -match '^[Nn]$' } {
                Write-Host 'Neighbors:'
                $result = Send-Or-EchoSerialCommand -Command 'neighbors'
                if ($result) { Write-Host $result }
            }
            { $_ -match '^[Xx]$' } {
                $reply = Trim-Text (Read-Host 'Neighbor pubkey to remove')
                if ($reply) {
                    $result = Send-Or-EchoSerialCommand -Command "neighbor.remove $reply"
                    if ($result) { Write-Host $result }
                }
                else {
                    Write-Host 'No pubkey entered.'
                }
            }
            { $_ -match '^[Oo]$' } {
                Write-Host 'Starting OTA...'
                $result = Send-Or-EchoSerialCommand -Command 'start ota'
                if ($result) { Write-Host $result }
            }
            { $_ -match '^[Kk]$' } {
                $reply = Read-Host 'Run clkreboot now? This resets the device clock and reboots the node. [y/N]'
                if ($reply -match '^[Yy]$') {
                    Write-Host 'Sending clkreboot...'
                    Send-OneWayOrEchoSerialCommand -Command 'clkreboot'
                }
                else {
                    Write-Host 'Clock-reset reboot skipped.'
                }
            }
            { $_ -match '^[Cc]$' } {
                Write-Host 'Clearing stats...'
                $result = Send-Or-EchoSerialCommand -Command 'clear stats'
                if ($result) { Write-Host $result }
            }
            default {
                Write-Host 'Invalid choice.'
            }
        }
    }
}

function Confirm-RestartRadio {
    while ($true) {
        $answer = Read-Host 'Restart radio now? [y/N]'
        switch ($answer) {
            { $_ -match '^[Yy]$' } { return $true }
            { $_ -eq '' -or $_ -match '^[Nn]$' } { return $false }
            default { Write-Host 'Please answer y or n.' }
        }
    }
}

function Read-DeviceClockEpoch {
    $clockText = Invoke-MeshCoreSerialCommand -Command 'clock'
    $match = [regex]::Match($clockText, '([0-9]{1,2}):([0-9]{2})\s*-\s*([0-9]{1,2})/([0-9]{1,2})/([0-9]{4})\s*UTC', 'IgnoreCase')
    if (-not $match.Success) {
        return $null
    }

    $day = [int]$match.Groups[3].Value
    $month = [int]$match.Groups[4].Value
    $year = [int]$match.Groups[5].Value
    $hour = [int]$match.Groups[1].Value
    $minute = [int]$match.Groups[2].Value

    $utc = [datetime]::SpecifyKind((Get-Date -Year $year -Month $month -Day $day -Hour $hour -Minute $minute -Second 0), [System.DateTimeKind]::Utc)
    return ([DateTimeOffset]$utc).ToUnixTimeSeconds()
}

function Prompt-PowercycleAndRetryTimeSync {
    param([Parameter(Mandatory)][long]$HostEpoch)

    while ($true) {
        $answer = Read-Host 'Power-cycle the node, wait for it to reconnect, then retry clock sync now? [Y/n]'
        switch ($answer) {
            '' { }
            { $_ -match '^[Yy]$' } { }
            { $_ -match '^[Nn]$' } { return $false }
            default {
                Write-Host 'Please answer y or n.'
                continue
            }
        }

        Write-Host "Retrying clock sync. Sending: time $HostEpoch"
        $response = Invoke-MeshCoreSerialCommand -Command "time $HostEpoch"
        if (-not $response) {
            Write-Host 'Warning: device did not acknowledge the retried time sync command'
        }
        return $true
    }
}

function Try-ForceHostTimeSync {
    $w32tm = Get-Command w32tm -ErrorAction SilentlyContinue
    if (-not $w32tm) {
        return
    }

    try {
        & $w32tm.Source /resync /force *> $null
    }
    catch {
    }
}

Initialize-EmptySettings

if ([string]::IsNullOrWhiteSpace($script:DeviceName)) {
    $script:DeviceName = Choose-SerialPort
}

if ([string]::IsNullOrWhiteSpace($script:DeviceName)) {
    Write-Host 'No COM port selected. Exiting.'
    return
}

if ($BootWait -gt 0) {
    Start-Sleep -Seconds $BootWait
}

Try-ForceHostTimeSync

$script:DeviceEpoch = Read-DeviceClockEpoch
$hostEpoch = [DateTimeOffset]::Now.ToUnixTimeSeconds()

Write-Host "device_epoch: $script:DeviceEpoch"
Write-Host "host_epoch  : $hostEpoch"
Write-Host ("Host   time (Local): {0}" -f ([DateTimeOffset]::FromUnixTimeSeconds($hostEpoch).ToLocalTime().ToString('yyyy-MM-dd HH:mm zzz')))

if ($null -ne $script:DeviceEpoch) {
    $deviceDiff = [math]::Abs([long]$script:DeviceEpoch - [long]$hostEpoch)
    Write-Host ("Device time (Local): {0}" -f ([DateTimeOffset]::FromUnixTimeSeconds([long]$script:DeviceEpoch).ToLocalTime().ToString('yyyy-MM-dd HH:mm zzz')))
}
else {
    $deviceDiff = 172801
    Write-Host 'Device time (Local): unavailable'
}

if ($deviceDiff -gt 172800) {
    if ($null -ne $script:DeviceEpoch) {
        Write-Host "Clock off by more than 2 days; syncing time now. Sending: time $hostEpoch"
    }
    else {
        Write-Host "Device clock unreadable; syncing time now. Sending: time $hostEpoch"
    }

    $timeResponse = Invoke-MeshCoreSerialCommand -Command "time $hostEpoch"
    if (-not $timeResponse) {
        Write-Host 'Warning: device did not acknowledge the time sync command'
    }
    Write-Host ''
}
else {
    Write-Host 'Clock within 2 days'
}

if ($null -ne $script:DeviceEpoch) {
    $script:CanSendCommands = $true
    $board = Get-UsableSerialResponse -Text (Invoke-MeshCoreSerialCommand -Command 'board') -Kind Board
    $ver = Get-UsableSerialResponse -Text (Invoke-MeshCoreSerialCommand -Command 'ver') -Kind Version
    if (-not $ver) {
        $ver = Get-UsableSerialResponse -Text (Invoke-MeshCoreSerialCommand -Command 'version') -Kind Version
    }
    Write-Host "$board - $ver"
    Load-RepeaterSettings
    Snapshot-RadioBaseline
}
else {
    Write-Host 'Serial commands seem to be broken'
    if (Prompt-PowercycleAndRetryTimeSync -HostEpoch $hostEpoch) {
        Start-Sleep -Seconds 2
        $script:DeviceEpoch = Read-DeviceClockEpoch
    }

    if ($null -ne $script:DeviceEpoch) {
        $script:CanSendCommands = $true
        $board = Get-UsableSerialResponse -Text (Invoke-MeshCoreSerialCommand -Command 'board') -Kind Board
        $ver = Get-UsableSerialResponse -Text (Invoke-MeshCoreSerialCommand -Command 'ver') -Kind Version
        if (-not $ver) {
            $ver = Get-UsableSerialResponse -Text (Invoke-MeshCoreSerialCommand -Command 'version') -Kind Version
        }
        Write-Host "$board - $ver"
        Load-RepeaterSettings
        Snapshot-RadioBaseline
    }
    else {
        Write-Host 'Changes here may not work'
        Initialize-EmptySettings
    }
}

Edit-RepeaterSettingsMenu

if (Confirm-RestartRadio) {
    Write-Host 'Restarting radio...'
    Send-OneWayOrEchoSerialCommand -Command 'reboot'
}
else {
    Write-Host 'Radio reboot skipped.'
}

Close-ActiveSerialSession
