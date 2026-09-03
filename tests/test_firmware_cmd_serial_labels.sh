#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script_path="${repo_root}/firmware.cmd"

python3 - "$script_path" <<'PY'
import sys

script = open(sys.argv[1], encoding="utf-8").read()

required = {
    "combined detected label": 'return "Detected: $Board. $Version"',
    "framed device query": '[byte[]]$deviceQuery = @(0x16, 0x0e)',
    "device-info response": '-ExpectedResponseCode 0x0d',
    "board field": '$ascii.GetString($deviceInfo, 20, 40)',
    "legacy version field": '$ascii.GetString($deviceInfo, 60, 20)',
    "full-version command": '$ascii.GetBytes("version")',
    "framed CLI response": '-ExpectedResponseCode 0x1d',
    "complete version allowance": '-Kind Version -MaxLength 120',
    "detected board propagation": 'DetectedBoard   = $script:DetectedMeshCoreBoard',
    "detected version propagation": 'DetectedVersion = $script:DetectedMeshCoreVersion',
}
for description, needle in required.items():
    if needle not in script:
        raise SystemExit(f"missing {description}: {needle}")

binary_probe = script.index(
    "$companionInfo = Get-MeshCoreCompanionInfo -SerialPort $sp"
)
ascii_probe = script.index(
    '$null = Invoke-SerialCommandWithRetry -MaxAttempts 1 -SerialPort $sp -Command "board"'
)
if binary_probe >= ascii_probe:
    raise SystemExit("Companion framed API must be tried before text CLI")

target_prompt = script.index(
    '$response = Read-HostWithConnectionMonitor -Prompt "Enter choice (1-2)"'
)
target_label = script.rfind("Write-DetectedMeshCoreIdentity", 0, target_prompt)
if target_label < 0 or target_prompt - target_label > 200:
    raise SystemExit("detected identity is not immediately above the flash-target choice")

device_prompt = script.index(
    '$choice = Read-Host ("Choice (Detected {0} on {1}, Enter will pick {2})"'
)
device_label = script.rfind("Write-DetectedMeshCoreIdentity", 0, device_prompt)
if device_label < 0 or device_prompt - device_label > 300:
    raise SystemExit("detected identity is not above the MeshCore device choice")

print("PASS: firmware.cmd reads and displays complete MeshCore board/version identity")
print("PASS: framed API precedes text CLI and both choices show the detected identity")
PY
