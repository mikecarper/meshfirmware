#!/usr/bin/env bash
# Static regression checks for the confirmed ESP32 flash path.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script_path="${repo_root}/mtfirmware.sh"

python3 - "$script_path" <<'PY'
import re
import sys
from pathlib import Path

source = Path(sys.argv[1]).read_text(encoding="utf-8")
start = source.index("run_update_script() {")
end = source.index("##################\n# Main Execution #", start)
flash_path = source[start:end]

assert not re.search(r"ESPTOOL_CMD.*--baud[ =]1200", flash_path)
assert 'export ESPTOOL_PORT=$device_port_name' in flash_path
assert '$ESPTOOL_CMD --baud 115200 write-flash 0x10000 "$basename_selected"' in flash_path
assert 'pipx run --spec esptool esptool version' in flash_path
assert 'pipx run --spec esptool esptool.py version' in flash_path
assert 'ESPTOOL_CMD="pipx run --spec esptool esptool.py"' in flash_path
assert '"$abs_script" -p "${device_port_name}" -f "$basename_selected"' in flash_path
assert flash_path.index('Would you like to $operation the firmware?') < flash_path.index(
    'export ESPTOOL_PORT=$device_port_name'
)
PY

echo 'PASS: mtfirmware selects a compatible esptool entry point without a redundant ESP32 reset'
