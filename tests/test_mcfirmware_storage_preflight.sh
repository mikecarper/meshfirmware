#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script_path="${repo_root}/mcfirmware.sh"
tmp_dir="$(mktemp -d)"
trap 'rm -rf -- "$tmp_dir"' EXIT

extract_function() {
	local function_name=$1
	awk -v signature="${function_name}() {" '
		$0 == signature { capture = 1 }
		capture { print }
		capture && $0 == "}" { exit }
	' "$script_path"
}

for function_name in \
	expand_home_path esp_merged_sibling_selection esp_app_sibling_selection \
	firmware_selection_url \
	query_companion_cli_command clean_storage_layout_reply read_esp32_storage_layout \
	parse_esp32_storage_layout_min_app_size esp32_selected_app_payload_size \
	esp32_runtime_storage_preflight; do
	definition="$(extract_function "$function_name")"
	[[ "$definition" == "${function_name}() {"* ]]
	# Deliberately evaluate functions extracted from the production script.
	# shellcheck disable=SC2294
	eval "$definition"
done

storage_layout_fixture='int:esp32=8192K ext:none; nvs@0x9000+20K,otadata@0xE000+8K,app0*@0x10000+2048K,app1@0x210000+2048K,spiffs@0x410000+512K'
[[ "$(parse_esp32_storage_layout_min_app_size "$storage_layout_fixture")" == 2097152 ]]
echo 'PASS: storage.layout parsing selects the smallest reported app slot'

fake_bin="${tmp_dir}/bin"
mkdir -p "$fake_bin"
fake_device="${tmp_dir}/ttyACM0"
touch "$fake_device"
cat > "${fake_bin}/socat" <<'PY'
#!/usr/bin/env python3
import struct
import sys

request = sys.stdin.buffer.read()
expected = b"<" + struct.pack("<H", 19) + b"\x42get storage.layout"
if request != expected:
    raise SystemExit(2)
reply = b"> int:esp32=8192K ext:none; app0*@0x10000+2048K,app1@0x210000+2048K"
payload = b"\x1d" + reply
sys.stdout.buffer.write(b">" + struct.pack("<H", len(payload)) + payload)
PY
chmod +x "${fake_bin}/socat"
ensure_command() { command -v "$1" >/dev/null; }
PATH="${fake_bin}:${PATH}"
[[ "$(read_esp32_storage_layout "$fake_device")" == \
	'int:esp32=8192K ext:none; app0*@0x10000+2048K,app1@0x210000+2048K' ]]
echo 'PASS: Companion command 0x42 returns a validated storage.layout reply'

query_companion_cli_command() { return 1; }
quick_node_info_cmd() {
	printf '%s\n' '> int:esp32=8192K ext:none; app0*@0x10000+2048K,app1@0x210000+2048K'
}
[[ "$(read_esp32_storage_layout "$fake_device")" == \
	'int:esp32=8192K ext:none; app0*@0x10000+2048K,app1@0x210000+2048K' ]]
echo 'PASS: text CLI remains the storage.layout fallback'

[[ "$(esp_merged_sibling_selection 'https://example.test/build/node.bin?key=1')" \
	== 'https://example.test/build/node-merged.bin?key=1' ]]
[[ "$(esp_app_sibling_selection 'https://example.test/build/node-merged.bin?key=1')" \
	== 'https://example.test/build/node.bin?key=1' ]]
[[ "$(firmware_selection_url '/home/test/node-merged.bin')" == \
	'/home/test/node-merged.bin' ]]
echo 'PASS: standard custom URL names map in both directions'

small_app="${tmp_dir}/node.bin"
large_app="${tmp_dir}/large.bin"
truncate -s 1048576 "$small_app"
truncate -s 3145728 "$large_app"

merged="${tmp_dir}/node-merged.bin"
python3 - "$merged" <<'PY'
import struct
import sys

path = sys.argv[1]
app_offset = 0x10000
app_size = 0x400000
payload_size = 0x100000
data = bytearray(app_offset + payload_size)
entry = bytearray(32)
entry[0:2] = b"\xaa\x50"
entry[2] = 0
entry[3] = 0x10
struct.pack_into("<II", entry, 4, app_offset, app_size)
data[0x8000:0x8020] = entry
data[0x8020:0x8022] = b"\xff\xff"
data[app_offset] = 0xE9
with open(path, "wb") as output:
    output.write(data)
PY
[[ "$(esp32_selected_app_payload_size "$merged" merged)" == 1048576 ]]
echo 'PASS: merged preflight compares its embedded app rather than the whole image'

selected_flash_serial_port() { printf '%s\n' /dev/mock; }
read_esp32_storage_layout() { printf '%s\n' "$storage_layout_fixture"; }
firmware_selection_exists() { return 0; }

small_output="${tmp_dir}/small.out"
esp32_runtime_storage_preflight /dev/mock "$small_app" app-only \
	'https://example.test/build/node.bin' > "$small_output" 2>&1
grep -Fq 'app-only image fits' "$small_output"
[[ -z "$ESP32_PREFLIGHT_ALTERNATE" ]]
echo 'PASS: a fitting app-only image needs no merged suggestion'

large_output="${tmp_dir}/large.out"
esp32_runtime_storage_preflight /dev/mock "$large_app" app-only \
	'https://example.test/build/node.bin' > "$large_output" 2>&1
grep -Fq 'app-only image is too large' "$large_output"
grep -Fq 'node-merged.bin' "$large_output"
[[ "$ESP32_PREFLIGHT_ALTERNATE" == 'https://example.test/build/node-merged.bin' ]]
[[ "$ESP32_PREFLIGHT_ALTERNATE_TYPE" == flash-wipe ]]
[[ "$ESP32_PREFLIGHT_ALTERNATE_AVAILABLE" -eq 1 ]]
echo 'PASS: an oversized app-only image offers the verified merged sibling'

merged_output="${tmp_dir}/merged.out"
esp32_runtime_storage_preflight /dev/mock "$merged" merged \
	'https://example.test/build/node-merged.bin' > "$merged_output" 2>&1
grep -Fq 'Merged firmware is not required for capacity' "$merged_output"
grep -Fq 'node.bin' "$merged_output"
[[ "$ESP32_PREFLIGHT_ALTERNATE" == 'https://example.test/build/node.bin' ]]
[[ "$ESP32_PREFLIGHT_ALTERNATE_TYPE" == flash-update ]]
[[ "$ESP32_PREFLIGHT_ALTERNATE_AVAILABLE" -eq 1 ]]
echo 'PASS: a merged image that fits offers the verified app-only sibling'

python3 - "$script_path" <<'PY'
import sys
from pathlib import Path

source = Path(sys.argv[1]).read_text(encoding="utf-8")
main = source[source.index("# MAIN\n"):]
preflight = main.index("esp32_runtime_storage_preflight")
choice = main.index("choose_flash_execution_mode")
raw_check = main.index("esp32_update_flash_offsets")
assert preflight < choice < raw_check
PY
echo 'PASS: runtime advice precedes confirmation and the raw partition check remains final'
