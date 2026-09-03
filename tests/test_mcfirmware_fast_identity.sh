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
	parse_esp32_meshcore_identity fast_detect_esp32_meshcore_identity; do
	definition="$(extract_function "$function_name")"
	[[ "$definition" == "${function_name}() {"* ]] || {
		echo "failed to extract ${function_name}" >&2
		exit 1
	}
	# Deliberately evaluate functions extracted from the production script.
	# shellcheck disable=SC2294
	eval "$definition"
done

valid_probe="${tmp_dir}/valid.bin"
invalid_probe="${tmp_dir}/invalid.bin"
python3 - "$valid_probe" <<'PY'
import struct
import sys

environment = b"heltec_v4_2_v4_3_companion_radio_full_femon"
version = b"v1.17.1.5-halo-keymind-cascade-dev-1f1ce55f"
record = struct.pack(
    "<8sHH96s96sI",
    b"MCFWID01",
    1,
    208,
    environment,
    version,
    0x3144494D,
)
image = bytearray(b"\xff" * 512)
image[0x120:0x120 + len(record)] = record
open(sys.argv[1], "wb").write(image)
PY

expected=$'heltec_v4_2_v4_3_companion_radio_full_femon\tv1.17.1.5-halo-keymind-cascade-dev-1f1ce55f'
[[ "$(parse_esp32_meshcore_identity "$valid_probe")" == "$expected" ]]
echo "PASS: fixed ESP32 identity record parses at app offset 0x120"

cp "$valid_probe" "$invalid_probe"
printf X | dd of="$invalid_probe" bs=1 seek=$((0x120)) conv=notrunc status=none
if parse_esp32_meshcore_identity "$invalid_probe" >/dev/null 2>&1; then
	echo "FAIL: parser accepted a bad identity magic" >&2
	exit 1
fi
echo "PASS: malformed fixed identity records are rejected"

read_log="${tmp_dir}/reads.log"
finish_calls=0
prepare_calls=0
AUTODETECT_DEVICE_FILE="${tmp_dir}/detected"
export NORESET=no-reset
export READFLASH=read-flash
export ESP32_SAFE_BAUD=115200
export BOOTLOADER_PROBE_ACTIVE=0
export BOOTLOADER_PROBE_PORT=''

udev_device_property() {
	[[ "$2" == ID_VENDOR_ID ]] && printf '%s\n' 303a
}
ensure_command() { return 0; }
selected_flash_serial_port() { printf '%s\n' "$1"; }
save_selected_serial_port() { return 0; }
get_espcmd() { return 0; }
prepare_esp32_flash_session() {
	prepare_calls=$((prepare_calls + 1))
	return 0
}
read_esp32_app_partitions() { printf '%s\n' '0x10000 0x200000 0x00'; }
run_esp32_session_esptool() {
	printf '%s\n' "$*" >> "$read_log"
	cp "$valid_probe" "${@: -1}"
}
finish_esp32_flash_session() {
	finish_calls=$((finish_calls + 1))
	return 0
}

fast_detect_esp32_meshcore_identity /dev/ttyACM0 >"${tmp_dir}/fast.out"
[[ "$FAST_DETECTED_ENVIRONMENT" == heltec_v4_2_v4_3_companion_radio_full_femon ]]
[[ "$FAST_DETECTED_VERSION" == v1.17.1.5-halo-keymind-cascade-dev-1f1ce55f ]]
[[ "$(<"$AUTODETECT_DEVICE_FILE")" == "$FAST_DETECTED_ENVIRONMENT" ]]
[[ "$prepare_calls" -eq 1 && "$finish_calls" -eq 1 ]]
grep -Fq '0x10000 0x200' "$read_log"
grep -Fq "Fast firmware identity: $FAST_DETECTED_ENVIRONMENT ($FAST_DETECTED_VERSION)" \
	"${tmp_dir}/fast.out"
echo "PASS: fast detection reads 512 bytes and returns the validated identity"

: > "$read_log"
cp "$invalid_probe" "$valid_probe"
if fast_detect_esp32_meshcore_identity /dev/ttyACM0 >"${tmp_dir}/legacy.out"; then
	echo "FAIL: fast detection accepted legacy firmware without the descriptor" >&2
	exit 1
fi
[[ "$finish_calls" -eq 2 ]]
grep -Fq 'use 0 for full firmware detection' "${tmp_dir}/legacy.out"
echo "PASS: legacy firmware returns to runtime and leaves full detection on option 0"

python3 - "$script_path" <<'PY'
import re
import sys

script = open(sys.argv[1], encoding="utf-8").read()
success_returns = re.findall(
    r'\[\[ -n "\$board" \]\] && printf .*?"\$AUTODETECT_DEVICE_FILE"\n\s*return 0',
    script,
)
if len(success_returns) != 2:
    raise SystemExit("choose_serial must succeed when the MeshCore board API is empty")
PY
echo "PASS: an empty MeshCore API reply does not invalidate serial selection"

grep -Fq "0x10000 0x70000 \"\$DOWNLOAD_DIR/CURRENT.BAK\"" "$script_path"
echo "PASS: option 0 retains the full legacy firmware scan"
