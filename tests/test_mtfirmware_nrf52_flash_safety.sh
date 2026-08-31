#!/usr/bin/env bash
# Functions from the production script are evaluated dynamically below.
# shellcheck disable=SC2034,SC2218,SC2317
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script_path="${repo_root}/mtfirmware.sh"
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

for function_name in cleanup serial_port_from_detection detect_device \
	normalize_usb_serial_identity nrf52_usb_path_stem \
	nrf52_device_identity_rank nrf52_uf2_mount_source \
	record_nrf52_owned_mount release_nrf52_owned_mount find_mounted_uf2_dir \
	capture_nrf52_selected_identity find_nrf52_serial_port_by_identity \
	nrf52_endpoint_instance capture_nrf52_pre_flash_endpoint \
	nrf52_pre_flash_endpoint_changed nrf52_candidate_proves_transition \
	nrf52_runtime_version_from_port nrf52_versions_match \
	nrf52_firmware_version_from_artifact \
	resolve_nrf52_runtime_serial_port check_nrf52_after_flash \
	nrf52_validate_uf2_mount_identity ensure_nrf52_flash_lock_file \
	acquire_nrf52_flash_lock release_nrf52_flash_lock \
	release_all_nrf52_flash_locks prepare_meshtastic_cli_for_verification \
	begin_nrf52_flash_operation end_nrf52_flash_operation \
	copy_nrf52_uf2_to_storage \
	nrf52_dfu_output_confirms_success run_nrf52_dfu_attempt \
	run_nrf52_serial_dfu record_stopped_service stop_service_names \
	probe_meshtastic_metadata stop_nrf52_serial_probe_services \
	stop_services_for_selected_port \
	restart_locked_service_if_needed; do
	definition="$(extract_function "$function_name")"
	[[ "$definition" == "${function_name}() {"* ]] || {
		echo "failed to extract ${function_name}" >&2
		exit 1
	}
	# Deliberately evaluate the functions extracted from the production script.
	# shellcheck disable=SC2294
	eval "$definition"
done

mkdir -p "${tmp_dir}/bin"
cat >"${tmp_dir}/bin/pipx" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$@" >"$NRFUTIL_ARGUMENT_LOG"
if [[ "${1:-}" == run && "${2:-}" == meshtastic && "${3:-}" == --version ]]; then
	if [[ -n "${MESHTASTIC_PREWARM_LOG:-}" ]]; then
		if [[ -n "${PREWARM_LOCK_PATH:-}" ]] \
			&& flock -n "$PREWARM_LOCK_PATH" -c true; then
			printf '%s\n' unlocked >>"$MESHTASTIC_PREWARM_LOG"
		else
			printf '%s\n' locked >>"$MESHTASTIC_PREWARM_LOG"
		fi
	fi
	[[ "${MESHTASTIC_PREWARM_RESULT:-success}" == success ]]
	exit $?
fi
case "$NRFUTIL_RESULT" in
	success)
		printf '%s\n' 'Device programmed.'
		exit 0
		;;
	marker-not-terminal)
		printf '%s\n' 'Device programmed.' 'DFU transport closed.'
		exit 0
		;;
	observed-timeout)
		printf '%s\n' \
			'Traceback (most recent call last):' \
			'  File "dfu_transport_serial.py", line 1, in send_packet' \
			'nordicsemi.exceptions.NordicSemiException: Timed out waiting for acknowledgement' \
			'No data received on serial port. Not able to proceed.' \
			'Failed to upgrade target.'
		exit 0
		;;
	conflicting)
		printf '%s\n' \
			'Device programmed.' \
			'Traceback (most recent call last):' \
			'Failed to upgrade target.'
		exit 0
		;;
	no-marker)
		printf '%s\n' 'DFU transport closed.'
		exit 0
		;;
	nonzero)
		printf '%s\n' 'Device programmed.'
		exit 42
		;;
esac
EOF
chmod +x "${tmp_dir}/bin/pipx"
export PATH="${tmp_dir}/bin:${PATH}"
export NRFUTIL_ARGUMENT_LOG="${tmp_dir}/nrfutil.arguments"
PYTHON="$(command -v python3)"

"$PYTHON" - "$tmp_dir" <<'PY'
import json
import pathlib
import struct
import sys
import zipfile


root = pathlib.Path(sys.argv[1])
application = b"library 1.6.1\0runtime 2.6.5.fc3d9f2a\0library 9.3.1\0"


def uf2(path, payload):
    chunks = [payload[index : index + 48] for index in range(0, len(payload), 48)]
    blocks = []
    target = 0x26000
    for index, chunk in enumerate(chunks):
        block = bytearray(512)
        struct.pack_into(
            "<8I",
            block,
            0,
            0x0A324655,
            0x9E5D5157,
            0x00002000,
            target,
            len(chunk),
            index,
            len(chunks),
            0xADA52840,
        )
        block[32 : 32 + len(chunk)] = chunk
        struct.pack_into("<I", block, 508, 0x0AB16F30)
        blocks.append(block)
        target += len(chunk)
    path.write_bytes(b"".join(blocks))


def hex_record(address, record_type, payload):
    record = bytes([len(payload), address >> 8, address & 0xFF, record_type]) + payload
    checksum = (-sum(record)) & 0xFF
    return ":" + (record + bytes([checksum])).hex().upper()


uf2(root / "firmware-rak4631-2.6.6.renamed.uf2", application)
(root / "firmware-rak4631-2.6.5.fc3d9f2a.bin").write_bytes(application)
(root / "firmware-rak4631-2.6.5.fc3d9f2a.hex").write_text(
    "\n".join(
        [
            hex_record(0, 0x04, b"\x00\x02"),
            hex_record(0x6000, 0x00, application[:32]),
            hex_record(0x6020, 0x00, application[32:]),
            hex_record(0, 0x01, b""),
        ]
    )
    + "\n",
    encoding="ascii",
)
with zipfile.ZipFile(root / "firmware-rak4631-2.6.5.fc3d9f2a-ota.zip", "w") as archive:
    archive.writestr(
        "manifest.json",
        json.dumps({"manifest": {"application": {"bin_file": "firmware.bin"}}}),
    )
    archive.writestr("firmware.bin", application)

(root / "firmware-rak4631-2.6.5.local.bin").write_bytes(b"2.6.5.local\0")
(root / "firmware-rak4631-9.9.9.wrong.bin").write_bytes(
    b"2.6.5.fc3d9f2a\0" + b"2.6.5.70ced735\0"
)
(root / "firmware-rak4631-2.6.5.bad.uf2").write_bytes(b"not a UF2")
PY

embedded_version="$(nrf52_firmware_version_from_artifact \
	"${tmp_dir}/firmware-rak4631-2.6.6.renamed.uf2" \
	2>"${tmp_dir}/renamed-version.err")"
[[ "$embedded_version" == 2.6.5.fc3d9f2a ]]
grep -Fq 'artifact name says 2.6.6.renamed' "${tmp_dir}/renamed-version.err"
for extension in bin hex; do
	[[ "$(nrf52_firmware_version_from_artifact \
		"${tmp_dir}/firmware-rak4631-2.6.5.fc3d9f2a.${extension}")" \
		== 2.6.5.fc3d9f2a ]]
done
[[ "$(nrf52_firmware_version_from_artifact \
	"${tmp_dir}/firmware-rak4631-2.6.5.fc3d9f2a-ota.zip")" \
	== 2.6.5.fc3d9f2a ]]
[[ "$(nrf52_firmware_version_from_artifact \
	"${tmp_dir}/firmware-rak4631-2.6.5.local.bin")" == 2.6.5.local ]]
if nrf52_firmware_version_from_artifact \
	"${tmp_dir}/firmware-rak4631-9.9.9.wrong.bin" \
	>"${tmp_dir}/ambiguous-version.out" 2>"${tmp_dir}/ambiguous-version.err"; then
	echo "FAIL: an artifact with ambiguous embedded versions was accepted" >&2
	exit 1
fi
grep -Fq 'multiple possible APP_VERSION strings' "${tmp_dir}/ambiguous-version.err"
if nrf52_firmware_version_from_artifact \
	"${tmp_dir}/firmware-rak4631-2.6.5.bad.uf2" \
	>"${tmp_dir}/bad-uf2.out" 2>"${tmp_dir}/bad-uf2.err"; then
	echo "FAIL: malformed UF2 supplied a post-flash version" >&2
	exit 1
fi
grep -Fq 'UF2 length is not a whole number' "${tmp_dir}/bad-uf2.err"
if grep -Fq 'selected_firmware_version="$(cat "$CHOSEN_TAG_FILE"' "$script_path"; then
	echo "FAIL: nRF52 verification still trusts the selected release tag" >&2
	exit 1
fi
grep -Fq 'nrf52_firmware_version_from_artifact "$abs_selected"' "$script_path"
echo "PASS: post-flash expected version is proven by the selected artifact"

ensure_serial_port_rw() { return 0; }
NRF52_DFU_TIMEOUT_SECONDS=5
NRF52_MANUAL_DFU_PROMPT_SECONDS=60
NRF52_LAST_DFU_PORT=""
package="${tmp_dir}/firmware.zip"
port="${tmp_dir}/ttyACM0"
touch "$package" "$port"

export NRFUTIL_RESULT=success
run_nrf52_dfu_attempt "$package" "$port" >"${tmp_dir}/success.out"
grep -Fxq -- '--touch' "$NRFUTIL_ARGUMENT_LOG"
grep -Fxq -- '1200' "$NRFUTIL_ARGUMENT_LOG"
[[ "$NRF52_LAST_DFU_PORT" == "$port" ]]
echo "PASS: mtfirmware accepts only nrfutil's exact positive completion"

for result in marker-not-terminal observed-timeout conflicting no-marker nonzero; do
	export NRFUTIL_RESULT="$result"
	if run_nrf52_dfu_attempt "$package" "$port" \
		>"${tmp_dir}/${result}.out" 2>"${tmp_dir}/${result}.err"; then
		echo "FAIL: ${result} nrfutil result was accepted" >&2
		exit 1
	fi
done
grep -Fq 'Timed out waiting for acknowledgement' \
	"${tmp_dir}/observed-timeout.out"
grep -Fq 'did not confirm that the selected nRF52 was programmed' \
	"${tmp_dir}/observed-timeout.err"
grep -Fq 'did not confirm that the selected nRF52 was programmed' \
	"${tmp_dir}/conflicting.err"
grep -Fq 'failed with status 42' "${tmp_dir}/nonzero.err"
echo "PASS: rc=0 traceback/timeout output cannot masquerade as successful DFU"

NRF52_FLASH_LOCK_FILE="${tmp_dir}/nrf52-flash.lock"
NRF52_FLASH_LOCK_FD=""
NRF52_FLASH_LOCK_DEPTH=0
export MESHTASTIC_PREWARM_LOG="${tmp_dir}/meshtastic-prewarm.log"
export PREWARM_LOCK_PATH="$NRF52_FLASH_LOCK_FILE"
export MESHTASTIC_PREWARM_RESULT=success
: >"$MESHTASTIC_PREWARM_LOG"

# A fresh host must finish the potentially slow pipx setup before taking the
# destructive-operation lock. Once acquired, the same lock must remain held
# through serial DFU and the caller's post-flash verification window.
begin_nrf52_flash_operation 2.7.4 >"${tmp_dir}/begin-operation.out"
[[ "$NRF52_EXPECTED_VERSION" == 2.7.4 ]]
[[ "$NRF52_FLASH_LOCK_DEPTH" -eq 1 ]]
grep -Fxq unlocked "$MESHTASTIC_PREWARM_LOG"
if flock -n "$NRF52_FLASH_LOCK_FILE" -c true; then
	echo "FAIL: another process acquired the operation-wide nRF52 flash lock" >&2
	exit 1
fi

find_nrf52_serial_port_by_identity() {
	printf '%s\n' "$port"
}
run_nrf52_dfu_attempt() {
	printf '%s\n' "$NRF52_FLASH_LOCK_DEPTH" >"$SERIAL_DFU_LOCK_DEPTH_LOG"
	return 0
}
export SERIAL_DFU_LOCK_DEPTH_LOG="${tmp_dir}/serial-dfu-lock-depth.log"
NRF52_SELECTED_SERIAL=selected-serial
NRF52_SELECTED_PATH_STEM=selected-path
NRF52_SELECTED_VENDOR_ID=selected-vendor
run_nrf52_serial_dfu "$package" "$port"
grep -Fxq 2 "$SERIAL_DFU_LOCK_DEPTH_LOG"
[[ "$NRF52_FLASH_LOCK_DEPTH" -eq 1 ]]
if flock -n "$NRF52_FLASH_LOCK_FILE" -c true; then
	echo "FAIL: serial DFU released the caller's post-flash verification lock" >&2
	exit 1
fi
end_nrf52_flash_operation
[[ "$NRF52_FLASH_LOCK_DEPTH" -eq 0 ]]
flock -n "$NRF52_FLASH_LOCK_FILE" -c true

# The serial helper is also safe when called independently: it acquires one
# lock for the attempt and releases it on return.
run_nrf52_serial_dfu "$package" "$port"
grep -Fxq 1 "$SERIAL_DFU_LOCK_DEPTH_LOG"
[[ "$NRF52_FLASH_LOCK_DEPTH" -eq 0 ]]

: >"$MESHTASTIC_PREWARM_LOG"
export MESHTASTIC_PREWARM_RESULT=fail
if begin_nrf52_flash_operation 2.7.4 \
	>"${tmp_dir}/prewarm-fail.out" 2>"${tmp_dir}/prewarm-fail.err"; then
	echo "FAIL: destructive lock began after Meshtastic CLI prewarm failed" >&2
	exit 1
fi
[[ "$NRF52_FLASH_LOCK_DEPTH" -eq 0 ]]
grep -Fxq unlocked "$MESHTASTIC_PREWARM_LOG"
grep -Fq 'Could not prepare the Meshtastic CLI' "${tmp_dir}/prewarm-fail.err"

: >"$MESHTASTIC_PREWARM_LOG"
export MESHTASTIC_PREWARM_RESULT=success
if begin_nrf52_flash_operation "" \
	>"${tmp_dir}/empty-version.out" 2>"${tmp_dir}/empty-version.err"; then
	echo "FAIL: an empty expected application version began a flash operation" >&2
	exit 1
fi
[[ "$NRF52_FLASH_LOCK_DEPTH" -eq 0 ]]
[[ ! -s "$MESHTASTIC_PREWARM_LOG" ]]
grep -Fq 'selected firmware version is empty' "${tmp_dir}/empty-version.err"
if nrf52_versions_match 2.7.4 ""; then
	echo "FAIL: an empty expected version accepted an arbitrary running app" >&2
	exit 1
fi
echo "PASS: prewarm and operation-wide lock cover serial DFU through verification"

# Restore production helpers replaced by the serial-lock test.
for function_name in find_nrf52_serial_port_by_identity run_nrf52_dfu_attempt; do
	definition="$(extract_function "$function_name")"
	# shellcheck disable=SC2294
	eval "$definition"
done

uf2_file="${tmp_dir}/firmware.uf2"
uf2_mount="${tmp_dir}/uf2"
uf2_device="${tmp_dir}/uf2-device"
mkdir -p "$uf2_mount"
printf 'UF2 payload\n' >"$uf2_file"
touch "$uf2_device"

find_uf2_mount_dir() {
	printf '%s\n' "$uf2_mount"
}
nrf52_validate_uf2_mount_identity() {
	printf '%s\n' "$*" >"$UF2_REVALIDATE_LOG"
	[[ "${UF2_REVALIDATE_RESULT:-success}" == success ]] || return 1
	printf '%s\n' "$uf2_device"
}
cat >"${tmp_dir}/bin/sudo" <<'EOF'
#!/usr/bin/env bash
if [[ "$UF2_CP_RESULT" == "fail" && "$1" == "cp" ]]; then
	exit 44
fi
exec "$@"
EOF
cat >"${tmp_dir}/bin/sync" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$@" >"$UF2_SYNC_ARGUMENT_LOG"
[[ "$UF2_SYNC_RESULT" != "fail" ]]
EOF
chmod +x "${tmp_dir}/bin/sudo" "${tmp_dir}/bin/sync"
export UF2_SYNC_ARGUMENT_LOG="${tmp_dir}/sync.arguments"
export UF2_REVALIDATE_LOG="${tmp_dir}/revalidate.arguments"
NRF52_FLASH_LOCK_FILE="${tmp_dir}/nrf52-flash.lock"

export UF2_CP_RESULT=success UF2_SYNC_RESULT=success
export UF2_REVALIDATE_RESULT=success
copy_nrf52_uf2_to_storage "$uf2_file" firmware selected-serial selected-path selected-vendor \
	>"${tmp_dir}/copy-success.out"
cmp "$uf2_file" "${uf2_mount}/$(basename "$uf2_file")"
grep -Fxq -- '-f' "$UF2_SYNC_ARGUMENT_LOG"
grep -Fxq -- "$uf2_mount" "$UF2_SYNC_ARGUMENT_LOG"
grep -Fxq -- "$uf2_mount selected-serial selected-path selected-vendor" \
	"$UF2_REVALIDATE_LOG"
[[ "$NRF52_FLASH_PRE_KIND" == block && "$NRF52_FLASH_PRE_PATH" == "$uf2_device" ]]

rm -f "${uf2_mount}/$(basename "$uf2_file")" "$UF2_SYNC_ARGUMENT_LOG"
export UF2_REVALIDATE_RESULT=fail
if copy_nrf52_uf2_to_storage "$uf2_file" firmware \
	selected-serial selected-path selected-vendor \
	>"${tmp_dir}/revalidate-fail.out" 2>"${tmp_dir}/revalidate-fail.err"; then
	echo "FAIL: changed UF2 mount identity reached the copy" >&2
	exit 1
fi
[[ ! -e "${uf2_mount}/$(basename "$uf2_file")" ]]
[[ ! -e "$UF2_SYNC_ARGUMENT_LOG" ]]
grep -Fq 'changed identity before firmware' "${tmp_dir}/revalidate-fail.err"

export UF2_REVALIDATE_RESULT=success
export UF2_CP_RESULT=fail UF2_SYNC_RESULT=success
if copy_nrf52_uf2_to_storage "$uf2_file" firmware \
	selected-serial selected-path selected-vendor \
	>"${tmp_dir}/copy-fail.out" 2>"${tmp_dir}/copy-fail.err"; then
	echo "FAIL: failed UF2 cp was masked by a later successful sync" >&2
	exit 1
fi
[[ ! -e "$UF2_SYNC_ARGUMENT_LOG" ]]
grep -Fq 'Copying the firmware UF2' "${tmp_dir}/copy-fail.err"

export UF2_CP_RESULT=success UF2_SYNC_RESULT=fail
if copy_nrf52_uf2_to_storage "$uf2_file" firmware \
	selected-serial selected-path selected-vendor \
	>"${tmp_dir}/sync-fail.out" 2>"${tmp_dir}/sync-fail.err"; then
	echo "FAIL: UF2 sync failure was accepted" >&2
	exit 1
fi
grep -Fq 'reported an error while flushing firmware data' \
	"${tmp_dir}/sync-fail.err"
echo "PASS: UF2 cp and mount-scoped sync failures propagate explicitly"

# Restore the production mounted-volume selector after the copy mock.
definition="$(extract_function find_mounted_uf2_dir)"
# shellcheck disable=SC2294
eval "$definition"

tower_device="${tmp_dir}/sda"
clone_device="${tmp_dir}/sdb"
other_device="${tmp_dir}/sdc"
tower_mount="${tmp_dir}/tower"
clone_mount="${tmp_dir}/clone"
other_mount="${tmp_dir}/other"
touch "$tower_device" "$clone_device" "$other_device"
mkdir -p "$tower_mount" "$clone_mount" "$other_mount"
touch "${tower_mount}/INFO_UF2.TXT" \
	"${clone_mount}/INFO_UF2.TXT" "${other_mount}/INFO_UF2.TXT"

is_uf2_mount_dir() {
	[[ -f "$1/INFO_UF2.TXT" ]]
}
udev_device_property() {
	local device=$1 property=$2
	case "${device}|${property}" in
		"${tower_device}|ID_BUS"|"${clone_device}|ID_BUS"|"${other_device}|ID_BUS") printf '%s\n' usb ;;
		"${tower_device}|ID_VENDOR_ID"|"${clone_device}|ID_VENDOR_ID") printf '%s\n' 239a ;;
		"${other_device}|ID_VENDOR_ID") printf '%s\n' 2886 ;;
		"${tower_device}|ID_SERIAL_SHORT") printf '%s\n' TOWER123 ;;
		"${tower_device}|ID_PATH") printf '%s\n' 'pci-test-usb-0:1.4:1.0-scsi-0:0:0:0' ;;
		"${clone_device}|ID_SERIAL_SHORT") printf '%s\n' TOWER123 ;;
		"${clone_device}|ID_PATH") printf '%s\n' 'pci-test-usb-0:1.9:1.0-scsi-0:0:0:0' ;;
		"${other_device}|ID_SERIAL_SHORT") printf '%s\n' OTHER999 ;;
		"${other_device}|ID_PATH") printf '%s\n' 'pci-test-usb-0:1.8:1.0-scsi-0:0:0:0' ;;
	esac
}
findmnt() {
	printf '%s %s\n' \
		"$other_device" "$other_mount" \
		"$clone_device" "$clone_mount" \
		"$tower_device" "$tower_mount"
}

expected_path="$(nrf52_usb_path_stem 'pci-test-usb-0:1.4:1.0')"
NRF52_SELECTED_SERIAL=""
NRF52_SELECTED_PATH_STEM=""
NRF52_SELECTED_VENDOR_ID=""
capture_nrf52_selected_identity "$tower_device"
[[ "$NRF52_SELECTED_SERIAL" == "tower123" ]]
[[ "$NRF52_SELECTED_PATH_STEM" == "$expected_path" ]]
[[ "$NRF52_SELECTED_VENDOR_ID" == "239a" ]]
selected_mount="$(find_mounted_uf2_dir tower123 "$expected_path" 239a)"
[[ "$selected_mount" == "$tower_mount" ]]
if find_mounted_uf2_dir tower123 "" 239a \
	>"${tmp_dir}/ambiguous.out" 2>"${tmp_dir}/ambiguous.err"; then
	echo "FAIL: duplicate serial-only UF2 identities were accepted" >&2
	exit 1
fi
grep -Fq 'Refusing ambiguous UF2 mounts' "${tmp_dir}/ambiguous.err"
echo "PASS: UF2 mount selection is bound to the selected physical USB identity"

list_serial_devs() {
	printf '%s\n' "$other_device" "$tower_device"
}
matched_port="$(find_nrf52_serial_port_by_identity \
	tower123 "$expected_path" 239a "$other_device")"
[[ "$matched_port" == "$tower_device" ]]

if [[ "$(nrf52_device_identity_rank "$other_device" \
	"" "$(nrf52_usb_path_stem 'pci-test-usb-0:1.8:1.0')" 239a)" != 0 ]]; then
	echo "FAIL: exact physical path accepted a different USB vendor" >&2
	exit 1
fi
echo "PASS: nRF52 identity requires USB path metadata and the selected vendor"

find_uf2_mount_dir() { return 1; }
NRF52_POST_FLASH_CHECK_TIMEOUT_SECONDS=1
NRF52_EXPECTED_VERSION=2.7.4
nrf52_runtime_version_from_port() { printf '%s\n' 2.7.4; }

# A matching endpoint that never disappeared or changed instance is not proof
# that either a UF2 copy or serial DFU actually ran.
capture_nrf52_pre_flash_endpoint serial "$tower_device"
list_serial_devs() {
	printf '%s\n' "$tower_device"
}
if check_nrf52_after_flash firmware "$tower_device" \
	tower123 "$expected_path" 239a 1 \
	>"${tmp_dir}/post-no-transition.out" 2>"${tmp_dir}/post-no-transition.err"; then
	echo "FAIL: unchanged pre-flash endpoint was accepted as a successful flash" >&2
	exit 1
fi
grep -Fq 'never re-enumerated' "${tmp_dir}/post-no-transition.err"

list_serial_devs() {
	printf '%s\n' "$other_device"
}
if check_nrf52_after_flash firmware "$other_device" \
	tower123 "$expected_path" 239a 1 \
	>"${tmp_dir}/post-unrelated.out" 2>"${tmp_dir}/post-unrelated.err"; then
	echo "FAIL: unrelated serial device satisfied the post-flash check" >&2
	exit 1
fi
grep -Fq 'never re-enumerated' "${tmp_dir}/post-unrelated.err"

# Simulate a real re-enumeration by retaining a snapshot of a different, now
# absent device-node instance before the selected identity returns.
pre_transition_device="${tmp_dir}/pre-transition-device"
touch "$pre_transition_device"
capture_nrf52_pre_flash_endpoint serial "$pre_transition_device"
rm -f "$pre_transition_device"
list_serial_devs() {
	printf '%s\n' "$other_device" "$tower_device"
}
check_nrf52_after_flash firmware "$tower_device" \
	tower123 "$expected_path" 239a 1 \
	>"${tmp_dir}/post-matching.out"
grep -Fq "application 2.7.4 is running at $tower_device" \
	"${tmp_dir}/post-matching.out"
echo "PASS: post-flash success requires re-enumeration and the expected app version"

NRF52_EXPECTED_VERSION=9.9.9
touch "$pre_transition_device"
capture_nrf52_pre_flash_endpoint serial "$pre_transition_device"
rm -f "$pre_transition_device"
if check_nrf52_after_flash firmware "$tower_device" \
	tower123 "$expected_path" 239a 1 \
	>"${tmp_dir}/post-version-mismatch.out" \
	2>"${tmp_dir}/post-version-mismatch.err"; then
	echo "FAIL: unexpected application version was accepted" >&2
	exit 1
fi
grep -Fq "did not match expected '9.9.9'" \
	"${tmp_dir}/post-version-mismatch.err"
echo "PASS: post-flash application version mismatch fails closed"

# Device identity must be captured when the chooser runs, not after downloads.
# Simulate the chosen board moving to ttyACM1 while another board reuses ttyACM0.
chosen_tty0="${tmp_dir}/chosen-ttyACM0"
chosen_tty1="${tmp_dir}/chosen-ttyACM1"
replacement_tty0="$chosen_tty0"
touch "$chosen_tty0" "$chosen_tty1"
[[ "$(serial_port_from_detection "$chosen_tty0")" == "$chosen_tty0" ]]
[[ "$(serial_port_from_detection "Chosen nRF52 -> $chosen_tty0")" == "$chosen_tty0" ]]
DEVICE_INFO_FILE="${tmp_dir}/selected-device.txt"
DETECTED_PRODUCT_FILE="${tmp_dir}/selected-product.txt"
identity_phase=selection

pick_serial_port() {
	printf 'Chosen nRF52 -> %s\n' "$chosen_tty0"
}
normalize() {
	printf '%s\n' "$1"
}
udev_device_property() {
	local device=$1 property=$2
	case "${identity_phase}|${device}|${property}" in
		"selection|${chosen_tty0}|ID_BUS") printf '%s\n' usb ;;
		"selection|${chosen_tty0}|ID_VENDOR_ID") printf '%s\n' 239a ;;
		"selection|${chosen_tty0}|ID_SERIAL_SHORT") printf '%s\n' SELECTED123 ;;
		"selection|${chosen_tty0}|ID_PATH") printf '%s\n' 'pci-test-usb-0:1.4:1.0' ;;
		"after-download|${replacement_tty0}|ID_BUS"|"after-download|${chosen_tty1}|ID_BUS") printf '%s\n' usb ;;
		"after-download|${replacement_tty0}|ID_VENDOR_ID") printf '%s\n' 2886 ;;
		"after-download|${chosen_tty1}|ID_VENDOR_ID") printf '%s\n' 239a ;;
		"after-download|${replacement_tty0}|ID_SERIAL_SHORT") printf '%s\n' REPLACEMENT999 ;;
		"after-download|${replacement_tty0}|ID_PATH") printf '%s\n' 'pci-test-usb-0:1.8:1.0' ;;
		"after-download|${chosen_tty1}|ID_SERIAL_SHORT") printf '%s\n' SELECTED123 ;;
		"after-download|${chosen_tty1}|ID_PATH") printf '%s\n' 'pci-test-usb-0:1.4:1.0' ;;
	esac
}

detect_device
[[ "$NRF52_SELECTED_SERIAL" == "selected123" ]]
[[ "$NRF52_SELECTED_PATH_STEM" == "$(nrf52_usb_path_stem 'pci-test-usb-0:1.4:1.0')" ]]
[[ "$NRF52_SELECTED_VENDOR_ID" == "239a" ]]
[[ "$(serial_port_from_detection "$(<"$DEVICE_INFO_FILE")")" == "$chosen_tty0" ]]

identity_phase=after-download
list_serial_devs() {
	printf '%s\n' "$replacement_tty0" "$chosen_tty1"
}
matched_port="$(find_nrf52_serial_port_by_identity \
	"$NRF52_SELECTED_SERIAL" "$NRF52_SELECTED_PATH_STEM" \
	"$NRF52_SELECTED_VENDOR_ID" "$replacement_tty0")"
[[ "$matched_port" == "$chosen_tty1" ]]

list_serial_devs() {
	printf '%s\n' "$replacement_tty0"
}
if find_nrf52_serial_port_by_identity \
	"$NRF52_SELECTED_SERIAL" "$NRF52_SELECTED_PATH_STEM" \
	"$NRF52_SELECTED_VENDOR_ID" "$replacement_tty0" \
	>"${tmp_dir}/tty-reuse.out" 2>"${tmp_dir}/tty-reuse.err"; then
	echo "FAIL: reused tty was allowed to replace the originally selected nRF52" >&2
	exit 1
fi
echo "PASS: nRF52 identity survives download delay and rejects tty reuse"

# A mount created by the script is recorded outside command-substitution
# subshells and removed only while the exact recorded source still owns it.
owned_source="${tmp_dir}/owned-sda"
replacement_source="${tmp_dir}/replacement-sdb"
owned_mount="${tmp_dir}/owned-mount"
touch "$owned_source" "$replacement_source"
mkdir -p "$owned_mount"
NRF52_MOUNT_STATE_FILE="${tmp_dir}/owned-mount.state"
mount_source_now="$owned_source"
sudo_log="${tmp_dir}/sudo-cleanup.log"
: >"$sudo_log"

mountpoint() {
	[[ "$1" == -q && "$2" == "$owned_mount" ]]
}
findmnt() {
	printf '%s\n' "$mount_source_now"
}
sudo() {
	printf '%s\n' "$*" >>"$sudo_log"
	return 0
}

record_nrf52_owned_mount "$owned_source" "$owned_mount"
release_nrf52_owned_mount
grep -Fxq "umount -- $owned_mount" "$sudo_log"
[[ ! -e "$NRF52_MOUNT_STATE_FILE" ]]

: >"$sudo_log"
record_nrf52_owned_mount "$owned_source" "$owned_mount"
mount_source_now="$replacement_source"
if release_nrf52_owned_mount \
	>"${tmp_dir}/changed-mount.out" 2>"${tmp_dir}/changed-mount.err"; then
	echo "FAIL: cleanup unmounted a replacement source it did not own" >&2
	exit 1
fi
[[ ! -s "$sudo_log" ]]
grep -Fq 'because its source changed' "${tmp_dir}/changed-mount.err"
echo "PASS: script-owned UF2 mounts clean up without unmounting replacements"

# systemctl may partially stop a list and still return failure. Every requested
# service must already be recorded so EXIT cleanup can restore the stopped one.
lockedService=""
sudo() {
	[[ "$1" == systemctl && "$2" == stop ]]
	return 47
}
if stop_service_names "serial-getty@ttyACM0.service gpsd.service" \
	>"${tmp_dir}/service-stop.out" 2>"${tmp_dir}/service-stop.err"; then
	echo "FAIL: mocked partial systemd stop failure was accepted" >&2
	exit 1
fi
[[ " $lockedService " == *" serial-getty@ttyACM0.service "* ]]
[[ " $lockedService " == *" gpsd.service "* ]]
echo "PASS: partial service-stop failures remain recoverable by EXIT cleanup"

# Chooser probes run inside command substitution, so they need their own EXIT
# restoration instead of relying on the parent shell's trap. Simulate a stop
# that partially succeeds but returns failure and verify the local trap starts
# every recorded service before the probe subshell exits.
probe_service_log="${tmp_dir}/probe-services.log"
: >"$probe_service_log"
get_locked_service() {
	printf '%s\n' 'serial-getty@ttyACM0.service gpsd.service'
}
sudo() {
	printf '%s\n' "$*" >>"$probe_service_log"
	if [[ "$1" == systemctl && "$2" == stop ]]; then
		return 47
	fi
	return 0
}
probe_output="$(probe_meshtastic_metadata "$port" || true)"
[[ -z "$probe_output" ]]
grep -Fxq 'systemctl stop serial-getty@ttyACM0.service gpsd.service' \
	"$probe_service_log"
grep -Fxq 'systemctl start serial-getty@ttyACM0.service gpsd.service' \
	"$probe_service_log"
echo "PASS: chooser-probe subshell restores services after a stop failure"

# Service lookup must use the identity-resolved tty, not the stale tty saved
# before release downloads. Otherwise tty reuse can stop the wrong service and
# leave the selected board locked.
resolved_service_log="${tmp_dir}/resolved-service.log"
: >"$resolved_service_log"
get_locked_service() {
	printf 'lookup %s\n' "$1" >>"$resolved_service_log"
	printf '%s\n' selected-device.service
}
stop_service_names() {
	printf 'stop %s\n' "$1" >>"$resolved_service_log"
}
stop_nrf52_serial_probe_services() {
	printf '%s\n' probers >>"$resolved_service_log"
}
lockedService=""
stop_services_for_selected_port /dev/ttyACM1 true
grep -Fxq 'lookup /dev/ttyACM1' "$resolved_service_log"
grep -Fxq 'stop selected-device.service' "$resolved_service_log"
grep -Fxq probers "$resolved_service_log"
if grep -Fq /dev/ttyACM0 "$resolved_service_log"; then
	echo "FAIL: service handling used the stale pre-download tty" >&2
	exit 1
fi
echo "PASS: service handling follows the identity-resolved tty"

# The generic UF2 path previously selected whichever block node happened to
# appear first and copied through a fixed mount directory. Keep that unsafe
# arrival-order fallback out; it must use the same identity-checked copy helper.
if grep -Fq 'comm -13' "$script_path" \
	|| grep -Fq 'sudo cp -v "$abs_selected" "$MOUNT_FOLDER/"' "$script_path"; then
	echo "FAIL: generic UF2 flashing still trusts block arrival order or a fixed mount" >&2
	exit 1
fi
grep -Fq 'copy_nrf52_uf2_to_storage "$abs_selected" "firmware"' "$script_path"
echo "PASS: generic UF2 flashing shares the identity-safe copy path"

# EXIT cleanup must invoke both resource restorers. Mock them here so the test
# cannot touch systemd, real mounts, sudo, or USB autosuspend.
cleanup_log="${tmp_dir}/cleanup.log"
: >"$cleanup_log"
release_nrf52_owned_mount() {
	printf '%s\n' mount-release >>"$cleanup_log"
	return 0
}
release_all_nrf52_flash_locks() {
	printf '%s\n' lock-release >>"$cleanup_log"
	return 0
}
restart_locked_service_if_needed() {
	printf '%s\n' service-restart >>"$cleanup_log"
	lockedService=""
}
cat() {
	printf '%s\n' -1
}
USB_AUTOSUSPEND=-1
NRF52_MOUNT_STATE_FILE="${tmp_dir}/empty-cleanup.state"
: >"$NRF52_MOUNT_STATE_FILE"
cleanup
grep -Fxq mount-release "$cleanup_log"
grep -Fxq lock-release "$cleanup_log"
grep -Fxq service-restart "$cleanup_log"
[[ ! -e "$NRF52_MOUNT_STATE_FILE" ]]
echo "PASS: EXIT cleanup restores stopped services and owned mount state"
