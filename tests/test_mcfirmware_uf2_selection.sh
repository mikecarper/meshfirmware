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

for function_name in normalize_usb_serial_identity nrf52_usb_path_stem \
	usb_block_device_identity_rank usb_block_device_matches_identity \
	scan_and_maybe_mount; do
	definition="$(extract_function "$function_name")"
	[[ "$definition" == "${function_name}() {"* ]] || {
		echo "failed to extract ${function_name}" >&2
		exit 1
	}
	# Deliberately evaluate functions extracted from the production script.
	# shellcheck disable=SC2294
	eval "$definition"
done

tower_device="${tmp_dir}/sda"
clone_device="${tmp_dir}/sdaa"
xiao_device="${tmp_dir}/sdb"
tower_mount="${tmp_dir}/tower"
clone_mount="${tmp_dir}/clone"
xiao_mount="${tmp_dir}/xiao"
touch "$tower_device" "$clone_device" "$xiao_device"
mkdir -p "$tower_mount" "$clone_mount" "$xiao_mount"
touch "${tower_mount}/CURRENT.UF2" "${tower_mount}/INFO_UF2.TXT"
touch "${clone_mount}/CURRENT.UF2" "${clone_mount}/INFO_UF2.TXT"
touch "${xiao_mount}/CURRENT.UF2" "${xiao_mount}/INFO_UF2.TXT"

list_usb_block_devs() {
	printf '%s\n' "$tower_device" "$clone_device" "$xiao_device"
}

lsblk() {
	local device="${*: -1}"
	case "$device" in
		"$tower_device") printf '%s\n' "$tower_mount" ;;
		"$clone_device") printf '%s\n' "$clone_mount" ;;
		"$xiao_device") printf '%s\n' "$xiao_mount" ;;
	esac
}

udev_device_property() {
	local device=$1 property=$2
	case "${device}|${property}" in
		"${tower_device}|ID_SERIAL_SHORT") printf '%s\n' 9352162A72082314 ;;
		"${tower_device}|ID_PATH") printf '%s\n' 'pci-test-usb-0:1.4:1.0-scsi-0:0:0:0' ;;
		"${clone_device}|ID_SERIAL_SHORT") printf '%s\n' B35E71C1C3726CE7 ;;
		"${clone_device}|ID_PATH") printf '%s\n' 'pci-test-usb-0:1.9:1.0-scsi-0:0:0:0' ;;
		"${xiao_device}|ID_SERIAL_SHORT") printf '%s\n' B35E71C1C3726CE7 ;;
		"${xiao_device}|ID_PATH") printf '%s\n' 'pci-test-usb-0:1.3:1.0-scsi-0:0:0:0' ;;
	esac
}

no_sudo_mode() { return 0; }
MOUNT_FOLDER="${tmp_dir}/fallback-mount"

scan_and_maybe_mount B35E71C1C3726CE7 pci-test-usb-0:1.3
[[ "$MOUNT_FOLDER" == "$xiao_mount" ]] || {
	echo "FAIL: selected XIAO identity resolved to '$MOUNT_FOLDER'" >&2
	exit 1
}
echo "PASS: exact UF2 USB path outranks another board and a cloned serial"

MOUNT_FOLDER="${tmp_dir}/fallback-mount"
if scan_and_maybe_mount B35E71C1C3726CE7 "" \
	>"${tmp_dir}/ambiguous.out" 2>"${tmp_dir}/ambiguous.err"; then
	echo "FAIL: duplicate serial-only UF2 identities were accepted" >&2
	exit 1
fi
grep -Fq 'Refusing ambiguous UF2 block-device identity' "${tmp_dir}/ambiguous.err"
[[ "$MOUNT_FOLDER" == "${tmp_dir}/fallback-mount" ]]
echo "PASS: duplicate best-rank UF2 identities fail closed"

MOUNT_FOLDER="${tmp_dir}/fallback-mount"
if scan_and_maybe_mount NOT-CONNECTED pci-test-usb-0:9.9 \
	>"${tmp_dir}/missing.out" 2>"${tmp_dir}/missing.err"; then
	echo "FAIL: missing selected USB identity fell back to another UF2 volume" >&2
	exit 1
fi
[[ "$MOUNT_FOLDER" == "${tmp_dir}/fallback-mount" ]]
echo "PASS: missing UF2 identity fails closed"
