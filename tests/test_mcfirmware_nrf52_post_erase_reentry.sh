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

for function_name in wait_for_nrf52_bootloader_port nrf52_port_is_dfu_bootloader \
	nrf52_confirm_unmatched_dfu_override run_nrf52_dfu_package_buttonless; do
	definition="$(extract_function "$function_name")"
	[[ "$definition" == "${function_name}() {"* ]] || {
		echo "failed to extract ${function_name}" >&2
		exit 1
	}
	# Deliberately test the production functions, with only their hardware
	# dependencies replaced below.
	# shellcheck disable=SC2294
	eval "$definition"
done

selected_port="${tmp_dir}/ttyACM0"
selected_link="${tmp_dir}/selected-by-id"
package="${tmp_dir}/application.zip"
resolver_log="${tmp_dir}/resolver.log"
touch "$selected_port" "$package"
ln -s "$selected_port" "$selected_link"

mock_instance="before"
mock_resolved_port=""
mock_resolver_status=0
mock_identity_match=1
mock_vendor_id=2886
mock_product_id=0057
mock_model="T1000-E"
dfu_calls=0
touch_calls=0

nrf52_port_instance() {
	printf '%s\n' "$mock_instance"
}

find_reenumerated_nrf52_port() {
	printf 'call\n' >>"$resolver_log"
	[[ "$mock_resolver_status" -eq 0 ]] || return "$mock_resolver_status"
	[[ -n "$mock_resolved_port" ]] || return 1
	printf '%s\n' "$mock_resolved_port"
}

# Keep timeout tests deterministic and fast.
sleep() {
	SECONDS=$((SECONDS + 1))
}

NRF52_DFU_REENUMERATE_TIMEOUT_SECONDS=0
NRF52_DFU_REENUMERATE_POLL_SECONDS=0

if wait_for_nrf52_bootloader_port "$selected_port" "$selected_link" serial path before \
	"initial bootloader CDC port" 0 >"${tmp_dir}/unchanged-disallowed.out"; then
	echo "FAIL: initial runtime-to-bootloader wait accepted an unchanged endpoint" >&2
	exit 1
fi
[[ ! -e "$resolver_log" ]]
echo "PASS: initial handoff still requires an observed endpoint transition"

mock_resolved_port="$selected_port"
resolved="$(wait_for_nrf52_bootloader_port "$selected_port" "$selected_link" serial path before \
	"serial port after erase" 1)"
[[ "$resolved" == "$selected_port" ]]
[[ -s "$resolver_log" ]]
echo "PASS: verified post-erase handoff accepts the uniquely resolved unchanged endpoint"

: >"$resolver_log"
mock_resolved_port=""
mock_resolver_status=2
if wait_for_nrf52_bootloader_port "$selected_port" "$selected_link" serial path before \
	"serial port after erase" 1 >"${tmp_dir}/ambiguous.out"; then
	echo "FAIL: post-erase handoff accepted an ambiguous or missing identity" >&2
	exit 1
fi
[[ -s "$resolver_log" ]]
[[ "$dfu_calls" -eq 0 ]]
echo "PASS: post-erase handoff refuses a missing or ambiguous identity"

mock_resolver_status=0
mock_resolved_port="$selected_port"
mock_instance="after"
resolved="$(wait_for_nrf52_bootloader_port "$selected_port" "$selected_link" serial path before \
	"bootloader CDC port" 0)"
[[ "$resolved" == "$selected_port" ]]
echo "PASS: observed endpoint transitions retain the existing behavior"

udev_device_property() {
	case "$2" in
	ID_BUS) printf '%s\n' usb ;;
	ID_VENDOR_ID) printf '%s\n' "$mock_vendor_id" ;;
	ID_MODEL_ID) printf '%s\n' "$mock_product_id" ;;
	ID_MODEL) printf '%s\n' "$mock_model" ;;
	ID_USB_INTERFACES) printf '%s\n' ':020201:0a0000:' ;;
	*) printf '\n' ;;
	esac
}

nrf52_candidate_matches_identity() {
	[[ "$mock_identity_match" -eq 1 ]]
}

nrf52_uf2_mount_matches_identity() {
	return 1
}

run_nrfutil_dfu_serial_live_port() {
	[[ "$1" == "$package" && "$2" == "$selected_port" ]]
	dfu_calls=$((dfu_calls + 1))
}

trigger_nrf52_1200_touch() {
	touch_calls=$((touch_calls + 1))
	return 1
}

NRF52_BOARD_GUARD_PASSED=1
NRF52_SELECTED_BY_ID="$selected_link"
NRF52_RUNTIME_SERIAL=serial
NRF52_RUNTIME_PATH_STEM=path
MCFIRMWARE_DFU_OVERRIDE_TTY="${tmp_dir}/no-interactive-tty"
mock_instance=before
run_nrf52_dfu_package_buttonless "$package" "$selected_port"
[[ "$dfu_calls" -eq 1 && "$touch_calls" -eq 0 ]]
echo "PASS: matching T1000-E DFU endpoint receives the application without a second touch"

# A T1000-E changes USB product identity between runtime and its 2886:0057
# serial-only DFU mode. That can make the original by-id link disappear even
# though wait_for_nrf52_bootloader_port already uniquely matched the physical
# USB path/serial after the verified erase.
rm -f -- "$selected_link"
dfu_calls=0
touch_calls=0
if run_nrf52_dfu_package_buttonless "$package" "$selected_port"; then
	echo "FAIL: ordinary DFU entry accepted a missing original by-id link" >&2
	exit 1
fi
[[ "$dfu_calls" -eq 0 && "$touch_calls" -eq 1 ]]
echo "PASS: ordinary DFU entry rejects a missing original by-id link"

# A human can explicitly continue once after physically checking the radio.
# The override never relaxes NRF52_BOARD_GUARD_PASSED, which remains checked
# before this point in the production function.
NRF52_BOARD_GUARD_PASSED=0
dfu_calls=0
touch_calls=0
if MCFIRMWARE_DFU_OVERRIDE=yes \
	run_nrf52_dfu_package_buttonless "$package" "$selected_port"; then
	echo "FAIL: unmatched DFU override bypassed the board guard" >&2
	exit 1
fi
[[ "$dfu_calls" -eq 0 && "$touch_calls" -eq 0 ]]
NRF52_BOARD_GUARD_PASSED=1
echo "PASS: unmatched DFU override cannot bypass the board guard"

mock_identity_match=0
dfu_calls=0
touch_calls=0
MCFIRMWARE_DFU_OVERRIDE=yes \
	run_nrf52_dfu_package_buttonless "$package" "$selected_port"
[[ "$dfu_calls" -eq 1 && "$touch_calls" -eq 0 ]]
echo "PASS: explicit yes override permits a missing or mismatched USB identity"

if MCFIRMWARE_DFU_OVERRIDE=no \
	nrf52_confirm_unmatched_dfu_override "$selected_port" "test decline"; then
	echo "FAIL: non-yes DFU override answer was accepted" >&2
	exit 1
fi
echo "PASS: non-yes DFU override answers cancel"

# Exercise the interactive y/N decision without a physical terminal.
MCFIRMWARE_DFU_OVERRIDE_TTY="${tmp_dir}/override-tty"
touch "$MCFIRMWARE_DFU_OVERRIDE_TTY"
read() {
	[[ $# == 2 && "$1" == -r && "$2" == answer ]] || return 1
	printf -v answer '%s' "$mock_answer"
}
mock_answer=y
nrf52_confirm_unmatched_dfu_override "$selected_port" "interactive test"
grep -Fq 'Continue with this unmatched DFU device? [y/N]' "$MCFIRMWARE_DFU_OVERRIDE_TTY"
mock_answer=''
if nrf52_confirm_unmatched_dfu_override "$selected_port" "interactive test"; then
	echo "FAIL: Enter accepted the interactive unmatched DFU override" >&2
	exit 1
fi
unset -f read
MCFIRMWARE_DFU_OVERRIDE_TTY="${tmp_dir}/no-interactive-tty"
echo "PASS: interactive y continues and Enter cancels"

# An unexpected PID may still be the board the user has just verified after a
# recovery erase. It stays rejected automatically, but an explicit yes may
# proceed without inventing a wider vendor/PID allow-list.
ln -s "$selected_port" "$selected_link"
mock_identity_match=1
mock_vendor_id=1234
mock_product_id=5678
mock_model="Unknown_nRF52_endpoint"
dfu_calls=0
touch_calls=0
run_nrf52_dfu_package_buttonless "$package" "$selected_port" 0 1
[[ "$dfu_calls" -eq 1 && "$touch_calls" -eq 0 ]]
echo "PASS: approved recovery override permits an unrecognised DFU PID"

mock_vendor_id=2886
mock_product_id=0057
mock_model="T1000-E"
mock_identity_match=1

mock_instance=before
mock_resolver_status=0
mock_resolved_port="$selected_port"
post_erase_port="$(wait_for_nrf52_bootloader_port "$selected_port" "$selected_link" serial path before \
	"serial port after erase" 1)"
[[ "$post_erase_port" == "$selected_port" ]]

dfu_calls=0
touch_calls=0
run_nrf52_dfu_package_buttonless "$package" "$post_erase_port" 1
[[ "$dfu_calls" -eq 1 && "$touch_calls" -eq 0 ]]
echo "PASS: verified post-erase identity permits a missing original by-id link without a second touch"

mock_vendor_id=239a
mock_product_id=002a
mock_model="WisCore_RAK3401_Board"
mock_instance=before
mock_resolver_status=0
mock_resolved_port="$selected_port"
post_erase_port="$(wait_for_nrf52_bootloader_port "$selected_port" "$selected_link" serial path before \
	"serial port after erase" 1)"
[[ "$post_erase_port" == "$selected_port" ]]
dfu_calls=0
touch_calls=0
run_nrf52_dfu_package_buttonless "$package" "$post_erase_port" 1
[[ "$dfu_calls" -eq 1 && "$touch_calls" -eq 0 ]]
echo "PASS: verified post-erase identity recognizes RAK3401 239a:002a without a second touch"

mock_vendor_id=239a
mock_product_id=0029
mock_model="Heltec_Mesh_Node_T1"
mock_instance=before
mock_resolver_status=0
mock_resolved_port="$selected_port"
post_erase_port="$(wait_for_nrf52_bootloader_port "$selected_port" "$selected_link" serial path before \
	"serial port after erase" 1)"
[[ "$post_erase_port" == "$selected_port" ]]
dfu_calls=0
touch_calls=0
run_nrf52_dfu_package_buttonless "$package" "$post_erase_port" 1
[[ "$dfu_calls" -eq 1 && "$touch_calls" -eq 0 ]]
echo "PASS: verified post-erase identity recognizes Heltec Mesh Node T1 239a:0029 without a second touch"

grep -Fq '"$NRF52_LAST_DFU_INSTANCE" "serial port after erase" 1)' "$script_path" || {
	echo "FAIL: flash-wipe does not opt in after the verified erase" >&2
	exit 1
}
if grep -A4 -F 'if ! bootloader_port="$(wait_for_nrf52_bootloader_port "$runtime_port"' \
	"$script_path" | grep -Fq ' 1)'; then
	echo "FAIL: initial runtime-to-bootloader handoff was relaxed" >&2
	exit 1
fi
grep -Fq '1 "$NRF52_ALLOW_UNMATCHED_DFU"; then' "$script_path" || {
	echo "FAIL: application install does not carry the verified post-erase proof" >&2
	exit 1
}
if grep -Fq 'run_nrf52_dfu_package_buttonless "$ERASE_FILE" "$NRF52_RUNTIME_PORT" 1' "$script_path"; then
	echo "FAIL: erase entry was incorrectly relaxed" >&2
	exit 1
fi
grep -Fq 'Continue with this unmatched DFU device? [y/N]' "$script_path" || {
	echo "FAIL: unmatched DFU recovery does not present a y/N decision" >&2
	exit 1
}
echo "PASS: relaxed re-entry is confined to the post-erase path"
