#!/usr/bin/env bash
# Exercise production native-USB classification and bootloader preparation.
# All USB, privilege, descriptor, tty and esptool operations are fixtures.
# shellcheck disable=SC2034,SC2317
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script_path="${repo_root}/mcfirmware.sh"
fixture_dir="$(mktemp -d)"
trap 'rm -rf -- "$fixture_dir"' EXIT

extract_function() {
	awk -v signature="$1() {" '
		$0 == signature { capture = 1 }
		capture { print }
		capture && $0 == "}" { exit }
	' "$script_path"
}

for function_name in normalize_usb_serial_identity nrf52_usb_path_stem \
	esp32_native_usb_mode request_esp32_tinyusb_bootloader \
	verify_esp32_mac_matches_usb_serial record_esp32_chip_from_esptool_output \
	esp32_mac_from_esptool_output esp32_record_and_verify_probe_output \
	raw_esptool_mac_probe prepare_esp32_flash_session \
	esp32_require_native_s3_watchdog_reset \
	esp32_recover_interrupted_transport; do
	definition="$(extract_function "$function_name")"
	[[ "$definition" == "$function_name() {"* ]] || {
		echo "FAIL: production function missing: $function_name" >&2
		exit 1
	}
	# shellcheck disable=SC2294
	eval "$definition"
done

production_native_mode="$(declare -f esp32_native_usb_mode)"
production_request="$(declare -f request_esp32_tinyusb_bootloader)"
app_port="$fixture_dir/ttyACM-app"
rom_port="$fixture_dir/ttyACM-rom"
app_link="$fixture_dir/app-by-id"
rom_link="$fixture_dir/rom-by-id"
event_log="$fixture_dir/events.log"
operation_log="$fixture_dir/destructive.log"
touch "$app_port" "$rom_port"
ln -s "$app_port" "$app_link"
ln -s "$rom_port" "$rom_link"

NORESET=no-reset
WATCHDOGRESET=watchdog-reset
USBRESET=usb-reset
DEFAULTRESET=default-reset
READMAC=read-mac
ESPTOOL_CMD=esptool
DOWNLOAD_DIR="$fixture_dir"
DEVICE_PORT_FILE="$fixture_dir/selected-port"
DEVICE_PORT_NAME_FILE="$fixture_dir/selected-name"
ESP32_PROBE_TIMEOUT_SECONDS=8

selected_flash_serial_port() { printf '%s\n' "$1"; }
save_selected_serial_port() {
	DEVICE_PORT="$1"
	printf '%s\n' "$1" >"$DEVICE_PORT_FILE"
	printf 'save %s\n' "$1" >>"$event_log"
}
prepare_serial_port_for_flash() { return 0; }
serial_by_id_link_for_port() {
	case "$1" in
		"$app_port") printf '%s\n' "$app_link" ;;
		"$rom_port") printf '%s\n' "$rom_link" ;;
		*) return 1 ;;
	esac
}
udev_device_property() {
	case "$2" in
		ID_SERIAL_SHORT) printf '%s\n' "$fixture_usb_serial" ;;
		ID_PATH) printf '%s\n' pci-test-usb-0:2:1.0 ;;
	esac
}
nrf52_port_instance() { printf '%s\n' application-generation; }
esp32_port_uses_native_usb() { return 0; }
esp32_native_usb_mode() {
	printf 'mode %s\n' "$1" >>"$event_log"
	if [[ "$1" == "$app_port" ]]; then
		printf '%s\n' "$fixture_app_mode"
	else
		printf '%s\n' "$fixture_rom_mode"
	fi
}
request_esp32_tinyusb_bootloader() {
	[[ "$1" == "$app_link" || "$1" == "$app_port" ]] || return 90
	printf 'tinyusb-request %s\n' "$1" >>"$event_log"
	return "$fixture_request_status"
}
wait_for_nrf52_bootloader_port() {
	# The production branch must pass the identity captured BEFORE its request.
	[[ "$1" == "$app_port" && "$2" == "$app_link" \
		&& "$3" == "$fixture_usb_serial" \
		&& "$4" == pci-test-usb-0:2 \
		&& "$5" == application-generation ]] || return 91
	grep -q '^tinyusb-request ' "$event_log" || return 92
	printf 'wait-same-identity\n' >>"$event_log"
	(( fixture_wait_status == 0 )) || return "$fixture_wait_status"
	printf '%s\n' "$rom_port"
}
find_reenumerated_nrf52_port() {
	[[ "$1" == "$app_port" && "$2" == "$app_link" \
		&& "$3" == "$fixture_usb_serial" \
		&& "$4" == pci-test-usb-0:2 ]] || return 101
	(( fixture_wait_status == 0 )) || return "$fixture_wait_status"
	printf '%s\n' "$rom_port"
}
sleep() { return 0; }
invoke_esptool_timeout() {
	printf 'probe %s\n' "$*" >>"$event_log"
	# No tty data or JTAG reset may precede the TinyUSB control request.
	grep -q '^tinyusb-request ' "$event_log" || return 93
	grep -Fxq "mode $rom_port" "$event_log" || return 94
	[[ "$*" == "8s --port $rom_port --before $NORESET --after $NORESET --baud 115200 $READMAC" ]] || return 95
	(( fixture_probe_status == 0 )) || return "$fixture_probe_status"
	printf 'Chip type: ESP32-S3\nMAC: %s\n' "$fixture_mac"
}
run_esptool() { printf '%s\n' "$*" >>"$operation_log"; }
offer_identity_safe_1200_touch() { echo 'FAIL: generic tty touch was used' >&2; return 96; }
probe_esptool_mac() { echo 'FAIL: guessed reset probe was used' >&2; return 98; }

fresh_fixture() {
	fixture_app_mode=tinyusb
	fixture_rom_mode=hardware_jtag
	fixture_usb_serial=441BF66AE844
	fixture_mac=44:1b:f6:6a:e8:44
	fixture_request_status=0
	fixture_wait_status=0
	fixture_probe_status=0
	DEVICE_PORT="$app_port"
	BOOTLOADER_PROBE_PORT=""
	BOOTLOADER_PROBE_ACTIVE=0
	ESP32_NATIVE_ROM_READY=0
	ESP32_FLASH_EXPECTED_MAC=""
	: >"$event_log"
	: >"$operation_log"
	touch "$DOWNLOAD_DIR/CURRENT.BAK"
}

expect_prepare_failure() {
	if prepare_esp32_flash_session "$app_port" 'Heltec V4' \
		>"$fixture_dir/preparation.out" 2>"$fixture_dir/preparation.err"; then
		run_esptool erase-flash
		run_esptool write-flash 0x0 firmware.bin
		echo 'FAIL: unverified handoff reached erase/write' >&2
		exit 1
	fi
	[[ ! -s "$operation_log" ]]
	[[ "$ESP32_NATIVE_ROM_READY" == 0 ]]
}

fresh_fixture
prepare_esp32_flash_session "$app_port" 'Heltec V4' >"$fixture_dir/success.out"
[[ "$DEVICE_PORT" == "$rom_port" && "$(<"$DEVICE_PORT_FILE")" == "$rom_port" ]]
[[ "$BOOTLOADER_PROBE_PORT" == "$rom_port" && "$BOOTLOADER_PROBE_ACTIVE" == 1 ]]
[[ "$ESP32_NATIVE_ROM_READY" == 1 && "$ESP32_OPERATION_BEFORE" == no-reset ]]
[[ "$ESP32_FLASH_EXPECTED_MAC" == 441bf66ae844 ]]
[[ ! -e "$DOWNLOAD_DIR/CURRENT.BAK" ]]
[[ "$(grep -c '^probe ' "$event_log")" == 1 ]]
[[ "$(grep -n '^tinyusb-request ' "$event_log" | cut -d: -f1)" \
	-lt "$(grep -n '^probe ' "$event_log" | cut -d: -f1)" ]]
! grep -q 'usb-reset\|default-reset' "$event_log"
echo 'PASS: TinyUSB control request precedes a same-identity ROM-only no-reset probe'

fresh_fixture
NORESET=no_reset
WATCHDOGRESET=watchdog_reset
READMAC=read_mac
if prepare_esp32_flash_session "$app_port" 'Heltec V4' \
	>"$fixture_dir/old-esptool.out" 2>"$fixture_dir/old-esptool.err"; then
	run_esptool erase_flash
	run_esptool write_flash 0x0 firmware.bin
	echo 'FAIL: native S3 esptool 4 reached a flash-ready session' >&2
	exit 1
fi
[[ ! -s "$operation_log" && -e "$DOWNLOAD_DIR/CURRENT.BAK" ]]
[[ "$ESP32_FLASH_EXPECTED_MAC" == 441bf66ae844 ]]
grep -Fq 'requires esptool 5 or newer' "$fixture_dir/old-esptool.err"
! grep -Fq 'ROM flashing session is ready' "$fixture_dir/old-esptool.out"
echo 'PASS: native S3 preparation rejects esptool 4 after identity proof, before erase or write'
NORESET=no-reset
WATCHDOGRESET=watchdog-reset
READMAC=read-mac

fresh_fixture
fixture_request_status=124
prepare_esp32_flash_session "$app_port" 'Heltec V4' >"$fixture_dir/disconnect.out"
[[ "$ESP32_NATIVE_ROM_READY" == 1 ]]
[[ "$(grep -c '^probe ' "$event_log")" == 1 ]]
echo 'PASS: request-stage timeout is accepted only after descriptor and MAC prove ROM handoff'

for wrong_mode in tinyusb unknown; do
	fresh_fixture
	fixture_request_status=124
	fixture_rom_mode="$wrong_mode"
	expect_prepare_failure
	! grep -q '^probe ' "$event_log"
done
echo 'PASS: unacknowledged request never sends SLIP to an application or unknown USB interface'

fresh_fixture
fixture_wait_status=124
expect_prepare_failure
! grep -q '^probe ' "$event_log"
echo 'PASS: missing same-identity re-enumeration blocks probe and flash'

fresh_fixture
fixture_app_mode=unknown
expect_prepare_failure
! grep -q '^tinyusb-request \|^probe ' "$event_log"
echo 'PASS: unknown native USB mode fails before reset or probe'

fresh_fixture
fixture_probe_status=42
expect_prepare_failure
[[ "$(grep -c '^probe ' "$event_log")" == 1 ]]
echo 'PASS: ROM descriptor without a successful MAC probe cannot arm flashing'

fresh_fixture
fixture_mac=d8:3b:da:75:23:ac
expect_prepare_failure
grep -Fq 'ROM MAC does not match' "$fixture_dir/preparation.err"
echo 'PASS: wrong ROM MAC cannot reach erase or write'

fresh_fixture
fixture_usb_serial=44:1B:F6:6A:E8:44
prepare_esp32_flash_session "$app_port" 'Heltec V4' >"$fixture_dir/punctuation.out"
[[ "$ESP32_NATIVE_ROM_READY" == 1 ]]
echo 'PASS: punctuated and unpunctuated USB MAC identities agree'

ESP32_FLASH_EXPECTED_MAC=441bf66ae844
verify_esp32_mac_matches_usb_serial board-defined-serial
if verify_esp32_mac_matches_usb_serial d8:3b:da:75:23:ac >/dev/null 2>&1; then
	echo 'FAIL: native USB MAC validator accepted another chip' >&2
	exit 1
fi
echo 'PASS: MAC-shaped USB serials are bound; board-defined serials retain physical-identity gating'

# During chunked-write recovery, an application may return as TinyUSB. It
# needs the same descriptor-driven request rather than a USB/JTAG reset.
fresh_fixture
ESP32_FLASH_SELECTED_BY_ID="$app_link"
ESP32_FLASH_EXPECTED_SERIAL="$fixture_usb_serial"
ESP32_FLASH_EXPECTED_PATH_STEM=pci-test-usb-0:2
ESP32_FLASH_EXPECTED_MAC=441bf66ae844
ESP32_FLASH_RECOVERY_ATTEMPTS=2
esp32_recover_interrupted_transport "$app_port" >"$fixture_dir/recovery.out"
[[ "$DEVICE_PORT" == "$rom_port" && "$ESP32_NATIVE_ROM_READY" == 1 ]]
! grep -q 'usb-reset\|default-reset' "$event_log"
echo 'PASS: interrupted TinyUSB transport recovers through the same identity-gated control request'

for recovery_failure in wrong-mac unknown-app unknown-rom wait-timeout; do
	fresh_fixture
	ESP32_FLASH_EXPECTED_SERIAL="$fixture_usb_serial"
	ESP32_FLASH_EXPECTED_MAC=441bf66ae844
	case "$recovery_failure" in
		wrong-mac) fixture_mac=d8:3b:da:75:23:ac ;;
		unknown-app) fixture_app_mode=unknown ;;
		unknown-rom) fixture_rom_mode=unknown ;;
		wait-timeout) fixture_wait_status=124 ;;
	esac
	if esp32_recover_interrupted_transport "$app_port" >"$fixture_dir/recovery-failure.out" 2>&1; then
		run_esptool erase-flash
		echo 'FAIL: unverified recovery reached a destructive operation' >&2
		exit 1
	fi
	[[ ! -s "$operation_log" && "$ESP32_NATIVE_ROM_READY" == 0 ]]
	if [[ "$recovery_failure" != wrong-mac ]]; then
		! grep -q '^probe ' "$event_log"
	fi
done
echo 'PASS: TinyUSB recovery rejects unknown descriptors, a changed chip MAC and a timed-out identity wait'

# Independently exercise the real JSON wrappers with a fake pinned helper.
# The real interpreter still validates JSON; no USB implementation is invoked.
# shellcheck disable=SC2294
eval "$production_native_mode"
# shellcheck disable=SC2294
eval "$production_request"
helper_log="$fixture_dir/helper.log"
helper_path=/fixture/pinned-esp32-helper.py
resolve_meshcore_esp32_bootloader_tool() { printf '%s\n' "$helper_path"; }
no_sudo_mode() { (( fixture_no_sudo )); }
python3() {
	if [[ "$1" == "$helper_path" ]]; then
		printf 'helper %s\n' "$*" >>"$helper_log"
		if [[ " $* " == *' --inspect '* ]]; then
			printf '%s\n' "$helper_inspect_json"
		else
			(( fixture_helper_status == 0 )) || return "$fixture_helper_status"
			printf '%s\n' "$helper_result_json"
		fi
	else
		command python3 "$@"
	fi
}
sudo() {
	[[ "$1" == -n ]] || return 99
	shift
	"$@"
}
timeout() {
	[[ "$1" == --kill-after=2 && "$2" == 10 ]] || return 100
	shift 2
	"$@"
}
udevadm() {
	[[ "$*" == "info --query=property --path=$fixture_snapshot_path" ]] || return 102
	printf 'udev-path %s\n' "$fixture_snapshot_path" >>"$helper_log"
	printf 'ID_PATH=%s\n' "$fixture_helper_path_stem"
}
fixture_no_sudo=0
fixture_helper_status=0
fixture_snapshot_path=/sys/devices/pci-test/usb1/1-2
fixture_helper_path_stem=pci-test-usb-0:2
ESP32_FLASH_EXPECTED_SERIAL=441BF66AE844
ESP32_FLASH_EXPECTED_PATH_STEM=pci-test-usb-0:2
helper_inspect_json='{"status":"inspected","native_mode":"tinyusb","identity":{"usb_serial":"441BF66AE844","usb_path":"/sys/devices/pci-test/usb1/1-2"}}'
helper_result_json='{"status":"request_issued","native_mode":"tinyusb","identity":{"usb_serial":"441BF66AE844","usb_path":"/sys/devices/pci-test/usb1/1-2"}}'
matching_inspect_json="$helper_inspect_json"
matching_result_json="$helper_result_json"
: >"$helper_log"
[[ "$(esp32_native_usb_mode "$app_link")" == tinyusb ]]
ESP32_NATIVE_ROM_READY=0
request_esp32_tinyusb_bootloader "$app_link"
[[ "$ESP32_NATIVE_ROM_READY" == 0 ]]
grep -Fq -- "--expected-identity $helper_inspect_json --timeout 5" "$helper_log"
echo 'PASS: pinned helper gets an exact identity snapshot and bounded request; acknowledgement alone does not prove ROM'

# Querying a physical USB DEVICE yields an interface-free ID_PATH. The tty
# path, and only that path, must lose its final :1.0 CDC interface component.
# In particular, physical port 0:1.2 is not itself an interface suffix.
for usb_ports in 2 1.2 1.3.3; do
	fixture_snapshot_path="/sys/devices/pci-test/usb1/1-$usb_ports"
	fixture_helper_path_stem="pci-test-usb-0:$usb_ports"
	ESP32_FLASH_EXPECTED_PATH_STEM="$(nrf52_usb_path_stem "$fixture_helper_path_stem:1.0")"
	[[ "$ESP32_FLASH_EXPECTED_PATH_STEM" == "$fixture_helper_path_stem" ]]
	helper_inspect_json="$(printf '{"status":"inspected","native_mode":"tinyusb","identity":{"usb_serial":"441BF66AE844","usb_path":"%s"}}' "$fixture_snapshot_path")"
	helper_result_json="$(printf '{"status":"request_issued","native_mode":"tinyusb","identity":{"usb_serial":"441BF66AE844","usb_path":"%s"}}' "$fixture_snapshot_path")"
	: >"$helper_log"
	request_esp32_tinyusb_bootloader "$app_link"
	grep -Fq -- "--expected-identity $helper_inspect_json --timeout 5" "$helper_log"
	[[ "$ESP32_NATIVE_ROM_READY" == 0 ]]
done
echo 'PASS: direct, two-level and nested USB ports retain their full physical path during TinyUSB qualification'
fixture_snapshot_path=/sys/devices/pci-test/usb1/1-2
fixture_helper_path_stem=pci-test-usb-0:2
ESP32_FLASH_EXPECTED_PATH_STEM=pci-test-usb-0:2
helper_inspect_json="$matching_inspect_json"
helper_result_json="$matching_result_json"

for result_json in \
	'{"status":"reset","native_mode":"tinyusb","identity":{"usb_serial":"441BF66AE844","usb_path":"/sys/devices/pci-test/usb1/1-2"}}' \
	'{"status":"request_issued","native_mode":"hardware_jtag","identity":{"usb_serial":"441BF66AE844","usb_path":"/sys/devices/pci-test/usb1/1-2"}}' \
	'{"status":"request_issued","native_mode":"tinyusb","identity":{"usb_serial":"OTHER","usb_path":"/sys/devices/pci-test/usb1/1-2"}}'; do
	helper_result_json="$result_json"
	if request_esp32_tinyusb_bootloader "$app_link" >/dev/null 2>&1; then
		echo 'FAIL: invalid helper acknowledgement was accepted' >&2
		exit 1
	fi
done
echo 'PASS: helper wrapper rejects wrong status, mode and physical identity'

# A fresh helper snapshot cannot authorize itself: it must agree with the
# original selected serial AND the original physical path before sudo/control.
for snapshot_failure in wrong-original-serial missing-original-serial \
	wrong-original-path missing-original-path invalid-snapshot-path; do
	helper_inspect_json="$matching_inspect_json"
	helper_result_json="$matching_result_json"
	ESP32_FLASH_EXPECTED_SERIAL=441BF66AE844
	ESP32_FLASH_EXPECTED_PATH_STEM=pci-test-usb-0:2
	fixture_helper_path_stem=pci-test-usb-0:2
	case "$snapshot_failure" in
		wrong-original-serial) ESP32_FLASH_EXPECTED_SERIAL=D83BDA7523AC ;;
		missing-original-serial) ESP32_FLASH_EXPECTED_SERIAL='' ;;
		wrong-original-path) ESP32_FLASH_EXPECTED_PATH_STEM=pci-test-usb-0:3 ;;
		missing-original-path) ESP32_FLASH_EXPECTED_PATH_STEM='' ;;
		invalid-snapshot-path)
			helper_inspect_json='{"status":"inspected","native_mode":"tinyusb","identity":{"usb_serial":"441BF66AE844","usb_path":"1-2"}}'
			;;
	esac
	: >"$helper_log"
	if request_esp32_tinyusb_bootloader "$app_link" \
		>"$fixture_dir/snapshot-failure.out" 2>"$fixture_dir/snapshot-failure.err"; then
		echo "FAIL: $snapshot_failure issued a TinyUSB request" >&2
		exit 1
	fi
	! grep -q -- ' --expected-identity ' "$helper_log"
	[[ "$ESP32_NATIVE_ROM_READY" == 0 ]]
done
echo 'PASS: missing or mismatched original serial/path blocks USB control before the request'

ESP32_FLASH_EXPECTED_SERIAL=44:1B:F6:6A:E8:44
ESP32_FLASH_EXPECTED_PATH_STEM=pci-test-usb-0:2
helper_inspect_json="$matching_inspect_json"
helper_result_json="$matching_result_json"
request_esp32_tinyusb_bootloader "$app_link"
echo 'PASS: original serial binding accepts only normalized punctuation differences'

# The same tty number can now belong to another radio, or a cloned serial can
# appear on another USB port. Neither may inherit the saved radio's authority.
for recycled_identity in different-chip cloned-serial-other-port; do
	ESP32_FLASH_EXPECTED_SERIAL=441BF66AE844
	ESP32_FLASH_EXPECTED_PATH_STEM=pci-test-usb-0:2
	fixture_snapshot_path=/sys/devices/pci-test/usb1/1-3
	fixture_helper_path_stem=pci-test-usb-0:3
	if [[ "$recycled_identity" == different-chip ]]; then
		helper_inspect_json='{"status":"inspected","native_mode":"tinyusb","identity":{"usb_serial":"D83BDA7523AC","usb_path":"/sys/devices/pci-test/usb1/1-3"}}'
	else
		helper_inspect_json='{"status":"inspected","native_mode":"tinyusb","identity":{"usb_serial":"441BF66AE844","usb_path":"/sys/devices/pci-test/usb1/1-3"}}'
	fi
	: >"$helper_log"
	if request_esp32_tinyusb_bootloader "$app_port" >/dev/null 2>&1; then
		echo "FAIL: recycled tty ($recycled_identity) authorized a USB control request" >&2
		exit 1
	fi
	! grep -q -- ' --expected-identity ' "$helper_log"
done
echo 'PASS: recycled tty and a cloned serial on another USB port cannot receive a bootloader request'

fixture_snapshot_path=/sys/devices/pci-test/usb1/1-2
fixture_helper_path_stem=pci-test-usb-0:2
helper_inspect_json="$matching_inspect_json"
helper_result_json="$matching_result_json"
fixture_no_sudo=1
: >"$helper_log"
if request_esp32_tinyusb_bootloader "$app_link" >"$fixture_dir/no-sudo.out" 2>&1; then
	echo 'FAIL: no-sudo mode issued a TinyUSB request' >&2
	exit 1
fi
[[ ! -s "$helper_log" ]]
echo 'PASS: no-sudo mode does not inspect, open, or reset a USB device'

fixture_no_sudo=0
fixture_helper_status=124
if request_esp32_tinyusb_bootloader "$app_link" >/dev/null 2>&1; then
	echo 'FAIL: timed-out helper was reported as a successful request' >&2
	exit 1
fi
echo 'PASS: request wrapper propagates helper timeout instead of declaring success'
