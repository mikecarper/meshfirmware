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
	esptool_safe_serial_bootstrap esptool_port_argument \
	configure_esptool_invocation; do
	definition="$(extract_function "$function_name")"
	[[ "$definition" == "${function_name}() {"* ]] || {
		echo "failed to extract ${function_name}" >&2
		exit 1
	}
	# Deliberately evaluate functions extracted from the production script.
	# shellcheck disable=SC2294
	eval "$definition"
done

expect_equal() {
	local label=$1 expected=$2 actual=$3
	if [[ "$actual" != "$expected" ]]; then
		echo "FAIL: ${label}: expected '${expected}', got '${actual}'" >&2
		exit 1
	fi
	echo "PASS: ${label}"
}

expect_equal "long port option is parsed" \
	"/dev/ttyACM4" "$(esptool_port_argument --chip esp32s3 --port /dev/ttyACM4 read-mac)"
expect_equal "short port option is parsed" \
	"/dev/ttyUSB2" "$(esptool_port_argument -p /dev/ttyUSB2 read-mac)"
expect_equal "equals port option is parsed" \
	"/dev/serial/by-id/test" "$(esptool_port_argument --port=/dev/serial/by-id/test read-mac)"

configure_esptool_invocation --port /dev/ttyACM4 --before no-reset read-mac
expect_equal "local serial uses pipx" "pipx" "${ESPTOOL_INVOKE_COMMAND[0]}"
expect_equal "local serial uses isolated esptool environment" \
	"run --quiet --spec esptool python -c" "${ESPTOOL_INVOKE_COMMAND[*]:1:6}"
[[ "${ESPTOOL_INVOKE_COMMAND[7]}" == *'port.rts = False'* \
	&& "${ESPTOOL_INVOKE_COMMAND[7]}" == *'port.dtr = False'* \
	&& "${ESPTOOL_INVOKE_COMMAND[7]}" == *'~termios.HUPCL'* ]] || {
	echo "FAIL: local serial bootstrap lacks idle-line or HUPCL protection" >&2
	exit 1
}
echo "PASS: local serial bootstrap contains idle-line and HUPCL protection"

configure_esptool_invocation image-info firmware.bin
expect_equal "non-serial command keeps ordinary runner" \
	"pipx run esptool" "${ESPTOOL_INVOKE_COMMAND[*]}"

configure_esptool_invocation --port socket://127.0.0.1:3333 read-mac
expect_equal "socket transport keeps ordinary runner" \
	"pipx run esptool" "${ESPTOOL_INVOKE_COMMAND[*]}"

cat >"${tmp_dir}/serial.py" <<'PY'
class FakePort:
    def __init__(self):
        self.rts = True
        self.dtr = True

    def open(self):
        print(f"OPEN_STATE={self.dtr},{self.rts}")

    def fileno(self):
        return -1


def serial_for_url(*args, **kwargs):
    print(f"FACTORY_DO_NOT_OPEN={kwargs.get('do_not_open')}")
    port = FakePort()
    if not kwargs.get("do_not_open", False):
        port.open()
    return port
PY

cat >"${tmp_dir}/esptool.py" <<'PY'
import serial


def main(argv):
    print("ARGV=" + ",".join(argv))
    port = serial.serial_for_url("/dev/ttyACM4", do_not_open=True)
    print(f"CACHED_STATE={port.dtr},{port.rts}")
    port.open()
PY

bootstrap="$(esptool_safe_serial_bootstrap)"
bootstrap_output="$(PYTHONPATH="$tmp_dir" python3 -c "$bootstrap" alpha beta)"
grep -qx 'ARGV=alpha,beta' <<<"$bootstrap_output"
grep -qx 'FACTORY_DO_NOT_OPEN=True' <<<"$bootstrap_output"
grep -qx 'CACHED_STATE=False,False' <<<"$bootstrap_output"
grep -qx 'OPEN_STATE=False,False' <<<"$bootstrap_output"
echo "PASS: bootstrap sets idle DTR/RTS before the underlying port open"

if rg -n 'pipx run esptool .*--port|pipx run esptool --port' "$script_path" >/dev/null; then
	echo "FAIL: a device esptool call bypasses the guarded invocation" >&2
	exit 1
fi
echo "PASS: device esptool calls do not bypass the guarded invocation"

if rg -n 'run_esptool --port "\$port" --after "\$NORESET".*"\$READFLASH"|run_esptool --port "\$\{DEVICE_PORT\}" --after' \
	"$script_path" >/dev/null; then
	echo "FAIL: a prepared ESP32 ROM operation can still request an implicit reset" >&2
	exit 1
fi
echo "PASS: prepared ESP32 reads, erases, and writes explicitly use --before no-reset"
