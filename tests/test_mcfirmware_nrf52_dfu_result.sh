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

for function_name in nrfutil_serial_timeout_bootstrap run_nrfutil_dfu_serial_checked; do
	definition="$(extract_function "$function_name")"
	[[ "$definition" == "${function_name}() {"* ]] || {
		echo "failed to extract ${function_name}" >&2
		exit 1
	}
	# Deliberately evaluate functions extracted from the production script.
	# shellcheck disable=SC2294
	eval "$definition"
done

mkdir -p "${tmp_dir}/bin"
cat >"${tmp_dir}/bin/pipx" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$@" >"$NRFUTIL_ARGUMENT_LOG"
case "$NRFUTIL_RESULT" in
	success)
		printf '%s\n' 'Device programmed.'
		exit 0
		;;
	false-success)
		printf '%s\n' 'Failed to upgrade target.'
		exit 0
		;;
	conflicting)
		printf '%s\n' 'Device programmed.' 'Failed to upgrade target.'
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
export NRFUTIL_ARGUMENT_LOG="${tmp_dir}/arguments"

nrf52_serial_port_access() { return 0; }
package="${tmp_dir}/firmware.zip"
port="${tmp_dir}/ttyACM0"
touch "$package" "$port"

export NRFUTIL_RESULT=success
run_nrfutil_dfu_serial_checked "$package" "$port"
grep -Fxq -- '--singlebank' "$NRFUTIL_ARGUMENT_LOG"
grep -Fxq -- '--verbose' "$NRFUTIL_ARGUMENT_LOG"
grep -Fq 'ACK_PACKET_TIMEOUT' "$NRFUTIL_ARGUMENT_LOG"
grep -Fxq -- '10' "$NRFUTIL_ARGUMENT_LOG"
if grep -Fxq -- '--touch' "$NRFUTIL_ARGUMENT_LOG"; then
	echo "FAIL: checked DFU duplicated the separately controlled 1200-baud touch" >&2
	exit 1
fi
echo "PASS: checked nRF52 DFU uses single-bank mode and requires positive completion"

export MCFIRMWARE_NRF52_ACK_TIMEOUT_SECONDS=17.5
run_nrfutil_dfu_serial_checked "$package" "$port" >/dev/null
grep -Fxq -- '17.5' "$NRFUTIL_ARGUMENT_LOG"
export MCFIRMWARE_NRF52_ACK_TIMEOUT_SECONDS=invalid
if run_nrfutil_dfu_serial_checked "$package" "$port" \
	>"${tmp_dir}/invalid-timeout.out" 2>"${tmp_dir}/invalid-timeout.err"; then
	echo "FAIL: an invalid DFU acknowledgement timeout was accepted" >&2
	exit 1
fi
grep -Fq 'must be a positive number' "${tmp_dir}/invalid-timeout.err"
unset MCFIRMWARE_NRF52_ACK_TIMEOUT_SECONDS
echo "PASS: DFU acknowledgement timeout is bounded, configurable, and validated"

for result in false-success conflicting nonzero; do
	export NRFUTIL_RESULT="$result"
	if run_nrfutil_dfu_serial_checked "$package" "$port" \
		>"${tmp_dir}/${result}.out" 2>"${tmp_dir}/${result}.err"; then
		echo "FAIL: ${result} nrfutil result was accepted" >&2
		exit 1
	fi
done

grep -Fq 'did not confirm that the device was programmed' \
	"${tmp_dir}/false-success.err"
grep -Fq 'did not confirm that the device was programmed' \
	"${tmp_dir}/conflicting.err"
grep -Fq 'exited with status 42' "${tmp_dir}/nonzero.err"
echo "PASS: rc=0 failures and nonzero exits cannot masquerade as successful DFU"
