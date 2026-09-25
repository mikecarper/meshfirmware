#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script_path="${repo_root}/mcfirmware.sh"

waiter="$({
	awk '
		$0 == "wait_for_nrf52_bootloader_port() {" { capture = 1 }
		capture { print }
		capture && $0 == "}" { exit }
	' "$script_path"
})"
[[ "$waiter" == wait_for_nrf52_bootloader_port* ]] || {
	echo "failed to extract wait_for_nrf52_bootloader_port" >&2
	exit 1
}
# Deliberately evaluate the function extracted from the production script.
# shellcheck disable=SC2294
eval "$waiter"

NRF52_DFU_REENUMERATE_TIMEOUT_SECONDS=0
NRF52_DFU_REENUMERATE_POLL_SECONDS=0
finder_mode="unique"
result_file="$(mktemp)"
finder_calls_file="$(mktemp)"
trap 'rm -f -- "$result_file" "$finder_calls_file"' EXIT

nrf52_port_instance() {
	printf '%s\n' 'unchanged-instance'
}

find_reenumerated_nrf52_port() {
	echo call >>"$finder_calls_file"
	case "$finder_mode" in
		unique) printf '%s\n' '/dev/ttyACM3' ;;
		ambiguous) return 2 ;;
		*) return 1 ;;
	esac
}

sleep() { :; }

if wait_for_nrf52_bootloader_port /dev/ttyACM3 selected serial path unchanged-instance \
	"initial DFU wait"; then
	echo "FAIL: initial wait accepted an unchanged endpoint" >&2
	exit 1
fi
[[ ! -s "$finder_calls_file" ]] || {
	echo "FAIL: initial wait called identity lookup without a reset" >&2
	exit 1
}
echo "PASS: initial wait remains reset-gated by default"

truncate -s 0 "$finder_calls_file"
finder_mode="unique"
wait_for_nrf52_bootloader_port /dev/ttyACM3 selected serial path unchanged-instance \
	"runtime CDC port after erase" 1 >"$result_file"
matched="$(<"$result_file")"
[[ "$matched" == /dev/ttyACM3 ]] || {
	echo "FAIL: post-erase wait did not accept a unique unchanged selected identity" >&2
	exit 1
}
[[ "$(wc -l <"$finder_calls_file")" -eq 1 ]] || {
	echo "FAIL: post-erase wait did not consult the identity matcher" >&2
	exit 1
}
echo "PASS: post-erase wait accepts only the identity matcher result"

truncate -s 0 "$finder_calls_file"
finder_mode="ambiguous"
if wait_for_nrf52_bootloader_port /dev/ttyACM3 selected serial path unchanged-instance \
	"runtime CDC port after erase" 1; then
	echo "FAIL: post-erase wait accepted an ambiguous identity" >&2
	exit 1
fi
[[ -s "$finder_calls_file" ]] || {
	echo "FAIL: post-erase ambiguous result did not reach the identity matcher" >&2
	exit 1
}
echo "PASS: post-erase wait refuses an ambiguous identity"

if wait_for_nrf52_bootloader_port /dev/ttyACM3 selected serial path unchanged-instance \
	"runtime CDC port after erase" invalid >/dev/null 2>&1; then
	echo "FAIL: invalid unchanged-identity flag was accepted" >&2
	exit 1
fi
echo "PASS: unchanged-identity flag is validated"

post_erase_calls="$(grep -Fc 'serial port after erase" 1)' "$script_path" || true)"
[[ "$post_erase_calls" -eq 1 ]] || {
	echo "FAIL: post-erase handoff is not the sole unchanged-identity caller" >&2
	exit 1
}
echo "PASS: only the post-erase handoff enables unchanged-identity matching"

post_erase_direct_calls="$(grep -Fc '1 "$NRF52_ALLOW_UNMATCHED_DFU"; then' "$script_path" || true)"
[[ "$post_erase_direct_calls" -eq 1 ]] || {
	echo "FAIL: post-erase app install is not the sole relaxed direct-DFU caller" >&2
	exit 1
}
echo "PASS: only the post-erase app install enables direct DFU without the old by-id link"
