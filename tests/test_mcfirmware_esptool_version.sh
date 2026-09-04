#!/usr/bin/env bash
# Ensure the version probe cannot abort the flasher when esptool writes more
# than the first matching version line under set -o pipefail.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script_path="${repo_root}/mcfirmware.sh"

extract_function() {
	local function_name=$1
	awk -v signature="${function_name}() {" '
		$0 == signature { capture = 1 }
		capture { print }
		capture && $0 == "}" { exit }
	' "$script_path"
}

definition="$(extract_function esptool_set_variables)"
[[ "$definition" == 'esptool_set_variables() {'* ]]
# Deliberately evaluate the function extracted from the production script.
# shellcheck disable=SC2294
eval "$definition"

fake_esptool_major=5
pipx() {
	printf 'esptool v%s.4.0\n' "$fake_esptool_major"
	if [[ "$fake_esptool_major" == 5 ]]; then
		# The old pipx|grep -m1 pipeline closed while this producer was still
		# writing, making pipefail terminate mcfirmware.sh.
		local i
		for ((i=0; i<20000; i++)); do
			printf 'additional version output %d\n' "$i"
		done
	fi
}

NORESET='unset'
WRITEFLASH='unset'
esptool_set_variables >/dev/null
[[ "$NORESET" == no-reset && "$WRITEFLASH" == write-flash ]]
echo "PASS: esptool 5 version output cannot terminate the flasher through pipefail"

fake_esptool_major=4
NORESET='unset'
WRITEFLASH='unset'
esptool_set_variables >/dev/null
[[ "$NORESET" == no_reset && "$WRITEFLASH" == write_flash ]]
echo "PASS: esptool 4 command spelling remains supported"
