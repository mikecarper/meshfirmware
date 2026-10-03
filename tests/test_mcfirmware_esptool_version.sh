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

for function_name in resolve_esptool_pipx_app esptool_set_variables; do
	definition="$(extract_function "$function_name")"
	[[ "$definition" == "${function_name}() {"* ]]
	# Deliberately evaluate the function extracted from the production script.
	# shellcheck disable=SC2294
	eval "$definition"
done

fake_esptool_major=5
fake_esptool_app=esptool
fake_esptool_prefix=''
pipx() {
	[[ "${4:-}" == "$fake_esptool_app" ]] || return 1
	if [[ -n "$fake_esptool_prefix" ]]; then
		printf '%s\n' "$fake_esptool_prefix"
	fi
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
ESPTOOL_PIPX_APP=''
ESPTOOL_VERSION_OUTPUT=''
esptool_set_variables >/dev/null
[[ "$NORESET" == no-reset && "$WRITEFLASH" == write-flash ]]
echo "PASS: esptool 5 version output cannot terminate the flasher through pipefail"

fake_esptool_major=4
fake_esptool_app=esptool.py
NORESET='unset'
WRITEFLASH='unset'
ESPTOOL_PIPX_APP=''
ESPTOOL_VERSION_OUTPUT=''
esptool_set_variables >/dev/null
[[ "$NORESET" == no_reset && "$WRITEFLASH" == write_flash ]]
[[ "$ESPTOOL_PIPX_APP" == esptool.py ]]
echo "PASS: esptool 4 falls back to its esptool.py entry point"

# Python/dependency warnings can contain an earlier dotted version. Only the
# actual esptool banner may select the underscore versus hyphen command form.
for fake_esptool_major in 4 5; do
	fake_esptool_app=esptool
	fake_esptool_prefix=$'Python 3.11 is deprecated\nWarning: helper v3.12.9 requires maintenance'
	NORESET=unset
	WRITEFLASH=unset
	ESPTOOL_PIPX_APP=''
	ESPTOOL_VERSION_OUTPUT=''
	esptool_set_variables >/dev/null
	if [[ "$fake_esptool_major" == 5 ]]; then
		[[ "$NORESET" == no-reset && "$WRITEFLASH" == write-flash ]]
	else
		[[ "$NORESET" == no_reset && "$WRITEFLASH" == write_flash ]]
	fi
done
echo 'PASS: Python and helper version warnings cannot override the esptool banner'
