#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script_path="${repo_root}/mcfirmware.sh"
tmp_dir="$(mktemp -d)"
trap 'rm -rf -- "$tmp_dir"' EXIT
trap 'echo "FAIL: erase-selection test at line $LINENO" >&2; [[ ! -f "$tmp_dir/messages" ]] || cat "$tmp_dir/messages" >&2' ERR

for function_name in _cached_json meshcore_erase_url nrf52_erase_entries choose_erase_zip; do
	definition="$(awk -v signature="${function_name}() {" '
		$0 == signature { capture = 1 }
		capture { print }
		capture && $0 == "}" { exit }
	' "$script_path")"
	[[ "$definition" == "${function_name}() {"* ]]
	# Exercise the production functions, without running the hardware flasher.
	# shellcheck disable=SC2294
	eval "$definition"
done

CONFIG_FILE="${tmp_dir}/provider.json"
DEFAULT_CONFIG_FILE="${tmp_dir}/official.json"
RELEASE_INFO1_URL="https://official.invalid/config.json"
RELEASE_INFO1_FALLBACK_URL="https://mirror.invalid/config.json"
CACHE_TIMEOUT_SECONDS=21600
CURL_FETCH_RETRIES=1
CURL_FETCH_MAX_TIME=1
MCFIRMWARE_ERASE_TTY="${tmp_dir}/tty"
mock_network_ok=1
mock_choices=()
mock_read_index=0
target='RAK WisBlock / WisMesh (RAK 4631)'
erase_v6='FLASH_ERASE_nrf52_softdevice_v6.zip'

ensure_command() { command -v "$1" >/dev/null; }
curl() {
	printf '%s\n' "$*" >>"${tmp_dir}/fetch.log"
	(( mock_network_ok )) || return 1
	while (( $# )); do
		if [[ "$1" == -o ]]; then
			cp -- "${tmp_dir}/remote.json" "$2"
			return 0
		fi
		shift
	done
	return 1
}
read() {
	if [[ $# == 2 && "$1" == -r && "$2" == choice ]]; then
		printf 'prompt\n' >>"${tmp_dir}/read.log"
		(( mock_read_index < ${#mock_choices[@]} )) || return 1
		printf -v choice '%s' "${mock_choices[$mock_read_index]}"
		mock_read_index=$((mock_read_index + 1))
	else
		builtin read "$@"
	fi
}

printf '%s\n' '{"device":[
  {"name":"RAK WisBlock / WisMesh (RAK 4631)","type":"nrf52",
   "firmware":[{"role":"bootloader","version":{}}]}
]}' >"$CONFIG_FILE"
cp -- "$CONFIG_FILE" "${tmp_dir}/provider.before"
printf '%s\n' '{"device":[
  {"name":"Other board","type":"nrf52","erase":"OTHER_BOARD_v7.zip"},
  {"name":"RAK WisBlock / WisMesh (RAK 4631)","type":"nrf52",
   "erase":"FLASH_ERASE_nrf52_softdevice_v6.zip"}
]}' >"${tmp_dir}/remote.json"
cp -- "${tmp_dir}/remote.json" "$DEFAULT_CONFIG_FILE"

DOWNLOADED_FILE="${tmp_dir}/RAK4631-bootloader.zip"
CHOSEN_FILE="$DOWNLOADED_FILE"
printf 'selected bootloader fixture\n' >"$DOWNLOADED_FILE"
cp -- "$DOWNLOADED_FILE" "${tmp_dir}/bootloader.before"
choose_erase_zip "$target" >"${tmp_dir}/result" 2>"${tmp_dir}/messages"
[[ "$(<"${tmp_dir}/result")" == "$erase_v6" ]]
[[ ! -e "${tmp_dir}/fetch.log" && ! -e "${tmp_dir}/read.log" ]]
[[ "$CONFIG_FILE" == "${tmp_dir}/provider.json" ]]
[[ "$CHOSEN_FILE" == "$DOWNLOADED_FILE" ]]
cmp -- "$CONFIG_FILE" "${tmp_dir}/provider.before"
cmp -- "$DOWNLOADED_FILE" "${tmp_dir}/bootloader.before"
echo 'PASS: a missing provider erase entry uses the exact official board, preserving the bootloader and provider'

printf '%s\n' '{"device":[
  {"name":"RAK WisBlock / WisMesh (RAK 4631)","type":"nrf52",
   "erase":"https://provider.invalid/RAK4631-erase.zip"}
]}' >"$CONFIG_FILE"
choose_erase_zip "$target" >"${tmp_dir}/result" 2>"${tmp_dir}/messages"
[[ "$(<"${tmp_dir}/result")" == 'https://provider.invalid/RAK4631-erase.zip' ]]
[[ ! -e "${tmp_dir}/fetch.log" ]]
echo 'PASS: an exact provider erase entry retains priority'

[[ "$(meshcore_erase_url "$erase_v6")" == "https://flasher.meshcore.io/firmware/$erase_v6" ]]
[[ "$(meshcore_erase_url "firmware/$erase_v6")" == "https://flasher.meshcore.io/firmware/$erase_v6" ]]
[[ "$(meshcore_erase_url "/firmware/$erase_v6")" == "https://flasher.meshcore.io/firmware/$erase_v6" ]]
[[ "$(meshcore_erase_url 'https://provider.invalid/erase.zip')" == 'https://provider.invalid/erase.zip' ]]
[[ "$(meshcore_erase_url 'http://provider.invalid/erase.zip')" == 'http://provider.invalid/erase.zip' ]]
if meshcore_erase_url '' 2>/dev/null || meshcore_erase_url $'one.zip\ntwo.zip' 2>/dev/null; then
	exit 1
fi
echo 'PASS: erase URLs are normalized without double-prefixing absolute URLs'

# Reproduce the reported missing .erase even in a freshly downloaded official JSON.
CONFIG_FILE="$DEFAULT_CONFIG_FILE"
cp -- "${tmp_dir}/provider.before" "$CONFIG_FILE"
choose_erase_zip "$target" >"${tmp_dir}/result" 2>"${tmp_dir}/messages"
[[ "$(<"${tmp_dir}/result")" == "$erase_v6" ]]
[[ "$(wc -l <"${tmp_dir}/fetch.log")" -eq 1 ]]
grep -Fq 'Downloading official.json' "${tmp_dir}/messages"
[[ "$CACHE_TIMEOUT_SECONDS" == 21600 ]]
echo 'PASS: a fresh catalog missing .erase is refreshed and download messages stay out of the package URL'

# Custom bootloader downloads have no catalog board name: require a manual choice.
mock_choices=(2)
choose_erase_zip CustomFirmware >"${tmp_dir}/result" 2>"${tmp_dir}/messages"
[[ "$(<"${tmp_dir}/result")" == "$erase_v6" ]]
[[ "$(wc -l <"${tmp_dir}/read.log")" -eq 1 ]]
echo 'PASS: custom bootloader recovery requires an explicit physical-board erase choice'

# No exact match must not silently pick a different board, even if only one remains.
printf '%s\n' '{"device":[
  {"name":"Other board","type":"nrf52","erase":"OTHER_BOARD_v7.zip"}
]}' >"$CONFIG_FILE"
cp -- "$CONFIG_FILE" "${tmp_dir}/unmatched.before"
mock_network_ok=0
mock_choices=(q)
mock_read_index=0
if choose_erase_zip "$target" >"${tmp_dir}/result" 2>"${tmp_dir}/messages"; then
	exit 1
fi
[[ ! -s "${tmp_dir}/result" ]]
cmp -- "$CONFIG_FILE" "${tmp_dir}/unmatched.before"
grep -Fq 'using cached official.json' "${tmp_dir}/messages"
echo 'PASS: offline lookup preserves the cache and cancellation never chooses an unrelated erase package'

# Conflicting exact entries require a choice instead of silently taking the first.
printf '%s\n' '{"device":[
  {"name":"RAK WisBlock / WisMesh (RAK 4631)","type":"nrf52","erase":"first.zip"},
  {"name":"RAK WisBlock / WisMesh (RAK 4631)","type":"nrf52","erase":"second.zip"}
]}' >"$CONFIG_FILE"
mock_choices=(q)
mock_read_index=0
if choose_erase_zip "$target" >"${tmp_dir}/result" 2>"${tmp_dir}/messages"; then
	exit 1
fi
[[ ! -s "${tmp_dir}/result" ]]
echo 'PASS: conflicting board erase entries cannot be auto-selected'

# Invalid/non-nRF52 erase fields and failed downloads cannot become DFU inputs.
printf '%s\n' '{"device":[
  {"name":"ESP","type":"esp32","erase":"esp.bin"},
  {"name":"Missing","type":"nrf52"},
  {"name":"Empty","type":"nrf52","erase":""},
  {"name":"Null","type":"nrf52","erase":null},
  {"name":"Object","type":"nrf52","erase":{}},
  {"name":"Number","type":"nrf52","erase":42}
]}' >"$CONFIG_FILE"
mock_choices=()
mock_read_index=0
if choose_erase_zip "$target" >"${tmp_dir}/result" 2>"${tmp_dir}/messages"; then
	exit 1
fi
[[ ! -s "${tmp_dir}/result" ]]
grep -Fq 'Cancelled before erase or DFU' "${tmp_dir}/messages"
echo 'PASS: missing/invalid erase metadata fails safely with an actionable message'

# An invalid successful download is rejected rather than replacing the cache.
cp -- "$CONFIG_FILE" "${tmp_dir}/invalid.before"
printf '%s\n' '{"device":[{"name":"No erase","type":"nrf52"}]}' >"${tmp_dir}/remote.json"
mock_network_ok=1
if choose_erase_zip "$target" >"${tmp_dir}/result" 2>"${tmp_dir}/messages"; then
	exit 1
fi
cmp -- "$CONFIG_FILE" "${tmp_dir}/invalid.before"
[[ ! -s "${tmp_dir}/result" ]]
echo 'PASS: refreshed JSON must contain usable nRF52 erase metadata'

# Run the real main-path erase preparation with a fake downloader; never load
# the rest of the flasher or any serial/DFU functions.
wipe_preparation="$(awk '
	/^\tif \[\[ \$ACTION == "flash-wipe" \]\]; then/ { capture = 1 }
	capture && /^\techo "Commands that would be run\."/ { exit }
	capture { print }
' "$script_path")"
[[ "$wipe_preparation" == *'choose_erase_zip "$DEVICE"'* ]]
download_and_verify() {
	[[ "$1" == "https://flasher.meshcore.io/firmware/$erase_v6" ]]
	[[ "$2" == "$ERASE_FILE_FILE" && "$3" == 0 && "$4" == Erase ]]
	printf 'download\n' >>"${tmp_dir}/download.log"
	printf '%s\n' "${tmp_dir}/erase.zip" >"$2"
}
ACTION=flash-wipe
DEVICE="$target"
ERASE_URL_FILE="${tmp_dir}/saved-erase-url"
ERASE_FILE_FILE="${tmp_dir}/saved-erase-file"
ERASE_URL=''
printf '%s\n' '{"device":[
  {"name":"RAK WisBlock / WisMesh (RAK 4631)","type":"nrf52",
   "erase":"FLASH_ERASE_nrf52_softdevice_v6.zip"}
]}' >"$DEFAULT_CONFIG_FILE"
CONFIG_FILE="${tmp_dir}/provider.json"
cp -- "${tmp_dir}/provider.before" "$CONFIG_FILE"
# shellcheck disable=SC2294
eval "$wipe_preparation"
[[ "$ERASE_FILE" == "${tmp_dir}/erase.zip" ]]
[[ "$DOWNLOADED_FILE" == "${tmp_dir}/RAK4631-bootloader.zip" ]]
cmp -- "$DOWNLOADED_FILE" "${tmp_dir}/bootloader.before"
[[ "$(wc -l <"${tmp_dir}/download.log")" -eq 1 ]]
echo 'PASS: the real wipe preparation downloads the matching erase and keeps the selected bootloader'

printf '%s\n' '{"device":[]}' >"$DEFAULT_CONFIG_FILE"
ERASE_URL=''
mock_network_ok=0
if ( eval "$wipe_preparation" ) >"${tmp_dir}/result" 2>"${tmp_dir}/messages"; then
	exit 1
fi
[[ "$(wc -l <"${tmp_dir}/download.log")" -eq 1 ]]
grep -Fq 'Cancelled before erase or DFU' "${tmp_dir}/messages"
echo 'PASS: the real wipe preparation exits without downloading when no erase package is available'
