#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script_path="${repo_root}/mcsetup.sh"

extract_function() {
	local function_name=$1
	awk -v signature="${function_name}() {" '
		$0 == signature { capture = 1 }
		capture { print }
		capture && $0 == "}" { exit }
	' "$script_path"
}

for function_name in system_clock_is_synchronized \
	restart_stopped_time_sync_services stop_active_time_sync_services force_time_sync; do
	definition="$(extract_function "$function_name")"
	[[ "$definition" == "${function_name}() {"* ]]
	# Deliberately evaluate functions extracted from the production script.
	# shellcheck disable=SC2294
	eval "$definition"
done

run_already_synchronized_case() (
	TIME_SYNC_STOPPED_SERVICES=()
	timedatectl() {
		[[ "$*" == 'show -p NTPSynchronized --value' ]]
		printf '%s\n' yes
	}
	ntpd() {
		echo 'FAIL: ntpd ran for an already synchronized host' >&2
		return 1
	}
	sudo() { "$@"; }
	output="$(force_time_sync)"
	[[ "$output" == 'System clock is already synchronized.' ]]
)
run_already_synchronized_case
echo 'PASS: an already synchronized host does not launch a competing ntpd'

run_ntpd_service_case() (
	local ntp_active=1
	local -a calls=()
	TIME_SYNC_STOPPED_SERVICES=()
	timedatectl() { printf '%s\n' no; }
	systemctl() {
		case "$1:$2" in
			is-active:--quiet)
				[[ "$3" == ntp.service && "$ntp_active" -eq 1 ]]
				;;
			stop:ntp.service)
				calls+=(stop)
				ntp_active=0
				;;
			start:ntp.service)
				calls+=(start)
				ntp_active=1
				;;
			*) return 1 ;;
		esac
	}
	ntpd() {
		[[ "$*" == '-gq' ]]
		calls+=(ntpd)
	}
	sudo() { "$@"; }
	force_time_sync >/dev/null
	[[ "${calls[*]}" == 'stop ntpd start' ]]
	[[ "$ntp_active" -eq 1 ]]
	((${#TIME_SYNC_STOPPED_SERVICES[@]} == 0))
)
run_ntpd_service_case
echo 'PASS: active ntp service is stopped for one-shot sync and restored afterwards'

run_failed_ntpd_case() (
	local ntp_active=1
	local -a calls=()
	TIME_SYNC_STOPPED_SERVICES=()
	timedatectl() { printf '%s\n' no; }
	systemctl() {
		case "$1:$2" in
			is-active:--quiet)
				[[ "$3" == ntp.service && "$ntp_active" -eq 1 ]]
				;;
			stop:ntp.service)
				calls+=(stop)
				ntp_active=0
				;;
			start:ntp.service)
				calls+=(start)
				ntp_active=1
				;;
			*) return 1 ;;
		esac
	}
	ntpd() {
		calls+=(ntpd-failed)
		return 7
	}
	sudo() { "$@"; }
	if force_time_sync >/dev/null 2>&1; then
		echo 'FAIL: failed ntpd run returned success' >&2
		exit 1
	fi
	[[ "${calls[*]}" == 'stop ntpd-failed start' ]]
	[[ "$ntp_active" -eq 1 ]]
)
run_failed_ntpd_case
echo 'PASS: ntp service is restored even when one-shot synchronization fails'

if ! grep -Fq 'restart_stopped_time_sync_services' < <(extract_function cleanup); then
	echo 'FAIL: mcsetup cleanup does not restore a stopped time service' >&2
	exit 1
fi
echo 'PASS: mcsetup cleanup restores time services after interruption'
