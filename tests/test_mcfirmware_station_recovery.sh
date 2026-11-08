#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
definition="$(sed -n '/^station_recovery_early_menu() {/,/^}/p' "$repo_root/mcfirmware.sh")"
eval "$definition"
run_station_recovery() {
    [[ "$*" == '--manual-boot --board g3' ]] || return 90
    return 7
}
set +e
(station_recovery_early_menu --recover-station --manual-boot --board g3)
status=$?
set -e
[[ "$status" == 7 ]]
printf '%s\n' 'PASS: direct recovery dispatch forwards options and preserves failure exit status'
