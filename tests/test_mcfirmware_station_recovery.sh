#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
definition="$(sed -n '/^esp32_recovery_early_menu() {/,/^}/p' "$repo_root/mcfirmware.sh")"
eval "$definition"
run_esp32_recovery() {
    [[ "$*" == '--station --manual-boot --board g3' ]] || return 90
    return 7
}
set +e
(esp32_recovery_early_menu --recover-station --manual-boot --board g3)
status=$?
set -e
[[ "$status" == 7 ]]
run_esp32_recovery() {
    [[ "$*" == '--manual-boot --firmware /tmp/board.bin' ]] || return 90
    return 2
}
set +e
(esp32_recovery_early_menu --recover-esp32 --manual-boot --firmware /tmp/board.bin)
status=$?
set -e
[[ "$status" == 2 ]]
printf '%s\n' 'PASS: direct recovery dispatch forwards options and preserves failure exit status'
