#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
definition="$(sed -n '/^meshcore_bluetooth_usb_notice() {/,/^}/p' "$repo_root/mcfirmware.sh")"
[[ "$definition" == 'meshcore_bluetooth_usb_notice() {'* ]]
eval "$definition"
device='Seeed Studio SenseCAP T1000-E'
file='t1000e_companion_radio_full-v1.18.0.1-halo-keymind-cascade-dev-12345678.zip'
for alias in "$device" 'Seeed Tracker T1000-E' 'T1000-E'; do
    for role in companionFull companionBle companion; do
        notice="$(meshcore_bluetooth_usb_notice "$alias" "$role" "$file")"
        [[ "$notice" == *'Bluetooth (BLE)'*'paused'*'computer by USB'* ]]
        [[ "$notice" == *'Finish any USB verification first, then unplug USB'* ]]
        [[ "$notice" == *"enabled in the radio's settings"* ]]
    done
done
for role in repeater roomServer sensor companionUsb '' auto; do
    [[ -z "$(meshcore_bluetooth_usb_notice "$device" "$role" "$file")" ]]
done
for other in 'RAK 4631' 'Seeed Studio Wio WM1110' 'Seeed Studio Xiao nRF52 WIO' 'Heltec v4' '' 'T1000-E Plus'; do
    [[ -z "$(meshcore_bluetooth_usb_notice "$other" companionFull "$file")" ]]
done
for other in \
    t1000e_companion_radio_full-v1.18.0.1.zip \
    t1000e_companion_radio_usb-v1.18.0.1-keymind.zip \
    t1000e_repeater-v1.18.0.1-keymind.zip \
    t1000e_companion_radio_full-bootloader-keymind.zip \
    t1000e_companion_radio_full-with-bootloader-unknown-keymind.zip \
    t1000e_companion_radio_full-with-bootloader-2.4.12.1.99-keymind.zip \
    t1000e_companion_radio_full-with-bootloader-2.4.12-bootloader-keymind.zip \
    t1000e_companion_radio_full-softdevice-keymind.zip \
    t1000e_companion_radio_full-erase-keymind.zip \
    t1000e_companion_radio_full-recovery-keymind.zip \
    R_t1000e_companion_radio_full-keymind.zip \
    unknown-keymind.zip \
    t1000e_companion_radio_full-keymind.uf2; do
    [[ -z "$(meshcore_bluetooth_usb_notice "$device" companionFull "$other")" ]]
done
[[ -n "$(meshcore_bluetooth_usb_notice "$device" companionBle "${file/_full-/_ble-}")" ]]
for version in 0.4 2.4.12 2.4.12.1; do
    [[ -n "$(meshcore_bluetooth_usb_notice "$device" companionFull "${file/_full-/_full-with-bootloader-$version-}")" ]]
done
[[ -z "$(meshcore_bluetooth_usb_notice)" ]]
# The call site is only after the final DFU branch succeeds, never inside the
# intermediate erase or before the echo-only early exit. The selected role is
# loaded explicitly because the firmware menu keeps its own role local.
python3 - "$repo_root/mcfirmware.sh" <<'PY'
import pathlib, sys
source = pathlib.Path(sys.argv[1]).read_text()
assert source.count('meshcore_bluetooth_usb_notice "$DEVICE" "${ROLE:-}" "$DOWNLOADED_FILE"') == 1
assert '[[ -f "$SELECTED_ROLE_FILE" ]] && ROLE="$(<"$SELECTED_ROLE_FILE")"' in source
call = source.index('meshcore_bluetooth_usb_notice "$DEVICE" "${ROLE:-}" "$DOWNLOADED_FILE"')
assert source.rindex('Echo-only selected; no nRF52 DFU commands were run.', 0, call) < source.rindex('run_nrf52_dfu_package_buttonless "$DOWNLOADED_FILE"', 0, call)
assert source.rindex('Application startup has not been verified;', 0, call) < call
assert source.rindex('Firmware ${ACTION} failed', 0, call) < call
assert source[call:].splitlines()[1] == 'fi'
PY
printf '%s\n' 'PASS: Keymind T1000-E BLE/Full completion reminders, exclusions, and Linux final-success integration'
