#!/bin/bash
set -euo pipefail

IFACE="wlan0"
PUBLIC_IP="1.1.1.1"
FAIL_FILE="/run/wifi-local-fail-start"
REBOOT_AFTER=1800

GW="$(ip route show default 0.0.0.0/0 dev "$IFACE" | awk '/default/ {print $3; exit}')"
CONN="$(nmcli -t -f NAME,DEVICE connection show --active | awk -F: -v i="$IFACE" '$2==i {print $1; exit}')"
NOW="$(date +%s)"

public_ok=0
private_ok=0

if [[ -z "${CONN:-}" ]]; then
    if [[ ! -f "$FAIL_FILE" ]]; then
        echo "$NOW" > "$FAIL_FILE"
        logger -t wifi-refresh "No active connection on $IFACE. Starting reboot timer."
    fi

    FAIL_START="$(cat "$FAIL_FILE" 2>/dev/null || echo "$NOW")"
    AGE=$((NOW - FAIL_START))

    logger -t wifi-refresh "No active connection on $IFACE for ${AGE}s. Cycling Wi-Fi."
    nmcli radio wifi off >/dev/null 2>&1 || true
    sleep 5
    nmcli radio wifi on >/dev/null 2>&1 || true
    nmcli device connect "$IFACE" >/dev/null 2>&1 || true

    if (( AGE >= REBOOT_AFTER )); then
        logger -t wifi-refresh "No active connection on $IFACE for ${AGE}s. Rebooting."
        /sbin/reboot
    fi

    exit 0
fi

if ping -I "$IFACE" -c 1 -W 3 "$PUBLIC_IP" >/dev/null 2>&1; then
    public_ok=1
fi

if [[ -n "${GW:-}" ]] && ping -I "$IFACE" -c 1 -W 2 "$GW" >/dev/null 2>&1; then
    private_ok=1
fi

# Case 1: both OK
if (( private_ok == 1 && public_ok == 1 )); then
    rm -f "$FAIL_FILE"
    exit 0
fi

# Case 2: private OK, public FAIL
# Router path is fine, likely ISP/upstream issue. Do not reboot.
if (( private_ok == 1 && public_ok == 0 )); then
    rm -f "$FAIL_FILE"
    logger -t wifi-refresh "Gateway OK but public ping failed. Likely upstream outage. No reboot."
    exit 0
fi

# Case 3: private FAIL, public OK
# Odd case. Refresh Wi-Fi/DHCP, but no reboot timer.
if (( private_ok == 0 && public_ok == 1 )); then
    logger -t wifi-refresh "Public OK but gateway failed. Reconnecting $CONN."
    nmcli connection down id "$CONN" >/dev/null 2>&1 || true
    sleep 3
    nmcli connection up id "$CONN" >/dev/null 2>&1 || true
    rm -f "$FAIL_FILE"
    exit 0
fi

# Case 4: both FAIL
# Local problem. Start timer, try reconnect, reboot after 30 min.
if [[ ! -f "$FAIL_FILE" ]]; then
    echo "$NOW" > "$FAIL_FILE"
    logger -t wifi-refresh "Both private and public checks failed. Starting reboot timer."
fi

FAIL_START="$(cat "$FAIL_FILE" 2>/dev/null || echo "$NOW")"
AGE=$((NOW - FAIL_START))

logger -t wifi-refresh "Both checks failed for ${AGE}s. Reconnecting $CONN."
nmcli connection down id "$CONN" >/dev/null 2>&1 || true
sleep 3
nmcli connection up id "$CONN" >/dev/null 2>&1 || true

if (( AGE >= REBOOT_AFTER )); then
    logger -t wifi-refresh "Both checks failed for ${AGE}s. Rebooting."
    /sbin/reboot
fi
