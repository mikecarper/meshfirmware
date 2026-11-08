#!/bin/sh
# ESP32-family USB recovery. Run the copy in the extracted recovery bundle.
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if ! command -v python3 >/dev/null 2>&1; then
    echo 'Install Python 3.10 or newer from https://www.python.org/downloads/ and run again.' >&2
    exit 1
fi
exec python3 "$here/tools/esp32_recovery.py" "$@"
