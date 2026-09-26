#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT

eval "$(sed -n '/^describe_esp32_partition_table() {/,/^}/p' "$repo_root/mcfirmware.sh")"
python3 - "$tmp_dir/partitions.bin" <<'PY'
import struct
import sys

data = bytearray(b'\xff' * 4096)
parts = [
    ('nvs', 1, 2, 0x9000, 0x5000),
    ('otadata', 1, 0, 0xe000, 0x2000),
    ('app0', 0, 0x10, 0x10000, 0x640000),
    ('app1', 0, 0x11, 0x650000, 0x640000),
    ('spiffs', 1, 0x82, 0xc90000, 0x360000),
]
for index, (name, kind, subtype, offset, size) in enumerate(parts):
    entry = struct.pack('<2sBBII16sI', b'\xaa\x50', kind, subtype,
                        offset, size, name.encode(), 0)
    data[index * 32:(index + 1) * 32] = entry
open(sys.argv[1], 'wb').write(data)
PY

report=$(describe_esp32_partition_table "$tmp_dir/partitions.bin" 2>&1)
[[ "$report" == *'app0: type=0x00 subtype=0x10 offset=0x10000 size=0x640000 (6400 KiB)'* ]]
[[ "$report" == *'app1: type=0x00 subtype=0x11 offset=0x650000 size=0x640000 (6400 KiB)'* ]]
[[ "$report" == *'nvs: type=0x01 subtype=0x02 offset=0x9000 size=0x5000 (20 KiB)'* ]]
[[ "$report" == *'spiffs: type=0x01 subtype=0x82 offset=0xc90000 size=0x360000 (3456 KiB)'* ]]
head -c 100 "$tmp_dir/partitions.bin" > "$tmp_dir/truncated.bin"
if describe_esp32_partition_table "$tmp_dir/truncated.bin" >/dev/null 2>&1; then
    echo 'incomplete ESP32 partition table was accepted' >&2
    exit 1
fi
echo 'ESP32 partition report: OK'
