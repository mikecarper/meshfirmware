#!/usr/bin/env bash
# Exercise the real resolver/manifest/hash with no devices or network.
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script_path="$repo_root/mcfirmware.sh"
scratch="$(mktemp -d)"
trap 'rm -rf -- "$scratch"' EXIT
for name in MESHCORE_PARTITION_EXPANSION_TOOL_URL MESHCORE_PARTITION_EXPANSION_TOOL_SHA256 \
    MESHCORE_PARTITION_EXPANSION_TOOL_MANIFEST MESHCORE_PARTITION_EXPANSION_TOOL_API_VERSION \
    MESHCORE_PARTITION_EXPANSION_TOOL_PLAN_FORMAT; do
    definition="$(grep -m1 "^${name}=" "$script_path")"
    [[ "$definition" == "$name="* ]] || exit 1
    eval "$definition"
done
for name in meshcore_partition_expansion_tool_hash_matches meshcore_partition_expansion_manifest_values \
    resolve_meshcore_partition_expansion_tool; do
    definition="$(awk -v signature="$name() {" '$0 == signature {capture=1} capture {print} capture && $0 == "}" {exit}' "$script_path")"
    [[ "$definition" == "$name() {"* ]] || exit 1
    eval "$definition"
done
FIRMWARE_ROOT="$scratch/cache"
network_log="$scratch/downloads"
curl() {
    printf 'attempt\n' >>"$network_log"
    local output="" previous="" argument
    for argument in "$@"; do
        [[ "$previous" != -o ]] || output="$argument"
        previous="$argument"
    done
    [[ "${download_failure:-1}" == 0 && -n "$output" ]] || return 1
    cp "$download_fixture" "$output"
}
expect_failure() {
    if "$@" >"$scratch/out" 2>"$scratch/err"; then
        echo 'Expected resolver refusal.' >&2; exit 1
    fi
}

# This production case has NO test-supplied hash. It catches the original bug.
PWD_SCRIPT="$repo_root"
[[ "$(resolve_meshcore_partition_expansion_tool)" == "$repo_root/tools/meshcore_partition_expansion.py" ]]
[[ ! -e "$network_log" ]]

PWD_SCRIPT="$scratch/checkout"
mkdir -p "$PWD_SCRIPT/tools"
helper="$PWD_SCRIPT/tools/meshcore_partition_expansion.py"
manifest="$PWD_SCRIPT/tools/$MESHCORE_PARTITION_EXPANSION_TOOL_MANIFEST"
cp "$repo_root/tools/meshcore_partition_expansion.py" "$helper"
cp "$repo_root/tools/$MESHCORE_PARTITION_EXPANSION_TOOL_MANIFEST" "$manifest"
printf '\nraise RuntimeError("resolver must not execute this future helper")\n' >>"$helper"
python3 "$repo_root/tools/generate_partition_helper_manifest.py" --helper "$helper" --output "$manifest" >/dev/null
[[ "$(resolve_meshcore_partition_expansion_tool)" == "$helper" ]]
cp "$manifest" "$scratch/good.json"
cp "$helper" "$scratch/good.py"

# Both platforms canonicalize Windows line endings without rewriting the file.
python3 - "$helper" <<'PY'
import pathlib,sys
p=pathlib.Path(sys.argv[1]); p.write_bytes(p.read_bytes().replace(b'\n',b'\r\n'))
PY
[[ "$(resolve_meshcore_partition_expansion_tool)" == "$helper" ]]

for field in api_version plan_format helper sha256 bytes schema duplicate unknown; do
    cp "$scratch/good.json" "$manifest"
    python3 - "$manifest" "$field" <<'PY'
import json,pathlib,sys
p=pathlib.Path(sys.argv[1]); d=json.loads(p.read_text()); field=sys.argv[2]
if field=='duplicate': p.write_text(p.read_text().replace('"api_version": 1','"api_version": 1, "api_version": 1'))
else:
    d[field]={'api_version':2,'plan_format':'meshcore-usb-partition-expansion-v3',
        'helper':'../untrusted.py','sha256':'0'*64,'bytes':True,'schema':'wrong','unknown':1}[field]
    p.write_text(json.dumps(d))
PY
    expect_failure resolve_meshcore_partition_expansion_tool
done
cp "$scratch/good.json" "$manifest"
printf 'tampered\n' >>"$helper"
expect_failure resolve_meshcore_partition_expansion_tool
cp "$scratch/good.py" "$helper"
mv "$helper" "$scratch/temporarily-absent.py"
expect_failure resolve_meshcore_partition_expansion_tool
mv "$scratch/temporarily-absent.py" "$helper"
rm "$manifest"
expect_failure resolve_meshcore_partition_expansion_tool
[[ ! -e "$network_log" ]]

# Standalone legacy fallback branch uses hermetic bytes, not network or Python
# execution. The production immutable URL/hash are checked separately in Python.
PWD_SCRIPT="$scratch/standalone"
download_fixture="$scratch/good.py"
MESHCORE_PARTITION_EXPANSION_TOOL_SHA256="$(python3 - "$download_fixture" <<'PY'
import hashlib,pathlib,sys
print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())
PY
)"
download_failure=0
cached="$(resolve_meshcore_partition_expansion_tool)"
[[ "$cached" == "$FIRMWARE_ROOT/tools/meshcore_partition_expansion.py" ]]
[[ "$(wc -l <"$network_log")" == 1 ]]
[[ "$(resolve_meshcore_partition_expansion_tool)" == "$cached" ]]
[[ "$(wc -l <"$network_log")" == 1 ]]
printf 'old cache\n' >"$cached"
cp "$cached" "$scratch/cache-before"
download_failure=1
expect_failure resolve_meshcore_partition_expansion_tool
cmp "$cached" "$scratch/cache-before"
download_failure=0
printf 'corrupt downloaded helper\n' >"$scratch/bad-download.py"
download_fixture="$scratch/bad-download.py"
expect_failure resolve_meshcore_partition_expansion_tool
cmp "$cached" "$scratch/cache-before"
[[ -z "$(find "$FIRMWARE_ROOT" -name '*.partial.*' -print)" ]]
echo 'Partition helper: real bundled contract, future compatibility, tampering, and immutable fallback checks passed.'
