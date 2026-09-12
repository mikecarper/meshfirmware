#!/usr/bin/env bash
# Test fixture functions are invoked indirectly by evaluated production code.
# shellcheck disable=SC2317

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script_path="${repo_root}/mcfirmware.sh"
tmp_dir="$(mktemp -d)"
trap 'rm -rf -- "$tmp_dir"' EXIT

definition="$(awk '
	/^ensure_pipx_uv_backend\(\) \{/ { capture = 1 }
	capture { print }
	capture && /^}$/ { exit }
' "$script_path")"
[[ "$definition" == 'ensure_pipx_uv_backend() {'* ]]
# Deliberately evaluate the function extracted from the production script.
# shellcheck disable=SC2294
eval "$definition"

ensure_command() {
	[[ "$1" == pipx ]]
}

run_uv_case() (
	local fake_uv="${tmp_dir}/uv"
	touch "$fake_uv"
	chmod +x "$fake_uv"
	pipx() {
		case "${*: -1}" in
			PIPX_UV_BINARY) printf '%s\n' "$fake_uv" ;;
			PIPX_RESOLVED_BACKEND) printf '%s\n' "${PIPX_DEFAULT_BACKEND:-pip}" ;;
		esac
	}
	ensure_pipx_uv_backend
	[[ "$PIPX_DEFAULT_BACKEND" == uv ]]
)

run_pip_fallback_case() (
	local output_file="${tmp_dir}/fallback-output"
	local output=""
	pipx() {
		case "${*: -1}" in
			PIPX_UV_BINARY) return 0 ;;
			PIPX_RESOLVED_BACKEND) printf '%s\n' pip ;;
		esac
	}
	ensure_pipx_uv_backend > "$output_file"
	output="$(<"$output_file")"
	[[ "$PIPX_DEFAULT_BACKEND" == pip ]]
	[[ "$output" == "pipx uv backend is unavailable; using the standard pip backend." ]]
)

run_uv_case
run_pip_fallback_case

if grep -Fq "install --force 'pipx[uv]'" <<< "$definition"; then
	echo "FAIL: unavailable uv still triggers a repeated pipx self-install" >&2
	exit 1
fi

echo "PASS: pipx uses uv when available and otherwise continues with pip"
