#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp_dir="$(mktemp -d)"
trap 'rm -rf -- "$tmp_dir"' EXIT

extract_function() {
	local script_path=$1
	local function_name=$2
	awk -v signature="${function_name}() {" '
		$0 == signature { capture = 1 }
		capture { print }
		capture && $0 == "}" { exit }
	' "$script_path"
}

for script_name in mcfirmware.sh mcsetup.sh mtfirmware.sh; do
	script_path="${repo_root}/${script_name}"
	for function_name in \
		package_name_for_manager apt_update_or_use_cached_metadata install_packages; do
		definition="$(extract_function "$script_path" "$function_name")"
		[[ "$definition" == "${function_name}() {"* ]] || {
			echo "FAIL: could not extract ${function_name} from ${script_name}" >&2
			exit 1
		}
		# Deliberately evaluate functions extracted from the production script.
		# shellcheck disable=SC2294
		eval "$definition"
	done

	PACKAGE_MANAGER=apt-get
	PACKAGE_METADATA_UPDATED=0
	sudo_log="${tmp_dir}/${script_name}.sudo.log"
	: > "$sudo_log"
	sudo() {
		printf '%s\n' "$*" >> "$sudo_log"
		if [[ "$*" == "apt-get update" ]]; then
			return 1
		fi
		return 0
	}
	detect_package_manager() {
		return 0
	}
	no_sudo_mode() {
		return 1
	}

	printf 'y\n' > "${tmp_dir}/answer"
	MESHFIRMWARE_TTY="${tmp_dir}/answer"
	install_packages lsof
	[[ "$PACKAGE_METADATA_UPDATED" -eq 1 ]]
	grep -Fxq -- "apt-get update" "$sudo_log"
	grep -Fxq -- "apt-get install -y lsof" "$sudo_log"
	if grep -Fq -- "allow-unauthenticated" "$sudo_log"; then
		echo "FAIL: ${script_name} disabled package authentication" >&2
		exit 1
	fi

	PACKAGE_METADATA_UPDATED=0
	: > "$sudo_log"
	printf 'n\n' > "${tmp_dir}/answer"
	if install_packages lsof; then
		echo "FAIL: ${script_name} ignored a declined cached-index prompt" >&2
		exit 1
	fi
	grep -Fxq -- "apt-get update" "$sudo_log"
	if grep -Fq -- "apt-get install" "$sudo_log"; then
		echo "FAIL: ${script_name} installed after the fallback was declined" >&2
		exit 1
	fi
done

echo "PASS: apt update failures offer a safe cached-metadata fallback"
