#!/usr/bin/env bash

# Hermetic integration/static checks for the Linux MeshCore backup gate.
# No hardware, network access, package installation, or firmware commands are used.

set -uo pipefail

TEST_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd -- "${TEST_DIR}/.." && pwd)"
FIRMWARE_SCRIPT="${REPO_DIR}/mcfirmware.sh"
BACKUP_HELPER="${REPO_DIR}/tools/meshcore_backup.py"
FAILURES=0

fail() {
	printf 'FAIL: %s\n' "$1" >&2
	FAILURES=$((FAILURES + 1))
}

pass() {
	printf 'PASS: %s\n' "$1"
}

extract_function() {
	local function_name="$1"
	awk -v signature="${function_name}() {" '
		$0 == signature { copying = 1 }
		copying { print }
		copying && $0 == "}" { exit }
	' "$FIRMWARE_SCRIPT"
}

extract_backup_region() {
	awk '
		/^resolve_meshcore_backup_tool\(\) \{/ { copying = 1 }
		/^print_nrfutil_dfu_command\(\) \{/ { exit }
		copying { print }
	' "$FIRMWARE_SCRIPT"
}

if [[ ! -r "$FIRMWARE_SCRIPT" ]]; then
	printf 'FAIL: cannot read %s\n' "$FIRMWARE_SCRIPT" >&2
	exit 1
fi

# Load only the backup integration functions. Removing the /dev/tty input
# redirections lets each case provide deterministic prompt responses on stdin.
BACKUP_REGION="$(extract_backup_region | sed -E 's@[[:space:]]*<[[:space:]]*/dev/tty@@g')"
if [[ -z "$BACKUP_REGION" ]]; then
	printf 'FAIL: could not extract the MeshCore backup integration functions\n' >&2
	exit 1
fi
eval "$BACKUP_REGION"

TEST_TMP="$(mktemp -d)"
case "$TEST_TMP" in
	/tmp/*|/var/tmp/*) ;;
	*) printf 'FAIL: unexpected temporary directory: %s\n' "$TEST_TMP" >&2; exit 1 ;;
esac
trap 'rm -rf -- "$TEST_TMP"' EXIT

FAKE_ARCHIVE="${TEST_TMP}/backup.json"
printf '{}\n' > "$FAKE_ARCHIVE"
FAKE_MODE=safe
BACKUP_CALLED_FILE="${TEST_TMP}/backup-called"

# Replace every external operation reached by the request function.
resolve_meshcore_backup_tool() {
	printf '%s\n' fake_helper
}

ensure_meshcore_backup_python() {
	printf '%s\n' fake_backup_python
}

meshcore_linux_usb_identity_args() {
	return 0
}

fake_backup_python() {
	local operation="${2:-}"
	if [[ "$operation" == "backup" ]]; then
		printf 'called\n' >> "$BACKUP_CALLED_FILE"
	fi

	case "$FAKE_MODE" in
		non_json)
			printf 'helper diagnostic, but no JSON summary\n'
			return 0
			;;
		unsafe)
			printf '{"ok":true,"exit_code":0,"archive":"%s","path":"%s","completeness":"partial","safe_for_wipe":false}\n' \
				"$FAKE_ARCHIVE" "$FAKE_ARCHIVE"
			if [[ "$operation" == "verify" ]]; then
				return 40
			fi
			return 0
			;;
		safe)
			printf '{"ok":true,"exit_code":0,"archive":"%s","path":"%s","completeness":"complete","safe_for_wipe":true}\n' \
				"$FAKE_ARCHIVE" "$FAKE_ARCHIVE"
			return 0
			;;
		*)
			printf 'unknown fake mode\n' >&2
			return 99
			;;
	esac
}

run_request() {
	local action="$1"
	local responses="$2"
	local output_file="${TEST_TMP}/request-output"

	printf '%b' "$responses" | request_meshcore_usb_backup_before_flash \
		"$action" /dev/ttyFAKE 'Test nRF52' companion test-if00 \
		>"$output_file" 2>&1
	REQUEST_RC=${PIPESTATUS[1]}
	REQUEST_OUTPUT="$(<"$output_file")"
}

# Exit status alone is not proof that a usable backup exists. A wipe must stay
# blocked when the helper does not emit its documented JSON summary.
FAKE_MODE=non_json
rm -f -- "$BACKUP_CALLED_FILE"
run_request flash-wipe '\n\n'
if (( REQUEST_RC == 0 )); then
	fail 'non-JSON helper output with exit 0 authorized a destructive wipe'
else
	pass 'non-JSON helper output cannot authorize a destructive wipe'
fi

# Even internally consistent exit-0 JSON is not wipe-safe unless the summary
# explicitly says safe_for_wipe=true (and the archive is verifiable).
FAKE_MODE=unsafe
rm -f -- "$BACKUP_CALLED_FILE"
run_request flash-wipe '\n\n'
if (( REQUEST_RC == 0 )); then
	fail 'safe_for_wipe=false helper summary authorized a destructive wipe'
else
	pass 'unsafe helper summary cannot authorize a destructive wipe'
fi

# An unrecognised answer must not be interpreted as an intentional "no" and
# silently authorize an update. Re-prompting and then making a backup, or
# rejecting EOF, are both safe outcomes.
FAKE_MODE=safe
rm -f -- "$BACKUP_CALLED_FILE"
run_request flash-update 'definitely-not-a-choice\n\n'
if (( REQUEST_RC == 0 )) && [[ ! -s "$BACKUP_CALLED_FILE" ]]; then
	fail 'invalid Y/n input silently skipped backup and authorized update'
else
	pass 'invalid Y/n input cannot silently skip backup'
fi

# Auto-detection runs before the final backup gate. It therefore must remain a
# read-only classification step and contain no direct or transitive baud-touch /
# DFU transition before its own early backup gate.
AUTODETECT_SOURCE="$(extract_function autodetect_device)"
AUTODETECT_BEFORE_BACKUP="${AUTODETECT_SOURCE%%request_meshcore_usb_backup_before_flash*}"
AUTO_RESET_SOURCE="$(extract_function auto_reset_serial_port)"
PREBACKUP_RESET_CHAIN=''
for probe_name in probe_esptool probe_esptool_mac; do
	if grep -Eq "(^|[^[:alnum:]_])${probe_name}([^[:alnum:]_]|$)" <<<"$AUTODETECT_BEFORE_BACKUP"; then
		probe_source="$(extract_function "$probe_name")"
		unguarded_calls="$(grep -E "(^|[^[:alnum:]_])${probe_name}([^[:alnum:]_]|$)" <<<"$AUTODETECT_BEFORE_BACKUP" \
			| grep -Ev "MESH_DISABLE_1200_RECOVERY=1[[:space:]]+${probe_name}([^[:alnum:]_]|$)" || true)"
		if [[ -n "$unguarded_calls" ]] \
			&& grep -Eq '(^|[^[:alnum:]_])auto_reset_serial_port([^[:alnum:]_]|$)' <<<"$probe_source" \
			&& grep -Eq -- 'stty.*[[:space:]]1200|--baud[[:space:]]+1200|--touch[[:space:]]+1200' <<<"$AUTO_RESET_SOURCE"; then
			PREBACKUP_RESET_CHAIN="${probe_name} -> auto_reset_serial_port -> 1200 baud"
			break
		fi
		if grep -Eq '(^|[^[:alnum:]_])auto_reset_serial_port([^[:alnum:]_]|$)' <<<"$probe_source" \
			&& ! grep -Fq 'MESH_DISABLE_1200_RECOVERY' <<<"$probe_source"; then
			PREBACKUP_RESET_CHAIN="${probe_name} ignores its pre-backup 1200-recovery guard"
			break
		fi
	fi
done
if [[ -z "$AUTODETECT_SOURCE" ]]; then
	fail 'could not extract autodetect_device for the pre-backup ordering check'
elif grep -Eq -- '--baud[[:space:]]+1200|stty.*[[:space:]]1200|--touch[[:space:]]+1200' <<<"$AUTODETECT_BEFORE_BACKUP"; then
	fail 'autodetect_device can trigger 1200 baud before the MeshCore backup gate'
elif [[ -n "$PREBACKUP_RESET_CHAIN" ]]; then
	fail "autodetect_device has a pre-backup reset chain: ${PREBACKUP_RESET_CHAIN}"
else
	pass 'autodetect_device performs no 1200-baud transition before backup'
fi

# Keep the supported dependency contract visible at both entry points.
for required_text in \
	"meshcore>=2.3.9,<3" \
	"meshcore-cli>=1.6.3,<2" \
	"PyNaCl>=1.5,<2" \
	"sys.version_info >= (3, 10)"
do
	if grep -Fq -- "$required_text" "$FIRMWARE_SCRIPT"; then
		pass "mcfirmware.sh enforces ${required_text}"
	else
		fail "mcfirmware.sh does not enforce ${required_text}"
	fi
done

# A cached helper is executable code and owns the archive safety contract. The
# launcher must reject an older helper instead of trusting its historical
# safe_for_wipe decision.
HELPER_VERSION="$(sed -n 's/^TOOL_VERSION = "\([^"]*\)"$/\1/p' "$BACKUP_HELPER" | head -n1)"
RESOLVER_SOURCE="$(extract_function resolve_meshcore_backup_tool)"
if [[ -z "$HELPER_VERSION" ]]; then
	fail 'could not read the bundled backup helper contract version'
elif ! grep -Fq -- "MESHCORE_BACKUP_TOOL_VERSION=\"${HELPER_VERSION}\"" "$FIRMWARE_SCRIPT"; then
	fail 'mcfirmware.sh helper contract version does not match the bundled helper'
elif ! grep -Fq -- 'meshcore_backup_tool_version_matches "$cached_tool"' <<<"$RESOLVER_SOURCE"; then
	fail 'mcfirmware.sh can reuse a cached helper without checking its contract version'
elif ! grep -Fq -- 'meshcore_backup_tool_version_matches "$partial_tool"' <<<"$RESOLVER_SOURCE"; then
	fail 'mcfirmware.sh can install a downloaded helper without checking its contract version'
else
	pass "mcfirmware.sh pins the backup helper contract at ${HELPER_VERSION}"
fi

HELPER_SHA256="$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "$BACKUP_HELPER")"
VERSION_CHECK_SOURCE="$(extract_function meshcore_backup_tool_version_matches)"
if ! grep -Fq -- "MESHCORE_BACKUP_TOOL_SHA256=\"${HELPER_SHA256}\"" "$FIRMWARE_SCRIPT"; then
	fail 'mcfirmware.sh helper SHA-256 pin does not match the bundled helper'
elif ! grep -Fq -- '[[ "$actual_hash" == "$MESHCORE_BACKUP_TOOL_SHA256" ]]' <<<"$VERSION_CHECK_SOURCE"; then
	fail 'mcfirmware.sh does not enforce its helper SHA-256 pin'
else
	pass "mcfirmware.sh pins the backup helper SHA-256 at ${HELPER_SHA256}"
fi

if (( FAILURES != 0 )); then
	printf '%d MeshCore backup integration test(s) failed.\n' "$FAILURES" >&2
	exit 1
fi

printf 'All mcfirmware.sh backup integration tests passed.\n'
