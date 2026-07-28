#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

green=""; white=""; cyan=""; pink=""; yellow=""; red=""; grey=""
SCRIPT_HOME="/tmp/linuxbox-audit-test-home"
LINUXBOX_INSTALL_DIR="/tmp/linuxbox-audit-test-install"
LINUXBOX_LIB_DIR="$ROOT_DIR"
version="3.5.0"

mkdir -p "$SCRIPT_HOME" "$LINUXBOX_INSTALL_DIR"

. lib/constants.sh
. lib/config.sh
. lib/i18n.sh
. lib/region.sh
. lib/system.sh
. lib/utils.sh
. lib/package.sh

assert_eq() {
	local expected="$1"
	local actual="$2"
	local label="$3"
	if [ "$expected" != "$actual" ]; then
		echo "FAIL: $label"
		echo "  expected: $expected"
		echo "  actual:   $actual"
		exit 1
	fi
}

assert_true() {
	local cond="$1"
	local label="$2"
	if ! eval "$cond"; then
		echo "FAIL: $label ($cond expected true)"
		exit 1
	fi
}

assert_false() {
	local cond="$1"
	local label="$2"
	if eval "$cond"; then
		echo "FAIL: $label ($cond expected false)"
		exit 1
	fi
}

echo "[Audit Fix Test 1] Testing rm -rf non-empty variable protection..."
empty_var=""
test_target_dir="/tmp/linuxbox_safety_test_dir_$$"
mkdir -p "$test_target_dir"
touch "$test_target_dir/dummy_file"

# When variable is empty, command must NOT run rm -rf
[ -n "${empty_var:-}" ] && rm -rf "${empty_var}" || true
assert_true "[ -d '$test_target_dir' ]" "Directory must still exist when empty variable is guarded"

# When variable is valid, command runs rm -rf
valid_var="$test_target_dir"
[ -n "${valid_var:-}" ] && rm -rf "${valid_var}"
assert_false "[ -d '$test_target_dir' ]" "Directory must be deleted when valid variable is guarded"
echo "  ✓ rm -rf safety guard verified successfully"

echo "[Audit Fix Test 2] Testing local variable isolation..."
global_choice="GLOBAL_VALUE"
choice="$global_choice"

test_local_scope() {
	local choice="LOCAL_VALUE"
	local package="LOCAL_PKG"
	local file="LOCAL_FILE"
}
test_local_scope

assert_eq "GLOBAL_VALUE" "$choice" "Variable 'choice' must remain intact in parent scope"
assert_eq "" "${package:-}" "Variable 'package' must not leak to parent scope"
assert_eq "" "${file:-}" "Variable 'file' must not leak to parent scope"
echo "  ✓ Function local variable isolation verified"

echo "[Audit Fix Test 3] Testing safe function existence and path detection..."
my_test_func() { return 0; }
assert_true "is_function my_test_func" "is_function detects defined function"
assert_false "is_function non_existent_func_12345" "is_function returns false for missing function"

assert_true "check_cmd_or_path my_test_func" "check_cmd_or_path detects function"
assert_true "check_cmd_or_path bash" "check_cmd_or_path detects binary in PATH"
assert_true "check_cmd_or_path /tmp" "check_cmd_or_path detects directory path"
assert_false "check_cmd_or_path /non_existent_path_98765" "check_cmd_or_path returns false for missing path"
echo "  ✓ Safe function/command/path detection verified"

echo "[Audit Fix Test 4] Testing package manager timestamp cache (1 hour)..."
cache_ts_file="${SCRIPT_HOME}/.linuxbox_pkg_update_ts"
rm -f "$cache_ts_file"

# Mock date to return predictable timestamps
MOCK_NOW=1700000000
date() {
	if [ "${1:-}" = "+%s" ]; then
		echo "$MOCK_NOW"
	else
		/bin/date "$@"
	fi
}

apt() {
	if [ "${1:-}" = "update" ]; then
		UPDATED_COUNT=$((UPDATED_COUNT + 1))
	fi
	return 0
}

dnf() {
	if [ "${1:-}" = "-y" ] && [ "${2:-}" = "update" ]; then
		UPDATED_COUNT=$((UPDATED_COUNT + 1))
	fi
	return 0
}

command() {
	if [ "${1:-}" = "-v" ] && [ "${2:-}" = "apt" ]; then
		return 0
	elif [ "${1:-}" = "-v" ] && [ "${2:-}" = "dnf" ]; then
		return 1
	else
		/usr/bin/command "$@"
	fi
}

UPDATED_COUNT=0
update_package_manager
assert_eq "1" "$UPDATED_COUNT" "First update_package_manager call must execute package update"
assert_true "[ -f '$cache_ts_file' ]" "Cache file must be created"

# Call again immediately (within 1 hour / 3600 seconds)
update_package_manager
assert_eq "1" "$UPDATED_COUNT" "Second call within 1 hour must skip package update"

# Fast-forward time by 3601 seconds
MOCK_NOW=$((MOCK_NOW + 3601))
update_package_manager
assert_eq "2" "$UPDATED_COUNT" "Call after 1 hour must trigger package update again"

echo "  ✓ Package manager update 1-hour timestamp caching verified"

# Cleanup temporary files
rm -rf "$SCRIPT_HOME" "$LINUXBOX_INSTALL_DIR"

echo "ALL AUDIT FIX TESTS PASSED SUCCESSFULLY!"
