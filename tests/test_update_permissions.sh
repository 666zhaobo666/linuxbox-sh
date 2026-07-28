#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

green=""; white=""; cyan=""; pink=""; yellow=""; red=""; grey=""
LX_update_check="Checking update..."
LX_update_latest="Latest: %s"
LX_update_found="Found update: %s -> %s"
LX_update_cancel="Cancelled"
LX_shortcut="Shortcut: %s"
key="j"
version="3.5.1"

TEST_DIR="/tmp/linuxbox_update_perm_test_$$"
mkdir -p "$TEST_DIR/lib" "$TEST_DIR/modules" "$TEST_DIR/backup"
touch "$TEST_DIR/LinuxBox.sh"

LINUXBOX_LIB_DIR="$TEST_DIR"
SCRIPT_HOME="$TEST_DIR"
SCRIPT_FILE="LinuxBox.sh"
LINUXBOX_LIB_FILES=("constants.sh")
LINUXBOX_MOD_FILES=("system_info.sh")

. lib/constants.sh
. lib/config.sh
. lib/i18n.sh
. lib/region.sh
. lib/system.sh
. lib/utils.sh
. lib/update.sh

clear() { :; }
break_end() { :; }

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

echo "[Update Permission Test 1] Testing writable directory permission check..."
res=0
check_write_permission "update" || res=$?
assert_eq "0" "$res" "Writable directory should pass check_write_permission"

echo "[Update Permission Test 2] Testing read-only directory permission check without sudo..."
readonly_dir="$TEST_DIR/readonly"
mkdir -p "$readonly_dir/lib" "$readonly_dir/modules"
touch "$readonly_dir/LinuxBox.sh"
chmod 555 "$readonly_dir"

LINUXBOX_LIB_DIR="$readonly_dir"
# Mock command to simulate sudo absence
sudo() { return 127; }

output=$(check_write_permission "update" 2>&1 || true)
res=0
check_write_permission "update" >/dev/null 2>&1 || res=$?
assert_eq "1" "$res" "Read-only directory should return 1 when sudo fails/absent"
assert_true "echo '$output' | grep -q '错误: 当前用户无权修改'" "Error message must match specification"

echo "[Update Permission Test 3] Testing update_script abort on permission failure..."
download_called=0
ensure_proxy() { :; }
get_remote_version() { echo "9.9.9"; }
download_file() { download_called=1; return 0; }

update_res=0
update_output=$(update_script 2>&1) || update_res=$?
assert_eq "1" "$update_res" "update_script must return 1 on permission error"
assert_eq "0" "$download_called" "download_file must NOT be called when permission check fails"
assert_true "echo '$update_output' | grep -q '错误: 当前用户无权修改'" "update_script must output permission error"

echo "[Update Permission Test 4] Testing rollback_version abort on permission failure..."
rollback_res=0
rollback_output=$(rollback_version 2>&1) || rollback_res=$?
assert_eq "1" "$rollback_res" "rollback_version must return 1 on permission error"
assert_true "echo '$rollback_output' | grep -q '错误: 当前用户无权修改'" "rollback_version must output permission error"

chmod 755 "$readonly_dir"

echo "[Update Permission Test 5] Testing file copy/chmod failure recording to FAILED_FILES..."
work_dir="$TEST_DIR/work"
mkdir -p "$work_dir/lib" "$work_dir/modules"
touch "$work_dir/LinuxBox.sh"
LINUXBOX_LIB_DIR="$work_dir"

# Stub read to automatically supply 'y' to the target variable
read() { local var_name="${!#}"; eval "$var_name='y'"; }

# Mock download to return success but chmod to fail
download_file() { return 0; }
chmod() { return 1; }

FAILED_FILES=()
update_fail_res=0
update_fail_output=$(update_script 2>&1) || update_fail_res=$?
assert_eq "1" "$update_fail_res" "update_script must fail when chmod fails"
assert_true "echo '$update_fail_output' | grep -q '以下文件下载失败'" "Output must report failed files when chmod fails"

rm -rf "$TEST_DIR"

echo "ALL UPDATE PERMISSION TESTS PASSED SUCCESSFULLY!"
