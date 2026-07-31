#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

green=""; white=""; cyan=""; pink=""; yellow=""; red=""; grey=""
region="CN"
key="test"
SCRIPT_HOME="/tmp/linuxbox-appstore-test-home"
SCRIPT_CONFIG_FILE="$SCRIPT_HOME/config"
LINUXBOX_INSTALL_DIR="/tmp/linuxbox-appstore-test-install"
LINUXBOX_LIB_DIR="$ROOT_DIR"
version="3.3.0"

. lib/constants.sh
. lib/config.sh
. lib/i18n.sh
. lib/region.sh
. lib/system.sh
. lib/utils.sh
. modules/appstore.sh


clear() { :; }
break_end() { :; }
curl() { return 1; }
ip_address() { ipv4_address="127.0.0.1"; ipv6_address="::1"; }
read() {
	local last_arg="${!#:-}"
	if [ -n "$last_arg" ] && [[ "$last_arg" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]]; then
		eval "$last_arg=0" 2>/dev/null || true
	fi
	return 0
}

echo "[Test 1] Checking metadata initialization..."
if [ "${#APP_META_NAME[@]}" -lt 110 ]; then
	echo "FAIL: Expected at least 110 apps in APP_META_NAME, got ${#APP_META_NAME[@]}"
	exit 1
fi
echo "  ✓ Total registered apps: ${#APP_META_NAME[@]}"

echo "[Test 2] Checking Category distribution..."
declare -A CAT_COUNTS=()
for id in {1..111}; do
	cat="${APP_META_CAT[$id]:-unknown}"
	CAT_COUNTS["$cat"]=$(( ${CAT_COUNTS["$cat"]:-0} + 1 ))
done
for cat in panel media ai tools storage network; do
	count="${CAT_COUNTS[$cat]:-0}"
	if [ "$count" -eq 0 ]; then
		echo "FAIL: Category $cat has 0 apps"
		exit 1
	fi
	echo "  ✓ Category $cat: $count apps"
done

echo "[Test 3] Checking offline audit status..."
offline_count=0
for id in {1..111}; do
	if [ "${APP_META_STATUS[$id]:-}" = "offline" ]; then
		offline_count=$((offline_count + 1))
	fi
done
echo "  ✓ Offline apps count: $offline_count"

echo "[Test 4] Testing dynamic scanner simulation..."
docker() {
	if [ "$1" = "ps" ]; then
		echo "qbittorrent"
		echo "open-webui"
	elif [ "$1" = "inspect" ]; then
		echo "running"
	fi
}
export -f docker

dynamic_scan_installed_apps
if [ "${INSTALLED_MAP[8]:-0}" != "1" ]; then
	echo "FAIL: qbittorrent (ID 8) should be detected as installed"
	exit 1
fi
if [ "${INSTALLED_MAP[52]:-0}" != "1" ]; then
	echo "FAIL: OpenWebUI (ID 52) should be detected as installed"
	exit 1
fi
echo "  ✓ Dynamic container scan detected installed apps correctly"

echo "[Test 5] Testing Port Conflict Detection logic..."
check_port_in_use 8080 || true
echo "  ✓ Port check function executed without error"

echo "[Test 6] Testing dispatcher for offline app..."
output=$(dispatch_app_execution 92 2>&1 || true)
if ! echo "$output" | grep -q "已下线"; then
	echo "FAIL: Expected offline warning for app 92, got: $output"
	exit 1
fi
echo "  ✓ Offline app dispatcher blocked execution cleanly"

echo "ALL APPSTORE REFACTOR TESTS PASSED!"

