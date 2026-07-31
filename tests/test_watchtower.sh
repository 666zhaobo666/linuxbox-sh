#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

green=""; white=""; cyan=""; pink=""; yellow=""; red=""; grey=""
region="CN"
key="test"
SCRIPT_HOME="/tmp/linuxbox-watchtower-test-home"
SCRIPT_CONFIG_FILE="$SCRIPT_HOME/config"
LINUXBOX_INSTALL_DIR="/tmp/linuxbox-watchtower-test-install"
LINUXBOX_LIB_DIR="$ROOT_DIR"
version="3.5.4"

. lib/constants.sh
. lib/config.sh
. lib/i18n.sh
. lib/region.sh
. lib/system.sh
. lib/utils.sh
. modules/docker.sh
. modules/appstore.sh

clear() { :; }
break_end() { :; }

echo "[Watchtower Test 1] Checking Watchtower app registry (ID 111)..."
if [ "${APP_META_NAME[111]:-}" != "Watchtower容器更新工具" ]; then
	echo "FAIL: App 111 metadata name mismatch: ${APP_META_NAME[111]:-none}"
	exit 1
fi
if [ "${APP_META_FUNC[111]:-}" != "watchtower_app" ]; then
	echo "FAIL: App 111 metadata func mismatch: ${APP_META_FUNC[111]:-none}"
	exit 1
fi
echo "  ✓ Watchtower registered in AppStore as ID 111"

echo "[Watchtower Test 2] Checking check_watchtower_installed when not installed..."
docker() {
	if [ "$1" = "ps" ]; then
		return 0
	elif [ "$1" = "images" ]; then
		return 0
	fi
}
export -f docker

if check_watchtower_installed; then
	echo "FAIL: check_watchtower_installed should return false when watchtower is not installed"
	exit 1
fi
echo "  ✓ Correctly detected Watchtower as not installed"

echo "[Watchtower Test 3] Checking update blocking when Watchtower is not installed..."
output=$(run_watchtower_update "test-container" 2>&1 || true)
if ! echo "$output" | grep -q "未安装 Watchtower，请先安装"; then
	echo "FAIL: Expected '未安装 Watchtower，请先安装', got: $output"
	exit 1
fi
echo "  ✓ Update blocked with warning message when Watchtower is missing"

echo "[Watchtower Test 4] Checking check_watchtower_installed when container exists..."
docker() {
	if [ "$1" = "ps" ]; then
		echo "watchtower"
	elif [ "$1" = "images" ]; then
		return 0
	fi
}
export -f docker

if ! check_watchtower_installed; then
	echo "FAIL: check_watchtower_installed should return true when watchtower container exists"
	exit 1
fi
echo "  ✓ Correctly detected Watchtower when container exists"

echo "ALL WATCHTOWER TESTS PASSED!"
