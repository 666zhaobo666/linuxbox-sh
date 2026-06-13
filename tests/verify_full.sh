#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

green=""; white=""; cyan=""; pink=""; yellow=""; red=""; grey=""
region="CN"
key="test"
SCRIPT_HOME="/tmp/linuxbox-test-home"
SCRIPT_CONFIG_FILE="$SCRIPT_HOME/config"
LINUXBOX_INSTALL_DIR="/tmp/linuxbox-test-install"
LINUXBOX_LIB_DIR="$ROOT_DIR"
version="3.3.0"

clear() { :; }
break_end() { :; }
curl() { return 1; }
ip_address() { ipv4_address="1.2.3.4"; ipv6_address="2400::1"; }

docker() {
	case "$1" in
		ps)
			[ "${DOCKER_HAS_NPM:-0}" = "1" ] && echo "npm"
			[ "${DOCKER_HAS_FRPS:-0}" = "1" ] && echo "frps"
			;;
		inspect)
			local format="$2"
			local target="$3"
			case "$target:$format" in
				frps:*State.Status*) echo "running" ;;
				frps:*State.StartedAt*) echo "2026-06-04T10:00:00+08:00" ;;
				npm:*State.Status*) echo "${DOCKER_NPM_STATE:-exited}" ;;
				npm:*State.StartedAt*) echo "2026-06-04T09:00:00+08:00" ;;
				*) echo "" ;;
			esac
			;;
		port)
			echo "8000/tcp -> 0.0.0.0:8000"
			;;
		*)
			echo "[stub] docker $*"
			;;
	esac
}

date() {
	if [ "${1:-}" = "-d" ]; then
		case "$2" in
			"2026-06-04T10:00:00+08:00") echo "1749002400" ;;
			"2026-06-04T09:00:00+08:00") echo "1748998800" ;;
			*) /bin/date "$@" ;;
		esac
	elif [ "${1:-}" = "-Iseconds" ]; then
		echo "2026-06-04T12:00:00+08:00"
	else
		/bin/date "$@"
	fi
}

. lib/constants.sh
. lib/config.sh
. lib/i18n.sh
. lib/region.sh
. lib/system.sh
. modules/appstore.sh

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

for fn in add_app_port render_app_ports_table get_primary_port format_uptime get_docker_app_status render_app_status_line docker_app linux_app; do
	declare -F "$fn" >/dev/null || { echo "missing function: $fn"; exit 1; }
done

APP_PORTS_LABELS=()
APP_PORTS_NUMBERS=()
add_app_port "Web管理界面" 81
add_app_port "HTTPS代理" 443
assert_eq "2" "${#APP_PORTS_LABELS[@]}" "add_app_port count"
assert_eq "81" "$(get_primary_port)" "primary port from registry"

APP_PORTS_LABELS=()
APP_PORTS_NUMBERS=()
docker_port=8080
_auto_register_fallback_port
assert_eq "1" "${#APP_PORTS_LABELS[@]}" "fallback port count"
assert_eq "8080" "$(get_primary_port)" "fallback primary port"

assert_eq "1分30秒" "$(format_uptime 90)" "format 90 seconds"
assert_eq "1小时0分" "$(format_uptime 3600)" "format 1 hour"
assert_eq "1天1小时" "$(format_uptime 90000)" "format 25 hours"

DOCKER_HAS_FRPS=1
docker_name="frps"
case "$(get_docker_app_status)" in
	running\ *) ;;
	*) echo "FAIL: expected frps running status"; exit 1 ;;
esac

docker_name="notexists"
assert_eq "not_installed" "$(get_docker_app_status)" "missing container status"

DOCKER_HAS_NPM=1
DOCKER_NPM_STATE=exited
docker_name="npm"
assert_eq "exited" "$(get_docker_app_status)" "exited container status"

echo "LinuxBox full verification passed."
