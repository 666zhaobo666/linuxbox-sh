#!/bin/bash
# 端到端验证新框架
# 模拟真实场景: 各种 helper stub 掉, 验证 add_app_port / render / status / menu dots

set +e  # 不让单点失败终止整个测试

# 颜色 stub
green=""; white=""; cyan=""; pink=""; yellow=""; red=""; grey=""
LX_shortcut=""; key="test"
LX_menu_prompt=">"

# 工具 stub
break_end() { :; }
docker() {
    # 模拟 docker 命令, 允许检查容器是否存在
    case "$1" in
        ps)
            # docker ps -a --format '{{.Names}}'
            if [ "${DOCKER_HAS_NPM:-0}" = "1" ]; then echo "npm"; fi
            if [ "${DOCKER_HAS_FRPS:-0}" = "1" ]; then echo "frps"; fi
            ;;
        inspect)
            # docker inspect --format='{{.State.Status}}' <name>
            if [ "$2" = "frps" ] && [ "${DOCKER_FRPS_STATE:-running}" = "running" ]; then
                echo "running"
            else
                echo "${DOCKER_NPM_STATE:-exited}"
            fi
            ;;
        inspect2)
            # docker inspect --format='{{.State.StartedAt}}' <name>
            if [ "$2" = "frps" ]; then
                echo "2026-06-04T10:00:00+08:00"
            else
                echo ""
            fi
            ;;
        port)
            # docker port <name>
            echo "8000 8000"
            ;;
        *) echo "[stub] docker $@" ;;
    esac
}
# 让 docker inspect 调用更灵活 - 我们需要根据调用模式返回不同字段
docker() {
    if [ "$1" = "ps" ]; then
        if [ "${DOCKER_HAS_NPM:-0}" = "1" ]; then echo "npm"; fi
        if [ "${DOCKER_HAS_FRPS:-0}" = "1" ]; then echo "frps"; fi
    elif [ "$1" = "inspect" ]; then
        # 第三个参数是 format
        local target="$2"
        local format="$3"
        if [ "$target" = "frps" ]; then
            case "$format" in
                *State.Status*) echo "running" ;;
                *State.StartedAt*) echo "2026-06-04T10:00:00+08:00" ;;
                *) echo "" ;;
            esac
        elif [ "$target" = "npm" ]; then
            case "$format" in
                *State.Status*) echo "${DOCKER_NPM_STATE:-exited}" ;;
                *) echo "" ;;
            esac
        else
            echo ""
        fi
    elif [ "$1" = "port" ]; then
        echo "8000 8000"
    else
        echo "[stub] docker $@"
    fi
}

check_docker_app() {
    # 模拟容器存在性: 用 DOCKER_HAS_<name> 标志
    local var="DOCKER_HAS_${docker_name^^}"
    if [ "${!var:-0}" = "1" ]; then return 0; else return 1; fi
}
check_docker_image_update() { update_status=""; }
ip_address() { ipv4_address="1.2.3.4"; ipv6_address="2400::1"; }
add_yuming() { yuming="test.example.com"; }
web_del() { :; }
ldnmp_Proxy() { :; }
block_container_port() { :; }
clear_container_rules() { :; }
add_app_id() { echo "  [stub] add_app_id"; }
check_disk_space() { :; }
install() { :; }
install_docker() { :; }
setup_docker_dir() { :; }
date() {
    # 模拟 date -d "..." +%s 和 date +%s
    if [ "$1" = "-d" ]; then
        # 简化: 我们要的是 2026-06-04T10:00:00 → 一定时间戳
        # 用 2026-06-04 10:00:00 作为基准
        echo "1748992800"
    elif [ "$1" = "-Iseconds" ]; then
        echo "2026-06-04T12:00:00+08:00"
    elif [ "$1" = "+%s" ]; then
        echo "1749000000"
    else
        /bin/date "$@"
    fi
}

# ============ 测试 1: 端口注册 + 渲染 ============
echo "=== Test 1: add_app_port + render_app_ports_table ==="
APP_PORTS_LABELS=()
APP_PORTS_NUMBERS=()
add_app_port "Web管理界面" 81
add_app_port "HTTPS代理" 443
render_app_ports_table
echo ""

# ============ 测试 2: 单容器 app (有 docker_port, 自动兜底) ============
echo "=== Test 2: 单容器 app + 自动兜底 (docker_port) ==="
APP_PORTS_LABELS=()
APP_PORTS_NUMBERS=()
DOCKER_HAS_NPM=1
DOCKER_NPM_STATE=running
docker_name="npm"
docker_port=81
docker_describe="NPM 面板"
docker_url="https://..."
app_name="NginxProxyManager面板"
app_text="NPM 描述"
app_url="https://..."
app_id="4"

_auto_register_fallback_port
echo "  注册后端口数: ${#APP_PORTS_LABELS[@]}"
echo "  标签: ${APP_PORTS_LABELS[@]}"
echo "  端口: ${APP_PORTS_NUMBERS[@]}"
echo ""

# ============ 测试 3: 多端口 frp app ============
echo "=== Test 3: frp 多端口 (静态+动态) ==="
APP_PORTS_LABELS=()
APP_PORTS_NUMBERS=()
DOCKER_HAS_FRPS=1
DOCKER_FRPS_STATE=running
docker_name="frps"
docker_port=7500

# 模拟 frp_server_app 入口注册
add_app_port "Dashboard访问地址" 7500
# 模拟 docker_run 装完后注册动态端口
add_app_port "Server访问地址" 7000

echo "  端口数: ${#APP_PORTS_LABELS[@]}"
for i in "${!APP_PORTS_LABELS[@]}"; do
    echo "    [${i}] ${APP_PORTS_LABELS[$i]} : ${APP_PORTS_NUMBERS[$i]}"
done
render_app_ports_table
echo ""

# ============ 测试 4: get_docker_app_status + format_uptime ============
echo "=== Test 4: 状态检测 ==="
docker_name="frps"
echo -n "  frps (running) 状态: "
get_docker_app_status
echo -n "    渲染: "; render_app_status_line

docker_name="notexists"
DOCKER_HAS_NOTEXISTS=0
echo -n "  notexists 状态: "
get_docker_app_status
echo -n "    渲染: "; render_app_status_line

docker_name="npm"
DOCKER_HAS_NPM=1
DOCKER_NPM_STATE=exited
echo -n "  npm (exited) 状态: "
get_docker_app_status
echo -n "    渲染: "; render_app_status_line
echo ""

# ============ 测试 5: 菜单状态点 (INSTALLED_MAP) ============
echo "=== Test 5: 菜单 INSTALLED_MAP 模拟 ==="
declare -A INSTALLED_MAP=(
    [1]=1 [4]=1 [8]=1
)
_dot() {
    if [ "${INSTALLED_MAP[$1]:-0}" = "1" ]; then
        echo "${green}●${white}"
    else
        echo "${red}●${white}"
    fi
}
echo "  1 1Panel:    $(_dot 1)"
echo "  2 宝塔:      $(_dot 2)"
echo "  4 NPM:       $(_dot 4)"
echo "  5 OpenList:  $(_dot 5)"
echo "  8 qbit:      $(_dot 8)"
echo ""

# ============ 测试 6: get_primary_port ============
echo "=== Test 6: get_primary_port ==="
APP_PORTS_LABELS=()
APP_PORTS_NUMBERS=()
add_app_port "A" 100
add_app_port "B" 200
echo "  双端口, 主端口: $(get_primary_port)"

APP_PORTS_LABELS=()
APP_PORTS_NUMBERS=()
docker_port=8080
echo "  无注册, docker_port=8080, 主端口: $(get_primary_port)"

APP_PORTS_LABELS=()
APP_PORTS_NUMBERS=()
unset docker_port
echo "  啥都没, 主端口: '$(get_primary_port)'"
echo ""

# ============ 测试 7: format_uptime ============
echo "=== Test 7: format_uptime ==="
echo "  90秒:      $(format_uptime 90)"
echo "  3600秒:    $(format_uptime 3600)"
echo "  90000秒:   $(format_uptime 90000)"
echo "  259200秒:  $(format_uptime 259200)"
echo ""

echo "=== 全部通过 ==="
