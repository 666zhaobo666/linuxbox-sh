#############################################################################
########################## 八、Caddy 反向代理管理 ############################
# 依赖: bash, grep, awk, sed, curl, systemctl, ps
# 文件布局:
#   /etc/caddy/Caddyfile              # 主配置 (必须 import /etc/caddy/vhosts/*.conf)
#   /etc/caddy/vhosts/<domain>.conf   # 每个反代一个独立文件
#   /var/lib/caddy/.local/share/caddy/certificates/  # Caddy 自动签发的证书目录
#############################################################################

## Caddy 关键路径常量 (集中维护方便后续修改)
CADDY_BIN="/usr/bin/caddy"                 # caddy 主程序路径
CADDY_CONFIG_DIR="/etc/caddy"             # caddy 配置根目录
CADDY_MAIN_CONF="${CADDY_CONFIG_DIR}/Caddyfile"  # 主配置文件
CADDY_VHOSTS_DIR="${CADDY_CONFIG_DIR}/vhosts"   # 反代 vhost 文件目录
CADDY_CERT_BASE="/var/lib/caddy/.local/share/caddy/certificates"  # 证书存储根目录
CADDY_LE_DIR="${CADDY_CERT_BASE}/acme-v02.api.letsencrypt.org-directory"  # Let's Encrypt 证书目录
CADDY_ZEROSSL_DIR="${CADDY_CERT_BASE}/acme.zerossl.com-v2-dv90"  # ZeroSSL 证书目录

## 检测 Caddy 是否安装
caddy_check_installed() {
    if [ -x "${CADDY_BIN}" ] || command -v caddy >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

## 检查 root 权限 (脚本开头调用)
caddy_check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${red}提示: ${white}Caddy 管理需要 root 权限, 请使用 sudo 或以 root 用户运行!"
        return 1
    fi
    return 0
}

## 初始化环境: 确保配置目录、vhosts 目录、主配置 import 行齐全
caddy_init_env() {
    # 确保目录存在
    mkdir -p "${CADDY_CONFIG_DIR}"
    mkdir -p "${CADDY_VHOSTS_DIR}"

    # 如果主配置不存在, 创建一个最小骨架
    if [ ! -f "${CADDY_MAIN_CONF}" ]; then
        cat > "${CADDY_MAIN_CONF}" <<'EOF'
# Caddy 主配置文件
# 由 LinuxBox 脚本自动维护
{
    # 全局选项: 启用 admin API
    admin off
}

# 自动加载所有反代配置
import /etc/caddy/vhosts/*.conf
EOF
    fi

    # 确保主配置中包含 import 行 (幂等)
    if ! grep -qE '^[[:space:]]*import[[:space:]]+/etc/caddy/vhosts/\*\.conf' "${CADDY_MAIN_CONF}" 2>/dev/null; then
        # 在文件末尾追加 import 行 (避免覆盖)
        echo "" >> "${CADDY_MAIN_CONF}"
        echo "# 自动追加: 加载 vhost 配置" >> "${CADDY_MAIN_CONF}"
        echo "import /etc/caddy/vhosts/*.conf" >> "${CADDY_MAIN_CONF}"
    fi
}

## 获取 Caddy 服务运行状态 (输出: 运行中/未运行/未安装)
caddy_service_status() {
    if ! caddy_check_installed; then
        echo "未安装"
        return 1
    fi
    if systemctl is-active --quiet caddy 2>/dev/null; then
        echo "运行中"
        return 0
    else
        echo "未运行"
        return 1
    fi
}

## 获取 Caddy 进程实际物理内存占用 (RSS, 单位 MB)
caddy_memory_usage() {
    # ps 取 RSS (KB), awk 求和并转 MB
    local rss_kb
    rss_kb=$(ps -C caddy -o rss= 2>/dev/null | awk '{sum+=$1} END {print sum+0}')
    if [ -z "${rss_kb}" ] || [ "${rss_kb}" -eq 0 ]; then
        echo "0"
        return
    fi
    echo $((rss_kb / 1024))
}

## 检查指定域名的 SSL 证书是否已签发
# 用法: caddy_ssl_status "example.com"
# 输出: "已签发" 或 "待签发/无"
caddy_ssl_status() {
    local domain="$1"
    # 同时检查 Let's Encrypt 与 ZeroSSL 目录
    if [ -f "${CADDY_LE_DIR}/${domain}/${domain}.crt" ] || \
       [ -f "${CADDY_ZEROSSL_DIR}/${domain}/${domain}.crt" ] || \
       [ -f "${CADDY_CERT_BASE}/${domain}/${domain}.crt" ]; then
        echo "已签发"
    else
        echo "待签发/无"
    fi
}

## 渲染顶部仪表盘
caddy_draw_dashboard() {
    caddy_init_env

    local status
    status=$(caddy_service_status)
    local mem
    mem=$(caddy_memory_usage)

    # 状态颜色: 运行中绿色, 异常红色
    local status_color="${red}"
    if [ "${status}" = "运行中" ]; then
        status_color="${green}"
    fi

    echo -e "${green}===== Caddy 反向代理管理 =====${white}"
    echo ""
    echo -e "${pink}--------------------------------------------------------${white}"
    printf "  ${cyan}%-26s${white} | ${cyan}%-26s${white} | ${cyan}%s${white}\n" "域名" "反代目标" "SSL 证书"
    echo -e "${pink}--------------------------------------------------------${white}"

    # 遍历 vhosts 目录, 解析每个 conf 文件
    if [ -d "${CADDY_VHOSTS_DIR}" ]; then
        local conf_file domain target ssl_text
        for conf_file in "${CADDY_VHOSTS_DIR}"/*.conf; do
            [ -e "${conf_file}" ] || continue
            # 文件名即域名 (去掉 .conf 后缀)
            domain=$(basename "${conf_file}" .conf)
            # 提取 reverse_proxy 后的目标
            target=$(grep -E '^\s*reverse_proxy' "${conf_file}" 2>/dev/null | \
                     head -n1 | awk '{print $2}')
            [ -z "${target}" ] && target="-"
            # SSL 状态着色
            ssl_text=$(caddy_ssl_status "${domain}")
            if [ "${ssl_text}" = "已签发" ]; then
                printf "  %-26s | %-26s | ${green}%s${white}\n" "${domain}" "${target}" "[已签发]"
            else
                printf "  %-26s | %-26s | ${yellow}%s${white}\n" "${domain}" "${target}" "[待签发/无]"
            fi
        done
    else
        echo "  (暂无配置)"
    fi

    echo -e "${pink}--------------------------------------------------------${white}"
    printf "  状态: ${status_color}%s${white}  |  内存占用: %s MB\n" "${status}" "${mem}"
    echo -e "${pink}--------------------------------------------------------${white}"
}

## 菜单 1: 添加反向代理
caddy_add_proxy() {
    caddy_init_env

    # 读取并校验域名
    local domain target
    read -e -p "请输入待绑定的域名 (例如 app.yourdomain.com): " domain
    # 基础格式校验: 非空, 无空格, 至少含一个点
    if [ -z "${domain}" ] || [[ "${domain}" == *" "* ]]; then
        echo -e "${red}域名不合法, 不能为空或包含空格!${white}"
        break_end
        return
    fi
    if [[ "${domain}" != *.* ]]; then
        echo -e "${red}域名不合法, 至少需要包含一个点 (如 example.com)!${white}"
        break_end
        return
    fi

    # 读取并校验目标地址
    read -e -p "请输入本地服务地址及端口 (例如 127.0.0.1:8080): " target
    if [ -z "${target}" ] || [[ "${target}" == *" "* ]]; then
        echo -e "${red}目标地址不合法!${white}"
        break_end
        return
    fi
    # 简单 IP:PORT 格式校验
    if ! [[ "${target}" =~ ^[0-9a-zA-Z\.\-]+:[0-9]+$ ]]; then
        echo -e "${red}目标格式不合法, 应为 IP:PORT 形式!${white}"
        break_end
        return
    fi

    # 生成 vhost 文件
    local vhost_file="${CADDY_VHOSTS_DIR}/${domain}.conf"
    cat > "${vhost_file}" <<EOF
${domain} {
    reverse_proxy ${target}
}
EOF

    # 重载 Caddy
    if systemctl reload caddy 2>/dev/null; then
        echo -e "${green}配置文件已生成并重载 Caddy。${white}"
        echo -e "${green}若域名已正确解析至本机, SSL 证书将在后台自动申请。${white}"
    else
        echo -e "${yellow}配置文件已生成, 但重载 Caddy 失败, 请检查: ${white}"
        echo -e "  1) Caddy 是否已启动 (systemctl status caddy)"
        echo -e "  2) 主配置语法是否正确 (${CADDY_MAIN_CONF})"
    fi
    break_end
}

## 菜单 2: 删除反向代理
caddy_del_proxy() {
    caddy_init_env

    # 收集现有域名列表
    local conf_files=()
    local domains=()
    local f domain
    for f in "${CADDY_VHOSTS_DIR}"/*.conf; do
        [ -e "${f}" ] || continue
        domain=$(basename "${f}" .conf)
        conf_files+=("${f}")
        domains+=("${domain}")
    done

    if [ ${#domains[@]} -eq 0 ]; then
        echo -e "${yellow}当前无配置可删除${white}"
        break_end
        return
    fi

    # 列出供选择
    local i
    for ((i=0; i<${#domains[@]}; i++)); do
        echo "  $((i+1)). ${domains[$i]}"
    done
    read -e -p "请输入要删除的序号 (输入 0 取消): " choice

    # 输入校验
    if ! [[ "${choice}" =~ ^[0-9]+$ ]]; then
        echo -e "${red}无效输入!${white}"
        sleep 1
        return
    fi
    if [ "${choice}" -eq 0 ]; then
        return
    fi
    if [ "${choice}" -lt 1 ] || [ "${choice}" -gt ${#domains[@]} ]; then
        echo -e "${red}序号超出范围!${white}"
        sleep 1
        return
    fi

    local idx=$((choice-1))
    local target_domain="${domains[$idx]}"
    local target_file="${conf_files[$idx]}"

    # 二次确认
    read -e -p "确定要删除 ${target_domain} 的反代配置吗？(y/n): " confirm
    if [[ ! "${confirm}" =~ ^[Yy]$ ]]; then
        echo -e "${yellow}已取消${white}"
        sleep 1
        return
    fi

    # 删除文件并重载
    rm -f "${target_file}"
    if systemctl reload caddy 2>/dev/null; then
        echo -e "${green}配置文件已删除并重载 Caddy。${white}"
    else
        echo -e "${yellow}文件已删除, 但重载 Caddy 失败, 请手动检查。${white}"
    fi
    break_end
}

## 菜单 3: 重载 Caddy 服务
caddy_reload_service() {
    caddy_init_env

    echo "请选择操作:"
    echo "  1.  reload (热重载, 默认)"
    echo "  2.  restart (完全重启)"
    echo "  0.  取消"
    read -e -p "请输入选择 [1]: " op
    op="${op:-1}"

    case "${op}" in
        1)
            if systemctl reload caddy 2>/dev/null; then
                echo -e "${green}Caddy 重新加载成功${white}"
            else
                echo -e "${red}重载失败, 请检查配置文件语法。${white}"
            fi
            ;;
        2)
            if systemctl restart caddy 2>/dev/null; then
                echo -e "${green}Caddy 重启成功${white}"
            else
                echo -e "${red}重启失败, 请检查 systemctl status caddy。${white}"
            fi
            ;;
        0)
            return
            ;;
        *)
            echo -e "${red}无效选择${white}"
            ;;
    esac
    break_end
}

## 菜单 4: 查看 Caddy 运行日志
caddy_view_logs() {
    echo -e "${cyan}最近 20 条 Caddy 日志:${white}"
    echo -e "${pink}--------------------------------------------------------${white}"
    journalctl -u caddy -n 20 --no-pager 2>/dev/null || echo -e "${red}无法读取日志, 请确认 caddy 服务已安装。${white}"
    echo -e "${pink}--------------------------------------------------------${white}"
    echo -e "${yellow}按任意键返回主菜单...${white}"
    read -n 1 -s -r
    echo ""
}

## 安装 Caddy (官方源安装流程)
caddy_install() {
    caddy_check_root || return 1

    echo -e "${cyan}开始安装 Caddy ...${white}"
    local os
    os=$(detect_os)

    case "${os}" in
        debian|ubuntu)
            # Caddy 官方 Debian/Ubuntu 安装流程 (来自 caddyserver.com 文档)
            install curl debian-keyring debian-archive-keyring apt-transport-https gnupg
            curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
                | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
            curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
                | tee /etc/apt/sources.list.d/caddy-stable.list
            apt update
            install caddy
            ;;
        rhel|centos|fedora|rocky|almalinux)
            # Caddy 官方 RHEL/CentOS/Fedora 安装流程
            install curl gnupg
            curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
                | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
            curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/rpm.rpm.txt' \
                | tee /etc/yum.repos.d/caddy-stable.repo
            if command -v dnf >/dev/null 2>&1; then
                dnf install -y caddy
            else
                yum install -y caddy
            fi
            ;;
        arch)
            # Arch 系 Caddy 不在官方仓库, 使用 pacman 安装 caddy (社区仓库, 失败回退)
            pacman -S --noconfirm caddy 2>/dev/null || \
                echo -e "${red}Arch 系请使用 AUR (yay -S caddy) 或参考官方文档安装${white}"
            ;;
        alpine)
            install caddy
            ;;
        *)
            echo -e "${red}暂不支持自动安装此系统, 请前往 https://caddyserver.com 下载二进制: ${white}"
            echo "  curl -o caddy \"https://caddyserver.com/api/download?os=linux&arch=amd64\""
            echo "  install -m 755 caddy /usr/bin/caddy"
            return 1
            ;;
    esac

    # 安装后初始化 + 启动
    if caddy_check_installed; then
        echo -e "${green}Caddy 已安装: $(caddy version 2>/dev/null || echo 'unknown')${white}"
        caddy_init_env
        systemctl enable caddy 2>/dev/null
        systemctl start caddy 2>/dev/null
        echo -e "${green}Caddy 服务已启动并设置开机自启。${white}"
    else
        echo -e "${red}Caddy 安装失败, 请检查上方错误信息。${white}"
        return 1
    fi
    break_end
}

## 卸载 Caddy
caddy_uninstall() {
    caddy_check_root || return 1

    read -e -p "确定要卸载 Caddy 吗？所有配置和证书将被保留在 /etc/caddy 和 /var/lib/caddy 中。(y/n): " confirm
    if [[ ! "${confirm}" =~ ^[Yy]$ ]]; then
        echo -e "${yellow}已取消${white}"
        return
    fi

    systemctl stop caddy 2>/dev/null
    systemctl disable caddy 2>/dev/null

    local os
    os=$(detect_os)
    case "${os}" in
        debian|ubuntu) apt remove --purge -y caddy 2>/dev/null ;;
        rhel|centos|fedora|rocky|almalinux)
            command -v dnf >/dev/null 2>&1 && dnf remove -y caddy 2>/dev/null \
                || yum remove -y caddy 2>/dev/null
            ;;
        arch) pacman -Rns --noconfirm caddy 2>/dev/null ;;
        alpine) apk del caddy 2>/dev/null ;;
    esac

    echo -e "${green}Caddy 已卸载。配置和证书文件未被删除。${white}"
    break_end
}

## 渲染 Caddy 主菜单
caddy_show_menu() {
    echo ""
    echo -e "${cyan}1.  ${white}添加反向代理"
    echo -e "${cyan}2.  ${white}删除反向代理"
    echo -e "${cyan}3.  ${white}重载 Caddy 服务"
    echo -e "${cyan}4.  ${white}查看 Caddy 运行日志"
    echo -e "${pink}--------------------------------------------------------${white}"
    echo -e "${red}99.${white} 卸载 Caddy"
    echo -e "${yellow}0.  ${white}返回上一级菜单"
    echo -e "${pink}--------------------------------------------------------${white}"
    read -e -p "请输入你的选择: " choice

    case "${choice}" in
        1) caddy_add_proxy ;;
        2) caddy_del_proxy ;;
        3) caddy_reload_service ;;
        4) caddy_view_logs ;;
        99) caddy_uninstall ;;
        0) return 0 ;;
        *)
            echo -e "${red}无效选择, 请重新输入 !${white}"
            sleep 1
            ;;
    esac
    return 1
}

## Caddy 模块入口: 主菜单第 8 项调用
linux_caddy() {
    # 入口 root 校验 (统一在面板最外层判断)
    caddy_check_root || { break_end; return; }

    # 未安装分支: 给出"安装 / 退出"二选一
    if ! caddy_check_installed; then
        clear
        echo -e "${green}===== Caddy 反向代理管理 =====${white}"
        echo -e "${red}未检测到 Caddy 安装, 请先安装。${white}"
        echo -e "${pink}--------------------------------------------------------${white}"
        echo -e "${cyan}1.  ${white}安装 Caddy"
        echo -e "${yellow}0.  ${white}返回上一级菜单"
        echo -e "${pink}--------------------------------------------------------${white}"
        read -e -p "请输入你的选择: " first_choice
        case "${first_choice}" in
            1)
                caddy_install
                # 安装成功后继续进入主面板 (下轮 while 会重新检测)
                ;;
            0|"")
                return
                ;;
            *)
                echo -e "${red}无效选择, 请重新输入 !${white}"
                sleep 1
                return
                ;;
        esac
    fi

    # 已安装: 进入正常管理面板
    while true; do
        clear
        caddy_draw_dashboard
        caddy_show_menu && return
    done
}
