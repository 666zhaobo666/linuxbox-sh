#############################################################################
########################## 八、Caddy 反向代理管理 ############################
# 依赖: bash, grep, awk, sed, curl, systemctl, ps, caddy
# 文件布局:
#   /etc/caddy/Caddyfile              # 主配置 (自动 import /etc/caddy/vhosts/*.conf)
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

#############################################################################
############################ 基础检测与状态 #################################

## 检测 Caddy 是否安装
caddy_check_installed() {
    if [ -x "${CADDY_BIN}" ] || command -v caddy >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

## 检查 root 权限
caddy_check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${red}提示: ${white}Caddy 管理需要 root 权限, 请使用 sudo 或以 root 用户运行!"
        return 1
    fi
    return 0
}

## 初始化环境: 确保配置目录、vhosts 目录、主配置 import 行齐全
caddy_init_env() {
    mkdir -p "${CADDY_CONFIG_DIR}"
    mkdir -p "${CADDY_VHOSTS_DIR}"

    # 如果主配置不存在, 创建一个最小骨架
    if [ ! -f "${CADDY_MAIN_CONF}" ]; then
        cat > "${CADDY_MAIN_CONF}" <<'EOF'
# Caddy 主配置文件
# 由 LinuxBox 脚本自动维护
{
    admin off
}

# 自动加载所有反代配置
import /etc/caddy/vhosts/*.conf
EOF
    fi

    # 确保主配置中包含 import 行 (幂等)
    if ! grep -qE '^[[:space:]]*import[[:space:]]+/etc/caddy/vhosts/\*\.conf' "${CADDY_MAIN_CONF}" 2>/dev/null; then
        echo "" >> "${CADDY_MAIN_CONF}"
        echo "# 自动追加: 加载 vhost 配置" >> "${CADDY_MAIN_CONF}"
        echo "import /etc/caddy/vhosts/*.conf" >> "${CADDY_MAIN_CONF}"
    fi
}

## 获取 Caddy 服务运行状态
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
    local rss_kb
    rss_kb=$(ps -C caddy -o rss= 2>/dev/null | awk '{sum+=$1} END {print sum+0}')
    if [ -z "${rss_kb}" ] || [ "${rss_kb}" -eq 0 ]; then
        echo "0"
        return
    fi
    echo $((rss_kb / 1024))
}

## 检查指定域名的 SSL 证书是否已签发
caddy_ssl_status() {
    local domain="$1"
    if [ -f "${CADDY_LE_DIR}/${domain}/${domain}.crt" ] || \
       [ -f "${CADDY_ZEROSSL_DIR}/${domain}/${domain}.crt" ] || \
       [ -f "${CADDY_CERT_BASE}/${domain}/${domain}.crt" ]; then
        echo "已签发"
    else
        echo "待签发/无"
    fi
}

#############################################################################
############################## 仪表盘渲染 ####################################

## 渲染顶部仪表盘
caddy_draw_dashboard() {
    caddy_init_env

    local status
    status=$(caddy_service_status)
    local mem
    mem=$(caddy_memory_usage)

    local status_color="${red}"
    if [ "${status}" = "运行中" ]; then
        status_color="${green}"
    fi

    echo -e "${green}===== Caddy 反向代理管理 =====${white}"
    echo ""
    echo -e "${pink}--------------------------------------------------------${white}"
    printf "  ${cyan}%-26s${white} | ${cyan}%-26s${white} | ${cyan}%s${white}\n" "域名" "反代目标" "SSL 证书"
    echo -e "${pink}--------------------------------------------------------${white}"

    if [ -d "${CADDY_VHOSTS_DIR}" ]; then
        local conf_file domain target ssl_text
        for conf_file in "${CADDY_VHOSTS_DIR}"/*.conf; do
            [ -e "${conf_file}" ] || continue
            domain=$(basename "${conf_file}" .conf)
            target=$(grep -E '^\s*reverse_proxy' "${conf_file}" 2>/dev/null | \
                     head -n1 | awk '{print $2}')
            [ -z "${target}" ] && target="-"
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

#############################################################################
######################## vhost 文件操作工具函数 ###############################
# 这几个函数是高级配置子功能共享的基础工具:
#   caddy_vhost_backup               备份当前 vhost
#   caddy_vhost_insert_block         在 `}` 之前插入一段指令块
#   caddy_vhost_remove_directive     删除指定行 (用于负载均衡替换)
#   caddy_vhost_validate_or_rollback 验证 + 失败回滚 + 成功 reload
#   caddy_select_vhost               列出域名让用户选, 选中后 echo 到 stdout
#############################################################################

## 备份 vhost 文件 (写到 <file>.bak)
caddy_vhost_backup() {
    local vhost_file="$1"
    cp -f "$vhost_file" "${vhost_file}.bak"
}

## 在 `}` 行之前插入一段指令块
# 用法: caddy_vhost_insert_block <vhost_file> "<block_text>"
caddy_vhost_insert_block() {
    local vhost_file="$1"
    local block="$2"
    local tmp="${vhost_file}.tmp"
    # 保留除最后一行 `}` 之外的全部
    head -n -1 "$vhost_file" > "$tmp"
    # 追加新块
    printf '%s\n' "$block" >> "$tmp"
    # 加回 `}`
    echo "}" >> "$tmp"
    mv -f "$tmp" "$vhost_file"
}

## 删除 vhost 中匹配 regex 的所有行 (用于负载均衡场景替换 reverse_proxy)
caddy_vhost_remove_directive() {
    local vhost_file="$1"
    local pattern="$2"
    local tmp="${vhost_file}.tmp"
    grep -vE "$pattern" "$vhost_file" > "$tmp" || true
    mv -f "$tmp" "$vhost_file"
}

## 验证主配置, 成功则 reload, 失败回滚到 .bak
caddy_vhost_validate_or_rollback() {
    local vhost_file="$1"

    # caddy validate 通过主配置 (它会 import 所有 vhost)
    local validate_out
    validate_out=$(caddy validate --config "${CADDY_MAIN_CONF}" 2>&1)
    if [ $? -eq 0 ]; then
        echo -e "${green}配置验证通过, 正在重载 Caddy...${white}"
        rm -f "${vhost_file}.bak"
        if systemctl reload caddy 2>/dev/null; then
            echo -e "${green}已生效${white}"
        else
            echo -e "${yellow}reload 失败, 请检查 caddy 服务状态${white}"
        fi
    else
        echo -e "${red}配置语法错误, 已回滚${white}"
        echo -e "${red}错误信息: ${validate_out}${white}"
        mv -f "${vhost_file}.bak" "$vhost_file"
    fi
    break_end
}

## 让用户从 vhost 列表中选一个域名, 选中的域名 echo 到 stdout, 取消时 echo 空
# 用法: domain=$(caddy_select_vhost) || return
caddy_select_vhost() {
    local conf_files=()
    local domains=()
    local f domain
    for f in "${CADDY_VHOSTS_DIR}"/*.conf; do
        [ -e "$f" ] || continue
        domain=$(basename "$f" .conf)
        conf_files+=("$f")
        domains+=("$domain")
    done

    if [ ${#domains[@]} -eq 0 ]; then
        echo -e "${yellow}当前没有任何域名配置, 请先添加一个${white}"
        break_end
        return 1
    fi

    echo -e "${cyan}请选择要操作的域名:${white}"
    local i
    for ((i=0; i<${#domains[@]}; i++)); do
        echo "  $((i+1)). ${domains[$i]}"
    done
    read -e -p "请输入序号 (输入 0 取消): " choice

    if ! [[ "$choice" =~ ^[0-9]+$ ]]; then
        echo -e "${red}无效输入${white}"
        sleep 1
        return 1
    fi
    if [ "$choice" -eq 0 ]; then
        return 1
    fi
    if [ "$choice" -lt 1 ] || [ "$choice" -gt ${#domains[@]} ]; then
        echo -e "${red}序号超出范围${white}"
        sleep 1
        return 1
    fi

    echo "${domains[$((choice-1))]}"
    return 0
}

#############################################################################
############################ 基础菜单功能 ####################################

## 菜单 1: 添加基础反向代理
caddy_add_proxy() {
    caddy_init_env

    local domain target
    read -e -p "请输入待绑定的域名 (例如 app.yourdomain.com): " domain
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

    read -e -p "请输入本地服务地址及端口 (例如 127.0.0.1:8080): " target
    if [ -z "${target}" ] || [[ "${target}" == *" "* ]]; then
        echo -e "${red}目标地址不合法!${white}"
        break_end
        return
    fi
    if ! [[ "${target}" =~ ^[0-9a-zA-Z\.\-]+:[0-9]+$ ]]; then
        echo -e "${red}目标格式不合法, 应为 IP:PORT 形式!${white}"
        break_end
        return
    fi

    local vhost_file="${CADDY_VHOSTS_DIR}/${domain}.conf"
    cat > "${vhost_file}" <<EOF
${domain} {
    reverse_proxy ${target}
}
EOF

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

## 菜单 2: 删除主机配置
caddy_del_proxy() {
    caddy_init_env

    local conf_files=()
    local domains=()
    local f domain
    for f in "${CADDY_VHOSTS_DIR}"/*.conf; do
        [ -e "$f" ] || continue
        domain=$(basename "$f" .conf)
        conf_files+=("$f")
        domains+=("$domain")
    done

    if [ ${#domains[@]} -eq 0 ]; then
        echo -e "${yellow}当前无配置可删除${white}"
        break_end
        return
    fi

    local i
    for ((i=0; i<${#domains[@]}; i++)); do
        echo "  $((i+1)). ${domains[$i]}"
    done
    read -e -p "请输入要删除的序号 (输入 0 取消): " choice

    if ! [[ "$choice" =~ ^[0-9]+$ ]]; then
        echo -e "${red}无效输入!${white}"
        sleep 1
        return
    fi
    if [ "$choice" -eq 0 ]; then
        return
    fi
    if [ "$choice" -lt 1 ] || [ "$choice" -gt ${#domains[@]} ]; then
        echo -e "${red}序号超出范围!${white}"
        sleep 1
        return
    fi

    local idx=$((choice-1))
    local target_domain="${domains[$idx]}"
    local target_file="${conf_files[$idx]}"

    read -e -p "确定要删除 ${target_domain} 的反代配置吗？(y/n): " confirm
    if [[ ! "${confirm}" =~ ^[Yy]$ ]]; then
        echo -e "${yellow}已取消${white}"
        sleep 1
        return
    fi

    rm -f "${target_file}"
    if systemctl reload caddy 2>/dev/null; then
        echo -e "${green}配置文件已删除并重载 Caddy。${white}"
    else
        echo -e "${yellow}文件已删除, 但重载 Caddy 失败, 请手动检查。${white}"
    fi
    break_end
}

## 菜单 4: 重载 Caddy 服务
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

## 菜单 5: 查看 Caddy 运行日志
caddy_view_logs() {
    echo -e "${cyan}最近 20 条 Caddy 日志:${white}"
    echo -e "${pink}--------------------------------------------------------${white}"
    journalctl -u caddy -n 20 --no-pager 2>/dev/null || echo -e "${red}无法读取日志, 请确认 caddy 服务已安装。${white}"
    echo -e "${pink}--------------------------------------------------------${white}"
    echo -e "${yellow}按任意键返回主菜单...${white}"
    read -n 1 -s -r
    echo ""
}

#############################################################################
######################## 高级配置子功能 (菜单 3) ##############################

## 高级 [1]: 静态文件托管
caddy_adv_fileserver() {
    local domain="$1"
    local vhost_file="${CADDY_VHOSTS_DIR}/${domain}.conf"

    local root_dir
    read -e -p "请输入网站根目录 (如 /var/www/html): " root_dir
    if [ -z "${root_dir}" ]; then
        echo -e "${yellow}已取消${white}"
        sleep 1
        return
    fi

    if grep -qE '^\s*root\s+\*' "$vhost_file"; then
        echo -e "${yellow}已存在 root 指令, 跳过${white}"
        break_end
        return
    fi
    if grep -qE '^\s*file_server\b' "$vhost_file"; then
        echo -e "${yellow}已存在 file_server 指令, 跳过${white}"
        break_end
        return
    fi

    caddy_vhost_backup "$vhost_file"
    caddy_vhost_insert_block "$vhost_file" "    root * ${root_dir}
    file_server"
    caddy_vhost_validate_or_rollback "$vhost_file"
}

## 高级 [2]: 基础密码保护
caddy_adv_basicauth() {
    local domain="$1"
    local vhost_file="${CADDY_VHOSTS_DIR}/${domain}.conf"

    local username pass
    read -e -p "请输入用户名: " username
    if [ -z "${username}" ]; then
        echo -e "${yellow}已取消${white}"
        sleep 1
        return
    fi
    read -s -p "请输入密码: " pass
    echo ""
    if [ -z "${pass}" ]; then
        echo -e "${yellow}已取消${white}"
        sleep 1
        return
    fi

    # 调用 caddy hash-password 生成 bcrypt 哈希
    local hash
    hash=$(caddy hash-password --plaintext "$pass" 2>/dev/null)
    if [ -z "$hash" ]; then
        echo -e "${red}生成密码哈希失败, 请确认 caddy 已正确安装${white}"
        break_end
        return
    fi

    if grep -qE '^\s*basicauth\b' "$vhost_file"; then
        echo -e "${yellow}已存在 basicauth 指令, 跳过${white}"
        break_end
        return
    fi

    caddy_vhost_backup "$vhost_file"
    caddy_vhost_insert_block "$vhost_file" "    basicauth /* {
        ${username} ${hash}
    }"
    caddy_vhost_validate_or_rollback "$vhost_file"
}

## 高级 [3]: 重定向 / URL 重写
caddy_adv_redirect() {
    local domain="$1"
    local vhost_file="${CADDY_VHOSTS_DIR}/${domain}.conf"

    echo "请选择操作:"
    echo "  1.  redir    (HTTP 重定向, 客户端会看到地址变化)"
    echo "  2.  rewrite  (URL 重写, 客户端地址栏不变)"
    read -e -p "请选择 [1]: " op
    op="${op:-1}"

    local target
    read -e -p "请输入目标路径 (如 /newpath 或 https://other.com/): " target
    if [ -z "${target}" ]; then
        echo -e "${yellow}已取消${white}"
        sleep 1
        return
    fi

    local directive
    case "$op" in
        1) directive="redir ${target}" ;;
        2) directive="rewrite * ${target}" ;;
        *)
            echo -e "${red}无效选择${white}"
            sleep 1
            return
            ;;
    esac

    if grep -qE '^\s*(redir|rewrite)\b' "$vhost_file"; then
        echo -e "${yellow}已存在 redir/rewrite 指令, 跳过${white}"
        break_end
        return
    fi

    caddy_vhost_backup "$vhost_file"
    caddy_vhost_insert_block "$vhost_file" "    ${directive}"
    caddy_vhost_validate_or_rollback "$vhost_file"
}

## 高级 [4]: 负载均衡 (替换原有 reverse_proxy 块)
caddy_adv_loadbalance() {
    local domain="$1"
    local vhost_file="${CADDY_VHOSTS_DIR}/${domain}.conf"

    local backends
    read -e -p "请输入多个后端 IP:端口 (空格分隔, 如 192.168.1.10:8080 192.168.1.11:8080): " backends
    if [ -z "${backends}" ]; then
        echo -e "${yellow}已取消${white}"
        sleep 1
        return
    fi

    # 验证每个 backend 格式
    local b
    for b in $backends; do
        if ! [[ "$b" =~ ^[0-9a-zA-Z\.\-]+:[0-9]+$ ]]; then
            echo -e "${red}后端格式不合法: ${b}, 应为 IP:PORT 形式${white}"
            break_end
            return
        fi
    done

    caddy_vhost_backup "$vhost_file"
    # 删除原 reverse_proxy 行 (替换为多块形式)
    caddy_vhost_remove_directive "$vhost_file" '^\s*reverse_proxy\s'
    # 插入新的 reverse_proxy 多行块
    caddy_vhost_insert_block "$vhost_file" "    reverse_proxy ${backends} {
        lb_policy round_robin
        health_uri /health
    }"
    caddy_vhost_validate_or_rollback "$vhost_file"
}

## 高级 [5]: HTTP 请求头管理
caddy_adv_header() {
    local domain="$1"
    local vhost_file="${CADDY_VHOSTS_DIR}/${domain}.conf"

    local key value
    read -e -p "请输入 Header 键 (如 X-Frame-Options): " key
    if [ -z "${key}" ]; then
        echo -e "${yellow}已取消${white}"
        sleep 1
        return
    fi
    read -e -p "请输入 Header 值 (如 DENY): " value
    if [ -z "${value}" ]; then
        echo -e "${yellow}已取消${white}"
        sleep 1
        return
    fi

    if grep -qE "^\s*header\s+${key}\b" "$vhost_file"; then
        echo -e "${yellow}已存在 header ${key}, 跳过${white}"
        break_end
        return
    fi

    caddy_vhost_backup "$vhost_file"
    caddy_vhost_insert_block "$vhost_file" "    header ${key} \"${value}\""
    caddy_vhost_validate_or_rollback "$vhost_file"
}

## 高级 [6]: IP 黑名单 / 访问限制
caddy_adv_blockip() {
    local domain="$1"
    local vhost_file="${CADDY_VHOSTS_DIR}/${domain}.conf"

    local ip
    read -e -p "请输入要屏蔽的 IP 或 CIDR 网段 (如 192.168.1.100 或 10.0.0.0/8): " ip
    if [ -z "${ip}" ]; then
        echo -e "${yellow}已取消${white}"
        sleep 1
        return
    fi

    if grep -qE '^\s*@blocked\b' "$vhost_file"; then
        echo -e "${yellow}已存在 IP 黑名单规则 (@blocked), 跳过${white}"
        break_end
        return
    fi

    caddy_vhost_backup "$vhost_file"
    caddy_vhost_insert_block "$vhost_file" "    @blocked {
        remote_ip ${ip}
    }
    abort @blocked"
    caddy_vhost_validate_or_rollback "$vhost_file"
}

## 高级 [7]: PHP FastCGI
caddy_adv_php() {
    local domain="$1"
    local vhost_file="${CADDY_VHOSTS_DIR}/${domain}.conf"

    local sock
    read -e -p "请输入 PHP-FPM sock 路径 (如 unix//run/php/php8.1-fpm.sock): " sock
    if [ -z "${sock}" ]; then
        echo -e "${yellow}已取消${white}"
        sleep 1
        return
    fi

    if grep -qE '^\s*php_fastcgi\b' "$vhost_file"; then
        echo -e "${yellow}已存在 php_fastcgi 指令, 跳过${white}"
        break_end
        return
    fi

    # 如果用户给的是 socket 文件而不是 unix://xxx 格式, 自动补全
    if [[ "$sock" == *.sock ]] && [[ "$sock" != unix://* ]]; then
        sock="unix://$sock"
    fi

    caddy_vhost_backup "$vhost_file"
    caddy_vhost_insert_block "$vhost_file" "    php_fastcgi ${sock}"
    caddy_vhost_validate_or_rollback "$vhost_file"
}

## 高级配置子菜单 (在 caddy_advanced_settings 内 while 循环)
caddy_advanced_settings() {
    caddy_init_env

    # 1. 先让用户选域名
    local domain
    if ! domain=$(caddy_select_vhost); then
        return
    fi

    # 2. 进入该域名的高级配置子菜单
    while true; do
        clear
        caddy_draw_dashboard
        echo ""
        echo -e "当前选中的域名: ${cyan}[ ${domain} ]${white}"
        echo -e "${pink}--------------------------------------------------------${white}"
        echo "请选择要追加的高级功能:"
        echo -e "${cyan}1.  ${white}开启静态文件托管 (File Server)"
        echo -e "${cyan}2.  ${white}开启基础密码保护 (Basic Auth)"
        echo -e "${cyan}3.  ${white}设置重定向与 URL 重写 (Redirect & Rewrite)"
        echo -e "${cyan}4.  ${white}配置负载均衡与健康检查 (Load Balancing)"
        echo -e "${cyan}5.  ${white}管理 HTTP 请求头 (Headers Management)"
        echo -e "${cyan}6.  ${white}IP 黑名单与访问限制 (IP/WAF)"
        echo -e "${cyan}7.  ${white}开启 PHP FastCGI"
        echo -e "${pink}--------------------------------------------------------${white}"
        echo -e "${yellow}0.  ${white}返回主菜单"
        echo -e "${pink}--------------------------------------------------------${white}"
        read -e -p "请输入你的选择: " adv_choice

        case "${adv_choice}" in
            1) caddy_adv_fileserver "$domain" ;;
            2) caddy_adv_basicauth  "$domain" ;;
            3) caddy_adv_redirect  "$domain" ;;
            4) caddy_adv_loadbalance "$domain" ;;
            5) caddy_adv_header     "$domain" ;;
            6) caddy_adv_blockip    "$domain" ;;
            7) caddy_adv_php        "$domain" ;;
            0) return 0 ;;
            *)
                echo -e "${red}无效选择, 请重新输入 !${white}"
                sleep 1
                ;;
        esac
    done
}

#############################################################################
############################ 安装 / 卸载 ####################################

## 安装 Caddy (官方源)
caddy_install() {
    caddy_check_root || return 1

    echo -e "${cyan}开始安装 Caddy ...${white}"
    local os
    os=$(detect_os)

    case "${os}" in
        debian|ubuntu)
            install curl debian-keyring debian-archive-keyring apt-transport-https gnupg
            curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
                | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
            curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
                | tee /etc/apt/sources.list.d/caddy-stable.list
            apt update
            install caddy
            ;;
        rhel|centos|fedora|rocky|almalinux)
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

#############################################################################
########################## 主菜单 / 入口 #####################################

## 渲染 Caddy 主菜单
caddy_show_menu() {
    echo ""
    echo -e "${cyan}1.  ${white}添加基础反向代理"
    echo -e "${cyan}2.  ${white}删除主机配置"
    echo -e "${cyan}3.  ${white}进入高级配置模式"
    echo -e "${cyan}4.  ${white}重载 Caddy 服务"
    echo -e "${cyan}5.  ${white}查看 Caddy 运行日志"
    echo -e "${pink}--------------------------------------------------------${white}"
    echo -e "${red}99.${white} 卸载 Caddy"
    echo -e "${yellow}0.  ${white}返回上一级菜单"
    echo -e "${pink}--------------------------------------------------------${white}"
    read -e -p "请输入你的选择: " choice

    case "${choice}" in
        1) caddy_add_proxy ;;
        2) caddy_del_proxy ;;
        3) caddy_advanced_settings ;;
        4) caddy_reload_service ;;
        5) caddy_view_logs ;;
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
    # 入口 root 校验
    caddy_check_root || { break_end; return; }

    # 未安装分支
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
