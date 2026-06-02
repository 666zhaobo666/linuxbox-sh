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

    # 列宽定义 (供表头和每行复用, 改一处即生效)
    # 顺序: 域名 | 反代目标 | 类型 | SSL 证书 | 备注 | 网站目录
    local W_DOMAIN=22 W_TARGET=20 W_TYPE=10 W_SSL=10 W_REMARK=18 W_ROOT=30

    echo -e "${green}===== Caddy 反向代理管理 =====${white}"
    echo ""
    echo -e "${pink}--------------------------------------------------------------------------------------------${white}"
    printf "  ${cyan}%-${W_DOMAIN}s${white} | ${cyan}%-${W_TARGET}s${white} | ${cyan}%-${W_TYPE}s${white} | ${cyan}%-${W_SSL}s${white} | ${cyan}%-${W_REMARK}s${white} | ${cyan}%s${white}\n" \
        "域名" "反代目标" "类型" "SSL 证书" "备注" "网站目录"
    echo -e "${pink}--------------------------------------------------------------------------------------------${white}"

    if [ -d "${CADDY_VHOSTS_DIR}" ]; then
        local conf_file domain target vtype ssl_text remark root_dir ssl_color
        for conf_file in "${CADDY_VHOSTS_DIR}"/*.conf; do
            [ -e "${conf_file}" ] || continue
            domain=$(basename "${conf_file}" .conf)
            target=$(grep -E '^\s*reverse_proxy' "${conf_file}" 2>/dev/null | \
                     head -n1 | awk '{print $2}')
            [ -z "${target}" ] && target="-"
            vtype=$(caddy_parse_type "${conf_file}")
            remark=$(caddy_parse_remark "${conf_file}")
            [ -z "${remark}" ] && remark="-"
            root_dir=$(caddy_parse_root "${conf_file}")

            # SSL 状态着色
            ssl_text=$(caddy_ssl_status "${domain}")
            if [ "${ssl_text}" = "已签发" ]; then
                ssl_color="${green}"
            else
                ssl_color="${yellow}"
            fi

            # 长字符串截断 (避免单行超宽破坏表格)
            [ "${#target}"    -gt ${W_TARGET} ] && target="${target:0:$((W_TARGET-1))}…"
            [ "${#vtype}"     -gt ${W_TYPE}  ] && vtype="${vtype:0:$((W_TYPE-1))}…"
            [ "${#remark}"    -gt ${W_REMARK} ] && remark="${remark:0:$((W_REMARK-1))}…"
            [ "${#root_dir}"  -gt ${W_ROOT}   ] && root_dir="${root_dir:0:$((W_ROOT-1))}…"

            printf "  %-${W_DOMAIN}s | %-${W_TARGET}s | %-${W_TYPE}s | ${ssl_color}%-${W_SSL}s${white} | %-${W_REMARK}s | %s\n" \
                "${domain}" "${target}" "${vtype}" "${ssl_text}" "${remark}" "${root_dir}"
        done
    else
        echo "  (暂无配置)"
    fi

    echo -e "${pink}--------------------------------------------------------------------------------------------${white}"
    printf "  状态: ${status_color}%s${white}  |  内存占用: %s MB\n" "${status}" "${mem}"
    echo -e "${pink}--------------------------------------------------------------------------------------------${white}"
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

## 解析 vhost 文件里的用户备注
# 用法: caddy_parse_remark <vhost_file>
# 输出: 备注字符串 (可能含空格), 无备注时输出空
caddy_parse_remark() {
    local vhost_file="$1"
    grep -E '^\s*#\s*remark:' "$vhost_file" 2>/dev/null | head -n1 | sed -E 's/.*remark:[[:space:]]*//'
}

## 解析 vhost 文件的网站根目录
# 用法: caddy_parse_root <vhost_file>
# 输出: 根目录路径, 无 root 指令时输出 -
caddy_parse_root() {
    local vhost_file="$1"
    local root
    root=$(grep -E '^\s*root\s+\*' "$vhost_file" 2>/dev/null | head -n1 | awk '{print $3}')
    [ -z "${root}" ] && root="-"
    echo "${root}"
}

## 解析 vhost 文件的类型 (按指令组合自动归类)
# 用法: caddy_parse_type <vhost_file>
# 输出: 反向代理 / 静态网站 / PHP 站点 / 负载均衡 / 重定向 / PHP+静态 / 反代+静态 / 反代+重定向 / 未知
caddy_parse_type() {
    local vhost_file="$1"
    local has_php has_fs has_root has_proxy has_redir
    has_php=$(grep -cE '^\s*php_fastcgi\b' "$vhost_file" 2>/dev/null)
    has_fs=$(grep -cE '^\s*file_server\b' "$vhost_file" 2>/dev/null)
    has_root=$(grep -cE '^\s*root\s+\*' "$vhost_file" 2>/dev/null)
    has_proxy=$(grep -cE '^\s*reverse_proxy\b' "$vhost_file" 2>/dev/null)
    has_redir=$(grep -cE '^\s*(redir|rewrite)\b' "$vhost_file" 2>/dev/null)

    # 1. PHP 站点优先 (PHP 通常配 file_server 处理静态资源)
    if [ "${has_php}" -gt 0 ]; then
        if [ "${has_fs}" -gt 0 ]; then
            echo "PHP+静态"
        else
            echo "PHP 站点"
        fi
        return
    fi

    # 2. 静态网站: 有 file_server + root, 没有 reverse_proxy
    if [ "${has_fs}" -gt 0 ] && [ "${has_root}" -gt 0 ]; then
        if [ "${has_proxy}" -gt 0 ]; then
            echo "反代+静态"
        else
            echo "静态网站"
        fi
        return
    fi

    # 3. 重定向
    if [ "${has_redir}" -gt 0 ]; then
        if [ "${has_proxy}" -gt 0 ]; then
            echo "反代+重定向"
        else
            echo "重定向"
        fi
        return
    fi

    # 4. 反向代理 (单后端 / 多后端=负载均衡)
    if [ "${has_proxy}" -gt 0 ]; then
        local backend_count
        # 取第一行 reverse_proxy 后面所有 IP:PORT 形式的参数
        backend_count=$(grep -E '^\s*reverse_proxy' "$vhost_file" 2>/dev/null | \
                        head -n1 | awk '{for(i=2;i<=NF;i++) if($i ~ /:/) c++} END{print c+0}')
        if [ "${backend_count}" -gt 1 ]; then
            echo "负载均衡"
        else
            echo "反向代理"
        fi
        return
    fi

    echo "未知"
}

## 让用户从 vhost 列表中选一个域名, 选中的域名 echo 到 stdout, 取消时 echo 空
# 重要: 所有诊断输出走 stderr, 避免污染 $(caddy_select_vhost) 捕获到的 stdout
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
        # 无域名: 走 stderr, 调用方负责提示用户
        echo -e "${yellow}当前没有任何域名配置${white}" >&2
        return 1
    fi

    echo -e "${cyan}请选择要操作的域名:${white}" >&2
    local i
    for ((i=0; i<${#domains[@]}; i++)); do
        echo "  $((i+1)). ${domains[$i]}" >&2
    done
    read -e -p "请输入序号 (输入 0 取消): " choice

    if ! [[ "$choice" =~ ^[0-9]+$ ]]; then
        echo -e "${red}无效输入${white}" >&2
        sleep 1
        return 1
    fi
    if [ "$choice" -eq 0 ]; then
        return 1
    fi
    if [ "$choice" -lt 1 ] || [ "$choice" -gt ${#domains[@]} ]]; then
        echo -e "${red}序号超出范围${white}" >&2
        sleep 1
        return 1
    fi

    # 只让选中的域名走 stdout, 供命令替换捕获
    echo "${domains[$((choice-1))]}"
    return 0
}

#############################################################################
############################ 基础菜单功能 ####################################

## 菜单 1: 添加基础反向代理
caddy_add_proxy() {
    caddy_init_env

    local domain target remark
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

    # 备注 (可选)
    read -e -p "请输入备注 (可选, 例如 \"家庭 NAS 主页\"): " remark

    local vhost_file="${CADDY_VHOSTS_DIR}/${domain}.conf"
    # 备注作为 Caddyfile 注释放在 vhost 块内 (caddy validate 会忽略 # 注释)
    # 备注放 `}` 之前, 这样 caddy_vhost_insert_block 不会误删
    {
        echo "${domain} {"
        echo "    reverse_proxy ${target}"
        if [ -n "${remark}" ]; then
            echo "    # remark: ${remark}"
        fi
        echo "}"
    } > "${vhost_file}"

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

## 菜单 3: 修改主机备注
caddy_edit_remark() {
    caddy_init_env

    # 入口自检: 没 vhost 时直接提示返回 (跟 caddy_advanced_settings 一样的处理)
    local vhost_count
    vhost_count=$(ls "${CADDY_VHOSTS_DIR}"/*.conf 2>/dev/null | wc -l)
    if [ "${vhost_count}" -eq 0 ]; then
        echo -e "${yellow}当前没有任何域名配置, 请先在主菜单 [1] 添加基础反向代理${white}"
        sleep 2
        return
    fi

    # 选域名
    local domain
    if ! domain=$(caddy_select_vhost); then
        return
    fi
    local vhost_file="${CADDY_VHOSTS_DIR}/${domain}.conf"

    # 显示当前备注 (方便用户续写)
    local current_remark
    current_remark=$(caddy_parse_remark "${vhost_file}")
    if [ -n "${current_remark}" ]; then
        echo -e "当前备注: ${cyan}${current_remark}${white}"
    else
        echo "当前无备注"
    fi

    # 读新备注 (留空 = 删除备注)
    local new_remark
    read -e -p "请输入新备注 (留空 = 删除备注): " new_remark

    caddy_vhost_backup "${vhost_file}"
    # 先删掉所有旧 # remark 行 (避免重复)
    caddy_vhost_remove_directive "${vhost_file}" '^[[:space:]]*#[[:space:]]*remark:'
    # 再在 `}` 之前插入新备注 (留空则不插)
    if [ -n "${new_remark}" ]; then
        caddy_vhost_insert_block "${vhost_file}" "    # remark: ${new_remark}"
    fi
    caddy_vhost_validate_or_rollback "${vhost_file}"
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

    # 入口自检: 没 vhost 时直接提示返回, 不让用户进入子流程后再被 break_end 弹回
    # (这样 UX 更明确: 一次性说清要去 [1] 添加, 而不是进了高级模式又被踢回主菜单)
    local vhost_count
    vhost_count=$(ls "${CADDY_VHOSTS_DIR}"/*.conf 2>/dev/null | wc -l)
    if [ "${vhost_count}" -eq 0 ]; then
        echo -e "${yellow}当前没有任何域名配置, 请先在主菜单 [1] 添加基础反向代理${white}"
        sleep 2
        return
    fi

    # 1. 让用户选域名 (选中的域名走 stdout, 诊断提示走 stderr)
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
            # 直接调 apt 不用 install 函数:
            #   - DEBIAN_FRONTEND=noninteractive 禁止任何交互式询问
            #   - --force-confold 强制保留用户现有的 /etc/caddy/Caddyfile
            #     (我们的 Caddyfile 已经 import /etc/caddy/vhosts/*.conf, 比包自带的完整)
            DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::="--force-confold" caddy
            ;;
        rhel|centos|fedora|rocky|almalinux)
            install curl gnupg
            curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
                | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
            curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/rpm.rpm.txt' \
                | tee /etc/yum.repos.d/caddy-stable.repo
            # 替换可能的 Caddyfile 冲突, -y 避免交互
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

    # 1. 确认卸载
    local confirm
    read -e -p "确定要卸载 Caddy 吗？(y/n): " confirm
    if [[ ! "${confirm}" =~ ^[Yy]$ ]]; then
        echo -e "${yellow}已取消${white}"
        sleep 1
        return
    fi

    # 2. 询问是否保留配置和证书
    echo ""
    echo -e "${cyan}是否保留以下目录?${white}"
    echo "  - /etc/caddy      (主配置 Caddyfile + vhost 文件)"
    echo "  - /var/lib/caddy  (SSL 证书 + ACME 账号 + 运行时数据)"
    local keep_config
    read -e -p "保留配置和证书? [Y/n]: " keep_config
    keep_config="${keep_config:-y}"

    # 3. 停止服务 + 卸载包
    systemctl stop caddy 2>/dev/null
    systemctl disable caddy 2>/dev/null

    local os
    os=$(detect_os)
    case "${os}" in
        debian|ubuntu) DEBIAN_FRONTEND=noninteractive apt-get remove --purge -y caddy 2>/dev/null ;;
        rhel|centos|fedora|rocky|almalinux)
            command -v dnf >/dev/null 2>&1 && dnf remove -y caddy 2>/dev/null \
                || yum remove -y caddy 2>/dev/null
            ;;
        arch) pacman -Rns --noconfirm caddy 2>/dev/null ;;
        alpine) apk del caddy 2>/dev/null ;;
    esac

    # 4. 根据用户选择处理配置目录
    if [[ "${keep_config}" =~ ^[Yy]$ ]]; then
        echo -e "${green}Caddy 已卸载, 以下目录已保留:${white}"
        echo "  /etc/caddy"
        echo "  /var/lib/caddy"
        echo "  重新安装 Caddy 后可继续使用"
    else
        echo -e "${yellow}正在清理配置和证书...${white}"
        rm -rf /etc/caddy /var/lib/caddy 2>/dev/null
        echo -e "${green}Caddy 已完全卸载, 配置和证书已全部清除${white}"
    fi
    break_end
}

#############################################################################
########################## 主菜单 / 入口 #####################################

## 渲染 Caddy 主菜单
caddy_show_menu() {
    echo ""
    echo -e "${cyan}1.  ${white}添加基础反向代理"
    echo -e "${cyan}2.  ${white}删除主机配置"
    echo -e "${cyan}3.  ${white}修改主机备注"
    echo -e "${cyan}4.  ${white}进入高级配置模式"
    echo -e "${cyan}5.  ${white}重载 Caddy 服务"
    echo -e "${cyan}6.  ${white}查看 Caddy 运行日志"
    echo -e "${pink}--------------------------------------------------------${white}"
    echo -e "${red}99.${white} 卸载 Caddy"
    echo -e "${yellow}0.  ${white}返回上一级菜单"
    echo -e "${pink}--------------------------------------------------------${white}"
    read -e -p "请输入你的选择: " choice

    case "${choice}" in
        1) caddy_add_proxy ;;
        2) caddy_del_proxy ;;
        3) caddy_edit_remark ;;
        4) caddy_advanced_settings ;;
        5) caddy_reload_service ;;
        6) caddy_view_logs ;;
        99) caddy_uninstall ;;
        0) return 0 ;;
        *)
            echo -e "${red}无效选择, 请重新输入 !${white}"
            sleep 1
            ;;
    esac
    return 1
}

## "未安装" 提示面板 (提取为独立函数, 安装前和卸载后都用这个)
# 用法: caddy_show_uninstalled_panel
# 返回 0 表示用户选了 0 退出整个 linux_caddy, 否则继续
caddy_show_uninstalled_panel() {
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
            # 安装完成返回, 调用方 while 会重新检测 caddy 是否真装上了
            return 1
            ;;
        0|"")
            return 0
            ;;
        *)
            echo -e "${red}无效选择, 请重新输入 !${white}"
            sleep 1
            return 1
            ;;
    esac
}

## Caddy 模块入口: 主菜单第 8 项调用
linux_caddy() {
    # 入口 root 校验
    caddy_check_root || { break_end; return; }

    # 主循环: 每次开头都重新检测 caddy 是否还在
    # (卸载后 caddy 二进制被删, 必须能自动跳回"未安装"面板)
    while true; do
        if ! caddy_check_installed; then
            # 未安装: 渲染未安装面板
            # 选了 0 → return 0 → 退出 linux_caddy
            # 选了 1 (安装) 或其他 → return 1 → 继续 while 重新检测
            caddy_show_uninstalled_panel && return
            continue
        fi

        # 已安装: 渲染主面板
        clear
        caddy_draw_dashboard
        caddy_show_menu && return
    done
}
