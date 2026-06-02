#!/bin/bash
###########################################################################
########################### 服务器集群管理模块 #############################
# 支持多服务器批量管理、批量命令执行

CLUSTER_DIR="$HOME/.linuxbox/cluster"
CLUSTER_SERVERS_FILE="$CLUSTER_DIR/servers.conf"

# 初始化集群配置目录
cluster_init() {
    mkdir -p "$CLUSTER_DIR"
    if [ ! -f "$CLUSTER_SERVERS_FILE" ]; then
        cat > "$CLUSTER_SERVERS_FILE" << 'EOF'
# LinuxBox 集群服务器配置文件
# 格式: 名称|IP|端口|用户名|密码
# 示例: server1|192.168.1.100|22|root|yourpassword
#
# 注意: 密码以明文存储，请确保此文件权限安全
# 建议使用 SSH 密钥认证替代密码认证
EOF
        chmod 600 "$CLUSTER_SERVERS_FILE"
    fi
}

# 添加服务器到集群
cluster_add_server() {
    clear
    echo -e "${cyan}===== 添加服务器 =====${white}"
    read -e -p "服务器名称: " server_name
    read -e -p "服务器IP地址: " server_ip
    read -e -p "SSH端口 (默认22): " server_port
    server_port=${server_port:-22}
    read -e -p "用户名 (默认root): " server_user
    server_user=${server_user:-root}
    read -e -p "密码 (留空则使用SSH密钥): " -s server_pass
    echo ""

    echo "$server_name|$server_ip|$server_port|$server_user|$server_pass" >> "$CLUSTER_SERVERS_FILE"
    echo -e "${green}服务器 '$server_name' ($server_ip) 已添加!${white}"
    break_end
}

# 删除集群服务器
cluster_remove_server() {
    clear
    echo -e "${cyan}===== 删除服务器 =====${white}"
    echo -e "${yellow}当前服务器列表:${white}"
    cluster_list_servers
    echo ""
    read -e -p "请输入要删除的服务器名称或IP: " keyword
    if [ -n "$keyword" ]; then
        sed -i "/^${keyword}|/d" "$CLUSTER_SERVERS_FILE"
        # 也尝试按IP删除
        grep -v "^.*|${keyword}|" "$CLUSTER_SERVERS_FILE" > "$CLUSTER_SERVERS_FILE.tmp"
        mv "$CLUSTER_SERVERS_FILE.tmp" "$CLUSTER_SERVERS_FILE"
        echo -e "${green}已删除包含 '$keyword' 的服务器${white}"
    fi
    break_end
}

# 编辑集群配置
cluster_edit_servers() {
    clear
    install nano
    nano "$CLUSTER_SERVERS_FILE"
}

# 列出所有服务器
cluster_list_servers() {
    if [ ! -f "$CLUSTER_SERVERS_FILE" ]; then
        echo -e "${yellow}暂无服务器配置${white}"
        return
    fi

    echo -e "${cyan}名称              IP地址            端口    用户${white}"
    echo -e "${pink}------------------------------------------------${white}"
    grep -v '^#' "$CLUSTER_SERVERS_FILE" | grep '|' | while IFS='|' read -r name ip port user pass; do
        if [ -n "$name" ] && [ "$name" != "" ]; then
            printf "%-18s %-17s %-7s %s\n" "$name" "$ip" "$port" "$user"
        fi
    done
}

# 备份集群配置
cluster_backup() {
    clear
    local backup_file="$CLUSTER_DIR/servers.conf.bak.$(date +%Y%m%d%H%M%S)"
    cp "$CLUSTER_SERVERS_FILE" "$backup_file"
    echo -e "${green}集群配置已备份到: $backup_file${white}"
    echo -e "${yellow}配置文件路径: $CLUSTER_SERVERS_FILE${white}"
    break_end
}

# 测试服务器连接
cluster_test_connection() {
    install sshpass
    clear
    echo -e "${cyan}===== 测试服务器连接 =====${white}"

    grep -v '^#' "$CLUSTER_SERVERS_FILE" | grep '|' | while IFS='|' read -r name ip port user pass; do
        if [ -n "$name" ] && [ "$name" != "" ]; then
            echo -n "  测试 $name ($ip)... "
            if [ -n "$pass" ]; then
                if sshpass -p "$pass" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 "$user@$ip" -p "$port" "echo ok" &>/dev/null; then
                    echo -e "${green}✓ 连接成功${white}"
                else
                    echo -e "${red}✗ 连接失败${white}"
                fi
            else
                if ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 "$user@$ip" -p "$port" "echo ok" &>/dev/null; then
                    echo -e "${green}✓ 连接成功${white}"
                else
                    echo -e "${red}✗ 连接失败${white}"
                fi
            fi
        fi
    done
    break_end
}

# 在所有服务器上执行命令
cluster_run_command() {
    install sshpass
    clear
    read -e -p "请输入要批量执行的命令: " cmd
    if [ -z "$cmd" ]; then
        echo -e "${yellow}命令不能为空${white}"
        break_end
        return 1
    fi

    echo -e "${cyan}===== 批量执行命令 =====${white}"
    echo -e "${yellow}命令: $cmd${white}"
    echo -e "${pink}------------------------${white}"

    grep -v '^#' "$CLUSTER_SERVERS_FILE" | grep '|' | while IFS='|' read -r name ip port user pass; do
        if [ -n "$name" ] && [ "$name" != "" ]; then
            echo -e "${cyan}[$name] ($ip)${white}"
            if [ -n "$pass" ]; then
                sshpass -p "$pass" ssh -t -o StrictHostKeyChecking=no "$user@$ip" -p "$port" "$cmd" 2>&1
            else
                ssh -t -o StrictHostKeyChecking=no "$user@$ip" -p "$port" "$cmd" 2>&1
            fi
            echo -e "${pink}------------------------${white}"
        fi
    done
    echo -e "${green}命令执行完毕!${white}"
    break_end
}

# 批量更新系统
cluster_update_all() {
    install sshpass
    clear
    echo -e "${cyan}===== 批量更新系统 =====${white}"

    grep -v '^#' "$CLUSTER_SERVERS_FILE" | grep '|' | while IFS='|' read -r name ip port user pass; do
        if [ -n "$name" ] && [ "$name" != "" ]; then
            echo -e "${cyan}[$name] ($ip) 正在更新...${white}"
            if [ -n "$pass" ]; then
                sshpass -p "$pass" ssh -o StrictHostKeyChecking=no "$user@$ip" -p "$port" "apt update -y && apt upgrade -y && apt autoremove -y" 2>&1
            else
                ssh -o StrictHostKeyChecking=no "$user@$ip" -p "$port" "apt update -y && apt upgrade -y && apt autoremove -y" 2>&1
            fi
            echo -e "${green}[$name] 更新完成${white}"
            echo -e "${pink}------------------------${white}"
        fi
    done
    break_end
}

# 批量安装Docker
cluster_install_docker() {
    install sshpass
    clear
    echo -e "${cyan}===== 批量安装 Docker =====${white}"

    local install_cmd='curl -fsSL https://get.docker.com | sh && systemctl enable docker && systemctl start docker'

    grep -v '^#' "$CLUSTER_SERVERS_FILE" | grep '|' | while IFS='|' read -r name ip port user pass; do
        if [ -n "$name" ] && [ "$name" != "" ]; then
            echo -e "${cyan}[$name] ($ip) 正在安装Docker...${white}"
            if [ -n "$pass" ]; then
                sshpass -p "$pass" ssh -o StrictHostKeyChecking=no "$user@$ip" -p "$port" "$install_cmd" 2>&1
            else
                ssh -o StrictHostKeyChecking=no "$user@$ip" -p "$port" "$install_cmd" 2>&1
            fi
            echo -e "${green}[$name] Docker安装完成${white}"
            echo -e "${pink}------------------------${white}"
        fi
    done
    break_end
}

# 批量设置时区
cluster_set_timezone() {
    install sshpass
    clear
    read -e -p "请输入时区 (默认 Asia/Shanghai): " tz
    tz=${tz:-Asia/Shanghai}

    echo -e "${cyan}===== 批量设置时区: $tz =====${white}"

    grep -v '^#' "$CLUSTER_SERVERS_FILE" | grep '|' | while IFS='|' read -r name ip port user pass; do
        if [ -n "$name" ] && [ "$name" != "" ]; then
            echo -e "${cyan}[$name] ($ip)${white}"
            if [ -n "$pass" ]; then
                sshpass -p "$pass" ssh -o StrictHostKeyChecking=no "$user@$ip" -p "$port" "timedatectl set-timezone $tz 2>/dev/null || ln -sf /usr/share/zoneinfo/$tz /etc/localtime" 2>&1
            else
                ssh -o StrictHostKeyChecking=no "$user@$ip" -p "$port" "timedatectl set-timezone $tz 2>/dev/null || ln -sf /usr/share/zoneinfo/$tz /etc/localtime" 2>&1
            fi
            echo -e "${green}[$name] 时区已设置${white}"
        fi
    done
    break_end
}

# 集群管理主菜单
linux_cluster() {
    cluster_init

    while true; do
        clear
        echo -e "${cyan}===== 服务器集群管理 =====${white}"
        cluster_list_servers
        echo ""
        echo -e "${pink}------------------------${white}"
        echo -e "${cyan}服务器列表管理${white}"
        echo -e "${cyan}1.   ${white}添加服务器"
        echo -e "${cyan}2.   ${white}删除服务器"
        echo -e "${cyan}3.   ${white}编辑服务器配置"
        echo -e "${cyan}4.   ${white}备份配置"
        echo -e "${cyan}5.   ${white}测试连接"
        echo -e "${pink}------------------------${white}"
        echo -e "${cyan}批量执行任务${white}"
        echo -e "${cyan}11.  ${white}自定义命令执行"
        echo -e "${cyan}12.  ${white}批量更新系统"
        echo -e "${cyan}13.  ${white}批量安装Docker"
        echo -e "${cyan}14.  ${white}批量设置时区"
        echo -e "${pink}------------------------${white}"
        echo -e "${yellow}0.   ${white}返回主菜单"
        echo -e "${pink}------------------------${white}"
        read -e -p "请选择功能编号: " choice

        case $choice in
            1) cluster_add_server ;;
            2) cluster_remove_server ;;
            3) cluster_edit_servers ;;
            4) cluster_backup ;;
            5) cluster_test_connection ;;
            11) cluster_run_command ;;
            12) cluster_update_all ;;
            13) cluster_install_docker ;;
            14) cluster_set_timezone ;;
            0) return_to_menu ;;
            *)
                echo -e "${red}${LX_invalid}${white}"
                sleep 1
                ;;
        esac
    done
}
