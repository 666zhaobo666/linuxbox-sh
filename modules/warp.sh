#!/bin/bash
###########################################################################
########################### WARP管理模块 ###################################
# Cloudflare WARP 客户端管理
# 支持 WARP 安装/卸载/状态查看/模式切换

# WARP 安装
warp_install() {
    root_use || return 1
    clear
    echo -e "${cyan}正在安装 Cloudflare WARP...${white}"

    # 检测系统类型并安装
    local os_id
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        os_id=$ID
    fi

    case "$os_id" in
        ubuntu|debian)
            # 添加 Cloudflare GPG 密钥和源
            install gnupg2 lsb-release
            curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | gpg --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
            echo "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/cloudflare-client.list
            apt update -y
            apt install -y cloudflare-warp
            ;;
        centos|rocky|almalinux)
            install yum-utils
            rpm -ivh https://pkg.cloudflareclient.com/cloudflare-release-el${VERSION_ID%%.*}.rpm
            yum install -y cloudflare-warp
            ;;
        fedora)
            rpm -ivh https://pkg.cloudflareclient.com/cloudflare-release-fc$(rpm -E %fedora).rpm
            dnf install -y cloudflare-warp
            ;;
        arch|manjaro)
            # Arch 使用 AUR 或直接安装
            if command -v pacman &>/dev/null; then
                pacman -Syu --noconfirm
                # 尝试从 AUR 安装
                if command -v yay &>/dev/null; then
                    yay -S --noconfirm cloudflare-warp-bin
                elif command -v paru &>/dev/null; then
                    paru -S --noconfirm cloudflare-warp-bin
                else
                    echo -e "${yellow}Arch系统需要安装 AUR helper (yay/paru) 来安装 WARP${white}"
                    echo -e "${yellow}或手动安装: yay -S cloudflare-warp-bin${white}"
                    break_end
                    return 1
                fi
            fi
            ;;
        alpine)
            # Alpine 使用 warp-cli 二进制
            install curl tar
            local arch_name
            arch_name=$(uname -m)
            case "$arch_name" in
                x86_64) arch_name="amd64" ;;
                aarch64) arch_name="arm64" ;;
                *) echo -e "${red}不支持的架构: $arch_name${white}"; break_end; return 1 ;;
            esac
            curl -fsSL "https://github.com/cloudflare/warp-release/releases/latest/download/warp-linux-${arch_name}.tar.gz" -o /tmp/warp.tar.gz
            tar xzf /tmp/warp.tar.gz -C /tmp/
            cp /tmp/warp-cli /usr/local/bin/
            chmod +x /usr/local/bin/warp-cli
            rm -f /tmp/warp.tar.gz
            ;;
        *)
            echo -e "${red}不支持的系统类型: $os_id${white}"
            break_end
            return 1
            ;;
    esac

    echo -e "${green}WARP 安装完成!${white}"
    warp_cli_register
    break_end
}

# WARP 注册
warp_cli_register() {
    if command -v warp-cli &>/dev/null; then
        echo -e "${cyan}正在注册 WARP...${white}"
        warp-cli registration new
        warp-cli connect
        echo -e "${green}WARP 已连接!${white}"
    fi
}

# WARP 卸载
warp_uninstall() {
    root_use || return 1
    clear
    echo -e "${red}警告: 即将卸载 Cloudflare WARP!${white}"
    read -r -p "是否确认卸载？(y/n): " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        if command -v warp-cli &>/dev/null; then
            warp-cli disconnect 2>/dev/null
        fi

        local os_id
        if [ -f /etc/os-release ]; then
            . /etc/os-release
            os_id=$ID
        fi

        case "$os_id" in
            ubuntu|debian)
                apt remove -y cloudflare-warp
                rm -f /etc/apt/sources.list.d/cloudflare-client.list
                rm -f /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
                apt update -y
                ;;
            centos|rocky|almalinux)
                yum remove -y cloudflare-warp
                rpm -e cloudflare-release 2>/dev/null
                ;;
            fedora)
                dnf remove -y cloudflare-warp
                rpm -e cloudflare-release 2>/dev/null
                ;;
            arch|manjaro)
                pacman -Rns --noconfirm cloudflare-warp-bin 2>/dev/null
                ;;
            alpine)
                rm -f /usr/local/bin/warp-cli
                ;;
        esac

        echo -e "${green}WARP 已卸载!${white}"
    else
        echo "已取消卸载."
    fi
    break_end
}

# 查看 WARP 状态
warp_status() {
    clear
    echo -e "${cyan}===== WARP 状态 =====${white}"
    if command -v warp-cli &>/dev/null; then
        warp-cli status
        echo ""
        echo -e "${cyan}===== WARP 设置 =====${white}"
        warp-cli settings
    else
        echo -e "${yellow}WARP 未安装${white}"
    fi
    break_end
}

# WARP 连接
warp_connect() {
    if command -v warp-cli &>/dev/null; then
        echo -e "${cyan}正在连接 WARP...${white}"
        warp-cli connect
        sleep 2
        warp-cli status
    else
        echo -e "${yellow}WARP 未安装${white}"
    fi
    break_end
}

# WARP 断开
warp_disconnect() {
    if command -v warp-cli &>/dev/null; then
        echo -e "${cyan}正在断开 WARP...${white}"
        warp-cli disconnect
        sleep 2
        warp-cli status
    else
        echo -e "${yellow}WARP 未安装${white}"
    fi
    break_end
}

# WARP 模式切换
warp_change_mode() {
    if ! command -v warp-cli &>/dev/null; then
        echo -e "${yellow}WARP 未安装${white}"
        break_end
        return 1
    fi

    clear
    echo -e "${cyan}===== WARP 代理模式 =====${white}"
    echo -e "${cyan}1.  ${white}WARP 模式 (全局代理，所有流量通过 WARP)"
    echo -e "${cyan}2.  ${white}代理模式 (仅代理流量，支持 SOCKS5)"
    echo -e "${cyan}3.  ${white}DNS 模式 (仅 DNS over HTTPS)"
    echo -e "${cyan}0.  ${white}返回"
    echo -e "${pink}------------------------${white}"
    read -e -p "请选择模式: " mode_choice

    case $mode_choice in
        1)
            warp-cli mode warp
            echo -e "${green}已切换为 WARP 全局模式${white}"
            ;;
        2)
            warp-cli mode proxy
            echo -e "${green}已切换为代理模式 (SOCKS5: 127.0.0.1:40000)${white}"
            ;;
        3)
            warp-cli mode dns
            echo -e "${green}已切换为 DNS 模式${white}"
            ;;
        0)
            return
            ;;
        *)
            echo -e "${red}无效选择${white}"
            ;;
    esac
    sleep 1
    warp-cli status
    break_end
}

# WARP DNS 设置
warp_dns_settings() {
    if ! command -v warp-cli &>/dev/null; then
        echo -e "${yellow}WARP 未安装${white}"
        break_end
        return 1
    fi

    clear
    echo -e "${cyan}===== WARP DNS 设置 =====${white}"
    echo -e "${cyan}1.  ${white}使用 WARP DNS"
    echo -e "${cyan}2.  ${white}使用自定义 DNS"
    echo -e "${cyan}0.  ${white}返回"
    echo -e "${pink}------------------------${white}"
    read -e -p "请选择: " dns_choice

    case $dns_choice in
        1)
            warp-cli dns warp
            echo -e "${green}已设置为 WARP DNS${white}"
            ;;
        2)
            read -e -p "请输入 DNS 服务器地址: " custom_dns
            warp-cli dns "$custom_dns"
            echo -e "${green}DNS 已设置为: $custom_dns${white}"
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

# WARP 管理主菜单
linux_warp() {
    while true; do
        clear
        echo -e "${cyan}===== WARP 管理 =====${white}"
        echo -e "${cyan}1.   ${white}安装 WARP"
        echo -e "${cyan}2.   ${white}卸载 WARP"
        echo -e "${cyan}3.   ${white}查看状态"
        echo -e "${cyan}4.   ${white}连接 WARP"
        echo -e "${cyan}5.   ${white}断开 WARP"
        echo -e "${cyan}6.   ${white}切换代理模式"
        echo -e "${cyan}7.   ${white}DNS 设置"
        echo -e "${pink}------------------------${white}"
        echo -e "${yellow}0.   ${white}返回主菜单"
        echo -e "${pink}------------------------${white}"
        read -e -p "请选择功能编号: " choice

        case $choice in
            1) warp_install ;;
            2) warp_uninstall ;;
            3) warp_status ;;
            4) warp_connect ;;
            5) warp_disconnect ;;
            6) warp_change_mode ;;
            7) warp_dns_settings ;;
            0) return ;;
            *)
                echo -e "${red}${LX_invalid}${white}"
                sleep 1
                ;;
        esac
    done
}
