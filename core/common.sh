#!/bin/bash
# core/common.sh - 全局共享变量与函数

# 颜色定义
white='\033[0m'
green='\033[0;32m'
blue='\033[0;34m'
red='\033[31m'
yellow='\033[33m'
grey='\e[37m'
pink='\033[38;5;218m'
cyan='\033[36m'
purple='\033[35m'

# echo 颜色函数
echo_white() { echo -e "${white}$*"; }
echo_green() { echo -e "${green}$*"; }
echo_blue() { echo -e "${blue}$*"; }
echo_red() { echo -e "${red}$*"; }
echo_yellow() { echo -e "${yellow}$*"; }
echo_grey() { echo -e "${grey}$*"; }
echo_pink() { echo -e "${pink}$*"; }
echo_cyan() { echo -e "${cyan}$*"; }
echo_purple() { echo -e "${purple}$*"; }

# 支持系统
SUPPORTED_OS=("ubuntu" "debian" "arch" "fedora")

# 地区默认值
region="CN"

# 默认快捷键
key="j"

# 初始化授权状态
user_authorization="false"

# 版本信息
version="3.0.12"

# 代理URL
url_proxy=""

# 脚本地址
script_url=""

detect_region() {
    local ip_services=(
        "https://ipapi.co/country/"
        "https://ipinfo.io/country"
        "https://api.ip.sb/country"
    )
    for service in "${ip_services[@]}"; do
        local country=$(curl -s --connect-timeout 3 "$service" | tr '[:lower:]' '[:upper:]')
        if [ -n "$country" ] && [ ${#country} -eq 2 ]; then
            region="$country"
            echo "检测到地区: $region"
            return 0
        fi
    done
    echo "无法检测地区, 使用默认值: $region"
    return 1
}

use_proxy() {
    detect_region
    if [ "$region" == "CN" ]; then
        url_proxy="https://proxy.cccg.top/"
    else
        url_proxy="https://"
    fi
}

authorization_check() {
    if grep -q '^user_authorization="true"' /usr/local/bin/${key} > /dev/null 2>&1; then
        sed -i 's/^user_authorization="false"/user_authorization="true"/' /usr/local/bin/${key}
    fi
    authorization_false
}

authorization_false() {
    if grep -q '^user_authorization="false"' /usr/local/bin/${key} > /dev/null 2>&1; then
        UserLicenseAgreement
    fi
}

CheckFirstRun() {
    if [ ! -f "/usr/local/bin/${key}" ]; then
        if [ ! -f "./LinuxBox.sh" ]; then
            echo -e "请稍后, 正在下载..."
            curl -sL "$script_url" -o ./LinuxBox.sh
            echo -e "下载完成!"
            chmod +x ./LinuxBox.sh
        fi
        cp -f ./LinuxBox.sh /usr/local/bin/${key} > /dev/null 2>&1
        chmod +x /usr/local/bin/${key} > /dev/null 2>&1
        echo -e "${cyan}安装完成!${white}"
        echo -e "${yellow}---------${white}"
        echo -e "命令行输入${yellow} ${key} ${cyan}可快速启动脚本${white}"
        rm -f ./LinuxBox.sh
        break_end
        UserLicenseAgreement
    else
        authorization_check
    fi
}

break_end() {
    echo -e "${green}操作完成${white}"
    echo "按任意键继续..."
    read -n 1 -s -r -p ""
    echo ""
    clear
}

return_to_menu() {
    echo "按任意键返回主菜单..."
    read -n 1 -s -r -p ""
    clear
}
