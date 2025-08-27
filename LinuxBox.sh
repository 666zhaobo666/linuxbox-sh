#!/bin/bash
# LinuxBox 多功能管理脚本
#版本信息
version="2.1.2"
## 全局颜色变量
white='\033[0m'			# 白色
green='\033[0;32m'		# 绿色
blue='\033[0;34m'		# 蓝色
red='\033[31m'			# 红色
yellow='\033[33m'		# 黄色
grey='\e[37m'			# 灰色
pink='\033[38;5;218m'	# 粉色
cyan='\033[36m'			# 青色
purple='\033[35m'		# 紫色

## 支持系统
SUPPORTED_OS=("ubuntu" "debian" "arch" "fedora")

## 地区默认值
region="CN"

## 默认快捷键
key="j"

#初始化授权状态
user_authorization="false"

## 检测地区并更新region
detect_region() {
    # 尝试通过IP解析服务获取地区代码
    # 使用多个服务提高可靠性
    local ip_services=(
        "https://ipapi.co/country/"
        "https://ipinfo.io/country"
        "https://api.ip.sb/country"
    )
    
    for service in "${ip_services[@]}"; do
        # 超时3秒，静默模式获取地区代码
        local country=$(curl -s --connect-timeout 3 "$service" | tr '[:lower:]' '[:upper:]')
        if [ -n "$country" ] && [ ${#country} -eq 2 ]; then
            region="$country"
            echo "检测到地区: $region"
            return 0
        fi
    done
    
    # 所有服务失败时使用默认值
    echo "无法检测地区，使用默认值: $region"
    return 1
}
## url加速服务
use_proxy(){
    # 先检测并更新地区
    detect_region
    
    if [ "$region" == "CN" ]; then
        url_proxy="https://proxy.cccg.top/"
    else
        url_proxy="https://"
    fi
}
use_proxy


# 脚本地址
script_url="${url_proxy}raw.githubusercontent.com/666zhaobo666/linuxbox-sh/main/LinuxBox.sh"


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
		# 文件不存在：下载安装并赋予权限
		if [ ! -f "./LinuxBox.sh" ]; then
			echo -e "请稍后, 正在下载..."
			# 下载并保存到本地当前目录
			curl -sL "$script_url" -o ./LinuxBox.sh
			echo -e "下载完成!"
			# 赋予执行权限
			chmod +x ./LinuxBox.sh
		fi
		cp -f ./LinuxBox.sh /usr/local/bin/${key} > /dev/null 2>&1
		chmod +x /usr/local/bin/${key} > /dev/null 2>&1
		echo -e "${cyan}安装完成！${white}"
		echo -e "命令行输入${yellow} ${key} ${cyan}可快速启动脚本${white}"
		rm -f ./LinuxBox.sh
		break_end
		UserLicenseAgreement
	else
		# 文件存在：运行authorization_false函数
		authorization_check
	fi
}
# 提示用户同意条款
UserLicenseAgreement() {
	clear
	echo -e "${cyan}欢迎使用LinuxBox脚本工具箱${white}"
	echo -e "命令行输入${yellow} j ${cyan}可快速启动脚本${white}"
	echo -e ""
	echo -e "${pink}-----------------------------${white}"
	echo -e "${yellow}此脚本基于自用开发${white}"
	echo -e "${yellow}请尽量通过选择脚本选项退出${white}"
	echo -e "${yellow}如有问题，后果自负！${white}"
	echo -e "${pink}-----------------------------${white}"
	read -r -p "是否同意以上条款？(y/n): " user_input

	if [ "$user_input" = "y" ] || [ "$user_input" = "Y" ]; then
		echo "已同意"
		sed -i 's/^user_authorization="false"/user_authorization="true"/' /usr/local/bin/${key}
		#安装sudo
        install sudo
	else
		echo "已拒绝"
		clear
		exit 1
	fi
}

## 卸载脚本
uninstall_script() {
	clear
	echo -e "${red}警告: 你即将卸载LinuxBox脚本工具箱！${white}"
	read -r -p "是否确认卸载？(y/n): " confirm
	if [[ "$confirm" =~ ^[Yy]$ ]]; then
		# 删除脚本文件
		## rm -f ~/LinuxBox.sh
		rm -f /usr/local/bin/${key}
		
		# 删除快捷键别名
		if [ -f "$HOME/.bashrc" ]; then
			sed -i "/alias ${key}='/d" "$HOME/.bashrc"
			source "$HOME/.bashrc"
		fi
		if [ -f "$HOME/.zshrc" ]; then
			sed -i "/alias ${key}='/d" "$HOME/.zshrc"
			source "$HOME/.zshrc"
		fi
		
		echo -e "${green}LinuxBox脚本工具箱已成功卸载!${white}"
		exit 0
	else
		echo "卸载已取消。"
		sleep 1
	fi
}

## 更新脚本
update_script() {
	echo "正在检查更新..."
	# 尝试获取远程脚本的版本号
    remote_version=$(curl -s "$script_url" | grep '^version=' | head -n 1 | cut -d '"' -f 2)
	# 检查是否成功获取远程版本
    if [ -z "$remote_version" ]; then
        echo "错误：无法获取远程版本信息"
		sleep 1
        return 1
    fi
	# 比较版本号
    if [ "$remote_version" = "$version" ]; then
        echo "当前已是最新版本 ($version)"
        break_end
		return 1
    fi
	# 提示更新并确认
    echo "发现新版本 V$remote_version,当前版本 V$version"
	read -r -p "是否确认更新？(y/n): " confirm
    echo
	if [[ $confirm =~ ^[Yy]$ ]]; then
        echo "正在更新脚本..."
        
        # 备份当前脚本
        mv /usr/local/bin/${key} /usr/local/bin/${key}.bak || { echo "备份失败"; return 1; }
        
        # 下载新脚本
        if curl -sL "$script_url" -o ./LinuxBox.sh; then
            chmod +x ./LinuxBox.sh
			cp -f ./LinuxBox.sh /usr/local/bin/j > /dev/null 2>&1
			chmod +x /usr/local/bin/j > /dev/null 2>&1
			echo -e "${cyan}更新完成! 请重新运行脚本${white}"
			echo -e "命令行输入${yellow} j ${cyan}可快速启动脚本${white}"
			rm -f ./LinuxBox.sh
			rm -f /usr/local/bin/${key}.bak
			break_end
			exit 0
        else
            echo "更新失败，恢复备份..."
            mv /usr/local/bin/${key}.bak /usr/local/bin/${key}
            break_end
			return 1
        fi
    else
        echo "已取消更新"
        break_end
		return 1
    fi
}

######################################################################
########################## 系统systemctl管理 ##########################
# 通用 systemctl 函数，适用于各种发行版
systemctl() {
	local COMMAND="$1"
	local SERVICE_NAME="$2"

	if command -v apk &>/dev/null; then
		service "$SERVICE_NAME" "$COMMAND"
	else
		/bin/systemctl "$COMMAND" "$SERVICE_NAME"
	fi
}
# 重启服务
restart() {
	systemctl restart "$1"
	if [ $? -eq 0 ]; then
		echo "$1 服务已重启。"
	else
		echo "错误：重启 $1 服务失败。"
	fi
}
# 启动服务
start() {
	systemctl start "$1"
	if [ $? -eq 0 ]; then
		echo "$1 服务已启动。"
	else
		echo "错误：启动 $1 服务失败。"
	fi
}
# 停止服务
stop() {
	systemctl stop "$1"
	if [ $? -eq 0 ]; then
		echo "$1 服务已停止。"
	else
		echo "错误：停止 $1 服务失败。"
	fi
}
# 查看服务状态
status() {
	systemctl status "$1"
	if [ $? -eq 0 ]; then
		echo "$1 服务状态已显示。"
	else
		echo "错误：无法显示 $1 服务状态。"
	fi
}
# 启用服务
enable() {
	local SERVICE_NAME="$1"
	if command -v apk &>/dev/null; then
		rc-update add "$SERVICE_NAME" default
	else
    /bin/systemctl enable "$SERVICE_NAME"
	fi

	echo "$SERVICE_NAME 已设置为开机自启。"
}
# 关闭服务
disable() {
	local SERVICE_NAME="$1"
	if command -v apk &>/dev/null; then
		rc-update del "$SERVICE_NAME" default
	else
    /bin/systemctl disable "$SERVICE_NAME"
	fi

	echo "$SERVICE_NAME 已设置为禁止开机自启。"
}


################################################################
########################### 全局函数 ###########################
## 脚本依赖检测
dependency_check(){
	echo -e "${cyan}正在进行依赖检测，请稍后......"
	if ! command -v curl &>/dev/null; then
		install curl
	fi
	if ! command -v sudo &>/dev/null; then
		install sudo
	fi
	if ! command -v wget &>/dev/null; then
		install wget
	fi
	if ! command -v bash &>/dev/null; then
		install bash
	fi
	if ! command -v unzip &>/dev/null; then
		install unzip
	fi
	if ! command -v tar &>/dev/null; then
		install tar
	fi
	if ! command -v jq &>/dev/null; then
		install jq
	fi
	if ! command -v grep &>/dev/null; then
		install grep
	fi
}

# 定义一个函数来执行命令
run_command() {
	if [ "$zhushi" -eq 0 ]; then
		"$@"
	fi
}

# 结束脚本
break_end() {
	echo -e "${cyan}按任意键继续...${white}"
	read -n 1 -s -r -p ""
	echo ""
	clear
}

##  返回主菜单
return_to_menu() {
	main_menu
}

##  获取IP地址
ip_address() {
get_public_ip() {
	curl -s https://ipinfo.io/ip && echo
}
get_local_ip() {
	ip route get 8.8.8.8 2>/dev/null | grep -oP 'src \K[^ ]+' || \
	hostname -I 2>/dev/null | awk '{print $1}' || \
	ifconfig 2>/dev/null | grep -E 'inet [0-9]' | grep -v '127.0.0.1' | awk '{print $2}' | head -n1
}

public_ip=$(get_public_ip)
isp_info=$(curl -s --max-time 3 http://ipinfo.io/org)

if echo "$isp_info" | grep -Eiq 'china|mobile|unicom|telecom'; then
    ipv4_address=$(get_local_ip)
else
    ipv4_address="$public_ip"
fi

# ipv4_address=$(curl -s https://ipinfo.io/ip && echo)
ipv6_address=$(curl -s --max-time 1 https://v6.ipinfo.io/ip && echo)
}

##  安装软件包
install() {
	if [ $# -eq 0 ]; then
		echo "未提供软件包参数!"
		return 1
	fi

	for package in "$@"; do
		if ! command -v "$package" &>/dev/null; then
			echo -e "${yellow}正在安装 $package...${white}"
			if command -v dnf &>/dev/null; then
				dnf -y update
				dnf install -y epel-release
				dnf install -y "$package"
			elif command -v yum &>/dev/null; then
				yum -y update
				yum install -y epel-release
				yum install -y "$package"
			elif command -v apt &>/dev/null; then
				apt update -y
				apt install -y "$package"
			elif command -v apk &>/dev/null; then
				apk update
				apk add "$package"
			elif command -v pacman &>/dev/null; then
				pacman -Syu --noconfirm
				pacman -S --noconfirm "$package"
			elif command -v zypper &>/dev/null; then
				zypper refresh
				zypper install -y "$package"
			elif command -v opkg &>/dev/null; then
				opkg update
				opkg install "$package"
			elif command -v pkg &>/dev/null; then
				pkg update
				pkg install -y "$package"
			else
				echo "未知的包管理器!"
				return 1
			fi
		fi
	done
}

##  检查系统类型
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        os_id=$ID
    else
        os_id=$(uname -s)
    fi
    for os in "${SUPPORTED_OS[@]}"; do
        if [[ "$os_id" == *"$os"* ]]; then
            echo "$os"
            return
        fi
    done
    echo "unsupported"
}

##  检查root权限
root_use() {
	clear
	[ "$EUID" -ne 0 ] && echo -e "${yellow}提示: ${white}该功能需要root用户才能运行！" && break_end && return_to_menu
}

## 检查磁盘空间
check_disk_space() {
	required_gb=$1
	required_space_mb=$((required_gb * 1024))
	available_space_mb=$(df -m / | awk 'NR==2 {print $4}')

	if [ $available_space_mb -lt $required_space_mb ]; then
		echo -e "${yellow}提示: ${white}磁盘空间不足！"
		echo "当前可用空间: $((available_space_mb/1024))G"
		echo "最小需求空间: ${required_gb}G"
		echo "无法继续安装，请清理磁盘空间后重试。"
		break_end
		return_to_menu
	fi
}

##  错误处理
error_exit() {
	echo -e "${red}[错误]${white} $1"
    exit 1
}

###########################################################################
########################### 一、系统信息查询模块 ###########################
system_info() {
    echo "系统信息查询"
    echo -e "${pink}-------------${white}"
    echo -e "${cyan}主机名:       ${white}$(hostname)"
    echo -e "${cyan}系统版本:     ${white}$(cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '"')"
    echo -e "${cyan}Linux版本:    ${white}$(uname -r)"
    echo -e "${pink}-------------${white}"
    echo -e "${cyan}CPU架构:      ${white}$(uname -m)"
    echo -e "${cyan}CPU型号:      ${white}$(lscpu | grep 'Model name' | awk -F: '{print $2}' | xargs)"
    echo -e "${cyan}CPU核心数:    ${white}$(nproc)"
    echo -e "${cyan}CPU频率:      ${white}$(lscpu | grep 'MHz' | awk '{print $2/1000 " GHz"}')"
    echo -e "${pink}-------------${white}"
    echo -e "${cyan}CPU占用:      ${white}$(top -bn1 | grep 'Cpu(s)' | awk '{print $2}')%"
    echo -e "${cyan}系统负载:     ${white}$(uptime | awk -F'load average:' '{print $2}' | xargs)"
    echo -e "${cyan}物理内存:     ${white}$(free -m | awk '/Mem:/ {printf "%0.2f/%0.2fM (%0.2f%%)", $3, $2, $3/$2*100}')"
    echo -e "${cyan}虚拟内存:     ${white}$(free -m | awk '/Swap:/ {printf "%0.2f/%0.2fM (%0.2f%%)", $3, $2, ($2==0?0:$3/$2*100)}')"
    echo -e "${cyan}硬盘占用:     ${white}$(df -h / | awk 'NR==2{print $3"/"$2" ("$5")"}')"
    echo -e "${pink}-------------${white}"
    echo -e "${cyan}总接收:       ${white}$(cat /proc/net/dev | awk '/eth|ens|eno|enp|wlan/ {rx+=$2} END {printf "%.2fG", rx/1024/1024/1024}')"
    echo -e "${cyan}总发送:       ${white}$(cat /proc/net/dev | awk '/eth|ens|eno|enp|wlan/ {tx+=$10} END {printf "%.2fG", tx/1024/1024/1024}')"
    echo -e "${pink}-------------${white}"
    echo -e "${cyan}网络算法:     ${white}$(sysctl net.ipv4.tcp_congestion_control | awk -F= '{print $2}' | xargs)"
    echo -e "${pink}-------------${white}"
    echo -e "${cyan}运营商:       ${white}$(curl -s ipinfo.io/org)"
    echo -e "${cyan}IPv4地址:     ${white}$(hostname -I | awk '{print $1}')"
    echo -e "${cyan}DNS地址:      ${white}$(cat /etc/resolv.conf | grep nameserver | awk '{print $2}' | xargs)"
    echo -e "${cyan}地理位置:     ${white}$(curl -s ipinfo.io/city), $(curl -s ipinfo.io/country)"
    echo -e "${cyan}系统时间:     ${white}$(date '+%Z %Y-%m-%d %I:%M %p')"
    echo -e "${pink}-------------${white}"
    echo -e "${cyan}运行时长:     ${white}$(uptime -p | cut -d' ' -f2-)"
    echo -e "${cyan}-------------${white}"
    echo -e "${green}操作完成${white}"
    read -n1 -s -r -p "按任意键继续..."
    clear
}

###########################################################################
########################### 二、系统工具合集 ###############################
# 依赖函数：操作暂停
pause() {
    read -p $'\n'"按回车键继续..." -n 1 -r
    echo -e "\n"
}

# ------------- 功能实现 -------------
# 1. 设置本脚本启动快捷键
set_script_shortcut() {
    clear
    echo -e "${blue}设置脚本启动快捷键${white}"
    read -e -p "请输入脚本路径（默认：$(pwd)/$(basename $0)）: " script_path
    script_path=${script_path:-$(pwd)/$(basename $0)}
    
    read -e -p "请设置快捷键别名（如sysadmin）: " alias_name
    [ -z "$alias_name" ] && { echo -e "${red}别名不能为空！${white}"; pause; return; }

    # 写入配置文件
    config_file="$HOME/.bashrc"
    [ -f "$HOME/.zshrc" ] && config_file="$HOME/.zshrc"  # 优先zsh
    
    echo "alias $alias_name='sudo $script_path'" >> "$config_file"
    source "$config_file"
    
    echo -e "${green}快捷键设置完成！可直接输入 $alias_name 启动脚本${white}"
    pause
}

# 2. 修改登录密码（当前用户）
change_user_password() {
    clear
    echo -e "${blue}修改当前用户密码${white}"
    current_user=$(whoami)
    echo "当前用户：$current_user"
    passwd
    if [ $? -eq 0 ]; then
        echo -e "${green}密码修改成功${white}"
    else
        echo -e "${red}密码修改失败${white}"
    fi
    pause
}

# 3. 修改root登录密码
change_root_password() {
    clear
    echo -e "${blue}修改root密码${white}"
    if [ $(id -u) -eq 0 ]; then
        passwd root
    else
        sudo passwd root
    fi
    if [ $? -eq 0 ]; then
        echo -e "${green}root密码修改成功${white}"
    else
        echo -e "${red}root密码修改失败${white}"
    fi
    pause
}

# 4. 修改ssh连接端口
change_ssh_port() {
	root_use
	clear
	sed -i 's/#Port/Port/' /etc/ssh/sshd_config

	# 读取当前的 SSH 端口号
	local current_port=$(grep -E '^ *Port [0-9]+' /etc/ssh/sshd_config | awk '{print $2}')

	# 打印当前的 SSH 端口号
	echo -e "当前的 SSH 端口号是:  ${yellow}$current_port ${white}"

	echo -e "${pink}------------------------${white}"
	echo "端口号范围1到65535之间的数字。（输入0退出）"

	# 提示用户输入新的 SSH 端口号
	read -e -p "请输入新的 SSH 端口号: " new_port

	# 判断端口号是否在有效范围内
	if [[ $new_port =~ ^[0-9]+$ ]]; then  # 检查输入是否为数字
		if [[ $new_port -ge 1 && $new_port -le 65535 ]]; then
			# 备份 SSH 配置文件
			cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

			sed -i 's/^\s*#\?\s*Port/Port/' /etc/ssh/sshd_config
			sed -i "s/Port [0-9]\+/Port $new_port/g" /etc/ssh/sshd_config

			correct_ssh_config
			rm -rf /etc/ssh/sshd_config.d/* /etc/ssh/ssh_config.d/*

			restart_ssh
			open_port $new_port
			remove iptables-persistent ufw firewalld iptables-services > /dev/null 2>&1

			echo "SSH 端口已修改为: $new_port"

			break_end
		elif [[ $new_port -eq 0 ]]; then
			break_end
		else
			echo "端口号无效，请输入1到65535之间的数字。"
			## "输入无效SSH端口"
			break_end
		fi
	else
		echo "输入无效，请输入数字。"
		## "输入无效SSH端口"
		break_end
	fi
	pause
}

# 5. 打开/关闭ssh密码登录
ssh_password_login() {
	root_use
    clear
    echo -e "${blue}SSH密码登录开关${white}"
    current_status=$(sudo grep -i "PasswordAuthentication" /etc/ssh/sshd_config | grep -v ^# | awk '{print $2}')
    
    if [ "$current_status" = "yes" ]; then
        echo "当前状态：允许密码登录"
        read -p "是否关闭密码登录？(y/n): " confirm
        if [ "$confirm" = "y" ]; then
            sudo sed -i "s/^PasswordAuthentication yes/PasswordAuthentication no/" /etc/ssh/sshd_config
            sudo systemctl restart sshd || sudo systemctl restart ssh
            echo -e "${green}已关闭SSH密码登录（请确保密钥登录可用）${white}"
        fi
    else
        echo "当前状态：禁止密码登录"
        read -p "是否开启密码登录？(y/n): " confirm
        if [ "$confirm" = "y" ]; then
            sudo sed -i "s/^PasswordAuthentication no/PasswordAuthentication yes/" /etc/ssh/sshd_config
            sudo systemctl restart sshd || sudo systemctl restart ssh
            echo -e "${green}已开启SSH密码登录${white}"
        fi
    fi
    pause
}

# 6. 打开/关闭ssh root登录
ssh_root_login() {
	root_use
    clear
    echo -e "${blue}SSH root登录开关${white}"
    current_status=$(sudo grep -i "PermitRootLogin" /etc/ssh/sshd_config | grep -v ^# | awk '{print $2}')
    
    if [ "$current_status" = "yes" ] || [ "$current_status" = "prohibit-password" ]; then
        echo "当前状态：允许root登录"
        read -p "是否禁止root登录？(y/n): " confirm
        if [ "$confirm" = "y" ]; then
            sudo sed -i "s/^PermitRootLogin yes/PermitRootLogin no/" /etc/ssh/sshd_config
            sudo sed -i "s/^PermitRootLogin prohibit-password/PermitRootLogin no/" /etc/ssh/sshd_config
            sudo systemctl restart sshd || sudo systemctl restart ssh
            echo -e "${green}已禁止SSH root登录${white}"
        fi
    else
        echo "当前状态：禁止root登录"
        read -p "是否允许root登录？(y/n): " confirm
        if [ "$confirm" = "y" ]; then
            sudo sed -i "s/^PermitRootLogin no/PermitRootLogin yes/" /etc/ssh/sshd_config
            sudo systemctl restart sshd || sudo systemctl restart ssh
            echo -e "${green}已允许SSH root登录${white}"
        fi
    fi
    pause
}

# 7. 优化DNS地址
optimize_dns() {
	root_use
	while true; do
		clear
		echo "优化DNS地址"
		echo -e "${pink}------------------------${white}"
		echo "当前DNS地址"
		cat /etc/resolv.conf
		echo -e "${pink}------------------------${white}"
		echo ""
		echo "1. 国外DNS优化: "
		echo " v4: 1.1.1.1 8.8.8.8"
		echo " v6: 2606:4700:4700::1111 2001:4860:4860::8888"
		echo "2. 国内DNS优化: "
		echo " v4: 223.5.5.5 183.60.83.19"
		echo " v6: 2400:3200::1 2400:da00::6666"
		echo "3. 手动编辑DNS配置"
		echo -e "${pink}------------------------${white}"
		echo "0. 返回上一级选单"
		echo -e "${pink}------------------------${white}"
		read -e -p "请输入你的选择: " Limiting
		case "$Limiting" in
		1)
			local dns1_ipv4="1.1.1.1"
			local dns2_ipv4="8.8.8.8"
			local dns1_ipv6="2606:4700:4700::1111"
			local dns2_ipv6="2001:4860:4860::8888"
			set_dns
			## "国外DNS优化"
			;;
		2)
			local dns1_ipv4="223.5.5.5"
			local dns2_ipv4="183.60.83.19"
			local dns1_ipv6="2400:3200::1"
			local dns2_ipv6="2400:da00::6666"
			set_dns
			## "国内DNS优化"
			;;
		3)
			install nano
			nano /etc/resolv.conf
			## "手动编辑DNS配置"
			;;
		*)
			break
			;;
		esac
	done
}

# 8. 切换优先ipv4/ipv6
change_ip_priority() {
	root_use
	while true; do
		clear
		echo "设置v4/v6优先级"
		echo -e "${pink}------------------------${white}"
		local ipv6_disabled=$(sysctl -n net.ipv6.conf.all.disable_ipv6)

		if [ "$ipv6_disabled" -eq 1 ]; then
			echo -e "当前网络优先级设置: ${yellow}IPv4${white} 优先"
		else
			echo -e "当前网络优先级设置: ${yellow}IPv6${white} 优先"
		fi
		echo ""
		echo -e "${pink}------------------------${white}"
		echo "1. IPv4 优先          2. IPv6 优先          3. IPv6 修复工具"
		echo -e "${pink}------------------------${white}"
		echo "0. 返回上一级选单"
		echo -e "${pink}------------------------${white}"
		read -e -p "选择优先的网络: " choice

		case $choice in
			1)
				sysctl -w net.ipv6.conf.all.disable_ipv6=1 > /dev/null 2>&1
				echo "已切换为 IPv4 优先"
				## "已切换为 IPv4 优先"
				;;
			2)
				sysctl -w net.ipv6.conf.all.disable_ipv6=0 > /dev/null 2>&1
				echo "已切换为 IPv6 优先"
				## "已切换为 IPv6 优先"
				;;

			3)
				clear
				bash <(curl -L -s jhb.ovh/jb/v6.sh)
				echo "该功能由jhb大神提供, 感谢!"
				## "ipv6修复"
				;;

			*)
				break
				;;
		esac
	done
}

# 9. 查看端口占用状态
linux_port() {
    clear
	ss -tulnape
	pause
}

# 10. 修改虚拟内存大小
# 检查虚拟内存
check_swap() {
	local swap_total=$(free -m | awk 'NR==3{print $2}')

	# 判断是否需要创建虚拟内存
	[ "$swap_total" -gt 0 ] || add_swap 1024
}
add_swap() {
	local new_swap=$1  # 获取传入的参数

	# 获取当前系统中所有的 swap 分区
	local swap_partitions=$(grep -E '^/dev/' /proc/swaps | awk '{print $1}')

	# 遍历并删除所有的 swap 分区
	for partition in $swap_partitions; do
		swapoff "$partition"
		wipefs -a "$partition"
		mkswap -f "$partition"
	done

	# 确保 /swapfile 不再被使用
	swapoff /swapfile

	# 删除旧的 /swapfile
	rm -f /swapfile

	# 创建新的 swap 分区
	fallocate -l ${new_swap}M /swapfile
	chmod 600 /swapfile
	mkswap /swapfile
	swapon /swapfile

	sed -i '/\/swapfile/d' /etc/fstab
	echo "/swapfile swap swap defaults 0 0" >> /etc/fstab

	if [ -f /etc/alpine-release ]; then
		echo "nohup swapon /swapfile" > /etc/local.d/swap.start
		chmod +x /etc/local.d/swap.start
		rc-update add local
	fi

	echo -e "虚拟内存大小已调整为${yellow}${new_swap}${white}M"
}
modify_swap_size() {
	root_use
	## "设置虚拟内存"
	while true; do
		clear
		echo "设置虚拟内存"
		local swap_used=$(free -m | awk 'NR==3{print $3}')
		local swap_total=$(free -m | awk 'NR==3{print $2}')
		local swap_info=$(free -m | awk 'NR==3{used=$3; total=$2; if (total == 0) {percentage=0} else {percentage=used*100/total}; printf "%dM/%dM (%d%%)", used, total, percentage}')

		echo -e "当前虚拟内存: ${yellow}$swap_info${white}"
		echo -e "${pink}------------------------${white}"
		echo "1. 分配1024M         2. 分配2048M         3. 分配4096M         4. 自定义大小"
		echo -e "${pink}------------------------${white}"
		echo "0. 返回上一级选单"
		echo -e "${pink}------------------------${white}"
		read -e -p "请输入你的选择: " choice

		case "$choice" in
			1)
			## "已设置1G虚拟内存"
			add_swap 1024

			;;
			2)
			## "已设置2G虚拟内存"
			add_swap 2048

			;;
			3)
			## "已设置4G虚拟内存"
			add_swap 4096

			;;

			4)
			read -e -p "请输入虚拟内存大小（单位M）: " new_swap
			add_swap "$new_swap"
			;;

			*)
			break
			;;
		esac
	done
}

# 11. 用户管理
user_management() {
	while true; do
	root_use
	echo "用户列表"
	echo -e "${pink}----------------------------------------------------------------------------${white}"
	printf "%-24s %-34s %-20s %-10s\n" "用户名" "用户权限" "用户组" "sudo权限"
	while IFS=: read -r username _ userid groupid _ _ homedir shell; do
		local groups=$(groups "$username" | cut -d : -f 2)
		local sudo_status=$(sudo -n -lU "$username" 2>/dev/null | grep -q '(ALL : ALL)' && echo "Yes" || echo "No")
		printf "%-20s %-30s %-20s %-10s\n" "$username" "$homedir" "$groups" "$sudo_status"
	done < /etc/passwd


		echo ""
		echo "账户操作"
		echo -e "${pink}------------------------------------------${white}"
		echo "1. 创建普通账户             2. 创建高级账户"
		echo -e "${pink}------------------------------------------${white}"
		echo "3. 赋予最高权限             4. 取消最高权限"
		echo -e "${pink}------------------------------------------${white}"
		echo "5. 删除账号"
		echo -e "${pink}------------------------------------------${white}"
		echo "0. 返回上一级选单"
		echo -e "${pink}------------------------------------------${white}"
		read -e -p "请输入你的选择: " sub_choice

		case $sub_choice in
			1)
			# 提示用户输入新用户名
			read -e -p "请输入新用户名: " new_username

			# 创建新用户并设置密码
			useradd -m -s /bin/bash "$new_username"
			passwd "$new_username"

			echo "操作已完成。"
				;;

			2)
			# 提示用户输入新用户名
			read -e -p "请输入新用户名: " new_username

			# 创建新用户并设置密码
			useradd -m -s /bin/bash "$new_username"
			passwd "$new_username"

			# 赋予新用户sudo权限
			echo "$new_username ALL=(ALL:ALL) ALL" | tee -a /etc/sudoers

			install sudo

			echo "操作已完成。"

				;;
			3)
			read -e -p "请输入用户名: " username
			# 赋予新用户sudo权限
			echo "$username ALL=(ALL:ALL) ALL" | tee -a /etc/sudoers

			install sudo
				;;
			4)
			read -e -p "请输入用户名: " username
			# 从sudoers文件中移除用户的sudo权限
			sed -i "/^$username\sALL=(ALL:ALL)\sALL/d" /etc/sudoers

				;;
			5)
			read -e -p "请输入要删除的用户名: " username
			# 删除用户及其主目录
			userdel -r "$username"
				;;

			*)
				break  # 跳出循环，退出菜单
				;;
		esac
	done
}

# 12. 系统时区调整
set_timedate() {
	local shiqu="$1"
	if grep -q 'Alpine' /etc/issue; then
		install tzdata
		cp /usr/share/zoneinfo/${shiqu} /etc/localtime
		hwclock --systohc
	else
		timedatectl set-timezone ${shiqu}
	fi
}
adjust_timezone() {
	root_use
	while true; do
		clear
		echo "系统时间信息"

		# 获取当前系统时区
		local timezone=$(current_timezone)

		# 获取当前系统时间
		local current_time=$(date +"%Y-%m-%d %H:%M:%S")

		# 显示时区和时间
		echo "当前系统时区：$timezone"
		echo "当前系统时间：$current_time"

		echo ""
		echo "时区切换"
		echo -e "${pink}------------------------${white}"
		echo "亚洲"
		echo "1.  中国上海时间             2.  中国香港时间"
		echo "3.  日本东京时间             4.  韩国首尔时间"
		echo "5.  新加坡时间               6.  印度加尔各答时间"
		echo "7.  阿联酋迪拜时间           8.  澳大利亚悉尼时间"
		echo "9.  泰国曼谷时间"
		echo -e "${pink}------------------------${white}"
		echo "欧洲"
		echo "11. 英国伦敦时间             12. 法国巴黎时间"
		echo "13. 德国柏林时间             14. 俄罗斯莫斯科时间"
		echo "15. 荷兰尤特赖赫特时间       16. 西班牙马德里时间"
		echo -e "${pink}------------------------${white}"
		echo "美洲"
		echo "21. 美国西部时间             22. 美国东部时间"
		echo "23. 加拿大时间               24. 墨西哥时间"
		echo "25. 巴西时间                 26. 阿根廷时间"
		echo -e "${pink}------------------------${white}"
		echo "31. UTC全球标准时间"
		echo -e "${pink}------------------------${white}"
		echo "0. 返回上一级选单"
		echo -e "${pink}------------------------${white}"
		read -e -p "请输入你的选择: " sub_choice


		case $sub_choice in
			1) set_timedate Asia/Shanghai ;;
			2) set_timedate Asia/Hong_Kong ;;
			3) set_timedate Asia/Tokyo ;;
			4) set_timedate Asia/Seoul ;;
			5) set_timedate Asia/Singapore ;;
			6) set_timedate Asia/Kolkata ;;
			7) set_timedate Asia/Dubai ;;
			8) set_timedate Australia/Sydney ;;
			9) set_timedate Asia/Bangkok ;;
			11) set_timedate Europe/London ;;
			12) set_timedate Europe/Paris ;;
			13) set_timedate Europe/Berlin ;;
			14) set_timedate Europe/Moscow ;;
			15) set_timedate Europe/Amsterdam ;;
			16) set_timedate Europe/Madrid ;;
			21) set_timedate America/Los_Angeles ;;
			22) set_timedate America/New_York ;;
			23) set_timedate America/Vancouver ;;
			24) set_timedate America/Mexico_City ;;
			25) set_timedate America/Sao_Paulo ;;
			26) set_timedate America/Argentina/Buenos_Aires ;;
			31) set_timedate UTC ;;
			*) break ;;
		esac
	done
}

# 13. 修改主机名
modify_hostname() {
	root_use

	while true; do
		clear
		local current_hostname=$(uname -n)
		echo -e "当前主机名: ${yellow}$current_hostname${white}"
		echo -e "${pink}------------------------${white}"
		read -e -p "请输入新的主机名（输入0退出）: " new_hostname
		if [ -n "$new_hostname" ] && [ "$new_hostname" != "0" ]; then
			if [ -f /etc/alpine-release ]; then
				# Alpine
				echo "$new_hostname" > /etc/hostname
				hostname "$new_hostname"
			else
				# 其他系统，如 Debian, Ubuntu, CentOS 等
				hostnamectl set-hostname "$new_hostname"
				sed -i "s/$current_hostname/$new_hostname/g" /etc/hostname
				systemctl restart systemd-hostnamed
			fi

			if grep -q "127.0.0.1" /etc/hosts; then
				sed -i "s/127.0.0.1 .*/127.0.0.1       $new_hostname localhost localhost.localdomain/g" /etc/hosts
			else
				echo "127.0.0.1       $new_hostname localhost localhost.localdomain" >> /etc/hosts
			fi

			if grep -q "^::1" /etc/hosts; then
				sed -i "s/^::1 .*/::1             $new_hostname localhost localhost.localdomain ipv6-localhost ipv6-loopback/g" /etc/hosts
			else
				echo "::1             $new_hostname localhost localhost.localdomain ipv6-localhost ipv6-loopback" >> /etc/hosts
			fi

			echo "主机名已更改为: $new_hostname"
			## "主机名已更改"
			break_end
		else
			echo "已退出，未更改主机名。"
			break
		fi
	done
}

# 14. 切换系统更新源
switch_update_source() {
	root_use
	clear
	echo "选择更新源区域"
	echo "接入LinuxMirrors切换系统更新源"
	echo -e "${pink}------------------------${white}"
	echo "1. 中国大陆【默认】          2. 中国大陆【教育网】          3. 海外地区"
	echo -e "${pink}------------------------${white}"
	echo "0. 返回上一级选单"
	echo -e "${pink}------------------------${white}"
	read -e -p "输入你的选择: " choice

	case $choice in
		1)
			#  "中国大陆默认源"
			bash <(curl -sSL https://linuxmirrors.cn/main.sh)
			;;
		2)
			#  "中国大陆教育源"
			bash <(curl -sSL https://linuxmirrors.cn/main.sh) --edu
			;;
		3)
			#  "海外源"
			bash <(curl -sSL https://linuxmirrors.cn/main.sh) --abroad
			;;
		*)
			echo "已取消"
			;;

	esac
}

# 15. 定时任务管理
cron_job_management() {
	while true; do
		clear
		check_crontab_installed
		clear
		echo "定时任务列表"
		crontab -l
		echo ""
		echo "操作"
		echo -e "${pink}------------------------${white}"
		echo "1. 添加定时任务              2. 删除定时任务              3. 编辑定时任务"
		echo -e "${pink}------------------------${white}"
		echo "0. 返回上一级选单"
		echo -e "${pink}------------------------${white}"
		read -e -p "请输入你的选择: " sub_choice

		case $sub_choice in
			1)
				read -e -p "请输入新任务的执行命令: " newquest
				echo -e "${pink}------------------------${white}"
				echo "1. 每月任务                 2. 每周任务"
				echo "3. 每天任务                 4. 每小时任务"
				echo -e "${pink}------------------------${white}"
				read -e -p "请输入你的选择: " dingshi

				case $dingshi in
					1)
						read -e -p "选择每月的几号执行任务？ (1-30): " day
						(crontab -l ; echo "0 0 $day * * $newquest") | crontab - > /dev/null 2>&1
						;;
					2)
						read -e -p "选择周几执行任务？ (0-6，0代表星期日): " weekday
						(crontab -l ; echo "0 0 * * $weekday $newquest") | crontab - > /dev/null 2>&1
						;;
					3)
						read -e -p "选择每天几点执行任务？（小时，0-23）: " hour
						(crontab -l ; echo "0 $hour * * * $newquest") | crontab - > /dev/null 2>&1
						;;
					4)
						read -e -p "输入每小时的第几分钟执行任务？（分钟，0-60）: " minute
						(crontab -l ; echo "$minute * * * * $newquest") | crontab - > /dev/null 2>&1
						;;
					*)
						break  # 跳出
						;;
				esac
				;;
			2)
				read -e -p "请输入需要删除任务的关键字: " kquest
				crontab -l | grep -v "$kquest" | crontab -
				;;
			3)
				crontab -e
				;;
			*)
				break  # 跳出循环，退出菜单
				;;
		esac
	done
}

# 16. 文件管理器（子菜单）
file_manager() {
    current_dir=$(pwd)
    # 检查压缩工具是否安装
    check_compress_tools() {
        local tool=$1
        if ! command -v $tool &> /dev/null; then
            echo -e "${red}错误：未安装 $tool，请先安装（例如: sudo apt install $tool 或 sudo yum install $tool）${white}"
            return 1
        fi
        return 0
    }

    while true; do
        clear
        echo -e "${blue}文件管理器 - 当前目录: $current_dir${white}"
        echo -e "${cyan}目录内容:${white}"
        ls -la --color=auto "$current_dir"

        echo -e "\n${yellow}功能菜单:${white}"
        echo "1. 进入目录		2. 创建目录		3. 重命名目录		4. 删除目录"
        echo "5. 修改目录权限		6. 返回上一级目录"
		echo -e "${cyan}-------------${white}"
        echo "7. 创建文件		8. 编辑文件		9. 重命名文件		10. 删除文件"
		echo "11. 修改文件权限"
		echo -e "${cyan}-------------${white}"
        echo "12. 压缩文件目录	13. 解压文件目录	14. 复制文件目录	15. 移动文件目录"
        echo "16. 传输文件至远程服务器（scp）"
        echo "0. 退出文件管理器"

        read -e -p "请选择功能: " file_choice
        case $file_choice in
            1)  # 进入目录
                read -p "请输入目录名: " subdir
                if [ -d "$current_dir/$subdir" ]; then
                    current_dir="$current_dir/$subdir"
                else
                    echo -e "${red}目录不存在${white}"; pause
                fi
                ;;
            2)  # 创建目录
                read -p "请输入新目录名: " newdir
                mkdir -p "$current_dir/$newdir"
                echo -e "${green}目录创建成功${white}"; pause
                ;;
            3)  # 重命名目录
                read -p "请输入原目录名: " oldname
                read -p "请输入新目录名: " newname
                if [ -d "$current_dir/$oldname" ]; then
                    mv "$current_dir/$oldname" "$current_dir/$newname"
                    echo -e "${green}目录重命名成功${white}"
                else
                    echo -e "${red}目录不存在${white}"
                fi
                pause
                ;;
            4)  # 删除目录
                read -p "请输入要删除的目录名: " delname
                if [ -d "$current_dir/$delname" ]; then
                    read -p "确认删除目录 $delname（含所有内容）？(y/n): " confirm
                    if [ "$confirm" = "y" ]; then
                        rm -rf "$current_dir/$delname"
                        echo -e "${green}目录删除成功${white}"
                    fi
                else
                    echo -e "${red}目录不存在${white}"
                fi
                pause
                ;;
            5)  # 修改目录权限
                read -p "请输入目标目录名: " target
                if [ -d "$current_dir/$target" ]; then
                    read -p "请输入权限值（如755）: " perm
                    chmod $perm "$current_dir/$target"
                    echo -e "${green}目录权限修改成功${white}"
                else
                    echo -e "${red}目录不存在${white}"
                fi
                pause
                ;;
            6)  # 返回上一级目录
                if [ "$current_dir" != "/" ]; then
                    current_dir=$(dirname "$current_dir")
                else
                    echo -e "${yellow}已在根目录${white}"; pause
                fi
                ;;
            7)  # 创建文件
                read -p "请输入文件名: " filename
                touch "$current_dir/$filename"
                echo -e "${green}文件创建成功${white}"; pause
                ;;
            8)  # 编辑文件（nano）
                read -p "请输入文件名: " filename
                if [ -f "$current_dir/$filename" ]; then
                    nano "$current_dir/$filename"
                else
                    echo -e "${red}文件不存在${white}"; pause
                fi
                ;;
            9)  # 重命名文件
                read -p "请输入原文件名: " oldname
                read -p "请输入新文件名: " newname
                if [ -f "$current_dir/$oldname" ]; then
                    mv "$current_dir/$oldname" "$current_dir/$newname"
                    echo -e "${green}文件重命名成功${white}"
                else
                    echo -e "${red}文件不存在${white}"
                fi
                pause
                ;;
            10)  # 删除文件
                read -p "请输入要删除的文件名: " delname
                if [ -f "$current_dir/$delname" ]; then
                    read -p "确认删除文件 $delname？(y/n): " confirm
                    if [ "$confirm" = "y" ]; then
                        rm -f "$current_dir/$delname"
                        echo -e "${green}文件删除成功${white}"
                    fi
                else
                    echo -e "${red}文件不存在${white}"
                fi
                pause
                ;;
            11)  # 修改文件权限
                read -p "请输入目标文件名: " target
                if [ -f "$current_dir/$target" ]; then
                    read -p "请输入权限值（如644）: " perm
                    chmod $perm "$current_dir/$target"
                    echo -e "${green}文件权限修改成功${white}"
                else
                    echo -e "${red}文件不存在${white}"
                fi
                pause
                ;;
            12)  # 压缩文件/目录（多格式选择）
                read -p "请输入要压缩的名称: " src
                if [ ! -e "$current_dir/$src" ]; then
                    echo -e "${red}目标不存在${white}"; pause; break
                fi
                
                echo -e "\n${cyan}支持的压缩格式:${white}"
                echo "1. tar.gz（推荐，跨平台）"
                echo "2. zip（Windows兼容）"
                echo "3. 7z（高压缩率）"
                read -p "请选择压缩格式(1-3): " compress_type
                
                read -p "请输入压缩包名（不含后缀）: " dst
                local success=0
                
                case $compress_type in
                    1)
                        # tar.gz 依赖 tar
                        if ! command -v tar &>/dev/null; then
                            echo -e "${cyan}检测到 tar 未安装，开始安装...${white}"
                            install tar
                        fi
                        tar -zcvf "$current_dir/$dst.tar.gz" -C "$current_dir" "$src"
                        echo -e "${green}压缩完成: $dst.tar.gz${white}"
                        ;;
                    2)
                        # zip 依赖 zip
                        if ! command -v zip &>/dev/null; then
                            echo -e "${cyan}检测到 zip 未安装，开始安装...${white}"
                            install zip
                        fi
                        zip -r "$current_dir/$dst.zip" "$current_dir/$src"
                        echo -e "${green}压缩完成: $dst.zip${white}"
                        ;;
                    3)
                        # 7z 依赖 7z，不同系统包名可能有差异，这里用 7z 作为参数调用 install
                        if ! command -v 7z &>/dev/null; then
                            echo -e "${cyan}检测到 7z 未安装，开始安装...${white}"
                            install p7zip  # 常见发行版中 7z 一般由 p7zip 包提供，若不行可根据实际调整
                        fi
                        7z a "$current_dir/$dst.7z" "$current_dir/$src"
                        echo -e "${green}压缩完成: $dst.7z${white}"
                        ;;
                    *)
                        echo -e "${red}无效的格式选择${white}"; success=0
                        ;;
                esac
                pause
                ;;
            13)  # 解压文件（自动识别格式）
                read -p "请输入要解压的文件名: " archive
                if [ ! -f "$current_dir/$archive" ]; then
                    echo -e "${red}压缩文件不存在${white}"; pause; break
                fi
                
                local ext="${archive##*.}"
                local success=0
                
                case $ext in
                    gz|tar.gz)
                        if ! command -v tar &>/dev/null; then
                            echo -e "${cyan}检测到 tar 未安装，开始安装...${white}"
                            install tar
                        fi
                        tar -zxvf "$current_dir/$archive" -C "$current_dir"
                        echo -e "${green}解压完成${white}"
                        ;;
                    zip)
                        if ! command -v unzip &>/dev/null; then
                            echo -e "${cyan}检测到 unzip 未安装，开始安装...${white}"
                            install unzip
                        fi
                        unzip "$current_dir/$archive" -d "$current_dir"
                        echo -e "${green}解压完成${white}"
                        ;;
                    7z)
                        if ! command -v 7z &>/dev/null; then
                            echo -e "${cyan}检测到 7z 未安装，开始安装...${white}"
                            install p7zip
                        fi
                        7z x "$current_dir/$archive" -o"$current_dir"
                        echo -e "${green}解压完成${white}"
                        ;;
                    *)
                        echo -e "${red}不支持的压缩格式（仅支持tar.gz/zip/7z）${white}"; success=0
                        ;;
                esac
                pause
                ;;
            14)  # 复制文件/目录
                read -p "请输入源名称: " src
                read -p "请输入目标路径: " dst
                if [ -e "$current_dir/$src" ]; then
                    cp -r "$current_dir/$src" "$dst"
                    echo -e "${green}复制完成${white}"
                else
                    echo -e "${red}源不存在${white}"
                fi
                pause
                ;;
            15)  # 移动文件/目录
                read -p "请输入源名称: " src
                read -p "请输入目标路径: " dst
                if [ -e "$current_dir/$src" ]; then
                    mv "$current_dir/$src" "$dst"
                    echo -e "${green}移动完成${white}"
                else
                    echo -e "${red}源不存在${white}"
                fi
                pause
                ;;
            16)  # 传输文件至远程服务器（scp）
                read -p "请输入要传输的文件: " file
                if [ -f "$current_dir/$file" ]; then
                    read -p "请输入远程地址（user@host:path）: " remote
                    scp "$current_dir/$file" "$remote" && echo -e "${green}传输完成${white}"
                else
                    echo -e "${red}文件不存在${white}"
                fi
                pause
                ;;
            0)  # 退出文件管理器
                return
                ;;
            *)
                echo -e "${red}无效选择，请输入0-16之间的数字${white}"; pause ;;
        esac
    done
}

# 17. 切换系统语言
update_locale() {
	local lang=$1
	local locale_file=$2

	if [ -f /etc/os-release ]; then
		. /etc/os-release
		case $ID in
			debian|ubuntu|kali)
				install locales
				sed -i "s/^\s*#\?\s*${locale_file}/${locale_file}/" /etc/locale.gen
				locale-gen
				echo "LANG=${lang}" > /etc/default/locale
				export LANG=${lang}
				echo -e "${green}系统语言已经修改为: $lang 重新连接SSH生效。${white}"
				hash -r
				break_end

				;;
			centos|rhel|almalinux|rocky|fedora)
				install glibc-langpack-zh
				localectl set-locale LANG=${lang}
				echo "LANG=${lang}" | tee /etc/locale.conf
				echo -e "${green}系统语言已经修改为: $lang 重新连接SSH生效。${white}"
				hash -r
				break_end
				;;
			*)
				echo "不支持的系统: $ID"
				break_end
				;;
		esac
	else
		echo "不支持的系统，无法识别系统类型。"
		break_end
	fi
}
# 切换系统语言
switch_system_language() {
	root_use
	while true; do
		clear
		echo "当前系统语言: $LANG"
		echo -e "${pink}------------------------${white}"
		echo "1. 英文          2. 简体中文          3. 繁体中文"
		echo -e "${pink}------------------------${white}"
		echo "0. 返回上一级选单"
		echo -e "${pink}------------------------${white}"
		read -e -p "输入你的选择: " choice

		case $choice in
			1)
				update_locale "en_US.UTF-8" "en_US.UTF-8"
				;;
			2)
				update_locale "zh_CN.UTF-8" "zh_CN.UTF-8"
				;;
			3)
				update_locale "zh_TW.UTF-8" "zh_TW.UTF-8"
				;;
			*)
				break
				;;
		esac
	done
}

# 18. 设置系统回收站
linux_trash() {
	root_use

	local bashrc_profile="/root/.bashrc"
	local TRASH_DIR="$HOME/.local/share/Trash/files"

	while true; do

		local trash_status
		if ! grep -q "trash-put" "$bashrc_profile"; then
			trash_status="${grey}未启用${white}"
		else
			trash_status="${green}已启用${white}"
		fi

		clear
		echo -e "当前回收站 ${trash_status}"
		echo -e "启用后rm删除的文件先进入回收站，防止误删重要文件！"
		echo -e "${pink}------------------------------------------------${white}"
		ls -l --color=auto "$TRASH_DIR" 2>/dev/null || echo "回收站为空"
		echo -e "${pink}------------------------${white}"
		echo "1. 启用回收站          2. 关闭回收站"
		echo "3. 还原内容            4. 清空回收站"
		echo -e "${pink}------------------------${white}"
		echo "0. 返回上一级选单"
		echo -e "${pink}------------------------${white}"
		read -e -p "输入你的选择: " choice

		case $choice in
		1)
			install trash-cli
			sed -i '/alias rm/d' "$bashrc_profile"
			echo "alias rm='trash-put'" >> "$bashrc_profile"
			source "$bashrc_profile"
			echo "回收站已启用，删除的文件将移至回收站。"
			break_end
			;;
		2)
			remove trash-cli
			sed -i '/alias rm/d' "$bashrc_profile"
			echo "alias rm='rm -i'" >> "$bashrc_profile"
			source "$bashrc_profile"
			echo "回收站已关闭，文件将直接删除。"
			break_end
			;;
		3)
			read -e -p "输入要还原的文件名: " file_to_restore
			if [ -e "$TRASH_DIR/$file_to_restore" ]; then
			mv "$TRASH_DIR/$file_to_restore" "$HOME/"
			echo "$file_to_restore 已还原到主目录。"
			else
			echo "文件不存在。"
			fi
			;;
		4)
			read -e -p "确认清空回收站？[y/n]: " confirm
			if [[ "$confirm" == "y" ]]; then
			trash-empty
			echo "回收站已清空。"
			fi
			;;
		*)
			break
			;;
		esac
	done
}

# 19. ssh远程连接工具
ssh_manager() {
	CONFIG_FILE="$HOME/.ssh_connections"
	KEY_DIR="$HOME/.ssh/ssh_manager_keys"

	# 检查配置文件和密钥目录是否存在，如果不存在则创建
	if [[ ! -f "$CONFIG_FILE" ]]; then
		touch "$CONFIG_FILE"
	fi

	if [[ ! -d "$KEY_DIR" ]]; then
		mkdir -p "$KEY_DIR"
		chmod 700 "$KEY_DIR"
	fi

	while true; do
		clear
		echo "SSH 远程连接工具"
		echo "可以通过SSH连接到其他Linux系统上"
		echo -e "${pink}------------------------${white}"
		list_connections
		echo "1. 创建新连接        2. 使用连接        3. 删除连接"
		echo -e "${pink}------------------------${white}"
		echo "0. 返回上一级选单"
		echo -e "${pink}------------------------${white}"
		read -e -p "请输入你的选择: " choice
		case $choice in
			1) add_connection ;;
			2) use_connection ;;
			3) delete_connection ;;
			0) break ;;
			*) echo "无效的选择，请重试。" ;;
		esac
	done
}

# 20. 硬盘分区管理工具
# 列出可用的硬盘分区
list_partitions() {
	echo "可用的硬盘分区："
	lsblk -o NAME,SIZE,FSTYPE,MOUNTPOINT | grep -v "sr\|loop"
}

# 挂载分区
mount_partition() {
	read -e -p "请输入要挂载的分区名称（例如 sda1）: " PARTITION

	# 检查分区是否存在
	if ! lsblk -o NAME | grep -w "$PARTITION" > /dev/null; then
		echo "分区不存在！"
		return
	fi

	# 检查分区是否已经挂载
	if lsblk -o MOUNTPOINT | grep -w "$PARTITION" > /dev/null; then
		echo "分区已经挂载！"
		return
	fi

	# 创建挂载点
	MOUNT_POINT="/mnt/$PARTITION"
	mkdir -p "$MOUNT_POINT"

	# 挂载分区
	mount "/dev/$PARTITION" "$MOUNT_POINT"

	if [ $? -eq 0 ]; then
		echo "分区挂载成功: $MOUNT_POINT"
	else
		echo "分区挂载失败！"
		rmdir "$MOUNT_POINT"
	fi
}

# 卸载分区
unmount_partition() {
	read -e -p "请输入要卸载的分区名称（例如 sda1）: " PARTITION

	# 检查分区是否已经挂载
	MOUNT_POINT=$(lsblk -o MOUNTPOINT | grep -w "$PARTITION")
	if [ -z "$MOUNT_POINT" ]; then
		echo "分区未挂载！"
		return
	fi

	# 卸载分区
	umount "/dev/$PARTITION"

	if [ $? -eq 0 ]; then
		echo "分区卸载成功: $MOUNT_POINT"
		rmdir "$MOUNT_POINT"
	else
		echo "分区卸载失败！"
	fi
}

# 列出已挂载的分区
list_mounted_partitions() {
	echo "已挂载的分区："
	df -h | grep -v "tmpfs\|udev\|overlay"
}

# 格式化分区
format_partition() {
	read -e -p "请输入要格式化的分区名称（例如 sda1）: " PARTITION

	# 检查分区是否存在
	if ! lsblk -o NAME | grep -w "$PARTITION" > /dev/null; then
		echo "分区不存在！"
		return
	fi

	# 检查分区是否已经挂载
	if lsblk -o MOUNTPOINT | grep -w "$PARTITION" > /dev/null; then
		echo "分区已经挂载，请先卸载！"
		return
	fi

	# 选择文件系统类型
	echo "请选择文件系统类型："
	echo "1. ext4"
	echo "2. xfs"
	echo "3. ntfs"
	echo "4. vfat"
	read -e -p "请输入你的选择: " FS_CHOICE

	case $FS_CHOICE in
		1) FS_TYPE="ext4" ;;
		2) FS_TYPE="xfs" ;;
		3) FS_TYPE="ntfs" ;;
		4) FS_TYPE="vfat" ;;
		*) echo "无效的选择！"; return ;;
	esac

	# 确认格式化
	read -e -p "确认格式化分区 /dev/$PARTITION 为 $FS_TYPE 吗？(y/n): " CONFIRM
	if [ "$CONFIRM" != "y" ]; then
		echo "操作已取消。"
		return
	fi

	# 格式化分区
	echo "正在格式化分区 /dev/$PARTITION 为 $FS_TYPE ..."
	mkfs.$FS_TYPE "/dev/$PARTITION"

	if [ $? -eq 0 ]; then
		echo "分区格式化成功！"
	else
		echo "分区格式化失败！"
	fi
}

# 检查分区状态
check_partition() {
	read -e -p "请输入要检查的分区名称（例如 sda1）: " PARTITION

	# 检查分区是否存在
	if ! lsblk -o NAME | grep -w "$PARTITION" > /dev/null; then
		echo "分区不存在！"
		return
	fi

	# 检查分区状态
	echo "检查分区 /dev/$PARTITION 的状态："
	fsck "/dev/$PARTITION"
}

# 主菜单
disk_manager() {
	while true; do
		clear
		echo "硬盘分区管理"
		echo -e "${yellow}该功能内部测试阶段，请勿在生产环境使用。${white}"
		echo -e "${pink}------------------------${white}"
		list_partitions
		echo -e "${pink}------------------------${white}"
		echo "1. 挂载分区        2. 卸载分区        3. 查看已挂载分区"
		echo "4. 格式化分区      5. 检查分区状态"
		echo -e "${pink}------------------------${white}"
		echo "0. 返回上一级选单"
		echo -e "${pink}------------------------${white}"
		read -e -p "请输入你的选择: " choice
		case $choice in
			1) mount_partition ;;
			2) unmount_partition ;;
			3) list_mounted_partitions ;;
			4) format_partition ;;
			5) check_partition ;;
			*) break ;;
		esac
		read -e -p "按回车键继续..."
	done
}



# 21. 命令行历史记录
cmd_history() {
	clear
	get_history_file() {
		for file in "$HOME"/.bash_history "$HOME"/.ash_history "$HOME"/.zsh_history "$HOME"/.local/share/fish/fish_history; do
			[ -f "$file" ] && { echo "$file"; return; }
		done
		return 1
	}

	history_file=$(get_history_file) && cat -n "$history_file"
}



# 22. 命令收藏夹
cmd_bookmark() {
	clear
	bash <(curl -l -s ${url_proxy}raw.githubusercontent.com/byJoey/cmdbox/refs/heads/main/install.sh)
}



# 23. 命令行美化工具（子菜单）
shell_bianse_profile() {

if command -v dnf &>/dev/null || command -v yum &>/dev/null; then
	sed -i '/^PS1=/d' ~/.bashrc
	echo "${bianse}" >> ~/.bashrc
	# source ~/.bashrc
else
	sed -i '/^PS1=/d' ~/.profile
	echo "${bianse}" >> ~/.profile
	# source ~/.profile
fi
echo -e "${green}变更完成。重新连接SSH后可查看变化！${white}"

hash -r
break_end

}
cmd_line_beautify_tool() {
	root_use
	while true; do
		clear
		echo "命令行美化工具"
		echo -e "${pink}------------------------${white}"
		echo -e "1. \033[1;32mroot \033[1;34mlocalhost \033[1;31m~ \033[0m${white}#"
		echo -e "2. \033[1;35mroot \033[1;36mlocalhost \033[1;33m~ \033[0m${white}#"
		echo -e "3. \033[1;31mroot \033[1;32mlocalhost \033[1;34m~ \033[0m${white}#"
		echo -e "4. \033[1;36mroot \033[1;33mlocalhost \033[1;37m~ \033[0m${white}#"
		echo -e "5. \033[1;37mroot \033[1;31mlocalhost \033[1;32m~ \033[0m${white}#"
		echo -e "6. \033[1;33mroot \033[1;34mlocalhost \033[1;35m~ \033[0m${white}#"
		echo -e "7. root localhost ~ #"
		echo -e "${pink}------------------------${white}"
		echo "${yellow}0. 返回上一级选单${white}"
		echo -e "${pink}------------------------${white}"
		read -e -p "输入你的选择: " choice

		case $choice in
		1)
			local bianse="PS1='\[\033[1;32m\]\u\[\033[0m\]@\[\033[1;34m\]\h\[\033[0m\] \[\033[1;31m\]\w\[\033[0m\] # '"
			shell_bianse_profile

			;;
		2)
			local bianse="PS1='\[\033[1;35m\]\u\[\033[0m\]@\[\033[1;36m\]\h\[\033[0m\] \[\033[1;33m\]\w\[\033[0m\] # '"
			shell_bianse_profile
			;;
		3)
			local bianse="PS1='\[\033[1;31m\]\u\[\033[0m\]@\[\033[1;32m\]\h\[\033[0m\] \[\033[1;34m\]\w\[\033[0m\] # '"
			shell_bianse_profile
			;;
		4)
			local bianse="PS1='\[\033[1;36m\]\u\[\033[0m\]@\[\033[1;33m\]\h\[\033[0m\] \[\033[1;37m\]\w\[\033[0m\] # '"
			shell_bianse_profile
			;;
		5)
			local bianse="PS1='\[\033[1;37m\]\u\[\033[0m\]@\[\033[1;31m\]\h\[\033[0m\] \[\033[1;32m\]\w\[\033[0m\] # '"
			shell_bianse_profile
			;;
		6)
			local bianse="PS1='\[\033[1;33m\]\u\[\033[0m\]@\[\033[1;34m\]\h\[\033[0m\] \[\033[1;35m\]\w\[\033[0m\] # '"
			shell_bianse_profile
			;;
		7)
			local bianse=""
			shell_bianse_profile
			;;
		*)
			break
			;;
		esac

	done
}



# ------------- 主菜单 -------------
linux_tools() {
    while true; do
        clear
        echo -e "${green}===== 系统工具菜单目录 =====${white}"
        echo -e "${cyan}1.  ${white}设置脚本启动快捷键          ${cyan}2.  ${white}修改用户登录密码"
        echo -e "${cyan}3.  ${white}修改root登录密码            ${cyan}4.  ${white}修改ssh连接端口"
        echo -e "${cyan}5.  ${white}打开/关闭ssh密码登录        ${cyan}6.  ${white}打开/关闭ssh root登录"
        echo -e "${cyan}7.  ${white}优化DNS地址                 ${cyan}8.  ${white}切换优先ipv4/ipv6"
        echo -e "${cyan}9.  ${white}查看端口占用状态            ${cyan}10. ${white}修改虚拟内存大小"
		echo -e "------------------------------------${white}"
        echo -e "${cyan}11. ${white}用户管理			${cyan}12. ${white}系统时区调整"
        echo -e "${cyan}13. ${white}修改主机名			${cyan}14. ${white}切换系统更新源"
        echo -e "${cyan}15. ${white}定时任务管理		${cyan}16. ${white}文件管理器"
        echo -e "${cyan}17. ${white}切换系统语言		${cyan}18. ${white}设置系统回收站"
        echo -e "${cyan}19. ${white}ssh远程连接工具		${cyan}20. ${white}硬盘分区管理工具"
		echo -e "--------------------------${white}"
        echo -e "${cyan}21. ${white}命令行历史记录		${cyan}22. ${white}命令收藏夹"
        echo -e "${cyan}23. ${white}命令行美化工具"
        echo -e "------------------------------${white}"
        echo -e "${yellow}0.  ${yellow}返回上一级菜单"
        echo -e "${purple}请输入你的选择: ${white}\c"
        read choice

        case $choice in
            1) set_script_shortcut ;;
            2) change_user_password ;;
            3) change_root_password ;;
            4) change_ssh_port ;;
            5) ssh_password_login ;;
            6) ssh_root_login ;;
            7) optimize_dns ;;
            8) change_ip_priority ;;
            9) linux_port ;;
            10) modify_swap_size ;;
            11) user_management ;;
            12) adjust_timezone ;;
            13) modify_hostname ;;
            14) switch_update_source ;;
            15) cron_job_management ;;
            16) file_manager ;;
            17) switch_system_language ;;
            18) linux_trash ;;
            19) ssh_manager ;;
            20) disk_manager ;;
            21) cmd_history ;;
            22) cmd_bookmark ;;
            23) cmd_line_beautify_tool ;;
            0) return ;;
            *) echo -e "${red}无效的输入，请重新选择！${white}"; pause ;;
        esac
    done
}

###########################################################################
########################### 三、测试工具合集 ###############################
network_tools() {
	while true; do
		clear
		echo -e "测试脚本合集"
		echo -e "${cyan}------------------------${white}"
		echo -e "${cyan}IP及解锁状态检测"
		echo -e "${cyan}1.   ${white}ChatGPT 解锁状态检测"
		echo -e "${cyan}2.   ${white}Region 流媒体解锁测试"
		echo -e "${cyan}3.   ${white}yeahwu 流媒体解锁检测"
		echo -e "${cyan}4.   ${white}xykt IP质量体检脚本 ${yellow}★${white}"

		echo -e "${cyan}------------------------${white}"
		echo -e "${cyan}网络线路测速"
		echo -e "${cyan}11.  ${white}besttrace 三网回程延迟路由测试"
		echo -e "${cyan}12.  ${white}mtr_trace 三网回程线路测试"
		echo -e "${cyan}13.  ${white}Superspeed 三网测速"
		echo -e "${cyan}14.  ${white}nxtrace 快速回程测试脚本"
		echo -e "${cyan}15.  ${white}nxtrace 指定IP回程测试脚本"
		echo -e "${cyan}16.  ${white}ludashi2020 三网线路测试"
		echo -e "${cyan}17.  ${white}i-abc 多功能测速脚本"
		echo -e "${cyan}18.  ${white}NetQuality 网络质量体检脚本 ${yellow}★${white}"

		echo -e "${cyan}------------------------${white}"
		echo -e "${cyan}硬件性能测试"
		echo -e "${cyan}21.  ${white}yabs 性能测试"
		echo -e "${cyan}22.  ${white}icu/gb5 CPU性能测试脚本"

		echo -e "${cyan}------------------------${white}"
		echo -e "${cyan}综合性测试"
		echo -e "${cyan}31.  ${white}bench 性能测试"
		echo -e "${cyan}32.  ${white}spiritysdx 融合怪测评 ${yellow}★${white}"
		echo -e "${cyan}------------------------${white}"
		echo -e "${yellow}0.   ${white}返回主菜单"
		echo -e "${cyan}------------------------${white}"
		read -e -p "请输入你的选择: " sub_choice

		case $sub_choice in
			1)
				clear
				## "ChatGPT解锁状态检测"
				bash <(curl -Ls https://cdn.jsdelivr.net/gh/missuo/OpenAI-Checker/openai.sh)
				;;
			2)
				clear
				## "Region流媒体解锁测试"
				bash <(curl -L -s check.unlock.media)
				;;
			3)
				clear
				## "yeahwu流媒体解锁检测"
				install wget
				wget -qO- ${url_proxy}github.com/yeahwu/check/raw/main/check.sh | bash
				;;
			4)
				clear
				## "xykt_IP质量体检脚本"
				bash <(curl -Ls IP.Check.Place)
				;;


			11)
				clear
				## "besttrace三网回程延迟路由测试"
				install wget
				wget -qO- git.io/besttrace | bash
				;;
			12)
				clear
				## "mtr_trace三网回程线路测试"
				curl ${url_proxy}raw.githubusercontent.com/zhucaidan/mtr_trace/main/mtr_trace.sh | bash
				;;
			13)
				clear
				## "Superspeed三网测速"
				bash <(curl -Lso- https://git.io/superspeed_uxh)
				;;
			14)
				clear
				## "nxtrace快速回程测试脚本"
				curl nxtrace.org/nt |bash
				nexttrace --fast-trace --tcp
				;;
			15)
				clear
				## "nxtrace指定IP回程测试脚本"
				echo "可参考的IP列表"
				echo -e "${pink}------------------------${white}"
				echo "北京电信: 219.141.136.12"
				echo "北京联通: 202.106.50.1"
				echo "北京移动: 221.179.155.161"
				echo "上海电信: 202.96.209.133"
				echo "上海联通: 210.22.97.1"
				echo "上海移动: 211.136.112.200"
				echo "广州电信: 58.60.188.222"
				echo "广州联通: 210.21.196.6"
				echo "广州移动: 120.196.165.24"
				echo "成都电信: 61.139.2.69"
				echo "成都联通: 119.6.6.6"
				echo "成都移动: 211.137.96.205"
				echo "湖南电信: 36.111.200.100"
				echo "湖南联通: 42.48.16.100"
				echo "湖南移动: 39.134.254.6"
				echo -e "${pink}------------------------${white}"

				read -e -p "输入一个指定IP: " testip
				curl nxtrace.org/nt |bash
				nexttrace $testip
				;;

			16)
				clear
				## "ludashi2020三网线路测试"
				curl ${url_proxy}raw.githubusercontent.com/ludashi2020/backtrace/main/install.sh -sSf | sh
				;;

			17)
				clear
				## "i-abc多功能测速脚本"
				bash <(curl -sL ${url_proxy}raw.githubusercontent.com/i-abc/Speedtest/main/speedtest.sh)
				;;

			18)
				clear
				## "网络质量测试脚本"
				bash <(curl -sL Net.Check.Place)
				;;

			21)
				clear
				## "yabs性能测试"
				check_swap
				curl -sL yabs.sh | bash -s -- -i -5
				;;
			22)
				clear
				## "icu/gb5 CPU性能测试脚本"
				check_swap
				bash <(curl -sL bash.icu/gb5)
				;;

			31)
				clear
				## "bench性能测试"
				curl -Lso- bench.sh | bash
				;;
			32)
				## "spiritysdx融合怪测评"
				clear
				curl -L https://gitlab.com/spiritysdx/za/-/raw/main/ecs.sh -o ecs.sh && chmod +x ecs.sh && bash ecs.sh
				;;

			0)
				return_to_menu
				;;
		  *)
				echo "无效的输入!"
				;;
		esac
		break_end

	done
}

#############################################################################
########################### 四、Docker管理模块 ###############################
## 1. Docker容器管理
docker_ps() {
while true; do
	clear
	echo "Docker容器列表"
	docker ps -a --format "table {{.ID}}\t{{.Names}}\t{{.Status}}\t{{.Ports}}"
	echo ""
	echo "容器操作"
	echo -e "${pink}------------------------${white}"
	echo "1. 创建新的容器"
	echo -e "${pink}------------------------${white}"
	echo "2. 启动指定容器             6. 启动所有容器"
	echo "3. 停止指定容器             7. 停止所有容器"
	echo "4. 删除指定容器             8. 删除所有容器"
	echo "5. 重启指定容器             9. 重启所有容器"
	echo -e "${pink}------------------------${white}"
	echo "11. 进入指定容器           12. 查看容器日志"
	echo "13. 查看容器网络           14. 查看容器占用"
	echo -e "${pink}------------------------${white}"
	echo "15. 开启容器端口访问       16. 关闭容器端口访问"
	echo -e "${pink}------------------------${white}"
	echo "0. 返回上一级选单"
	echo -e "${pink}------------------------${white}"
	read -e -p "请输入你的选择: " sub_choice
	case $sub_choice in
		1)
			## "新建容器"
			read -e -p "请输入创建命令: " dockername
			$dockername
			;;
		2)
			## "启动指定容器"
			read -e -p "请输入容器名（多个容器名请用空格分隔）: " dockername
			docker start $dockername
			;;
		3)
			## "停止指定容器"
			read -e -p "请输入容器名（多个容器名请用空格分隔）: " dockername
			docker stop $dockername
			;;
		4)
			## "删除指定容器"
			read -e -p "请输入容器名（多个容器名请用空格分隔）: " dockername
			docker rm -f $dockername
			;;
		5)
			## "重启指定容器"
			read -e -p "请输入容器名（多个容器名请用空格分隔）: " dockername
			docker restart $dockername
			;;
		6)
			## "启动所有容器"
			docker start $(docker ps -a -q)
			;;
		7)
			## "停止所有容器"
			docker stop $(docker ps -q)
			;;
		8)
			## "删除所有容器"
			read -e -p "$(echo -e "${red}注意: ${white}确定删除所有容器吗？(Y/N): ")" choice
			case "$choice" in
			[Yy])
				docker rm -f $(docker ps -a -q)
				;;
			[Nn])
				;;
			  *)
				echo "无效的选择，请输入 Y 或 N。"
				;;
			esac
			;;
		9)
			## "重启所有容器"
			docker restart $(docker ps -q)
			;;
		11)
			## "进入容器"
			read -e -p "请输入容器名: " dockername
			docker exec -it $dockername /bin/sh
			break_end
			;;
		12)
			## "查看容器日志"
			read -e -p "请输入容器名: " dockername
			docker logs $dockername
			break_end
			;;
		13)
			## "查看容器网络"
			echo ""
			container_ids=$(docker ps -q)
			echo -e "${pink}------------------------------------------------------------${white}"
			printf "%-25s %-25s %-25s\n" "容器名称" "网络名称" "IP地址"
			for container_id in $container_ids; do
				local container_info=$(docker inspect --format '{{ .Name }}{{ range $network, $config := .NetworkSettings.Networks }} {{ $network }} {{ $config.IPAddress }}{{ end }}' "$container_id")
				local container_name=$(echo "$container_info" | awk '{print $1}')
				local network_info=$(echo "$container_info" | cut -d' ' -f2-)
				while IFS= read -r line; do
					local network_name=$(echo "$line" | awk '{print $1}')
					local ip_address=$(echo "$line" | awk '{print $2}')
					printf "%-20s %-20s %-15s\n" "$container_name" "$network_name" "$ip_address"
				done <<< "$network_info"
			done
			break_end
			;;
		14)
			## "查看容器占用"
			docker stats --no-stream
			break_end
			;;

		15)
			## "允许容器端口访问"
			read -e -p "请输入容器名: " docker_name
			ip_address
			clear_container_rules "$docker_name" "$ipv4_address"
			local docker_port=$(docker port $docker_name | awk -F'[:]' '/->/ {print $NF}' | uniq)
			check_docker_app_ip
			break_end
			;;

		16)
			## "阻止容器端口访问"
			read -e -p "请输入容器名: " docker_name
			ip_address
			block_container_port "$docker_name" "$ipv4_address"
			local docker_port=$(docker port $docker_name | awk -F'[:]' '/->/ {print $NF}' | uniq)
			check_docker_app_ip
			break_end
			;;

		*)
			break  # 跳出循环，退出菜单
			;;
	esac
done
}

## 2. Docker镜像管理
docker_image() {
while true; do
	clear
	## "Docker镜像管理"
	echo "Docker镜像列表"
	docker image ls
	echo ""
	echo "镜像操作"
	echo -e "${pink}------------------------${white}"
	echo "1. 获取指定镜像             3. 删除指定镜像"
	echo "2. 更新指定镜像             4. 删除所有镜像"
	echo -e "${pink}------------------------${white}"
	echo "0. 返回上一级选单"
	echo -e "${pink}------------------------${white}"
	read -e -p "请输入你的选择: " sub_choice
	case $sub_choice in
		1)
			## "拉取镜像"
			read -e -p "请输入镜像名（多个镜像名请用空格分隔）: " imagenames
			for name in $imagenames; do
				echo -e "${yellow}正在获取镜像: $name${white}"
				docker pull $name
			done
			;;
		2)
			## "更新镜像"
			read -e -p "请输入镜像名（多个镜像名请用空格分隔）: " imagenames
			for name in $imagenames; do
				echo -e "${yellow}正在更新镜像: $name${white}"
				docker pull $name
			done
			;;
		3)
			## "删除镜像"
			read -e -p "请输入镜像名（多个镜像名请用空格分隔）: " imagenames
			for name in $imagenames; do
				docker rmi -f $name
			done
			;;
		4)
			## "删除所有镜像"
			read -e -p "$(echo -e "${red}注意: ${white}确定删除所有镜像吗？(Y/N): ")" choice
			case "$choice" in
				[Yy])
				docker rmi -f $(docker images -q)
				;;
				[Nn])
				;;
			  *)
				echo "无效的选择，请输入 Y 或 N。"
				;;
			esac
			;;
		*)
			break  # 跳出循环，退出菜单
			;;
	esac
done
}

## 3. 打开Docker IPv6
docker_ipv6_on() {
	root_use
	install jq

	local CONFIG_FILE="/etc/docker/daemon.json"
	local REQUIred_IPV6_CONFIG='{"ipv6": true, "fixed-cidr-v6": "2001:db8:1::/64"}'

	# 检查配置文件是否存在，如果不存在则创建文件并写入默认设置
	if [ ! -f "$CONFIG_FILE" ]; then
		echo "$REQUIred_IPV6_CONFIG" | jq . > "$CONFIG_FILE"
		restart docker
	else
		# 使用jq处理配置文件的更新
		local ORIGINAL_CONFIG=$(<"$CONFIG_FILE")

		# 检查当前配置是否已经有 ipv6 设置
		local CURRENT_IPV6=$(echo "$ORIGINAL_CONFIG" | jq '.ipv6 // false')

		# 更新配置，开启 IPv6
		if [[ "$CURRENT_IPV6" == "false" ]]; then
			UPDATED_CONFIG=$(echo "$ORIGINAL_CONFIG" | jq '. + {ipv6: true, "fixed-cidr-v6": "2001:db8:1::/64"}')
		else
			UPDATED_CONFIG=$(echo "$ORIGINAL_CONFIG" | jq '. + {"fixed-cidr-v6": "2001:db8:1::/64"}')
		fi

		# 对比原始配置与新配置
		if [[ "$ORIGINAL_CONFIG" == "$UPDATED_CONFIG" ]]; then
			echo -e "${yellow}当前已开启ipv6访问${white}"
		else

			echo "$UPDATED_CONFIG" | jq . > "$CONFIG_FILE"
			restart docker
			echo -e "${yellow}已成功开启ipv6访问${white}"
		fi
	fi
}

## 4. 关闭Docker IPv6
docker_ipv6_off() {
	root_use
	install jq

	local CONFIG_FILE="/etc/docker/daemon.json"

	# 检查配置文件是否存在
	if [ ! -f "$CONFIG_FILE" ]; then
		echo -e "${red}配置文件不存在${white}"
		return
	fi

	# 读取当前配置
	local ORIGINAL_CONFIG=$(<"$CONFIG_FILE")

	# 使用jq处理配置文件的更新
	local UPDATED_CONFIG=$(echo "$ORIGINAL_CONFIG" | jq 'del(.["fixed-cidr-v6"]) | .ipv6 = false')

	# 检查当前的 ipv6 状态
	local CURRENT_IPV6=$(echo "$ORIGINAL_CONFIG" | jq -r '.ipv6 // false')

	# 对比原始配置与新配置
	if [[ "$CURRENT_IPV6" == "false" ]]; then
		echo -e "${yellow}当前已关闭ipv6访问${white}"
	else
		echo "$UPDATED_CONFIG" | jq . > "$CONFIG_FILE"
		restart docker
		echo -e "${yellow}已成功关闭ipv6访问${white}"
	fi
}

## 5. 添加Docker中国镜像源
install_add_docker_cn() {
    local country=$(curl -s ipinfo.io/country 2>/dev/null)
    if [ "$country" = "CN" ]; then
        cat > /etc/docker/daemon.json << EOF
{
    "registry-mirrors": [
        "https://docker.mirrors.ustc.edu.cn",
        "https://hub-mirror.c.163.com",
        "https://mirror.baidubce.com"
    ]
}
EOF
    fi
    sudo systemctl daemon-reload
    sudo systemctl enable docker --now
}

## 6. 添加Docker官方源
install_add_docker_guanfang() {
    local country=$(curl -s ipinfo.io/country 2>/dev/null)
    if [ "$country" = "CN" ]; then
        curl -fsSL https://get.docker.com | sed 's/download.docker.com/mirrors.aliyun.com\/docker-ce/g' | sh
    else
        curl -fsSL https://get.docker.com | sh
    fi
    install_add_docker_cn
}

## 7. 添加Docker源
install_add_docker() {
    echo -e "${yellow}正在安装 Docker 环境...${white}"
    
    # 统一处理依赖（以 Debian/Ubuntu 为例，其他系统需适配）
    if command -v apt &> /dev/null; then
        sudo apt update
        sudo apt install -y apt-transport-https ca-certificates curl gnupg lsb-release
    elif command -v dnf &> /dev/null; then
        sudo dnf install -y yum-utils device-mapper-persistent-data lvm2
    fi
    
    install_add_docker_guanfang
    break_end
}

## 8. 安装Docker
install_docker() {
    if ! command -v docker &> /dev/null; then
        install_add_docker
    else
        echo -e "${yellow}Docker 已安装，跳过安装流程${white}"
    fi
}

## 9. Docker 卸载函数
uninstall_docker() {
    clear
    read -e -p "$(echo -e "${red}注意: ${white}确定卸载 Docker 环境吗？(Y/N): ")" choice
    case "$choice" in
        [Yy])
            # 1. 停止并删除所有容器、镜像、网络、卷
            docker ps -a -q | xargs -r docker rm -f >/dev/null 2>&1
            docker images -q | xargs -r docker rmi -f >/dev/null 2>&1
            docker network prune -f >/dev/null 2>&1
            docker volume prune -f >/dev/null 2>&1

            # 2. 根据系统发行版选择卸载命令
            if command -v apt &> /dev/null; then  # Debian/Ubuntu 系列
                sudo apt purge -y docker-ce docker-ce-cli containerd.io docker-compose-plugin >/dev/null 2>&1
                sudo apt autoremove -y >/dev/null 2>&1
            elif command -v dnf &> /dev/null; then  # CentOS/RHEL 8+ 系列
                sudo dnf remove -y docker-ce docker-ce-cli containerd.io docker-compose-plugin >/dev/null 2>&1
                sudo dnf autoremove -y >/dev/null 2>&1
            elif command -v yum &> /dev/null; then  # CentOS/RHEL 7 系列
                sudo yum remove -y docker-ce docker-ce-cli containerd.io docker-compose-plugin >/dev/null 2>&1
                sudo yum autoremove -y >/dev/null 2>&1
            elif command -v pacman &> /dev/null; then  # Arch 系列
                sudo pacman -Rns --noconfirm docker docker-compose >/dev/null 2>&1
            fi

            # 3. 清理残留文件和目录
            sudo rm -rf /etc/docker /var/lib/docker /var/run/docker.sock
            sudo rm -f /etc/apt/sources.list.d/docker*.repo  # Debian/Ubuntu 源文件清理
            sudo rm -f /etc/yum.repos.d/docker*.repo        # CentOS/RHEL 源文件清理

            # 4. 刷新环境变量
            hash -r

            echo -e "${red}Docker 环境已卸载完成${white}"
            ;;
        [Nn])
            echo -e "${white}已取消 Docker 卸载操作${white}"
            ;;
        *)
            echo -e "${red}无效的选择，请输入 Y 或 N${white}"
            ;;
    esac
}

# 10. Docker管理界面
linux_docker() {

	while true; do
		clear
		check_docker
		echo -e "Docker管理"
		docker_tato
		echo -e "${cyan}------------------------${white}"
		echo -e "${cyan}1.   ${white}安装更新Docker环境 ${yellow}★${white}"
		echo -e "${cyan}------------------------${white}"
		echo -e "${cyan}2.   ${white}查看Docker全局状态 ${yellow}★${white}"
		echo -e "${cyan}------------------------${white}"
		echo -e "${cyan}3.   ${white}Docker容器管理 ${yellow}★${white}"
		echo -e "${cyan}4.   ${white}Docker镜像管理"
		echo -e "${cyan}5.   ${white}Docker网络管理"
		echo -e "${cyan}6.   ${white}Docker卷管理"
		echo -e "${cyan}------------------------${white}"
		echo -e "${cyan}7.   ${white}清理无用的docker容器和镜像网络数据卷"
		echo -e "${cyan}------------------------${white}"
		echo -e "${cyan}8.   ${white}更换Docker源"
		echo -e "${cyan}9.   ${white}编辑daemon.json文件"
		echo -e "${cyan}------------------------${white}"
		echo -e "${cyan}11.  ${white}开启Docker-ipv6访问"
		echo -e "${cyan}12.  ${white}关闭Docker-ipv6访问"
		echo -e "${cyan}------------------------${white}"
		echo -e "${cyan}20.  ${white}卸载Docker环境"
		echo -e "${cyan}------------------------${white}"
		echo -e "${cyan}0.   ${white}返回主菜单"
		echo -e "${cyan}------------------------${white}"
		read -e -p "请输入你的选择: " sub_choice

		case $sub_choice in
			1)
				clear
				## "安装docker环境"
				install_add_docker
				;;
			2)
				clear
				local container_count=$(docker ps -a -q 2>/dev/null | wc -l)
				local image_count=$(docker images -q 2>/dev/null | wc -l)
				local network_count=$(docker network ls -q 2>/dev/null | wc -l)
				local volume_count=$(docker volume ls -q 2>/dev/null | wc -l)

				## "docker全局状态"
				echo "Docker版本"
				docker -v
				docker compose version

				echo ""
				echo -e "Docker镜像: ${green}$image_count${white} "
				docker image ls
				echo ""
				echo -e "Docker容器: ${green}$container_count${white}"
				docker ps -a
				echo ""
				echo -e "Docker卷: ${green}$volume_count${white}"
				docker volume ls
				echo ""
				echo -e "Docker网络: ${green}$network_count${white}"
				docker network ls
				echo ""

				;;
			3)
				docker_ps
				;;
			4)
				docker_image
				;;

			5)
				while true; do
					clear
					## "Docker网络管理"
					echo "Docker网络列表"
					echo -e "${pink}------------------------------------------------------------${white}"
					docker network ls
					echo ""

					echo -e "${pink}------------------------------------------------------------${white}"
					container_ids=$(docker ps -q)
					printf "%-25s %-25s %-25s\n" "容器名称" "网络名称" "IP地址"

					for container_id in $container_ids; do
						local container_info=$(docker inspect --format '{{ .Name }}{{ range $network, $config := .NetworkSettings.Networks }} {{ $network }} {{ $config.IPAddress }}{{ end }}' "$container_id")

						local container_name=$(echo "$container_info" | awk '{print $1}')
						local network_info=$(echo "$container_info" | cut -d' ' -f2-)

						while IFS= read -r line; do
							local network_name=$(echo "$line" | awk '{print $1}')
							local ip_address=$(echo "$line" | awk '{print $2}')

							printf "%-20s %-20s %-15s\n" "$container_name" "$network_name" "$ip_address"
						done <<< "$network_info"
					done

					echo ""
					echo "网络操作"
					echo -e "${pink}------------------------${white}"
					echo "1. 创建网络"
					echo "2. 加入网络"
					echo "3. 退出网络"
					echo "4. 删除网络"
					echo -e "${pink}------------------------${white}"
					echo "0. 返回上一级选单"
					echo -e "${pink}------------------------${white}"
					read -e -p "请输入你的选择: " sub_choice

					case $sub_choice in
						1)
							## "创建网络"
							read -e -p "设置新网络名: " dockernetwork
							docker network create $dockernetwork
							;;
						2)
							## "加入网络"
							read -e -p "加入网络名: " dockernetwork
							read -e -p "那些容器加入该网络（多个容器名请用空格分隔）: " dockernames

							for dockername in $dockernames; do
								docker network connect $dockernetwork $dockername
							done
							;;
						3)
							## "加入网络"
							read -e -p "退出网络名: " dockernetwork
							read -e -p "那些容器退出该网络（多个容器名请用空格分隔）: " dockernames

							for dockername in $dockernames; do
								docker network disconnect $dockernetwork $dockername
							done

							;;

						4)
							## "删除网络"
							read -e -p "请输入要删除的网络名: " dockernetwork
							docker network rm $dockernetwork
							;;

						*)
							break  # 跳出循环，退出菜单
							;;
					esac
				done
				;;

			6)
				while true; do
					clear
					## "Docker卷管理"
					echo "Docker卷列表"
					docker volume ls
					echo ""
					echo "卷操作"
					echo -e "${pink}------------------------${white}"
					echo "1. 创建新卷"
					echo "2. 删除指定卷"
					echo "3. 删除所有卷"
					echo -e "${pink}------------------------${white}"
					echo "0. 返回上一级选单"
					echo -e "${pink}------------------------${white}"
					read -e -p "请输入你的选择: " sub_choice

					case $sub_choice in
						1)
							## "新建卷"
							read -e -p "设置新卷名: " dockerjuan
							docker volume create $dockerjuan

							;;
						2)
							read -e -p "输入删除卷名（多个卷名请用空格分隔）: " dockerjuans

							for dockerjuan in $dockerjuans; do
								docker volume rm $dockerjuan
							done

							;;

						3)
							## "删除所有卷"
							read -e -p "$(echo -e "${red}注意: ${white}确定删除所有未使用的卷吗？(Y/N): ")" choice
							case "$choice" in
							[Yy])
								docker volume prune -f
								;;
							[Nn])
								;;
							*)
								echo "无效的选择，请输入 Y 或 N。"
								;;
							esac
							;;

						*)
							break  # 跳出循环，退出菜单
							;;
					esac
				done
				;;
			7)
				clear
				## "Docker清理"
				read -e -p "$(echo -e "${yellow}提示: ${white}将清理无用的镜像容器网络，包括停止的容器，确定清理吗？(Y/N): ")" choice
				case "$choice" in
				[Yy])
					docker system prune -af --volumes
					;;
				[Nn])
					;;
				*)
					echo "无效的选择，请输入 Y 或 N。"
					;;
				esac
				;;
			8)
				clear
				## "Docker源"
				bash <(curl -sSL https://linuxmirrors.cn/docker.sh)
				;;

			9)
				clear
				install nano
				mkdir -p /etc/docker && nano /etc/docker/daemon.json
				restart docker
				;;

			11)
				clear
				## "Docker v6 开"
				docker_ipv6_on
				;;

			12)
				clear
				## "Docker v6 关"
				docker_ipv6_off
				;;

			20)
				uninstall_docker
				;;

			0)
				return_to_menu
				;;
			*)
				echo "无效的输入!"
				;;
		esac
		break_end

	done
}
#############################################################################
############################### 五、LDNMP建站管理 ############################
# 版本信息
ldnmp_v() {
	# 获取nginx版本
	local nginx_version=$(docker exec nginx nginx -v 2>&1)
	local nginx_version=$(echo "$nginx_version" | grep -oP "nginx/\K[0-9]+\.[0-9]+\.[0-9]+")
	echo -n -e "nginx : ${yellow}v$nginx_version${white}"

	# 获取mysql版本
	local dbrootpasswd=$(grep -oP 'MYSQL_ROOT_PASSWORD:\s*\K.*' /home/web/docker-compose.yml | tr -d '[:space:]')
	local mysql_version=$(docker exec mysql mysql -u root -p"$dbrootpasswd" -e "SELECT VERSION();" 2>/dev/null | tail -n 1)
	echo -n -e "            mysql : ${yellow}v$mysql_version${white}"

	# 获取php版本
	local php_version=$(docker exec php php -v 2>/dev/null | grep -oP "PHP \K[0-9]+\.[0-9]+\.[0-9]+")
	echo -n -e "            php : ${yellow}v$php_version${white}"

	# 获取redis版本
	local redis_version=$(docker exec redis redis-server -v 2>&1 | grep -oP "v=+\K[0-9]+\.[0-9]+")
	echo -e "            redis : ${yellow}v$redis_version${white}"

	echo "------------------------"
	echo ""
}

# 修复PHP-FPM配置
fix_phpfpm_conf() {
	local container_name=$1
	docker exec "$container_name" sh -c "mkdir -p /run/$container_name && chmod 777 /run/$container_name"
	docker exec "$container_name" sh -c "sed -i '1i [global]\\ndaemonize = no' /usr/local/etc/php-fpm.d/www.conf"
	docker exec "$container_name" sh -c "sed -i '/^listen =/d' /usr/local/etc/php-fpm.d/www.conf"
	docker exec "$container_name" sh -c "echo -e '\nlisten = /run/$container_name/php-fpm.sock\nlisten.owner = www-data\nlisten.group = www-data\nlisten.mode = 0777' >> /usr/local/etc/php-fpm.d/www.conf"
	docker exec "$container_name" sh -c "rm -f /usr/local/etc/php-fpm.d/zz-docker.conf"

	find /home/web/conf.d/ -type f -name "*.conf" -exec sed -i "s#fastcgi_pass ${container_name}:9000;#fastcgi_pass unix:/run/${container_name}/php-fpm.sock;#g" {} \;
}

# 安装LDNMP配置
install_ldnmp_conf() {
	# 创建必要的目录和文件
	cd /home && mkdir -p web/html web/mysql web/certs web/conf.d web/redis web/log/nginx && touch web/docker-compose.yml
	wget -O /home/web/nginx.conf ${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/nginx10.conf
	wget -O /home/web/conf.d/default.conf ${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/default10.conf
	wget -O /home/web/redis/valkey.conf ${gh_proxy}raw.githubusercontent.com/kejilion/sh/main/valkey.conf


	default_server_ssl

	# 下载 docker-compose.yml 文件并进行替换
	wget -O /home/web/docker-compose.yml ${gh_proxy}raw.githubusercontent.com/kejilion/docker/main/LNMP-docker-compose-10.yml
	dbrootpasswd=$(openssl rand -base64 16) ; dbuse=$(openssl rand -hex 4) ; dbusepasswd=$(openssl rand -base64 8)

	# 在 docker-compose.yml 文件中进行替换
	sed -i "s#webroot#$dbrootpasswd#g" /home/web/docker-compose.yml
	sed -i "s#kejilionYYDS#$dbusepasswd#g" /home/web/docker-compose.yml
	sed -i "s#kejilion#$dbuse#g" /home/web/docker-compose.yml
}

# 安装LDNMP
install_ldnmp() {
	check_swap
	cp /home/web/docker-compose.yml /home/web/docker-compose1.yml

	if ! grep -q "network_mode" /home/web/docker-compose.yml; then
	wget -O /home/web/docker-compose.yml ${gh_proxy}raw.githubusercontent.com/kejilion/docker/main/LNMP-docker-compose-10.yml
	dbrootpasswd=$(grep -oP 'MYSQL_ROOT_PASSWORD:\s*\K.*' /home/web/docker-compose1.yml | tr -d '[:space:]')
	dbuse=$(grep -oP 'MYSQL_USER:\s*\K.*' /home/web/docker-compose1.yml | tr -d '[:space:]')
	dbusepasswd=$(grep -oP 'MYSQL_PASSWORD:\s*\K.*' /home/web/docker-compose1.yml | tr -d '[:space:]')

	sed -i "s#webroot#$dbrootpasswd#g" /home/web/docker-compose.yml
	sed -i "s#kejilionYYDS#$dbusepasswd#g" /home/web/docker-compose.yml
	sed -i "s#kejilion#$dbuse#g" /home/web/docker-compose.yml

	fi

	if grep -q "kjlion/nginx:alpine" /home/web/docker-compose1.yml; then
	sed -i 's|kjlion/nginx:alpine|nginx:alpine|g' /home/web/docker-compose.yml  > /dev/null 2>&1
	sed -i 's|nginx:alpine|kjlion/nginx:alpine|g' /home/web/docker-compose.yml  > /dev/null 2>&1
	fi

	cd /home/web && docker compose up -d
	sleep 1
	crontab -l 2>/dev/null | grep -v 'logrotate' | crontab -
	(crontab -l 2>/dev/null; echo '0 2 * * * docker exec nginx apk add logrotate && docker exec nginx logrotate -f /etc/logrotate.conf') | crontab -

	fix_phpfpm_conf php
	fix_phpfpm_conf php74
	restart_ldnmp


	clear
	echo "LDNMP环境安装完毕"
	echo "------------------------"
	ldnmp_v
}

# 安装Certbot
install_certbot() {
	cd ~
	curl -sS -O ${gh_proxy}raw.githubusercontent.com/kejilion/sh/main/auto_cert_renewal.sh
	chmod +x auto_cert_renewal.sh

	check_crontab_installed
	local cron_job="0 0 * * * ~/auto_cert_renewal.sh"
	crontab -l 2>/dev/null | grep -vF "$cron_job" | crontab -
	(crontab -l 2>/dev/null; echo "$cron_job") | crontab -
	echo "续签任务已更新"
}

# 安装SSL/TLS
install_ssltls() {
	docker stop nginx > /dev/null 2>&1
	check_port > /dev/null 2>&1
	cd ~

	local file_path="/etc/letsencrypt/live/$yuming/fullchain.pem"
	if [ ! -f "$file_path" ]; then
		local ipv4_pattern='^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
		local ipv6_pattern='^(([0-9A-Fa-f]{1,4}:){1,7}:|([0-9A-Fa-f]{1,4}:){7,7}[0-9A-Fa-f]{1,4}|::1)$'
		# local ipv6_pattern='^([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}$'
		# local ipv6_pattern='^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|(2[0-4][0-9]|[01]?[0-9][0-9]?))|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|(2[0-4][0-9]|[01]?[0-9][0-9]?))|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|(2[0-4][0-9]|[01]?[0-9][0-9]?))|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|(2[0-4][0-9]|[01]?[0-9][0-9]?))))$'
		if [[ ($yuming =~ $ipv4_pattern || $yuming =~ $ipv6_pattern) ]]; then
			mkdir -p /etc/letsencrypt/live/$yuming/
			if command -v dnf &>/dev/null || command -v yum &>/dev/null; then
				openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -keyout /etc/letsencrypt/live/$yuming/privkey.pem -out /etc/letsencrypt/live/$yuming/fullchain.pem -days 5475 -subj "/C=US/ST=State/L=City/O=Organization/OU=Organizational Unit/CN=Common Name"
			else
				openssl genpkey -algorithm Ed25519 -out /etc/letsencrypt/live/$yuming/privkey.pem
				openssl req -x509 -key /etc/letsencrypt/live/$yuming/privkey.pem -out /etc/letsencrypt/live/$yuming/fullchain.pem -days 5475 -subj "/C=US/ST=State/L=City/O=Organization/OU=Organizational Unit/CN=Common Name"
			fi
		else
			docker run -it --rm -p 80:80 -v /etc/letsencrypt/:/etc/letsencrypt certbot/certbot certonly --standalone -d "$yuming" --email your@email.com --agree-tos --no-eff-email --force-renewal --key-type ecdsa
		fi
	fi
	mkdir -p /home/web/certs/
	cp /etc/letsencrypt/live/$yuming/fullchain.pem /home/web/certs/${yuming}_cert.pem > /dev/null 2>&1
	cp /etc/letsencrypt/live/$yuming/privkey.pem /home/web/certs/${yuming}_key.pem > /dev/null 2>&1

	docker start nginx > /dev/null 2>&1
}


# 证书信息
install_ssltls_text() {
	echo -e "${yellow}$yuming 公钥信息${white}"
	cat /etc/letsencrypt/live/$yuming/fullchain.pem
	echo ""
	echo -e "${yellow}$yuming 私钥信息${white}"
	cat /etc/letsencrypt/live/$yuming/privkey.pem
	echo ""
	echo -e "${yellow}证书存放路径${white}"
	echo "公钥: /etc/letsencrypt/live/$yuming/fullchain.pem"
	echo "私钥: /etc/letsencrypt/live/$yuming/privkey.pem"
	echo ""
}

# 添加SSL证书
add_ssl() {
	echo -e "${yellow}快速申请SSL证书，过期前自动续签${white}"
	yuming="${1:-}"
	if [ -z "$yuming" ]; then
		add_yuming
	fi
	install_docker
	install_certbot
	docker run -it --rm -v /etc/letsencrypt/:/etc/letsencrypt certbot/certbot delete --cert-name "$yuming" -n 2>/dev/null
	install_ssltls
	certs_status
	install_ssltls_text
	ssl_ps
}

# 证书到期情况
ssl_ps() {
	echo -e "${yellow}已申请的证书到期情况${white}"
	echo "站点信息                      证书到期时间"
	echo "------------------------"
	for cert_dir in /etc/letsencrypt/live/*; do
		local cert_file="$cert_dir/fullchain.pem"
		if [ -f "$cert_file" ]; then
			local domain=$(basename "$cert_dir")
			local expire_date=$(openssl x509 -noout -enddate -in "$cert_file" | awk -F'=' '{print $2}')
			local formatted_date=$(date -d "$expire_date" '+%Y-%m-%d')
			printf "%-30s%s\n" "$domain" "$formatted_date"
		fi
	done
	echo ""
}



# 默认服务器 SSL
default_server_ssl() {
	install openssl
	if command -v dnf &>/dev/null || command -v yum &>/dev/null; then
		openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -keyout /home/web/certs/default_server.key -out /home/web/certs/default_server.crt -days 5475 -subj "/C=US/ST=State/L=City/O=Organization/OU=Organizational Unit/CN=Common Name"
	else
		openssl genpkey -algorithm Ed25519 -out /home/web/certs/default_server.key
		openssl req -x509 -key /home/web/certs/default_server.key -out /home/web/certs/default_server.crt -days 5475 -subj "/C=US/ST=State/L=City/O=Organization/OU=Organizational Unit/CN=Common Name"
	fi
	openssl rand -out /home/web/certs/ticket12.key 48
	openssl rand -out /home/web/certs/ticket13.key 80
}

# 证书状态
certs_status() {
	sleep 1
	local file_path="/etc/letsencrypt/live/$yuming/fullchain.pem"
	if [ -f "$file_path" ]; then
		echo "域名证书申请成功"
	else
		# "域名证书申请失败"
		echo -e "${red}注意: ${white}证书申请失败，请检查以下可能原因并重试："
		echo -e "1. 域名拼写错误 ➠ 请检查域名输入是否正确"
		echo -e "2. DNS解析问题 ➠ 确认域名已正确解析到本服务器IP"
		echo -e "3. 网络配置问题 ➠ 如使用Cloudflare Warp等虚拟网络请暂时关闭"
		echo -e "4. 防火墙限制 ➠ 检查80/443端口是否开放，确保验证可访问"
		echo -e "5. 申请次数超限 ➠ Let's Encrypt有每周限额(5次/域名/周)"
		echo -e "6. 国内备案限制 ➠ 中国大陆环境请确认域名是否备案"
		break_end
		clear
		echo "请再次尝试部署 $webname"
		add_yuming
		install_ssltls
		certs_status
	fi
}

# 重复添加域名
repeat_add_yuming() {
	if [ -e /home/web/conf.d/$yuming.conf ]; then
		# "域名重复使用"
		web_del "${yuming}" > /dev/null 2>&1
	fi
}

# 添加域名
add_yuming() {
	ip_address
	echo -e "先将域名解析到本机IP: ${yellow}$ipv4_address  $ipv6_address${white}"
	read -e -p "请输入你的IP或者解析过的域名: " yuming
}

# 添加数据库
add_db() {
	dbname=$(echo "$yuming" | sed -e 's/[^A-Za-z0-9]/_/g')
	dbname="${dbname}"

	dbrootpasswd=$(grep -oP 'MYSQL_ROOT_PASSWORD:\s*\K.*' /home/web/docker-compose.yml | tr -d '[:space:]')
	dbuse=$(grep -oP 'MYSQL_USER:\s*\K.*' /home/web/docker-compose.yml | tr -d '[:space:]')
	dbusepasswd=$(grep -oP 'MYSQL_PASSWORD:\s*\K.*' /home/web/docker-compose.yml | tr -d '[:space:]')
	docker exec mysql mysql -u root -p"$dbrootpasswd" -e "CREATE DATABASE $dbname; GRANT ALL PRIVILEGES ON $dbname.* TO \"$dbuse\"@\"%\";"
}

# 反向代理
reverse_proxy() {
	ip_address
	wget -O /home/web/conf.d/$yuming.conf ${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/reverse-proxy.conf
	sed -i "s/yuming.com/$yuming/g" /home/web/conf.d/$yuming.conf
	sed -i "s/0.0.0.0/$ipv4_address/g" /home/web/conf.d/$yuming.conf
	sed -i "s|0000|$duankou|g" /home/web/conf.d/$yuming.conf
	nginx_http_on
	docker exec nginx nginx -s reload
}

# 重启 Redis
restart_redis() {
	rm -rf /home/web/redis/*
	docker exec redis redis-cli FLUSHALL > /dev/null 2>&1
	# docker exec -it redis redis-cli CONFIG SET maxmemory 1gb > /dev/null 2>&1
	# docker exec -it redis redis-cli CONFIG SET maxmemory-policy allkeys-lru > /dev/null 2>&1
}


# 重启 LDNMP
restart_ldnmp() {
	restart_redis
	docker exec nginx chown -R nginx:nginx /var/www/html > /dev/null 2>&1
	docker exec nginx mkdir -p /var/cache/nginx/proxy > /dev/null 2>&1
	docker exec nginx mkdir -p /var/cache/nginx/fastcgi > /dev/null 2>&1
	docker exec nginx chown -R nginx:nginx /var/cache/nginx/proxy > /dev/null 2>&1
	docker exec nginx chown -R nginx:nginx /var/cache/nginx/fastcgi > /dev/null 2>&1
	docker exec php chown -R www-data:www-data /var/www/html > /dev/null 2>&1
	docker exec php74 chown -R www-data:www-data /var/www/html > /dev/null 2>&1
	cd /home/web && docker compose restart nginx php php74
}

# 升级 nginx
nginx_upgrade() {
	local ldnmp_pods="nginx"
	cd /home/web/
	docker rm -f $ldnmp_pods > /dev/null 2>&1
	docker images --filter=reference="kjlion/${ldnmp_pods}*" -q | xargs docker rmi > /dev/null 2>&1
	docker images --filter=reference="${ldnmp_pods}*" -q | xargs docker rmi > /dev/null 2>&1
	docker compose up -d --force-recreate $ldnmp_pods
	crontab -l 2>/dev/null | grep -v 'logrotate' | crontab -
	(crontab -l 2>/dev/null; echo '0 2 * * * docker exec nginx apk add logrotate && docker exec nginx logrotate -f /etc/logrotate.conf') | crontab -
	docker exec nginx chown -R nginx:nginx /var/www/html
	docker exec nginx mkdir -p /var/cache/nginx/proxy
	docker exec nginx mkdir -p /var/cache/nginx/fastcgi
	docker exec nginx chown -R nginx:nginx /var/cache/nginx/proxy
	docker exec nginx chown -R nginx:nginx /var/cache/nginx/fastcgi
	docker restart $ldnmp_pods > /dev/null 2>&1

	# "更新$ldnmp_pods"
	echo "更新${ldnmp_pods}完成"
}

# 升级 phpMyAdmin
phpmyadmin_upgrade() {
	local ldnmp_pods="phpmyadmin"
	local docker_port=8877
	local dbuse=$(grep -oP 'MYSQL_USER:\s*\K.*' /home/web/docker-compose.yml | tr -d '[:space:]')
	local dbusepasswd=$(grep -oP 'MYSQL_PASSWORD:\s*\K.*' /home/web/docker-compose.yml | tr -d '[:space:]')

	cd /home/web/
	docker rm -f $ldnmp_pods > /dev/null 2>&1
	docker images --filter=reference="$ldnmp_pods*" -q | xargs docker rmi > /dev/null 2>&1
	curl -sS -O https://raw.githubusercontent.com/kejilion/docker/refs/heads/main/docker-compose.phpmyadmin.yml
	docker compose -f docker-compose.phpmyadmin.yml up -d
	clear
	ip_address

	check_docker_app_ip
	echo "登录信息: "
	echo "用户名: $dbuse"
	echo "密码: $dbusepasswd"
	echo
	# "启动$ldnmp_pods"
}

# 清理 Cloudflare 缓存
cf_purge_cache() {
	local CONFIG_FILE="/home/web/config/cf-purge-cache.txt"
	local API_TOKEN
	local EMAIL
	local ZONE_IDS

	# 检查配置文件是否存在
	if [ -f "$CONFIG_FILE" ]; then
	# 从配置文件读取 API_TOKEN 和 zone_id
	read API_TOKEN EMAIL ZONE_IDS < "$CONFIG_FILE"
	# 将 ZONE_IDS 转换为数组
	ZONE_IDS=($ZONE_IDS)
	else
	# 提示用户是否清理缓存
	read -e -p "需要清理 Cloudflare 的缓存吗？（y/n）: " answer
	if [[ "$answer" == "y" ]]; then
		echo "CF信息保存在$CONFIG_FILE，可以后期修改CF信息"
		read -e -p "请输入你的 API_TOKEN: " API_TOKEN
		read -e -p "请输入你的CF用户名: " EMAIL
		read -e -p "请输入 zone_id（多个用空格分隔）: " -a ZONE_IDS

		mkdir -p /home/web/config/
		echo "$API_TOKEN $EMAIL ${ZONE_IDS[*]}" > "$CONFIG_FILE"
	fi
	fi

	# 循环遍历每个 zone_id 并执行清除缓存命令
	for ZONE_ID in "${ZONE_IDS[@]}"; do
	echo "正在清除缓存 for zone_id: $ZONE_ID"
	curl -X POST "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/purge_cache" \
	-H "X-Auth-Email: $EMAIL" \
	-H "X-Auth-Key: $API_TOKEN" \
	-H "Content-Type: application/json" \
	--data '{"purge_everything":true}'
	done

	echo "缓存清除请求已发送完毕。"
}


# 清理站点缓存
web_cache() {
	# "清理站点缓存"
	cf_purge_cache
	cd /home/web && docker compose restart
	restart_redis
}


# 删除站点数据
web_del() {
	# "删除站点数据"
	yuming_list="${1:-}"
	if [ -z "$yuming_list" ]; then
		read -e -p "删除站点数据，请输入你的域名（多个域名用空格隔开）: " yuming_list
		if [[ -z "$yuming_list" ]]; then
			return
		fi
	fi

	for yuming in $yuming_list; do
		echo "正在删除域名: $yuming"
		rm -r /home/web/html/$yuming > /dev/null 2>&1
		rm /home/web/conf.d/$yuming.conf > /dev/null 2>&1
		rm /home/web/certs/${yuming}_key.pem > /dev/null 2>&1
		rm /home/web/certs/${yuming}_cert.pem > /dev/null 2>&1

		# 将域名转换为数据库名
		dbname=$(echo "$yuming" | sed -e 's/[^A-Za-z0-9]/_/g')
		dbrootpasswd=$(grep -oP 'MYSQL_ROOT_PASSWORD:\s*\K.*' /home/web/docker-compose.yml | tr -d '[:space:]')

		# 删除数据库前检查是否存在，避免报错
		echo "正在删除数据库: $dbname"
		docker exec mysql mysql -u root -p"$dbrootpasswd" -e "DROP DATABASE ${dbname};" > /dev/null 2>&1
	done

	docker exec nginx nginx -s reload
}

# 开启WAF
nginx_waf() {
	local mode=$1
	if ! grep -q "kjlion/nginx:alpine" /home/web/docker-compose.yml; then
		wget -O /home/web/nginx.conf "${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/nginx10.conf"
	fi

	# 根据 mode 参数来决定开启或关闭 WAF
	if [ "$mode" == "on" ]; then
		# 开启 WAF：去掉注释
		sed -i 's|# load_module /etc/nginx/modules/ngx_http_modsecurity_module.so;|load_module /etc/nginx/modules/ngx_http_modsecurity_module.so;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i 's|^\(\s*\)# modsecurity on;|\1modsecurity on;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i 's|^\(\s*\)# modsecurity_rules_file /etc/nginx/modsec/modsecurity.conf;|\1modsecurity_rules_file /etc/nginx/modsec/modsecurity.conf;|' /home/web/nginx.conf > /dev/null 2>&1
	elif [ "$mode" == "off" ]; then
		# 关闭 WAF：加上注释
		sed -i 's|^load_module /etc/nginx/modules/ngx_http_modsecurity_module.so;|# load_module /etc/nginx/modules/ngx_http_modsecurity_module.so;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i 's|^\(\s*\)modsecurity on;|\1# modsecurity on;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i 's|^\(\s*\)modsecurity_rules_file /etc/nginx/modsec/modsecurity.conf;|\1# modsecurity_rules_file /etc/nginx/modsec/modsecurity.conf;|' /home/web/nginx.conf > /dev/null 2>&1
	else
		echo "无效的参数：使用 'on' 或 'off'"
		return 1
	fi

	# 检查 nginx 镜像并根据情况处理
	if grep -q "kjlion/nginx:alpine" /home/web/docker-compose.yml; then
		docker exec nginx nginx -s reload
	else
		sed -i 's|nginx:alpine|kjlion/nginx:alpine|g' /home/web/docker-compose.yml
		nginx_upgrade
	fi
}

# 检查WAF状态
check_waf_status() {
	if grep -q "^\s*#\s*modsecurity on;" /home/web/nginx.conf; then
		waf_status=""
	elif grep -q "modsecurity on;" /home/web/nginx.conf; then
		waf_status=" WAF已开启"
	else
		waf_status=""
	fi
}

# 检查CF模式
check_cf_mode() {
	if [ -f "/path/to/fail2ban/config/fail2ban/action.d/cloudflare-docker.conf" ]; then
		CFmessage=" cf模式已开启"
	else
		CFmessage=""
	fi
}

# 开启HTTP
nginx_http_on() {
	local ipv4_pattern='^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
	local ipv6_pattern='^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|(2[0-4][0-9]|[01]?[0-9][0-9]?))|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|(2[0-4][0-9]|[01]?[0-9][0-9]?))|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|(2[0-4][0-9]|[01]?[0-9][0-9]?))|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|(2[0-4][0-9]|[01]?[0-9][0-9]?))))$'
	if [[ ($yuming =~ $ipv4_pattern || $yuming =~ $ipv6_pattern) ]]; then
		sed -i '/if (\$scheme = http) {/,/}/s/^/#/' /home/web/conf.d/${yuming}.conf
	fi
}

# WP_MEMORY_LIMIT
patch_wp_memory_limit() {
	local MEMORY_LIMIT="${1:-256M}"      # 第一个参数，默认256M
	local MAX_MEMORY_LIMIT="${2:-256M}"  # 第二个参数，默认256M
	local TARGET_DIR="/home/web/html"    # 路径写死

	find "$TARGET_DIR" -type f -name "wp-config.php" | while read -r FILE; do
	# 删除旧定义
	sed -i "/define(['\"]WP_MEMORY_LIMIT['\"].*/d" "$FILE"
	sed -i "/define(['\"]WP_MAX_MEMORY_LIMIT['\"].*/d" "$FILE"

	# 插入新定义，放在含 "Happy publishing" 的行前
	awk -v insert="define('WP_MEMORY_LIMIT', '$MEMORY_LIMIT');\ndefine('WP_MAX_MEMORY_LIMIT', '$MAX_MEMORY_LIMIT');" \
	'
		/Happy publishing/ {
		print insert
		}
		{ print }
	' "$FILE" > "$FILE.tmp" && mv -f "$FILE.tmp" "$FILE"

	echo "[+] Replaced WP_MEMORY_LIMIT in $FILE"
	done
}

# WP_DEBUG
patch_wp_debug() {
	local DEBUG="${1:-false}"           # 第一个参数，默认false
	local DEBUG_DISPLAY="${2:-false}"   # 第二个参数，默认false
	local DEBUG_LOG="${3:-false}"       # 第三个参数，默认false
	local TARGET_DIR="/home/web/html"   # 路径写死

	find "$TARGET_DIR" -type f -name "wp-config.php" | while read -r FILE; do
	# 删除旧定义
	sed -i "/define(['\"]WP_DEBUG['\"].*/d" "$FILE"
	sed -i "/define(['\"]WP_DEBUG_DISPLAY['\"].*/d" "$FILE"
	sed -i "/define(['\"]WP_DEBUG_LOG['\"].*/d" "$FILE"

	# 插入新定义，放在含 "Happy publishing" 的行前
	awk -v insert="define('WP_DEBUG_DISPLAY', $DEBUG_DISPLAY);\ndefine('WP_DEBUG_LOG', $DEBUG_LOG);" \
	'
		/Happy publishing/ {
		print insert
		}
		{ print }
	' "$FILE" > "$FILE.tmp" && mv -f "$FILE.tmp" "$FILE"

	echo "[+] Replaced WP_DEBUG settings in $FILE"
	done
}

# Brotli压缩
nginx_br() {
	local mode=$1

	if ! grep -q "kjlion/nginx:alpine" /home/web/docker-compose.yml; then
		wget -O /home/web/nginx.conf "${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/nginx10.conf"
	fi

	if [ "$mode" == "on" ]; then
		# 开启 Brotli：去掉注释
		sed -i 's|# load_module /etc/nginx/modules/ngx_http_brotli_filter_module.so;|load_module /etc/nginx/modules/ngx_http_brotli_filter_module.so;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i 's|# load_module /etc/nginx/modules/ngx_http_brotli_static_module.so;|load_module /etc/nginx/modules/ngx_http_brotli_static_module.so;|' /home/web/nginx.conf > /dev/null 2>&1

		sed -i 's|^\(\s*\)# brotli on;|\1brotli on;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i 's|^\(\s*\)# brotli_static on;|\1brotli_static on;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i 's|^\(\s*\)# brotli_comp_level \(.*\);|\1brotli_comp_level \2;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i 's|^\(\s*\)# brotli_buffers \(.*\);|\1brotli_buffers \2;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i 's|^\(\s*\)# brotli_min_length \(.*\);|\1brotli_min_length \2;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i 's|^\(\s*\)# brotli_window \(.*\);|\1brotli_window \2;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i 's|^\(\s*\)# brotli_types \(.*\);|\1brotli_types \2;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i '/brotli_types/,+6 s/^\(\s*\)#\s*/\1/' /home/web/nginx.conf

	elif [ "$mode" == "off" ]; then
		# 关闭 Brotli：加上注释
		sed -i 's|^load_module /etc/nginx/modules/ngx_http_brotli_filter_module.so;|# load_module /etc/nginx/modules/ngx_http_brotli_filter_module.so;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i 's|^load_module /etc/nginx/modules/ngx_http_brotli_static_module.so;|# load_module /etc/nginx/modules/ngx_http_brotli_static_module.so;|' /home/web/nginx.conf > /dev/null 2>&1

		sed -i 's|^\(\s*\)brotli on;|\1# brotli on;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i 's|^\(\s*\)brotli_static on;|\1# brotli_static on;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i 's|^\(\s*\)brotli_comp_level \(.*\);|\1# brotli_comp_level \2;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i 's|^\(\s*\)brotli_buffers \(.*\);|\1# brotli_buffers \2;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i 's|^\(\s*\)brotli_min_length \(.*\);|\1# brotli_min_length \2;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i 's|^\(\s*\)brotli_window \(.*\);|\1# brotli_window \2;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i 's|^\(\s*\)brotli_types \(.*\);|\1# brotli_types \2;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i '/brotli_types/,+6 {
			/^[[:space:]]*[^#[:space:]]/ s/^\(\s*\)/\1# /
		}' /home/web/nginx.conf

	else
		echo "无效的参数：使用 'on' 或 'off'"
		return 1
	fi

	# 检查 nginx 镜像并根据情况处理
	if grep -q "kjlion/nginx:alpine" /home/web/docker-compose.yml; then
		docker exec nginx nginx -s reload
	else
		sed -i 's|nginx:alpine|kjlion/nginx:alpine|g' /home/web/docker-compose.yml
		nginx_upgrade
	fi
}

# Zstd压缩
nginx_zstd() {
	local mode=$1
	if ! grep -q "kjlion/nginx:alpine" /home/web/docker-compose.yml; then
		wget -O /home/web/nginx.conf "${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/nginx10.conf"
	fi

	if [ "$mode" == "on" ]; then
		# 开启 Zstd：去掉注释
		sed -i 's|# load_module /etc/nginx/modules/ngx_http_zstd_filter_module.so;|load_module /etc/nginx/modules/ngx_http_zstd_filter_module.so;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i 's|# load_module /etc/nginx/modules/ngx_http_zstd_static_module.so;|load_module /etc/nginx/modules/ngx_http_zstd_static_module.so;|' /home/web/nginx.conf > /dev/null 2>&1

		sed -i 's|^\(\s*\)# zstd on;|\1zstd on;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i 's|^\(\s*\)# zstd_static on;|\1zstd_static on;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i 's|^\(\s*\)# zstd_comp_level \(.*\);|\1zstd_comp_level \2;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i 's|^\(\s*\)# zstd_buffers \(.*\);|\1zstd_buffers \2;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i 's|^\(\s*\)# zstd_min_length \(.*\);|\1zstd_min_length \2;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i 's|^\(\s*\)# zstd_types \(.*\);|\1zstd_types \2;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i '/zstd_types/,+6 s/^\(\s*\)#\s*/\1/' /home/web/nginx.conf

	elif [ "$mode" == "off" ]; then
		# 关闭 Zstd：加上注释
		sed -i 's|^load_module /etc/nginx/modules/ngx_http_zstd_filter_module.so;|# load_module /etc/nginx/modules/ngx_http_zstd_filter_module.so;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i 's|^load_module /etc/nginx/modules/ngx_http_zstd_static_module.so;|# load_module /etc/nginx/modules/ngx_http_zstd_static_module.so;|' /home/web/nginx.conf > /dev/null 2>&1

		sed -i 's|^\(\s*\)zstd on;|\1# zstd on;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i 's|^\(\s*\)zstd_static on;|\1# zstd_static on;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i 's|^\(\s*\)zstd_comp_level \(.*\);|\1# zstd_comp_level \2;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i 's|^\(\s*\)zstd_buffers \(.*\);|\1# zstd_buffers \2;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i 's|^\(\s*\)zstd_min_length \(.*\);|\1# zstd_min_length \2;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i 's|^\(\s*\)zstd_types \(.*\);|\1# zstd_types \2;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i '/zstd_types/,+6 {
			/^[[:space:]]*[^#[:space:]]/ s/^\(\s*\)/\1# /
		}' /home/web/nginx.conf

	else
		echo "无效的参数：使用 'on' 或 'off'"
		return 1
	fi

	# 检查 nginx 镜像并根据情况处理
	if grep -q "kjlion/nginx:alpine" /home/web/docker-compose.yml; then
		docker exec nginx nginx -s reload
	else
		sed -i 's|nginx:alpine|kjlion/nginx:alpine|g' /home/web/docker-compose.yml
		nginx_upgrade
	fi
}

# Gzip压缩
nginx_gzip() {
	local mode=$1
	if [ "$mode" == "on" ]; then
		sed -i 's|^\(\s*\)# gzip on;|\1gzip on;|' /home/web/nginx.conf > /dev/null 2>&1
	elif [ "$mode" == "off" ]; then
		sed -i 's|^\(\s*\)gzip on;|\1# gzip on;|' /home/web/nginx.conf > /dev/null 2>&1
	else
		echo "无效的参数：使用 'on' 或 'off'"
		return 1
	fi

	docker exec nginx nginx -s reload
}

# Fail2Ban状态
f2b_status() {
	docker exec -it fail2ban fail2ban-client reload
	sleep 3
	docker exec -it fail2ban fail2ban-client status
}

f2b_status_xxx() {
	docker exec -it fail2ban fail2ban-client status $xxx
}

# SSHD安装
f2b_install_sshd() {

	docker run -d \
		--name=fail2ban \
		--net=host \
		--cap-add=NET_ADMIN \
		--cap-add=NET_RAW \
		-e PUID=1000 \
		-e PGID=1000 \
		-e TZ=Etc/UTC \
		-e VERBOSITY=-vv \
		-v /path/to/fail2ban/config:/config \
		-v /var/log:/var/log:ro \
		-v /home/web/log/nginx/:/remotelogs/nginx:ro \
		--restart unless-stopped \
		lscr.io/linuxserver/fail2ban:latest

	sleep 3
	if grep -q 'Alpine' /etc/issue; then
		cd /path/to/fail2ban/config/fail2ban/filter.d
		curl -sS -O ${gh_proxy}raw.githubusercontent.com/kejilion/config/main/fail2ban/alpine-sshd.conf
		curl -sS -O ${gh_proxy}raw.githubusercontent.com/kejilion/config/main/fail2ban/alpine-sshd-ddos.conf
		cd /path/to/fail2ban/config/fail2ban/jail.d/
		curl -sS -O ${gh_proxy}raw.githubusercontent.com/kejilion/config/main/fail2ban/alpine-ssh.conf
	elif command -v dnf &>/dev/null; then
		cd /path/to/fail2ban/config/fail2ban/jail.d/
		curl -sS -O ${gh_proxy}raw.githubusercontent.com/kejilion/config/main/fail2ban/centos-ssh.conf
	else
		install rsyslog
		systemctl start rsyslog
		systemctl enable rsyslog
		cd /path/to/fail2ban/config/fail2ban/jail.d/
		curl -sS -O ${gh_proxy}raw.githubusercontent.com/kejilion/config/main/fail2ban/linux-ssh.conf
		systemctl restart rsyslog
	fi

	rm -f /path/to/fail2ban/config/fail2ban/jail.d/sshd.conf
}

# SSHD状态
f2b_sshd() {
	if grep -q 'Alpine' /etc/issue; then
		xxx=alpine-sshd
		f2b_status_xxx
	else
		xxx=sshd
		f2b_status_xxx
	fi
}

# 网络安全
web_security() {
	# "LDNMP环境防御"
	while true; do
	check_waf_status
	check_cf_mode
	if [ -x "$(command -v fail2ban-client)" ] ; then
		clear
		remove fail2ban
		rm -rf /etc/fail2ban
	else
			clear
			rm -f /path/to/fail2ban/config/fail2ban/jail.d/sshd.conf > /dev/null 2>&1
			docker exec -it fail2ban fail2ban-client reload > /dev/null 2>&1
			docker_name="fail2ban"
			check_docker_app
			echo -e "服务器网站防御程序 ${check_docker}${green}${CFmessage}${waf_status}${white}"
			echo "------------------------"
			echo "1. 安装防御程序"
			echo "------------------------"
			echo "5. 查看SSH拦截记录                6. 查看网站拦截记录"
			echo "7. 查看防御规则列表               8. 查看日志实时监控"
			echo "------------------------"
			echo "11. 配置拦截参数                  12. 清除所有拉黑的IP"
			echo "------------------------"
			echo "21. cloudflare模式                22. 高负载开启5秒盾"
			echo "------------------------"
			echo "31. 开启WAF                       32. 关闭WAF"
			echo "33. 开启DDOS防御                  34. 关闭DDOS防御"
			echo "------------------------"
			echo "9. 卸载防御程序"
			echo "------------------------"
			echo "0. 返回上一级选单"
			echo "------------------------"
			read -e -p "请输入你的选择: " sub_choice
			case $sub_choice in
				1)
					f2b_install_sshd
					cd /path/to/fail2ban/config/fail2ban/filter.d
					curl -sS -O ${gh_proxy}raw.githubusercontent.com/kejilion/sh/main/fail2ban-nginx-cc.conf
					cd /path/to/fail2ban/config/fail2ban/jail.d/
					curl -sS -O ${gh_proxy}raw.githubusercontent.com/kejilion/config/main/fail2ban/nginx-docker-cc.conf
					sed -i "/cloudflare/d" /path/to/fail2ban/config/fail2ban/jail.d/nginx-docker-cc.conf
					f2b_status
					;;
				5)
					echo "------------------------"
					f2b_sshd
					echo "------------------------"
					;;
				6)

					echo "------------------------"
					local xxx="fail2ban-nginx-cc"
					f2b_status_xxx
					echo "------------------------"
					local xxx="docker-nginx-418"
					f2b_status_xxx
					echo "------------------------"
					local xxx="docker-nginx-bad-request"
					f2b_status_xxx
					echo "------------------------"
					local xxx="docker-nginx-badbots"
					f2b_status_xxx
					echo "------------------------"
					local xxx="docker-nginx-botsearch"
					f2b_status_xxx
					echo "------------------------"
					local xxx="docker-nginx-deny"
					f2b_status_xxx
					echo "------------------------"
					local xxx="docker-nginx-http-auth"
					f2b_status_xxx
					echo "------------------------"
					local xxx="docker-nginx-unauthorized"
					f2b_status_xxx
					echo "------------------------"
					local xxx="docker-php-url-fopen"
					f2b_status_xxx
					echo "------------------------"

					;;

				7)
					docker exec -it fail2ban fail2ban-client status
					;;
				8)
					tail -f /path/to/fail2ban/config/log/fail2ban/fail2ban.log

					;;
				9)
					docker rm -f fail2ban
					rm -rf /path/to/fail2ban
					crontab -l | grep -v "CF-Under-Attack.sh" | crontab - 2>/dev/null
					echo "Fail2Ban防御程序已卸载"
					;;

				11)
					install nano
					nano /path/to/fail2ban/config/fail2ban/jail.d/nginx-docker-cc.conf
					f2b_status
					break
					;;

				12)
					docker exec -it fail2ban fail2ban-client unban --all
					;;

				21)
					# "cloudflare模式"
					echo "到cf后台右上角我的个人资料，选择左侧API令牌，获取Global API Key"
					echo "https://dash.cloudflare.com/login"
					read -e -p "输入CF的账号: " cfuser
					read -e -p "输入CF的Global API Key: " cftoken

					wget -O /home/web/conf.d/default.conf ${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/default11.conf
					docker exec nginx nginx -s reload

					cd /path/to/fail2ban/config/fail2ban/jail.d/
					curl -sS -O ${gh_proxy}raw.githubusercontent.com/kejilion/config/main/fail2ban/nginx-docker-cc.conf

					cd /path/to/fail2ban/config/fail2ban/action.d
					curl -sS -O ${gh_proxy}raw.githubusercontent.com/kejilion/config/main/fail2ban/cloudflare-docker.conf

					sed -i "s/kejilion@outlook.com/$cfuser/g" /path/to/fail2ban/config/fail2ban/action.d/cloudflare-docker.conf
					sed -i "s/APIKEY00000/$cftoken/g" /path/to/fail2ban/config/fail2ban/action.d/cloudflare-docker.conf
					f2b_status

					echo "已配置cloudflare模式，可在cf后台，站点-安全性-事件中查看拦截记录"
					;;

				22)
					# "高负载开启5秒盾"
					echo -e "${yellow}网站每5分钟自动检测，当达检测到高负载会自动开盾，低负载也会自动关闭5秒盾。${white}"
					echo "--------------"
					echo "获取CF参数: "
					echo -e "到cf后台右上角我的个人资料，选择左侧API令牌，获取${yellow}Global API Key${white}"
					echo -e "到cf后台域名概要页面右下方获取${yellow}区域ID${white}"
					echo "https://dash.cloudflare.com/login"
					echo "--------------"
					read -e -p "输入CF的账号: " cfuser
					read -e -p "输入CF的Global API Key: " cftoken
					read -e -p "输入CF中域名的区域ID: " cfzonID

					cd ~
					install jq bc
					check_crontab_installed
					curl -sS -O ${gh_proxy}raw.githubusercontent.com/kejilion/sh/main/CF-Under-Attack.sh
					chmod +x CF-Under-Attack.sh
					sed -i "s/AAAA/$cfuser/g" ~/CF-Under-Attack.sh
					sed -i "s/BBBB/$cftoken/g" ~/CF-Under-Attack.sh
					sed -i "s/CCCC/$cfzonID/g" ~/CF-Under-Attack.sh

					local cron_job="*/5 * * * * ~/CF-Under-Attack.sh"

					local existing_cron=$(crontab -l 2>/dev/null | grep -F "$cron_job")

					if [ -z "$existing_cron" ]; then
						(crontab -l 2>/dev/null; echo "$cron_job") | crontab -
						echo "高负载自动开盾脚本已添加"
					else
						echo "自动开盾脚本已存在，无需添加"
					fi

					;;

				31)
					nginx_waf on
					echo "站点WAF已开启"
					# "站点WAF已开启"
					;;

				32)
					nginx_waf off
					echo "站点WAF已关闭"
					# "站点WAF已关闭"
					;;

				33)
					enable_ddos_defense
					;;

				34)
					disable_ddos_defense
					;;

				*)
					break
					;;
			esac
	fi
	break_end
	done
}

# 打开iptables
iptables_open() {
	install iptables
	save_iptables_rules
	iptables -P INPUT ACCEPT
	iptables -P FORWARD ACCEPT
	iptables -P OUTPUT ACCEPT
	iptables -F

	ip6tables -P INPUT ACCEPT
	ip6tables -P FORWARD ACCEPT
	ip6tables -P OUTPUT ACCEPT
	ip6tables -F

}


open_port() {
	local ports=($@)  # 将传入的参数转换为数组
	if [ ${#ports[@]} -eq 0 ]; then
		echo "请提供至少一个端口号"
		return 1
	fi

	install iptables

	for port in "${ports[@]}"; do
		# 删除已存在的关闭规则
		iptables -D INPUT -p tcp --dport $port -j DROP 2>/dev/null
		iptables -D INPUT -p udp --dport $port -j DROP 2>/dev/null

		# 添加打开规则
		if ! iptables -C INPUT -p tcp --dport $port -j ACCEPT 2>/dev/null; then
			iptables -I INPUT 1 -p tcp --dport $port -j ACCEPT
		fi

		if ! iptables -C INPUT -p udp --dport $port -j ACCEPT 2>/dev/null; then
			iptables -I INPUT 1 -p udp --dport $port -j ACCEPT
			echo "已打开端口 $port"
		fi
	done

	save_iptables_rules
	# "已打开端口"
}


close_port() {
	local ports=($@)  # 将传入的参数转换为数组
	if [ ${#ports[@]} -eq 0 ]; then
		echo "请提供至少一个端口号"
		return 1
	fi

	install iptables

	for port in "${ports[@]}"; do
		# 删除已存在的打开规则
		iptables -D INPUT -p tcp --dport $port -j ACCEPT 2>/dev/null
		iptables -D INPUT -p udp --dport $port -j ACCEPT 2>/dev/null

		# 添加关闭规则
		if ! iptables -C INPUT -p tcp --dport $port -j DROP 2>/dev/null; then
			iptables -I INPUT 1 -p tcp --dport $port -j DROP
		fi

		if ! iptables -C INPUT -p udp --dport $port -j DROP 2>/dev/null; then
			iptables -I INPUT 1 -p udp --dport $port -j DROP
			echo "已关闭端口 $port"
		fi
	done

	# 删除已存在的规则（如果有）
	iptables -D INPUT -i lo -j ACCEPT 2>/dev/null
	iptables -D FORWARD -i lo -j ACCEPT 2>/dev/null

	# 插入新规则到第一条
	iptables -I INPUT 1 -i lo -j ACCEPT
	iptables -I FORWARD 1 -i lo -j ACCEPT

	save_iptables_rules
	# "已关闭端口"
}


allow_ip() {
	local ips=($@)  # 将传入的参数转换为数组
	if [ ${#ips[@]} -eq 0 ]; then
		echo "请提供至少一个IP地址或IP段"
		return 1
	fi

	install iptables

	for ip in "${ips[@]}"; do
		# 删除已存在的阻止规则
		iptables -D INPUT -s $ip -j DROP 2>/dev/null

		# 添加允许规则
		if ! iptables -C INPUT -s $ip -j ACCEPT 2>/dev/null; then
			iptables -I INPUT 1 -s $ip -j ACCEPT
			echo "已放行IP $ip"
		fi
	done

	save_iptables_rules
	# "已放行IP"
}

block_ip() {
	local ips=($@)  # 将传入的参数转换为数组
	if [ ${#ips[@]} -eq 0 ]; then
		echo "请提供至少一个IP地址或IP段"
		return 1
	fi

	install iptables

	for ip in "${ips[@]}"; do
		# 删除已存在的允许规则
		iptables -D INPUT -s $ip -j ACCEPT 2>/dev/null

		# 添加阻止规则
		if ! iptables -C INPUT -s $ip -j DROP 2>/dev/null; then
			iptables -I INPUT 1 -s $ip -j DROP
			echo "已阻止IP $ip"
		fi
	done

	save_iptables_rules
	# "已阻止IP"
}

# 检查nginx模式
check_nginx_mode() {

	CONFIG_FILE="/home/web/nginx.conf"

	# 获取当前的 worker_processes 设置值
	current_value=$(grep -E '^\s*worker_processes\s+[0-9]+;' "$CONFIG_FILE" | awk '{print $2}' | tr -d ';')

	# 根据值设置模式信息
	if [ "$current_value" = "8" ]; then
		mode_info=" 高性能模式"
	else
		mode_info=" 标准模式"
	fi
}

# 检查nginx压缩设置
check_nginx_compression() {

	CONFIG_FILE="/home/web/nginx.conf"

	# 检查 zstd 是否开启且未被注释（整行以 zstd on; 开头）
	if grep -qE '^\s*zstd\s+on;' "$CONFIG_FILE"; then
		zstd_status=" zstd压缩已开启"
	else
		zstd_status=""
	fi

	# 检查 brotli 是否开启且未被注释
	if grep -qE '^\s*brotli\s+on;' "$CONFIG_FILE"; then
		br_status=" br压缩已开启"
	else
		br_status=""
	fi

	# 检查 gzip 是否开启且未被注释
	if grep -qE '^\s*gzip\s+on;' "$CONFIG_FILE"; then
		gzip_status=" gzip压缩已开启"
	else
		gzip_status=""
	fi
}

# 网站搭建优化函数
optimize_web_server() {
	echo -e "${gl_lv}切换到网站搭建优化模式...${gl_bai}"

	echo -e "${gl_lv}优化文件描述符...${gl_bai}"
	ulimit -n 65535

	echo -e "${gl_lv}优化虚拟内存...${gl_bai}"
	sysctl -w vm.swappiness=10 2>/dev/null
	sysctl -w vm.dirty_ratio=20 2>/dev/null
	sysctl -w vm.dirty_background_ratio=10 2>/dev/null
	sysctl -w vm.overcommit_memory=1 2>/dev/null
	sysctl -w vm.min_free_kbytes=65536 2>/dev/null

	echo -e "${gl_lv}优化网络设置...${gl_bai}"
	sysctl -w net.core.rmem_max=16777216 2>/dev/null
	sysctl -w net.core.wmem_max=16777216 2>/dev/null
	sysctl -w net.core.netdev_max_backlog=5000 2>/dev/null
	sysctl -w net.core.somaxconn=4096 2>/dev/null
	sysctl -w net.ipv4.tcp_rmem='4096 87380 16777216' 2>/dev/null
	sysctl -w net.ipv4.tcp_wmem='4096 65536 16777216' 2>/dev/null
	sysctl -w net.ipv4.tcp_congestion_control=bbr 2>/dev/null
	sysctl -w net.ipv4.tcp_max_syn_backlog=8192 2>/dev/null
	sysctl -w net.ipv4.tcp_tw_reuse=1 2>/dev/null
	sysctl -w net.ipv4.ip_local_port_range='1024 65535' 2>/dev/null

	echo -e "${gl_lv}优化缓存管理...${gl_bai}"
	sysctl -w vm.vfs_cache_pressure=50 2>/dev/null

	echo -e "${gl_lv}优化CPU设置...${gl_bai}"
	sysctl -w kernel.sched_autogroup_enabled=0 2>/dev/null

	echo -e "${gl_lv}其他优化...${gl_bai}"
	# 禁用透明大页面，减少延迟
	echo never > /sys/kernel/mm/transparent_hugepage/enabled
	# 禁用 NUMA balancing
	sysctl -w kernel.numa_balancing=0 2>/dev/null
}

# 均衡模式优化函数
optimize_balanced() {
	echo -e "${gl_lv}切换到均衡模式...${gl_bai}"

	echo -e "${gl_lv}优化文件描述符...${gl_bai}"
	ulimit -n 32768

	echo -e "${gl_lv}优化虚拟内存...${gl_bai}"
	sysctl -w vm.swappiness=30 2>/dev/null
	sysctl -w vm.dirty_ratio=20 2>/dev/null
	sysctl -w vm.dirty_background_ratio=10 2>/dev/null
	sysctl -w vm.overcommit_memory=0 2>/dev/null
	sysctl -w vm.min_free_kbytes=32768 2>/dev/null

	echo -e "${gl_lv}优化网络设置...${gl_bai}"
	sysctl -w net.core.rmem_max=8388608 2>/dev/null
	sysctl -w net.core.wmem_max=8388608 2>/dev/null
	sysctl -w net.core.netdev_max_backlog=125000 2>/dev/null
	sysctl -w net.core.somaxconn=2048 2>/dev/null
	sysctl -w net.ipv4.tcp_rmem='4096 87380 8388608' 2>/dev/null
	sysctl -w net.ipv4.tcp_wmem='4096 32768 8388608' 2>/dev/null
	sysctl -w net.ipv4.tcp_congestion_control=bbr 2>/dev/null
	sysctl -w net.ipv4.tcp_max_syn_backlog=4096 2>/dev/null
	sysctl -w net.ipv4.tcp_tw_reuse=1 2>/dev/null
	sysctl -w net.ipv4.ip_local_port_range='1024 49151' 2>/dev/null

	echo -e "${gl_lv}优化缓存管理...${gl_bai}"
	sysctl -w vm.vfs_cache_pressure=75 2>/dev/null

	echo -e "${gl_lv}优化CPU设置...${gl_bai}"
	sysctl -w kernel.sched_autogroup_enabled=1 2>/dev/null

	echo -e "${gl_lv}其他优化...${gl_bai}"
	# 还原透明大页面
	echo always > /sys/kernel/mm/transparent_hugepage/enabled
	# 还原 NUMA balancing
	sysctl -w kernel.numa_balancing=1 2>/dev/null
}

# 网站优化
web_optimization() {
	while true; do
		check_nginx_mode
		check_nginx_compression
		clear
		# "优化LDNMP环境"
		echo -e "优化LDNMP环境${green}${mode_info}${gzip_status}${br_status}${zstd_status}${white}"
		echo "------------------------"
		echo "1. 标准模式              2. 高性能模式 (推荐2H4G以上)"
		echo "------------------------"
		echo "3. 开启gzip压缩          4. 关闭gzip压缩"
		echo "5. 开启br压缩            6. 关闭br压缩"
		echo "7. 开启zstd压缩          8. 关闭zstd压缩"
		echo "------------------------"
		echo "0. 返回上一级选单"
		echo "------------------------"
		read -e -p "请输入你的选择: " sub_choice
		case $sub_choice in
			1)
			# "站点标准模式"

			# nginx调优
			sed -i 's/worker_connections.*/worker_connections 10240;/' /home/web/nginx.conf
			sed -i 's/worker_processes.*/worker_processes 4;/' /home/web/nginx.conf

			# php调优
			wget -O /home/optimized_php.ini ${gh_proxy}raw.githubusercontent.com/kejilion/sh/main/optimized_php.ini
			docker cp /home/optimized_php.ini php:/usr/local/etc/php/conf.d/optimized_php.ini
			docker cp /home/optimized_php.ini php74:/usr/local/etc/php/conf.d/optimized_php.ini
			rm -rf /home/optimized_php.ini

			# php调优
			wget -O /home/www.conf ${gh_proxy}raw.githubusercontent.com/kejilion/sh/main/www-1.conf
			docker cp /home/www.conf php:/usr/local/etc/php-fpm.d/www.conf
			docker cp /home/www.conf php74:/usr/local/etc/php-fpm.d/www.conf
			rm -rf /home/www.conf

			patch_wp_memory_limit
			patch_wp_debug

			fix_phpfpm_conf php
			fix_phpfpm_conf php74

			# mysql调优
			wget -O /home/custom_mysql_config.cnf ${gh_proxy}raw.githubusercontent.com/kejilion/sh/main/custom_mysql_config-1.cnf
			docker cp /home/custom_mysql_config.cnf mysql:/etc/mysql/conf.d/
			rm -rf /home/custom_mysql_config.cnf


			cd /home/web && docker compose restart

			restart_redis
			optimize_balanced


			echo "LDNMP环境已设置成 标准模式"

				;;
			2)
			# "站点高性能模式"

			# nginx调优
			sed -i 's/worker_connections.*/worker_connections 20480;/' /home/web/nginx.conf
			sed -i 's/worker_processes.*/worker_processes 8;/' /home/web/nginx.conf

			# php调优
			wget -O /home/optimized_php.ini ${gh_proxy}raw.githubusercontent.com/kejilion/sh/main/optimized_php.ini
			docker cp /home/optimized_php.ini php:/usr/local/etc/php/conf.d/optimized_php.ini
			docker cp /home/optimized_php.ini php74:/usr/local/etc/php/conf.d/optimized_php.ini
			rm -rf /home/optimized_php.ini

			# php调优
			wget -O /home/www.conf ${gh_proxy}raw.githubusercontent.com/kejilion/sh/main/www.conf
			docker cp /home/www.conf php:/usr/local/etc/php-fpm.d/www.conf
			docker cp /home/www.conf php74:/usr/local/etc/php-fpm.d/www.conf
			rm -rf /home/www.conf

			patch_wp_memory_limit 512M 512M
			patch_wp_debug

			fix_phpfpm_conf php
			fix_phpfpm_conf php74

			# mysql调优
			wget -O /home/custom_mysql_config.cnf ${gh_proxy}raw.githubusercontent.com/kejilion/sh/main/custom_mysql_config.cnf
			docker cp /home/custom_mysql_config.cnf mysql:/etc/mysql/conf.d/
			rm -rf /home/custom_mysql_config.cnf

			cd /home/web && docker compose restart

			restart_redis
			optimize_web_server

			echo "LDNMP环境已设置成 高性能模式"

				;;
			3)
			# "nginx_gzip on"
			nginx_gzip on
				;;
			4)
			# "nginx_gzip off"
			nginx_gzip off
				;;
			5)
			# "nginx_br on"
			nginx_br on
				;;
			6)
			# "nginx_br off"
			nginx_br off
				;;
			7)
			# "nginx_zstd on"
			nginx_zstd on
				;;
			8)
			# "nginx_zstd off"
			nginx_zstd off
				;;
			*)
				break
				;;
		esac
		break_end

	done
}

# 网页状态
ldnmp_web_status() {
	root_use
	while true; do
		local cert_count=$(ls /home/web/certs/*_cert.pem 2>/dev/null | wc -l)
		local output="${green}${cert_count}${white}"

		local dbrootpasswd=$(grep -oP 'MYSQL_ROOT_PASSWORD:\s*\K.*' /home/web/docker-compose.yml | tr -d '[:space:]')
		local db_count=$(docker exec mysql mysql -u root -p"$dbrootpasswd" -e "SHOW DATABASES;" 2> /dev/null | grep -Ev "Database|information_schema|mysql|performance_schema|sys" | wc -l)
		local db_output="${green}${db_count}${white}"

		clear
		#  "LDNMP站点管理"
		echo "LDNMP环境"
		echo "------------------------"
		ldnmp_v

		echo -e "站点: ${output}                      证书到期时间"
		echo -e "------------------------"
		for cert_file in /home/web/certs/*_cert.pem; do
			local domain=$(basename "$cert_file" | sed 's/_cert.pem//')
			if [ -n "$domain" ]; then
			local expire_date=$(openssl x509 -noout -enddate -in "$cert_file" | awk -F'=' '{print $2}')
			local formatted_date=$(date -d "$expire_date" '+%Y-%m-%d')
			printf "%-30s%s\n" "$domain" "$formatted_date"
			fi
		done

		echo "------------------------"
		echo ""
		echo -e "数据库: ${db_output}"
		echo -e "------------------------"
		local dbrootpasswd=$(grep -oP 'MYSQL_ROOT_PASSWORD:\s*\K.*' /home/web/docker-compose.yml | tr -d '[:space:]')
		docker exec mysql mysql -u root -p"$dbrootpasswd" -e "SHOW DATABASES;" 2> /dev/null | grep -Ev "Database|information_schema|mysql|performance_schema|sys"

		echo "------------------------"
		echo ""
		echo "站点目录"
		echo "------------------------"
		echo -e "数据 ${grey}/home/web/html${white}     证书 ${grey}/home/web/certs${white}     配置 ${grey}/home/web/conf.d${white}"
		echo "------------------------"
		echo ""
		echo "操作"
		echo "------------------------"
		echo "1.  申请/更新域名证书               2.  更换站点域名"
		echo "3.  清理站点缓存                    4.  创建关联站点"
		echo "5.  查看访问日志                    6.  查看错误日志"
		echo "7.  编辑全局配置                    8.  编辑站点配置"
		echo "9.  管理站点数据库		    10. 查看站点分析报告"
		echo "------------------------"
		echo "20. 删除指定站点数据"
		echo "------------------------"
		echo "0. 返回上一级选单"
		echo "------------------------"
		read -e -p "请输入你的选择: " sub_choice
		case $sub_choice in
			1)
				#  "申请域名证书"
				read -e -p "请输入你的域名: " yuming
				install_certbot
				docker run -it --rm -v /etc/letsencrypt/:/etc/letsencrypt certbot/certbot delete --cert-name "$yuming" -n 2>/dev/null
				install_ssltls
				certs_status

				;;

			2)
				#  "更换站点域名"
				echo -e "${red}强烈建议: ${white}先备份好全站数据再更换站点域名！"
				read -e -p "请输入旧域名: " oddyuming
				read -e -p "请输入新域名: " yuming
				install_certbot
				install_ssltls
				certs_status

				# mysql替换
				add_db

				local odd_dbname=$(echo "$oddyuming" | sed -e 's/[^A-Za-z0-9]/_/g')
				local odd_dbname="${odd_dbname}"

				docker exec mysql mysqldump -u root -p"$dbrootpasswd" $odd_dbname | docker exec -i mysql mysql -u root -p"$dbrootpasswd" $dbname
				docker exec mysql mysql -u root -p"$dbrootpasswd" -e "DROP DATABASE $odd_dbname;"


				local tables=$(docker exec mysql mysql -u root -p"$dbrootpasswd" -D $dbname -e "SHOW TABLES;" | awk '{ if (NR>1) print $1 }')
				for table in $tables; do
					columns=$(docker exec mysql mysql -u root -p"$dbrootpasswd" -D $dbname -e "SHOW COLUMNS FROM $table;" | awk '{ if (NR>1) print $1 }')
					for column in $columns; do
						docker exec mysql mysql -u root -p"$dbrootpasswd" -D $dbname -e "UPDATE $table SET $column = REPLACE($column, '$oddyuming', '$yuming') WHERE $column LIKE '%$oddyuming%';"
					done
				done

				# 网站目录替换
				mv /home/web/html/$oddyuming /home/web/html/$yuming

				find /home/web/html/$yuming -type f -exec sed -i "s/$odd_dbname/$dbname/g" {} +
				find /home/web/html/$yuming -type f -exec sed -i "s/$oddyuming/$yuming/g" {} +

				mv /home/web/conf.d/$oddyuming.conf /home/web/conf.d/$yuming.conf
				sed -i "s/$oddyuming/$yuming/g" /home/web/conf.d/$yuming.conf

				rm /home/web/certs/${oddyuming}_key.pem
				rm /home/web/certs/${oddyuming}_cert.pem

				docker exec nginx nginx -s reload

				;;


			3)
				web_cache
				;;
			4)
				#  "创建关联站点"
				echo -e "为现有的站点再关联一个新域名用于访问"
				read -e -p "请输入现有的域名: " oddyuming
				read -e -p "请输入新域名: " yuming
				install_certbot
				install_ssltls
				certs_status

				cp /home/web/conf.d/$oddyuming.conf /home/web/conf.d/$yuming.conf
				sed -i "s|server_name $oddyuming|server_name $yuming|g" /home/web/conf.d/$yuming.conf
				sed -i "s|/etc/nginx/certs/${oddyuming}_cert.pem|/etc/nginx/certs/${yuming}_cert.pem|g" /home/web/conf.d/$yuming.conf
				sed -i "s|/etc/nginx/certs/${oddyuming}_key.pem|/etc/nginx/certs/${yuming}_key.pem|g" /home/web/conf.d/$yuming.conf

				docker exec nginx nginx -s reload

				;;
			5)
				#  "查看访问日志"
				tail -n 200 /home/web/log/nginx/access.log
				break_end
				;;
			6)
				#  "查看错误日志"
				tail -n 200 /home/web/log/nginx/error.log
				break_end
				;;
			7)
				#  "编辑全局配置"
				install nano
				nano /home/web/nginx.conf
				docker exec nginx nginx -s reload
				;;

			8)
				#  "编辑站点配置"
				read -e -p "编辑站点配置，请输入你要编辑的域名: " yuming
				install nano
				nano /home/web/conf.d/$yuming.conf
				docker exec nginx nginx -s reload
				;;
			9)
				phpmyadmin_upgrade
				break_end
				;;
			10)
				#  "查看站点数据"
				install goaccess
				goaccess --log-format=COMBINED /home/web/log/nginx/access.log
				;;

			20)
				web_del
				docker run -it --rm -v /etc/letsencrypt/:/etc/letsencrypt certbot/certbot delete --cert-name "$yuming" -n 2>/dev/null

				;;
			*)
				break  # 跳出循环，退出菜单
				;;
		esac
	done
}

# 站点信息
ldnmp_tato() {
local cert_count=$(ls /home/web/certs/*_cert.pem 2>/dev/null | wc -l)
local output="${green}${cert_count}${white}"

local dbrootpasswd=$(grep -oP 'MYSQL_ROOT_PASSWORD:\s*\K.*' /home/web/docker-compose.yml 2>/dev/null | tr -d '[:space:]')
if [ -n "$dbrootpasswd" ]; then
	local db_count=$(docker exec mysql mysql -u root -p"$dbrootpasswd" -e "SHOW DATABASES;" 2>/dev/null | grep -Ev "Database|information_schema|mysql|performance_schema|sys" | wc -l)
fi

local db_output="${green}${db_count}${white}"


if command -v docker &>/dev/null; then
	if docker ps --filter "name=nginx" --filter "status=running" | grep -q nginx; then
		echo -e "${yellow}------------------------"
		echo -e "${green}环境已安装${white}  站点: $output  数据库: $db_output"
	fi
fi

}

# 修复PHP-FPM配置
fix_phpfpm_conf() {
	local container_name=$1
	docker exec "$container_name" sh -c "mkdir -p /run/$container_name && chmod 777 /run/$container_name"
	docker exec "$container_name" sh -c "sed -i '1i [global]\\ndaemonize = no' /usr/local/etc/php-fpm.d/www.conf"
	docker exec "$container_name" sh -c "sed -i '/^listen =/d' /usr/local/etc/php-fpm.d/www.conf"
	docker exec "$container_name" sh -c "echo -e '\nlisten = /run/$container_name/php-fpm.sock\nlisten.owner = www-data\nlisten.group = www-data\nlisten.mode = 0777' >> /usr/local/etc/php-fpm.d/www.conf"
	docker exec "$container_name" sh -c "rm -f /usr/local/etc/php-fpm.d/zz-docker.conf"

	find /home/web/conf.d/ -type f -name "*.conf" -exec sed -i "s#fastcgi_pass ${container_name}:9000;#fastcgi_pass unix:/run/${container_name}/php-fpm.sock;#g" {} \;

}

# 检查LDNMP环境安装状态
ldnmp_install_status_one() {

	if docker inspect "php" &>/dev/null; then
		clear
		# "无法再次安装LDNMP环境"
		echo -e "${yellow}提示: ${white}建站环境已安装。无需再次安装！"
		break_end
		linux_ldnmp
	fi
}

# LDNMP环境安装
ldnmp_install_all() {
	cd ~
	# "安装LDNMP环境"
	root_use
	clear
	echo -e "${yellow}LDNMP环境未安装，开始安装LDNMP环境...${white}"
	check_disk_space 3
	check_port
	dependency_check
	install_docker
	install_certbot
	install_ldnmp_conf
	install_ldnmp
}

# Nginx环境安装
nginx_install_all() {
	cd ~
	# "安装nginx环境"
	root_use
	clear
	echo -e "${yellow}nginx未安装，开始安装nginx环境...${white}"
	check_disk_space 1
	check_port
	dependency_check
	install_docker
	install_certbot
	install_ldnmp_conf
	nginx_upgrade
	clear
	local nginx_version=$(docker exec nginx nginx -v 2>&1)
	local nginx_version=$(echo "$nginx_version" | grep -oP "nginx/\K[0-9]+\.[0-9]+\.[0-9]+")
	echo "nginx已安装完成"
	echo -e "当前版本: ${yellow}v$nginx_version${white}"
	echo ""
}

# LDNMP环境检测
ldnmp_install_status() {
	if ! docker inspect "php" &>/dev/null; then
		# "请先安装LDNMP环境"
		ldnmp_install_all
	fi
}

# Nginx环境检测
nginx_install_status() {
	if ! docker inspect "nginx" &>/dev/null; then
		# "请先安装nginx环境"
		nginx_install_all
	fi
}

# 	Web_ON
ldnmp_web_on() {
	clear
	echo "您的 $webname 搭建好了！"
	echo "https://$yuming"
	echo "------------------------"
	echo "$webname 安装信息如下: "
}

# Nginx
nginx_web_on() {
	clear
	echo "您的 $webname 搭建好了！"
	echo "https://$yuming"

}


# WordPress
ldnmp_wp() {
	clear
	# wordpress
	webname="WordPress"
	yuming="${1:-}"
	# "安装$webname"
	echo "开始部署 $webname"
	if [ -z "$yuming" ]; then
		add_yuming
	fi
	repeat_add_yuming
	ldnmp_install_status
	install_ssltls
	certs_status
	add_db
	wget -O /home/web/conf.d/map.conf ${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/map.conf
	wget -O /home/web/conf.d/$yuming.conf ${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/wordpress.com.conf
	sed -i "s/yuming.com/$yuming/g" /home/web/conf.d/$yuming.conf
	nginx_http_on

	cd /home/web/html
	mkdir $yuming
	cd $yuming
	wget -O latest.zip ${gh_proxy}github.com/kejilion/Website_source_code/raw/refs/heads/main/wp-latest.zip
	unzip latest.zip
	rm latest.zip
	echo "define('FS_METHOD', 'direct'); define('WP_REDIS_HOST', 'redis'); define('WP_REDIS_PORT', '6379');" >> /home/web/html/$yuming/wordpress/wp-config-sample.php
	sed -i "s|database_name_here|$dbname|g" /home/web/html/$yuming/wordpress/wp-config-sample.php
	sed -i "s|username_here|$dbuse|g" /home/web/html/$yuming/wordpress/wp-config-sample.php
	sed -i "s|password_here|$dbusepasswd|g" /home/web/html/$yuming/wordpress/wp-config-sample.php
	sed -i "s|localhost|mysql|g" /home/web/html/$yuming/wordpress/wp-config-sample.php
	cp /home/web/html/$yuming/wordpress/wp-config-sample.php /home/web/html/$yuming/wordpress/wp-config.php

	restart_ldnmp
	nginx_web_on
}

# 反向代理-IP+端口
ldnmp_Proxy() {
	clear
	webname="反向代理-IP+端口"
	yuming="${1:-}"
	reverseproxy="${2:-}"
	port="${3:-}"

	# "安装$webname"
	echo "开始部署 $webname"
	if [ -z "$yuming" ]; then
		add_yuming
	fi
	if [ -z "$reverseproxy" ]; then
		read -e -p "请输入你的反代IP: " reverseproxy
	fi

	if [ -z "$port" ]; then
		read -e -p "请输入你的反代端口: " port
	fi
	nginx_install_status
	install_ssltls
	certs_status
	wget -O /home/web/conf.d/map.conf ${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/map.conf
	wget -O /home/web/conf.d/$yuming.conf ${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/reverse-proxy.conf
	sed -i "s/yuming.com/$yuming/g" /home/web/conf.d/$yuming.conf
	sed -i "s/0.0.0.0/$reverseproxy/g" /home/web/conf.d/$yuming.conf
	sed -i "s|0000|$port|g" /home/web/conf.d/$yuming.conf
	nginx_http_on
	docker exec nginx nginx -s reload
	nginx_web_on
}


# 反向代理-负载均衡
ldnmp_Proxy_backend() {
	clear
	webname="反向代理-负载均衡"
	yuming="${1:-}"
	reverseproxy_port="${2:-}"

	# "安装$webname"
	echo "开始部署 $webname"
	if [ -z "$yuming" ]; then
		add_yuming
	fi

	if [ -z "$reverseproxy_port" ]; then
		read -e -p "请输入你的多个反代IP+端口用空格隔开（例如 127.0.0.1:3000 127.0.0.1:3002）： " reverseproxy_port
	fi

	nginx_install_status
	install_ssltls
	certs_status
	wget -O /home/web/conf.d/map.conf ${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/map.conf
	wget -O /home/web/conf.d/$yuming.conf ${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/reverse-proxy-backend.conf

	backend=$(tr -dc 'A-Za-z' < /dev/urandom | head -c 8)
	sed -i "s/backend_yuming_com/backend_$backend/g" /home/web/conf.d/"$yuming".conf


	sed -i "s/yuming.com/$yuming/g" /home/web/conf.d/$yuming.conf

	upstream_servers=""
	for server in $reverseproxy_port; do
		upstream_servers="$upstream_servers    server $server;\n"
	done

	sed -i "s/# 动态添加/$upstream_servers/g" /home/web/conf.d/$yuming.conf

	nginx_http_on
	docker exec nginx nginx -s reload
	nginx_web_on
}


# 查找容器名称
find_container_by_host_port() {
	port="$1"
	docker_name=$(docker ps --format '{{.ID}} {{.Names}}' | while read id name; do
		if docker port "$id" | grep -q ":$port"; then
			echo "$name"
			break
		fi
	done)
}

# 检查端口
check_port() {
	install lsof

	stop_containers_or_kill_process() {
		local port=$1
		local containers=$(docker ps --filter "publish=$port" --format "{{.ID}}" 2>/dev/null)

		if [ -n "$containers" ]; then
			docker stop $containers
		else
			for pid in $(lsof -t -i:$port); do
				kill -9 $pid
			done
		fi
	}

	stop_containers_or_kill_process 80
	stop_containers_or_kill_process 443
}


# LDNMP环境菜单
linux_ldnmp() {
	while true; do
		clear
		# #  "LDNMP建站"
		echo -e "${yellow}LDNMP建站"
		ldnmp_tato
		echo -e "${yellow}------------------------"
		echo -e "${yellow}1.   ${white}安装LDNMP环境 ${yellow}★${white}                   ${yellow}2.   ${white}安装WordPress ${yellow}★${white}"
		echo -e "${yellow}3.   ${white}安装Discuz论坛                    ${yellow}4.   ${white}安装可道云桌面"
		echo -e "${yellow}5.   ${white}安装苹果CMS影视站                 ${yellow}6.   ${white}安装独角数发卡网"
		echo -e "${yellow}7.   ${white}安装flarum论坛网站                ${yellow}8.   ${white}安装typecho轻量博客网站"
		echo -e "${yellow}9.   ${white}安装LinkStack共享链接平台         ${yellow}20.  ${white}自定义动态站点"
		echo -e "${yellow}------------------------"
		echo -e "${yellow}21.  ${white}仅安装nginx ${yellow}★${white}                     ${yellow}22.  ${white}站点重定向"
		echo -e "${yellow}23.  ${white}站点反向代理-IP+端口 ${yellow}★${white}            ${yellow}24.  ${white}站点反向代理-域名"
		echo -e "${yellow}25.  ${white}安装Bitwarden密码管理平台         ${yellow}26.  ${white}安装Halo博客网站"
		echo -e "${yellow}27.  ${white}安装AI绘画提示词生成器            ${yellow}28.  ${white}站点反向代理-负载均衡"
		echo -e "${yellow}30.  ${white}自定义静态站点"
		echo -e "${yellow}------------------------"
		echo -e "${yellow}31.  ${white}站点数据管理 ${yellow}★${white}                    ${yellow}32.  ${white}备份全站数据"
		echo -e "${yellow}33.  ${white}定时远程备份                      ${yellow}34.  ${white}还原全站数据"
		echo -e "${yellow}------------------------"
		echo -e "${yellow}35.  ${white}防护LDNMP环境                     ${yellow}36.  ${white}优化LDNMP环境"
		echo -e "${yellow}37.  ${white}更新LDNMP环境                     ${yellow}38.  ${white}卸载LDNMP环境"
		echo -e "${yellow}------------------------"
		echo -e "${yellow}0.   ${white}返回主菜单"
		echo -e "${yellow}------------------------${white}"
		read -e -p "请输入你的选择: " sub_choice

		case $sub_choice in
		1)
		ldnmp_install_status_one
		ldnmp_install_all
			;;
		2)
		ldnmp_wp
			;;

		3)
		clear
		# Discuz论坛
		webname="Discuz论坛"
		#  "安装$webname"
		echo "开始部署 $webname"
		add_yuming
		repeat_add_yuming
		ldnmp_install_status
		install_ssltls
		certs_status
		add_db
		wget -O /home/web/conf.d/map.conf ${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/map.conf
		wget -O /home/web/conf.d/$yuming.conf ${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/discuz.com.conf
		sed -i "s/yuming.com/$yuming/g" /home/web/conf.d/$yuming.conf
		nginx_http_on

		cd /home/web/html
		mkdir $yuming
		cd $yuming
		wget -O latest.zip ${gh_proxy}github.com/kejilion/Website_source_code/raw/main/Discuz_X3.5_SC_UTF8_20240520.zip
		unzip latest.zip
		rm latest.zip

		restart_ldnmp

		ldnmp_web_on
		echo "数据库地址: mysql"
		echo "数据库名: $dbname"
		echo "用户名: $dbuse"
		echo "密码: $dbusepasswd"
		echo "表前缀: discuz_"


			;;

		4)
		clear
		# 可道云桌面
		webname="可道云桌面"
		#  "安装$webname"
		echo "开始部署 $webname"
		add_yuming
		repeat_add_yuming
		ldnmp_install_status
		install_ssltls
		certs_status
		add_db
		wget -O /home/web/conf.d/map.conf ${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/map.conf
		wget -O /home/web/conf.d/$yuming.conf ${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/kdy.com.conf
		sed -i "s/yuming.com/$yuming/g" /home/web/conf.d/$yuming.conf
		nginx_http_on

		cd /home/web/html
		mkdir $yuming
		cd $yuming
		wget -O latest.zip ${gh_proxy}github.com/kalcaddle/kodbox/archive/refs/tags/1.50.02.zip
		unzip -o latest.zip
		rm latest.zip
		mv /home/web/html/$yuming/kodbox* /home/web/html/$yuming/kodbox
		restart_ldnmp

		ldnmp_web_on
		echo "数据库地址: mysql"
		echo "用户名: $dbuse"
		echo "密码: $dbusepasswd"
		echo "数据库名: $dbname"
		echo "redis主机: redis"

			;;

		5)
		clear
		# 苹果CMS
		webname="苹果CMS"
		#  "安装$webname"
		echo "开始部署 $webname"
		add_yuming
		repeat_add_yuming
		ldnmp_install_status
		install_ssltls
		certs_status
		add_db
		wget -O /home/web/conf.d/map.conf ${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/map.conf
		wget -O /home/web/conf.d/$yuming.conf ${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/maccms.com.conf
		sed -i "s/yuming.com/$yuming/g" /home/web/conf.d/$yuming.conf
		nginx_http_on

		cd /home/web/html
		mkdir $yuming
		cd $yuming
		# wget ${gh_proxy}github.com/magicblack/maccms_down/raw/master/maccms10.zip && unzip maccms10.zip && rm maccms10.zip
		wget ${gh_proxy}github.com/magicblack/maccms_down/raw/master/maccms10.zip && unzip maccms10.zip && mv maccms10-*/* . && rm -r maccms10-* && rm maccms10.zip
		cd /home/web/html/$yuming/template/ && wget ${gh_proxy}github.com/kejilion/Website_source_code/raw/main/DYXS2.zip && unzip DYXS2.zip && rm /home/web/html/$yuming/template/DYXS2.zip
		cp /home/web/html/$yuming/template/DYXS2/asset/admin/Dyxs2.php /home/web/html/$yuming/application/admin/controller
		cp /home/web/html/$yuming/template/DYXS2/asset/admin/dycms.html /home/web/html/$yuming/application/admin/view/system
		mv /home/web/html/$yuming/admin.php /home/web/html/$yuming/vip.php && wget -O /home/web/html/$yuming/application/extra/maccms.php ${gh_proxy}raw.githubusercontent.com/kejilion/Website_source_code/main/maccms.php

		restart_ldnmp

		ldnmp_web_on
		echo "数据库地址: mysql"
		echo "数据库端口: 3306"
		echo "数据库名: $dbname"
		echo "用户名: $dbuse"
		echo "密码: $dbusepasswd"
		echo "数据库前缀: mac_"
		echo "------------------------"
		echo "安装成功后登录后台地址"
		echo "https://$yuming/vip.php"

			;;

		6)
		clear
		# 独脚数卡
		webname="独脚数卡"
		#  "安装$webname"
		echo "开始部署 $webname"
		add_yuming
		repeat_add_yuming
		ldnmp_install_status
		install_ssltls
		certs_status
		add_db
		wget -O /home/web/conf.d/map.conf ${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/map.conf
		wget -O /home/web/conf.d/$yuming.conf ${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/dujiaoka.com.conf
		sed -i "s/yuming.com/$yuming/g" /home/web/conf.d/$yuming.conf
		nginx_http_on

		cd /home/web/html
		mkdir $yuming
		cd $yuming
		wget ${gh_proxy}github.com/assimon/dujiaoka/releases/download/2.0.6/2.0.6-antibody.tar.gz && tar -zxvf 2.0.6-antibody.tar.gz && rm 2.0.6-antibody.tar.gz

		restart_ldnmp

		ldnmp_web_on
		echo "数据库地址: mysql"
		echo "数据库端口: 3306"
		echo "数据库名: $dbname"
		echo "用户名: $dbuse"
		echo "密码: $dbusepasswd"
		echo ""
		echo "redis地址: redis"
		echo "redis密码: 默认不填写"
		echo "redis端口: 6379"
		echo ""
		echo "网站url: https://$yuming"
		echo "后台登录路径: /admin"
		echo "------------------------"
		echo "用户名: admin"
		echo "密码: admin"
		echo "------------------------"
		echo "登录时右上角如果出现红色error0请使用如下命令: "
		echo "我也很气愤独角数卡为啥这么麻烦，会有这样的问题！"
		echo "sed -i 's/ADMIN_HTTPS=false/ADMIN_HTTPS=true/g' /home/web/html/$yuming/dujiaoka/.env"

			;;

		7)
		clear
		# flarum论坛
		webname="flarum论坛"
		#  "安装$webname"
		echo "开始部署 $webname"
		add_yuming
		repeat_add_yuming
		ldnmp_install_status
		install_ssltls
		certs_status
		add_db
		wget -O /home/web/conf.d/map.conf ${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/map.conf
		wget -O /home/web/conf.d/$yuming.conf ${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/flarum.com.conf
		sed -i "s/yuming.com/$yuming/g" /home/web/conf.d/$yuming.conf
		nginx_http_on

		docker exec php rm -f /usr/local/etc/php/conf.d/optimized_php.ini

		cd /home/web/html
		mkdir $yuming
		cd $yuming

		docker exec php sh -c "php -r \"copy('https://getcomposer.org/installer', 'composer-setup.php');\""
		docker exec php sh -c "php composer-setup.php"
		docker exec php sh -c "php -r \"unlink('composer-setup.php');\""
		docker exec php sh -c "mv composer.phar /usr/local/bin/composer"

		docker exec php composer create-project flarum/flarum /var/www/html/$yuming
		docker exec php sh -c "cd /var/www/html/$yuming && composer require flarum-lang/chinese-simplified"
		docker exec php sh -c "cd /var/www/html/$yuming && composer require flarum/extension-manager:*"
		docker exec php sh -c "cd /var/www/html/$yuming && composer require fof/polls"
		docker exec php sh -c "cd /var/www/html/$yuming && composer require fof/sitemap"
		docker exec php sh -c "cd /var/www/html/$yuming && composer require fof/oauth"
		docker exec php sh -c "cd /var/www/html/$yuming && composer require fof/best-answer:*"
		docker exec php sh -c "cd /var/www/html/$yuming && composer require v17development/flarum-seo"
		docker exec php sh -c "cd /var/www/html/$yuming && composer require clarkwinkelmann/flarum-ext-emojionearea"

		restart_ldnmp


		ldnmp_web_on
		echo "数据库地址: mysql"
		echo "数据库名: $dbname"
		echo "用户名: $dbuse"
		echo "密码: $dbusepasswd"
		echo "表前缀: flarum_"
		echo "管理员信息自行设置"

			;;

		8)
		clear
		# typecho
		webname="typecho"
		#  "安装$webname"
		echo "开始部署 $webname"
		add_yuming
		repeat_add_yuming
		ldnmp_install_status
		install_ssltls
		certs_status
		add_db
		wget -O /home/web/conf.d/map.conf ${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/map.conf
		wget -O /home/web/conf.d/$yuming.conf ${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/typecho.com.conf
		sed -i "s/yuming.com/$yuming/g" /home/web/conf.d/$yuming.conf
		nginx_http_on

		cd /home/web/html
		mkdir $yuming
		cd $yuming
		wget -O latest.zip ${gh_proxy}github.com/typecho/typecho/releases/latest/download/typecho.zip
		unzip latest.zip
		rm latest.zip

		restart_ldnmp

		clear
		ldnmp_web_on
		echo "数据库前缀: typecho_"
		echo "数据库地址: mysql"
		echo "用户名: $dbuse"
		echo "密码: $dbusepasswd"
		echo "数据库名: $dbname"

			;;


		9)
		clear
		# LinkStack
		webname="LinkStack"
		#  "安装$webname"
		echo "开始部署 $webname"
		add_yuming
		repeat_add_yuming
		ldnmp_install_status
		install_ssltls
		certs_status
		add_db
		wget -O /home/web/conf.d/map.conf ${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/map.conf
		wget -O /home/web/conf.d/$yuming.conf ${gh_proxy}raw.githubusercontent.com/kejilion/nginx/refs/heads/main/index_php.conf
		sed -i "s|/var/www/html/yuming.com/|/var/www/html/yuming.com/linkstack|g" /home/web/conf.d/$yuming.conf
		sed -i "s|yuming.com|$yuming|g" /home/web/conf.d/$yuming.conf
		nginx_http_on

		cd /home/web/html
		mkdir $yuming
		cd $yuming
		wget -O latest.zip ${gh_proxy}github.com/linkstackorg/linkstack/releases/latest/download/linkstack.zip
		unzip latest.zip
		rm latest.zip

		restart_ldnmp

		clear
		ldnmp_web_on
		echo "数据库地址: mysql"
		echo "数据库端口: 3306"
		echo "数据库名: $dbname"
		echo "用户名: $dbuse"
		echo "密码: $dbusepasswd"
			;;

		20)
		clear
		webname="PHP动态站点"
		#  "安装$webname"
		echo "开始部署 $webname"
		add_yuming
		repeat_add_yuming
		ldnmp_install_status
		install_ssltls
		certs_status
		add_db
		wget -O /home/web/conf.d/map.conf ${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/map.conf
		wget -O /home/web/conf.d/$yuming.conf ${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/index_php.conf
		sed -i "s/yuming.com/$yuming/g" /home/web/conf.d/$yuming.conf
		nginx_http_on

		cd /home/web/html
		mkdir $yuming
		cd $yuming

		clear
		echo -e "[${yellow}1/6${white}] 上传PHP源码"
		echo "-------------"
		echo "目前只允许上传zip格式的源码包，请将源码包放到/home/web/html/${yuming}目录下"
		read -e -p "也可以输入下载链接，远程下载源码包，直接回车将跳过远程下载： " url_download

		if [ -n "$url_download" ]; then
			wget "$url_download"
		fi

		unzip $(ls -t *.zip | head -n 1)
		rm -f $(ls -t *.zip | head -n 1)

		clear
		echo -e "[${yellow}2/6${white}] index.php所在路径"
		echo "-------------"
		# find "$(realpath .)" -name "index.php" -print
		find "$(realpath .)" -name "index.php" -print | xargs -I {} dirname {}

		read -e -p "请输入index.php的路径，类似（/home/web/html/$yuming/wordpress/）： " index_lujing

		sed -i "s#root /var/www/html/$yuming/#root $index_lujing#g" /home/web/conf.d/$yuming.conf
		sed -i "s#/home/web/#/var/www/#g" /home/web/conf.d/$yuming.conf

		clear
		echo -e "[${yellow}3/6${white}] 请选择PHP版本"
		echo "-------------"
		read -e -p "1. php最新版 | 2. php7.4 : " pho_v
		case "$pho_v" in
			1)
			sed -i "s#php:9000#php:9000#g" /home/web/conf.d/$yuming.conf
			local PHP_Version="php"
			;;
			2)
			sed -i "s#php:9000#php74:9000#g" /home/web/conf.d/$yuming.conf
			local PHP_Version="php74"
			;;
			*)
			echo "无效的选择，请重新输入。"
			;;
		esac


		clear
		echo -e "[${yellow}4/6${white}] 安装指定扩展"
		echo "-------------"
		echo "已经安装的扩展"
		docker exec php php -m

		read -e -p "$(echo -e "输入需要安装的扩展名称，如 ${yellow}SourceGuardian imap ftp${white} 等等。直接回车将跳过安装 ： ")" php_extensions
		if [ -n "$php_extensions" ]; then
			docker exec $PHP_Version install-php-extensions $php_extensions
		fi


		clear
		echo -e "[${yellow}5/6${white}] 编辑站点配置"
		echo "-------------"
		echo "按任意键继续，可以详细设置站点配置，如伪静态等内容"
		read -n 1 -s -r -p ""
		install nano
		nano /home/web/conf.d/$yuming.conf


		clear
		echo -e "[${yellow}6/6${white}] 数据库管理"
		echo "-------------"
		read -e -p "1. 我搭建新站        2. 我搭建老站有数据库备份： " use_db
		case $use_db in
			1)
				echo
				;;
			2)
				echo "数据库备份必须是.gz结尾的压缩包。请放到/home/目录下，支持宝塔/1panel备份数据导入。"
				read -e -p "也可以输入下载链接，远程下载备份数据，直接回车将跳过远程下载： " url_download_db

				cd /home/
				if [ -n "$url_download_db" ]; then
					wget "$url_download_db"
				fi
				gunzip $(ls -t *.gz | head -n 1)
				latest_sql=$(ls -t *.sql | head -n 1)
				dbrootpasswd=$(grep -oP 'MYSQL_ROOT_PASSWORD:\s*\K.*' /home/web/docker-compose.yml | tr -d '[:space:]')
				docker exec -i mysql mysql -u root -p"$dbrootpasswd" $dbname < "/home/$latest_sql"
				echo "数据库导入的表数据"
				docker exec -i mysql mysql -u root -p"$dbrootpasswd" -e "USE $dbname; SHOW TABLES;"
				rm -f *.sql
				echo "数据库导入完成"
				;;
			*)
				echo
				;;
		esac

		docker exec php rm -f /usr/local/etc/php/conf.d/optimized_php.ini

		restart_ldnmp
		ldnmp_web_on
		prefix="web$(shuf -i 10-99 -n 1)_"
		echo "数据库地址: mysql"
		echo "数据库名: $dbname"
		echo "用户名: $dbuse"
		echo "密码: $dbusepasswd"
		echo "表前缀: $prefix"
		echo "管理员登录信息自行设置"

			;;


		21)
		ldnmp_install_status_one
		nginx_install_all
			;;

		22)
		clear
		webname="站点重定向"
		#  "安装$webname"
		echo "开始部署 $webname"
		add_yuming
		read -e -p "请输入跳转域名: " reverseproxy
		nginx_install_status
		install_ssltls
		certs_status

		wget -O /home/web/conf.d/$yuming.conf ${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/rewrite.conf
		sed -i "s/yuming.com/$yuming/g" /home/web/conf.d/$yuming.conf
		sed -i "s/baidu.com/$reverseproxy/g" /home/web/conf.d/$yuming.conf
		nginx_http_on

		docker exec nginx nginx -s reload

		nginx_web_on


			;;

		23)
		ldnmp_Proxy
		find_container_by_host_port "$port"
		if [ -z "$docker_name" ]; then
			# 询问用户是否确认阻止访问
			read -p "是否阻止IP+端口访问该服务？[y/N] " confirm
			# 检查用户输入，仅当输入y或Y时执行关闭操作
			if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
				close_port "$port"
				echo "已阻止IP+端口访问该服务"
			else
				echo "完成!"
			fi
		else
			ip_address
			block_container_port "$docker_name" "$ipv4_address"
		fi
			;;

		24)
		clear
		webname="反向代理-域名"
		#  "安装$webname"
		echo "开始部署 $webname"
		add_yuming
		echo -e "域名格式: ${yellow}google.com${white}"
		read -e -p "请输入你的反代域名: " fandai_yuming
		nginx_install_status
		install_ssltls
		certs_status

		wget -O /home/web/conf.d/$yuming.conf ${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/reverse-proxy-domain.conf
		sed -i "s/yuming.com/$yuming/g" /home/web/conf.d/$yuming.conf
		sed -i "s|fandaicom|$fandai_yuming|g" /home/web/conf.d/$yuming.conf
		nginx_http_on

		docker exec nginx nginx -s reload

		nginx_web_on

			;;


		25)
		clear
		webname="Bitwarden"
		#  "安装$webname"
		echo "开始部署 $webname"
		add_yuming
		nginx_install_status
		install_ssltls
		certs_status

		docker run -d \
			--name bitwarden \
			--restart always \
			-p 3280:80 \
			-v /home/web/html/$yuming/bitwarden/data:/data \
			vaultwarden/server
		duankou=3280
		reverse_proxy

		nginx_web_on

			;;

		26)
		clear
		webname="halo"
		#  "安装$webname"
		echo "开始部署 $webname"
		add_yuming
		nginx_install_status
		install_ssltls
		certs_status

		docker run -d --name halo --restart always -p 8010:8090 -v /home/web/html/$yuming/.halo2:/root/.halo2 halohub/halo:2
		duankou=8010
		reverse_proxy

		nginx_web_on

			;;

		27)
		clear
		webname="AI绘画提示词生成器"
		#  "安装$webname"
		echo "开始部署 $webname"
		add_yuming
		nginx_install_status
		install_ssltls
		certs_status

		wget -O /home/web/conf.d/$yuming.conf ${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/html.conf
		sed -i "s/yuming.com/$yuming/g" /home/web/conf.d/$yuming.conf
		nginx_http_on

		cd /home/web/html
		mkdir $yuming
		cd $yuming

		wget ${gh_proxy}github.com/kejilion/Website_source_code/raw/refs/heads/main/ai_prompt_generator.zip
		unzip $(ls -t *.zip | head -n 1)
		rm -f $(ls -t *.zip | head -n 1)

		docker exec nginx chmod -R nginx:nginx /var/www/html
		docker exec nginx nginx -s reload

		nginx_web_on

			;;

		28)
		ldnmp_Proxy_backend
			;;


		30)
		clear
		webname="静态站点"
		#  "安装$webname"
		echo "开始部署 $webname"
		add_yuming
		repeat_add_yuming
		nginx_install_status
		install_ssltls
		certs_status

		wget -O /home/web/conf.d/$yuming.conf ${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/html.conf
		sed -i "s/yuming.com/$yuming/g" /home/web/conf.d/$yuming.conf
		nginx_http_on

		cd /home/web/html
		mkdir $yuming
		cd $yuming


		clear
		echo -e "[${yellow}1/2${white}] 上传静态源码"
		echo "-------------"
		echo "目前只允许上传zip格式的源码包，请将源码包放到/home/web/html/${yuming}目录下"
		read -e -p "也可以输入下载链接，远程下载源码包，直接回车将跳过远程下载： " url_download

		if [ -n "$url_download" ]; then
			wget "$url_download"
		fi

		unzip $(ls -t *.zip | head -n 1)
		rm -f $(ls -t *.zip | head -n 1)

		clear
		echo -e "[${yellow}2/2${white}] index.html所在路径"
		echo "-------------"
		# find "$(realpath .)" -name "index.html" -print
		find "$(realpath .)" -name "index.html" -print | xargs -I {} dirname {}

		read -e -p "请输入index.html的路径，类似（/home/web/html/$yuming/index/）： " index_lujing

		sed -i "s#root /var/www/html/$yuming/#root $index_lujing#g" /home/web/conf.d/$yuming.conf
		sed -i "s#/home/web/#/var/www/#g" /home/web/conf.d/$yuming.conf

		docker exec nginx chmod -R nginx:nginx /var/www/html
		docker exec nginx nginx -s reload

		nginx_web_on

			;;

		31)
		ldnmp_web_status
		;;


		32)
		clear
		#  "LDNMP环境备份"

		local backup_filename="web_$(date +"%Y%m%d%H%M%S").tar.gz"
		echo -e "${yellow}正在备份 $backup_filename ...${white}"
		cd /home/ && tar czvf "$backup_filename" web

		while true; do
			clear
			echo "备份文件已创建: /home/$backup_filename"
			read -e -p "要传送备份数据到远程服务器吗？(Y/N): " choice
			case "$choice" in
			[Yy])
				read -e -p "请输入远端服务器IP:  " remote_ip
				if [ -z "$remote_ip" ]; then
				echo "错误: 请输入远端服务器IP。"
				continue
				fi
				local latest_tar=$(ls -t /home/*.tar.gz | head -1)
				if [ -n "$latest_tar" ]; then
				ssh-keygen -f "/root/.ssh/known_hosts" -R "$remote_ip"
				sleep 2  # 添加等待时间
				scp -o StrictHostKeyChecking=no "$latest_tar" "root@$remote_ip:/home/"
				echo "文件已传送至远程服务器home目录。"
				else
				echo "未找到要传送的文件。"
				fi
				break
				;;
			[Nn])
				break
				;;
			*)
				echo "无效的选择，请输入 Y 或 N。"
				;;
			esac
		done
		;;

		33)
		clear
		#  "定时远程备份"
		read -e -p "输入远程服务器IP: " useip
		read -e -p "输入远程服务器密码: " usepasswd

		cd ~
		wget -O ${useip}_beifen.sh ${gh_proxy}raw.githubusercontent.com/kejilion/sh/main/beifen.sh > /dev/null 2>&1
		chmod +x ${useip}_beifen.sh

		sed -i "s/0.0.0.0/$useip/g" ${useip}_beifen.sh
		sed -i "s/123456/$usepasswd/g" ${useip}_beifen.sh

		echo "------------------------"
		echo "1. 每周备份                 2. 每天备份"
		read -e -p "请输入你的选择: " dingshi

		case $dingshi in
			1)
				check_crontab_installed
				read -e -p "选择每周备份的星期几 (0-6，0代表星期日): " weekday
				(crontab -l ; echo "0 0 * * $weekday ./${useip}_beifen.sh") | crontab - > /dev/null 2>&1
				;;
			2)
				check_crontab_installed
				read -e -p "选择每天备份的时间（小时，0-23）: " hour
				(crontab -l ; echo "0 $hour * * * ./${useip}_beifen.sh") | crontab - > /dev/null 2>&1
				;;
			*)
				break  # 跳出
				;;
		esac

		install sshpass

		;;

		34)
		root_use
		#  "LDNMP环境还原"
		echo "可用的站点备份"
		echo "-------------------------"
		ls -lt /home/*.gz | awk '{print $NF}'
		echo ""
		read -e -p  "回车键还原最新的备份,输入备份文件名还原指定的备份，输入0退出：" filename

		if [ "$filename" == "0" ]; then
			break_end
			linux_ldnmp
		fi

		# 如果用户没有输入文件名，使用最新的压缩包
		if [ -z "$filename" ]; then
			local filename=$(ls -t /home/*.tar.gz | head -1)
		fi

		if [ -n "$filename" ]; then
			cd /home/web/ > /dev/null 2>&1
			docker compose down > /dev/null 2>&1
			rm -rf /home/web > /dev/null 2>&1

			echo -e "${yellow}正在解压 $filename ...${white}"
			cd /home/ && tar -xzf "$filename"

			check_port
			dependency_check
			install_docker
			install_certbot
			install_ldnmp
		else
			echo "没有找到压缩包。"
		fi

		;;

		35)
			web_security
			;;

		36)
			web_optimization
			;;


		37)
		root_use
		while true; do
			clear
			#  "更新LDNMP环境"
			echo "更新LDNMP环境"
			echo "------------------------"
			ldnmp_v
			echo "发现新版本的组件"
			echo "------------------------"
			check_docker_image_update nginx
			if [ -n "$update_status" ]; then
				echo -e "${yellow}nginx $update_status${white}"
			fi
			check_docker_image_update php
			if [ -n "$update_status" ]; then
				echo -e "${yellow}php $update_status${white}"
			fi
			check_docker_image_update mysql
			if [ -n "$update_status" ]; then
				echo -e "${yellow}mysql $update_status${white}"
			fi
			check_docker_image_update redis
			if [ -n "$update_status" ]; then
				echo -e "${yellow}redis $update_status${white}"
			fi
			echo "------------------------"
			echo
			echo "1. 更新nginx               2. 更新mysql              3. 更新php              4. 更新redis"
			echo "------------------------"
			echo "5. 更新完整环境"
			echo "------------------------"
			echo "0. 返回上一级选单"
			echo "------------------------"
			read -e -p "请输入你的选择: " sub_choice
			case $sub_choice in
				1)
				nginx_upgrade

					;;

				2)
				local ldnmp_pods="mysql"
				read -e -p "请输入${ldnmp_pods}版本号 （如: 8.0 8.3 8.4 9.0）（回车获取最新版）: " version
				local version=${version:-latest}

				cd /home/web/
				cp /home/web/docker-compose.yml /home/web/docker-compose1.yml
				sed -i "s/image: mysql/image: mysql:${version}/" /home/web/docker-compose.yml
				docker rm -f $ldnmp_pods
				docker images --filter=reference="$ldnmp_pods*" -q | xargs docker rmi > /dev/null 2>&1
				docker compose up -d --force-recreate $ldnmp_pods
				docker restart $ldnmp_pods
				cp /home/web/docker-compose1.yml /home/web/docker-compose.yml
				#  "更新$ldnmp_pods"
				echo "更新${ldnmp_pods}完成"

					;;
				3)
				local ldnmp_pods="php"
				read -e -p "请输入${ldnmp_pods}版本号 （如: 7.4 8.0 8.1 8.2 8.3）（回车获取最新版）: " version
				local version=${version:-8.3}
				cd /home/web/
				cp /home/web/docker-compose.yml /home/web/docker-compose1.yml
				sed -i "s/kjlion\///g" /home/web/docker-compose.yml > /dev/null 2>&1
				sed -i "s/image: php:fpm-alpine/image: php:${version}-fpm-alpine/" /home/web/docker-compose.yml
				docker rm -f $ldnmp_pods
				docker images --filter=reference="$ldnmp_pods*" -q | xargs docker rmi > /dev/null 2>&1
				docker images --filter=reference="kjlion/${ldnmp_pods}*" -q | xargs docker rmi > /dev/null 2>&1
				docker compose up -d --force-recreate $ldnmp_pods
				docker exec php chown -R www-data:www-data /var/www/html

				run_command docker exec php sed -i "s/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g" /etc/apk/repositories > /dev/null 2>&1

				docker exec php apk update
				curl -sL ${gh_proxy}github.com/mlocati/docker-php-extension-installer/releases/latest/download/install-php-extensions -o /usr/local/bin/install-php-extensions
				docker exec php mkdir -p /usr/local/bin/
				docker cp /usr/local/bin/install-php-extensions php:/usr/local/bin/
				docker exec php chmod +x /usr/local/bin/install-php-extensions
				docker exec php install-php-extensions mysqli pdo_mysql gd intl zip exif bcmath opcache redis imagick soap


				docker exec php sh -c 'echo "upload_max_filesize=50M " > /usr/local/etc/php/conf.d/uploads.ini' > /dev/null 2>&1
				docker exec php sh -c 'echo "post_max_size=50M " > /usr/local/etc/php/conf.d/post.ini' > /dev/null 2>&1
				docker exec php sh -c 'echo "memory_limit=512M" > /usr/local/etc/php/conf.d/memory.ini' > /dev/null 2>&1
				docker exec php sh -c 'echo "max_execution_time=1200" > /usr/local/etc/php/conf.d/max_execution_time.ini' > /dev/null 2>&1
				docker exec php sh -c 'echo "max_input_time=600" > /usr/local/etc/php/conf.d/max_input_time.ini' > /dev/null 2>&1
				docker exec php sh -c 'echo "max_input_vars=5000" > /usr/local/etc/php/conf.d/max_input_vars.ini' > /dev/null 2>&1

				fix_phpfpm_conf $ldnmp_pods

				docker restart $ldnmp_pods > /dev/null 2>&1
				cp /home/web/docker-compose1.yml /home/web/docker-compose.yml
				#  "更新$ldnmp_pods"
				echo "更新${ldnmp_pods}完成"

					;;
				4)
				local ldnmp_pods="redis"
				cd /home/web/
				docker rm -f $ldnmp_pods
				docker images --filter=reference="$ldnmp_pods*" -q | xargs docker rmi > /dev/null 2>&1
				docker compose up -d --force-recreate $ldnmp_pods
				docker restart $ldnmp_pods > /dev/null 2>&1
				restart_redis
				#  "更新$ldnmp_pods"
				echo "更新${ldnmp_pods}完成"

					;;
				5)
					read -e -p "$(echo -e "${yellow}提示: ${white}长时间不更新环境的用户，请慎重更新LDNMP环境，会有数据库更新失败的风险。确定更新LDNMP环境吗？(Y/N): ")" choice
					case "$choice" in
					[Yy])
						#  "完整更新LDNMP环境"
						cd /home/web/
						docker compose down --rmi all

						check_port
						dependency_check
						install_docker
						install_certbot
						install_ldnmp
						;;
					*)
						;;
					esac
					;;
				*)
					break
					;;
			esac
			break_end
			done
			;;

		38)
			root_use
			#  "卸载LDNMP环境"
			read -e -p "$(echo -e "${red}强烈建议：${white}先备份全部网站数据，再卸载LDNMP环境。确定删除所有网站数据吗？(Y/N): ")" choice
			case "$choice" in
			[Yy])
				cd /home/web/
				docker compose down --rmi all
				docker compose -f docker-compose.phpmyadmin.yml down > /dev/null 2>&1
				docker compose -f docker-compose.phpmyadmin.yml down --rmi all > /dev/null 2>&1
				rm -rf /home/web
				;;
			[Nn])

				;;
			*)
				echo "无效的选择，请输入 Y 或 N。"
				;;
			esac
			;;

		0)
			return_to_menu
		;;

		*)
			echo "无效的输入!"
		esac
	break_end
	done
}

#############################################################################
################################ 六、防火墙管理 ##############################
# 检测防火墙类型
detect_firewall() {
    if command -v firewalld >/dev/null 2>&1; then
        echo "firewalld"
    elif command -v iptables >/dev/null 2>&1; then
        echo "iptables"
    else
        echo "none"
    fi
}

# 安装防火墙
install_firewall() {
    clear
    echo -e "${blue}===== 防火墙安装 ====="${white}
    echo "1. 安装 iptables"
    echo "2. 安装 firewalld"
    echo "0. 返回"
    echo -e "${cyan}------------------------${white}"
    read -p "请选择要安装的防火墙: " choice
    
    case $choice in
        1)
            install iptables
            install iptables-persistent 2>/dev/null  # 对于debian系
            install iptables-services 2>/dev/null    # 对于rhel系
            sudo systemctl enable iptables 2>/dev/null
            sudo systemctl start iptables 2>/dev/null
            echo -e "${green}iptables 已安装并启动${white}"
            pause
            ;;
        2)
            install firewalld
            sudo systemctl enable firewalld
            sudo systemctl start firewalld
            echo -e "${green}firewalld 已安装并启动${white}"
            pause
            ;;
        0)
            return
            ;;
        *)
            echo -e "${red}无效选择${white}"
            pause
            ;;
    esac
}

# 卸载防火墙
uninstall_firewall() {
    local firewall=$1
    clear
    echo -e "${blue}===== 卸载 $firewall ====="${white}
    read -p "确定要卸载 $firewall 吗? (y/N) " confirm
    
    if [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
        local os=$(detect_os)
        
        if [ "$firewall" = "firewalld" ]; then
            sudo systemctl stop firewalld 2>/dev/null
            sudo systemctl disable firewalld 2>/dev/null
            
            if [ "$os" = "debian" ]; then
                sudo apt remove --purge -y firewalld >/dev/null 2>&1
            elif [ "$os" = "rhel" ]; then
                if command -v dnf >/dev/null 2>&1; then
                    sudo dnf remove -y firewalld >/dev/null 2>&1
                else
                    sudo yum remove -y firewalld >/dev/null 2>&1
                fi
            elif [ "$os" = "arch" ]; then
                sudo pacman -Rns --noconfirm firewalld >/dev/null 2>&1
            fi
        elif [ "$firewall" = "iptables" ]; then
            sudo systemctl stop iptables 2>/dev/null
            sudo systemctl disable iptables 2>/dev/null
            
            if [ "$os" = "debian" ]; then
                sudo apt remove --purge -y iptables iptables-persistent >/dev/null 2>&1
            elif [ "$os" = "rhel" ]; then
                if command -v dnf >/dev/null 2>&1; then
                    sudo dnf remove -y iptables iptables-services >/dev/null 2>&1
                else
                    sudo yum remove -y iptables iptables-services >/dev/null 2>&1
                fi
            elif [ "$os" = "arch" ]; then
                sudo pacman -Rns --noconfirm iptables >/dev/null 2>&1
            fi
        fi
        
        echo -e "${green}$firewall 已卸载${white}"
    else
        echo -e "${yellow}取消卸载操作${white}"
    fi
    pause
}

# 国家IP规则管理（依赖ipset+ipdeny.com IP库）
manage_country_rules() {
    local firewall=$1
    local action=$2
    local country=$3
    local ipset_name="country_$country"
    local ip_url="https://www.ipdeny.com/ipblocks/data/countries/$country.zone"

    # 检查ipset是否安装
    if ! command -v ipset >/dev/null 2>&1; then
        echo -e "${yellow}检测到未安装ipset，正在安装...${white}"
        install ipset || return 1
    fi

    case $action in
        block)
            # 创建ipset集合并导入国家IP
            sudo ipset create $ipset_name hash:net 2>/dev/null
            echo -e "${cyan}正在下载$country的IP列表...${white}"
            sudo curl -s $ip_url | while read ip; do
                sudo ipset add $ipset_name $ip 2>/dev/null
            done
            
            # 应用到防火墙
            if [ "$firewall" = "firewalld" ]; then
                sudo firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source ipset=$ipset_name drop"
                sudo firewall-cmd --reload
            elif [ "$firewall" = "iptables" ]; then
                sudo iptables -A INPUT -m set --match-set $ipset_name src -j DROP
                sudo iptables-save > /etc/iptables/rules.v4 2>/dev/null
                sudo service iptables save 2>/dev/null
            fi
            echo -e "${green}已封锁$country国家IP${white}"
            ;;
        allow)
            # 创建ipset集合并导入国家IP
            sudo ipset create $ipset_name hash:net 2>/dev/null
            echo -e "${cyan}正在下载$country的IP列表...${white}"
            sudo curl -s $ip_url | while read ip; do
                sudo ipset add $ipset_name $ip 2>/dev/null
            done
            
            # 先默认拒绝所有，再允许国家IP+基础端口
            if [ "$firewall" = "firewalld" ]; then
                sudo firewall-cmd --permanent --set-default-zone=drop
                sudo firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source ipset=$ipset_name accept"
                sudo firewall-cmd --permanent --add-port=22/tcp  # 保留SSH端口
                sudo firewall-cmd --reload
            elif [ "$firewall" = "iptables" ]; then
                sudo iptables -P INPUT DROP
                sudo iptables -A INPUT -m set --match-set $ipset_name src -j ACCEPT
                sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT  # 保留SSH端口
                sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
                sudo iptables-save > /etc/iptables/rules.v4 2>/dev/null
                sudo service iptables save 2>/dev/null
            fi
            echo -e "${green}仅允许$country国家IP访问${white}"
            ;;
        unblock)
            # 删除关联规则
            if [ "$firewall" = "firewalld" ]; then
                sudo firewall-cmd --permanent --remove-rich-rule="rule family=ipv4 source ipset=$ipset_name drop"
                sudo firewall-cmd --permanent --remove-rich-rule="rule family=ipv4 source ipset=$ipset_name accept"
                sudo firewall-cmd --reload
            elif [ "$firewall" = "iptables" ]; then
                sudo iptables -D INPUT -m set --match-set $ipset_name src -j DROP 2>/dev/null
                sudo iptables -D INPUT -m set --match-set $ipset_name src -j ACCEPT 2>/dev/null
                sudo iptables-save > /etc/iptables/rules.v4 2>/dev/null
                sudo service iptables save 2>/dev/null
            fi
            
            # 销毁ipset集合
            sudo ipset destroy $ipset_name 2>/dev/null
            echo -e "${green}已解除$country国家IP限制${white}"
            ;;
        *)
            echo -e "${red}无效操作（仅支持block/allow/unblock）${white}"
            ;;
    esac
}

# 启动DDOS防御
enable_ddos_defense() {
    local firewall=$1
    
    case $firewall in
        firewalld)
            # 限制单IP并发连接
            sudo firewall-cmd --permanent --add-rich-rule="rule family=ipv4 port port=0-65535 protocol=tcp limit value=200/minute accept"
            sudo firewall-cmd --permanent --add-rich-rule="rule family=ipv4 port port=0-65535 protocol=udp limit value=100/minute accept"
            sudo firewall-cmd --reload
            ;;
        iptables)
            # 添加连接数限制
            sudo iptables -A INPUT -p tcp --syn -m connlimit --connlimit-above 100 -j REJECT --reject-with tcp-white
            sudo iptables -A INPUT -p tcp -m state --state NEW -m limit --limit 200/minute --limit-burst 50 -j ACCEPT
            sudo iptables -A INPUT -p udp -m state --state NEW -m limit --limit 100/minute --limit-burst 20 -j ACCEPT
            sudo iptables-save > /etc/iptables/rules.v4 2>/dev/null
            sudo service iptables save 2>/dev/null
            ;;
    esac
    echo -e "${green}DDOS防御已启动${white}"
}

# 关闭DDOS防御
disable_ddos_defense() {
    local firewall=$1
    
    case $firewall in
        firewalld)
            sudo firewall-cmd --permanent --remove-rich-rule="rule family=ipv4 port port=0-65535 protocol=tcp limit value=200/minute accept"
            sudo firewall-cmd --permanent --remove-rich-rule="rule family=ipv4 port port=0-65535 protocol=udp limit value=100/minute accept"
            sudo firewall-cmd --reload
            ;;
        iptables)
            sudo iptables -D INPUT -p tcp --syn -m connlimit --connlimit-above 100 -j REJECT --reject-with tcp-white 2>/dev/null
            sudo iptables -D INPUT -p tcp -m state --state NEW -m limit --limit 200/minute --limit-burst 50 -j ACCEPT 2>/dev/null
            sudo iptables -D INPUT -p udp -m state --state NEW -m limit --limit 100/minute --limit-burst 20 -j ACCEPT 2>/dev/null
            sudo iptables-save > /etc/iptables/rules.v4 2>/dev/null
            sudo service iptables save 2>/dev/null
            ;;
    esac
    echo -e "${green}DDOS防御已关闭${white}"
}

# firewalld管理面板
firewalld_panel() {
    while true; do
        clear
        echo -e "${blue}===== firewalld 高级防火墙管理 ====="${white}
        echo -e "${cyan}高级防火墙管理${white}"
        echo -e "${cyan}------------------------${white}"
        echo -e "${yellow}Chain INPUT (policy $(sudo firewall-cmd --get-default-zone | awk '{if ($1 == "drop") print "DROP"; else print "ACCEPT"}'))${white}"
        echo -e "${cyan}------------------------${white}"
        
        echo "1.  开放指定端口                 2.  关闭指定端口"
        echo "3.  开放所有端口                 4.  关闭所有端口"
        echo -e "${cyan}------------------------${white}"
        echo "5.  IP白名单                     6.  IP黑名单"
        echo "7.  清除指定IP"
        echo -e "${cyan}------------------------${white}"
        echo "11. 允许PING                     12. 禁止PING"
        echo -e "${cyan}------------------------${white}"
        echo "13. 启动DDOS防御                 14. 关闭DDOS防御"
        echo -e "${cyan}------------------------${white}"
        echo "15. 阻止指定国家IP               16. 仅允许指定国家IP"
        echo "17. 解除指定国家IP限制"
        echo -e "${cyan}------------------------${white}"
        echo -e "${red}99. 卸载防火墙${white}"
        echo -e "${yellow}0.  返回上一级选单${white}"
        echo -e "${cyan}------------------------${white}"
        
        read -p "请输入你的选择: " choice
        
        case $choice in
            1)  # 开放指定端口
				read -p "请输入端口号: " port
                read -p "请选择协议 (tcp/udp/all): " proto
                
                if [ "$proto" = "tcp" ] || [ "$proto" = "all" ]; then
                    sudo firewall-cmd --permanent --add-port=$port/tcp
                fi
                if [ "$proto" = "udp" ] || [ "$proto" = "all" ]; then
                    sudo firewall-cmd --permanent --add-port=$port/udp
                fi
                sudo firewall-cmd --reload
                echo -e "${green}端口 $port ($proto) 已开放${white}"
                pause
                ;;
                
            2)  # 关闭指定端口
                read -p "请输入端口号: " port
                read -p "请选择协议 (tcp/udp/all): " proto
                
                if [ "$proto" = "tcp" ] || [ "$proto" = "all" ]; then
                    sudo firewall-cmd --permanent --remove-port=$port/tcp
                fi
                if [ "$proto" = "udp" ] || [ "$proto" = "all" ]; then
                    sudo firewall-cmd --permanent --remove-port=$port/udp
                fi
                sudo firewall-cmd --reload
                echo -e "${green}端口 $port ($proto) 已关闭${white}"
                pause
                ;;
                
            3)  # 开放所有端口
                sudo firewall-cmd --permanent --set-default-zone=public
                sudo firewall-cmd --permanent --zone=public --add-rich-rule='rule family=ipv4 source address=0.0.0.0/0 accept'
                sudo firewall-cmd --reload
                echo -e "${yellow}警告: 已开放所有端口，安全性降低${white}"
                pause
                ;;
                
            4)  # 关闭所有端口
                sudo firewall-cmd --permanent --set-default-zone=drop
                sudo firewall-cmd --reload
                echo -e "${green}已设置默认拒绝所有流量${white}"
                pause
                ;;
                
            5)  # IP白名单
                read -p "请输入允许的IP/IP段 (如192.168.1.0/24): " ip
                sudo firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=$ip accept"
                sudo firewall-cmd --reload
                echo -e "${green}IP $ip 已添加到白名单${white}"
                pause
                ;;
                
            6)  # IP黑名单
                read -p "请输入禁止的IP/IP段 (如192.168.1.0/24): " ip
                sudo firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=$ip drop"
                sudo firewall-cmd --reload
                echo -e "${green}IP $ip 已添加到黑名单${white}"
                pause
                ;;
                
            7)  # 清除指定IP
                read -p "请输入要清除规则的IP/IP段: " ip
                sudo firewall-cmd --permanent --remove-rich-rule="rule family=ipv4 source address=$ip accept" 2>/dev/null
                sudo firewall-cmd --permanent --remove-rich-rule="rule family=ipv4 source address=$ip drop" 2>/dev/null
                sudo firewall-cmd --reload
                echo -e "${green}IP $ip 的规则已清除${white}"
                pause
                ;;
                
            11)  # 允许PING
                sudo firewall-cmd --permanent --remove-icmp-block=echo-request
                sudo firewall-cmd --reload
                echo -e "${green}已允许PING${white}"
                pause
                ;;
                
            12)  # 禁止PING
                sudo firewall-cmd --permanent --add-icmp-block=echo-request
                sudo firewall-cmd --reload
                echo -e "${green}已禁止PING${white}"
                pause
                ;;
                
            13)  # 启动DDOS防御
                enable_ddos_defense "firewalld"
                pause
                ;;
                
            14)  # 关闭DDOS防御
                disable_ddos_defense "firewalld"
                pause
                ;;
                
            15)  # 阻止指定国家IP
                read -p "请输入国家代码 (如CN/US, 大写): " country
                manage_country_rules "firewalld" "block" $country
                pause
                ;;
                
            16)  # 仅允许指定国家IP
                read -p "请输入国家代码 (如CN/US, 大写): " country
                manage_country_rules "firewalld" "allow" $country
                pause
                ;;
                
            17)  # 解除指定国家IP限制
                read -p "请输入国家代码 (如CN/US, 大写): " country
                manage_country_rules "firewalld" "unblock" $country
                pause
                ;;
                
            99)  # 卸载防火墙
                uninstall_firewall "firewalld"
                return_to_menu
                ;;
			0)  # 返回上一级
				return_to_menu
				;;
                
            *)
                echo -e "${red}无效选择，请重试${white}"
                pause
                ;;
        esac
    done
}

# iptables管理面板
iptables_panel() {
    while true; do
        clear
        echo -e "${blue}===== iptables 高级防火墙管理 ====="${white}
        echo -e "${cyan}高级防火墙管理${white}"
        echo -e "${cyan}------------------------${white}"
        echo -e "${yellow}Chain INPUT (policy $(sudo iptables -L INPUT -n | head -n 1 | awk '{print $4}'))${white}"
        echo -e "${cyan}------------------------${white}"
        
        echo "1.  开放指定端口                 2.  关闭指定端口"
        echo "3.  开放所有端口                 4.  关闭所有端口"
        echo -e "${cyan}------------------------${white}"
        echo "5.  IP白名单                     6.  IP黑名单"
        echo "7.  清除指定IP"
        echo -e "${cyan}------------------------${white}"
        echo "11. 允许PING                     12. 禁止PING"
        echo -e "${cyan}------------------------${white}"
        echo "13. 启动DDOS防御                 14. 关闭DDOS防御"
        echo -e "${cyan}------------------------${white}"
        echo "15. 阻止指定国家IP               16. 仅允许指定国家IP"
        echo "17. 解除指定国家IP限制"
        echo -e "${cyan}------------------------${white}"
        echo -e "${red}99. 卸载防火墙${white}"
        echo -e "${yellow}0.  返回上一级选单${white}"
        echo -e "${cyan}------------------------${white}"
        
        read -p "请输入你的选择: " choice
        
        case $choice in
            1)  # 开放指定端口
                read -p "请输入端口号: " port
                read -p "请选择协议 (tcp/udp/all): " proto
                
                if [ "$proto" = "tcp" ] || [ "$proto" = "all" ]; then
                    sudo iptables -A INPUT -p tcp --dport $port -j ACCEPT
                fi
                if [ "$proto" = "udp" ] || [ "$proto" = "all" ]; then
                    sudo iptables -A INPUT -p udp --dport $port -j ACCEPT
                fi
                sudo iptables-save > /etc/iptables/rules.v4 2>/dev/null
                sudo service iptables save 2>/dev/null
                echo -e "${green}端口 $port ($proto) 已开放${white}"
                pause
                ;;
                
            2)  # 关闭指定端口
                read -p "请输入端口号: " port
                read -p "请选择协议 (tcp/udp/all): " proto
                
                if [ "$proto" = "tcp" ] || [ "$proto" = "all" ]; then
                    sudo iptables -D INPUT -p tcp --dport $port -j ACCEPT 2>/dev/null
                    sudo iptables -A INPUT -p tcp --dport $port -j DROP
                fi
                if [ "$proto" = "udp" ] || [ "$proto" = "all" ]; then
                    sudo iptables -D INPUT -p udp --dport $port -j ACCEPT 2>/dev/null
                    sudo iptables -A INPUT -p udp --dport $port -j DROP
                fi
                sudo iptables-save > /etc/iptables/rules.v4 2>/dev/null
                sudo service iptables save 2>/dev/null
                echo -e "${green}端口 $port ($proto) 已关闭${white}"
                pause
                ;;
                
            3)  # 开放所有端口
                sudo iptables -P INPUT ACCEPT
                sudo iptables -F INPUT
                sudo iptables-save > /etc/iptables/rules.v4 2>/dev/null
                sudo service iptables save 2>/dev/null
                echo -e "${yellow}警告: 已开放所有端口，安全性降低${white}"
                pause
                ;;
                
            4)  # 关闭所有端口
                sudo iptables -P INPUT DROP
                # 保留已建立的连接
                sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
                sudo iptables-save > /etc/iptables/rules.v4 2>/dev/null
                sudo service iptables save 2>/dev/null
                echo -e "${green}已设置默认拒绝所有流量${white}"
                pause
                ;;
                
            5)  # IP白名单
                read -p "请输入允许的IP/IP段 (如192.168.1.0/24): " ip
                sudo iptables -A INPUT -s $ip -j ACCEPT
                sudo iptables-save > /etc/iptables/rules.v4 2>/dev/null
                sudo service iptables save 2>/dev/null
                echo -e "${green}IP $ip 已添加到白名单${white}"
                pause
                ;;
                
            6)  # IP黑名单
                read -p "请输入禁止的IP/IP段 (如192.168.1.0/24): " ip
                sudo iptables -A INPUT -s $ip -j DROP
                sudo iptables-save > /etc/iptables/rules.v4 2>/dev/null
                sudo service iptables save 2>/dev/null
                echo -e "${green}IP $ip 已添加到黑名单${white}"
                pause
                ;;
                
            7)  # 清除指定IP
                read -p "请输入要清除规则的IP/IP段: " ip
                # 删除所有与该IP相关的规则
                while sudo iptables -D INPUT -s $ip -j ACCEPT 2>/dev/null; do :; done
                while sudo iptables -D INPUT -s $ip -j DROP 2>/dev/null; do :; done
                sudo iptables-save > /etc/iptables/rules.v4 2>/dev/null
                sudo service iptables save 2>/dev/null
                echo -e "${green}IP $ip 的规则已清除${white}"
                pause
                ;;
                
            11)  # 允许PING
                sudo iptables -D INPUT -p icmp --icmp-type echo-request -j DROP 2>/dev/null
                sudo iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
                sudo iptables-save > /etc/iptables/rules.v4 2>/dev/null
                sudo service iptables save 2>/dev/null
                echo -e "${green}已允许PING${white}"
                pause
                ;;
                
            12)  # 禁止PING
                sudo iptables -D INPUT -p icmp --icmp-type echo-request -j ACCEPT 2>/dev/null
                sudo iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
                sudo iptables-save > /etc/iptables/rules.v4 2>/dev/null
                sudo service iptables save 2>/dev/null
                echo -e "${green}已禁止PING${white}"
                pause
                ;;
                
            13)  # 启动DDOS防御
                enable_ddos_defense "iptables"
                pause
                ;;
                
            14)  # 关闭DDOS防御
                disable_ddos_defense "iptables"
                pause
                ;;
                
            15)  # 阻止指定国家IP
                read -p "请输入国家代码 (如CN/US，大写): " country
                manage_country_rules "iptables" "block" $country
                pause
                ;;
                
            16)  # 仅允许指定国家IP
                read -p "请输入国家代码 (如CN/US，大写): " country
                manage_country_rules "iptables" "allow" $country
                pause
                ;;
                
            17)  # 解除指定国家IP限制
                read -p "请输入国家代码 (如CN/US，大写): " country
                manage_country_rules "iptables" "unblock" $country
                pause
                ;;
			99)  # 卸载防火墙
                uninstall_firewall "iptables"
                return_to_menu
                ;;
                
            0)  # 返回上一级
                return_to_menu
                ;;
                
            *)
                echo -e "${red}无效选择，请重试${white}"
                pause
                ;;
        esac
    done
}

# 主防火墙管理函数
linux_firewall() {
    while true; do
        local firewall=$(detect_firewall)
        
        if [ "$firewall" = "none" ]; then
            clear
            echo -e "${blue}===== 防火墙管理 ====="${white}
            echo -e "${red}未检测到已安装的防火墙${white}"
            echo "1. 安装 iptables"
            echo "2. 安装 firewalld"
            echo "0. 退出"
            echo -e "${cyan}------------------------${white}"
            read -p "请选择操作: " choice
            
            case $choice in
                1)
                    install_firewall
                    ;;
                2)
                    install_firewall
                    ;;
                0)
                    return
                    ;;
                *)
                    echo -e "${red}无效选择${white}"
                    pause
                    ;;
            esac
        else
            # 根据检测到的防火墙类型进入相应的管理面板
            if [ "$firewall" = "firewalld" ]; then
                firewalld_panel
            elif [ "$firewall" = "iptables" ]; then
                iptables_panel
            fi
        fi
    done
}


#############################################################################
################################ 七、BBR加速管理 #############################

linux_bbr() {
	clear
	if [ -f "/etc/alpine-release" ]; then
		while true; do
			clear
			local congestion_algorithm=$(sysctl -n net.ipv4.tcp_congestion_control)
			local queue_algorithm=$(sysctl -n net.core.default_qdisc)
			echo "当前TCP阻塞算法: $congestion_algorithm $queue_algorithm"

			echo ""
			echo "BBR管理"
			echo -e "${pink}------------------------${white}"
			echo "1. 开启BBRv3              2. 关闭BBRv3（会重启）"
			echo -e "${pink}------------------------${white}"
			echo "0. 返回上一级选单"
			echo -e "${pink}------------------------${white}"
			read -e -p "请输入你的选择: " sub_choice

			case $sub_choice in
				1)
				bbr_on
				## "alpine开启bbr3"
					;;
				2)
				sed -i '/net.ipv4.tcp_congestion_control=bbr/d' /etc/sysctl.conf
				sysctl -p
				server_reboot
					;;
				*)
					break  # 跳出循环，退出菜单
					;;

			esac
		done
	else
		install wget
		wget --no-check-certificate -O tcpx.sh ${url_proxy}raw.githubusercontent.com/ylx2016/Linux-NetSpeed/master/tcpx.sh
		chmod +x tcpx.sh
		./tcpx.sh
	fi
}


#############################################################################
################################# 八、应用市场 ###############################

###########################
###### 面板类应用管理 ######
###########################
# 检查panel是否安装
check_panel_app() {
	if $panel_path > /dev/null 2>&1; then
		check_panel="${green}已安装${white}"
	else
		check_panel="${white}未安装${white}"
	fi
}
# 面板管理
panel_manage() {
	while true; do
		clear
		check_panel_app
		echo -e "$panelname $check_panel"
		echo "${panelname}是一款时下流行且强大的运维管理面板。"
		echo "官网介绍: $panelurl "

		echo ""
		echo -e "${pink}------------------------${white}"
		echo "1. 安装            2. 管理            3. 卸载"
		echo -e "${pink}------------------------${white}"
		echo "0. 返回上一级选单"
		echo -e "${pink}------------------------${white}"
		read -e -p "请输入你的选择: " choice
		case $choice in
			1)
				check_disk_space 1
				install wget
				iptables_open
				panel_app_install

				mkdir -p /home/docker && touch /home/docker/appno.txt && (add_app_id)
				;;
			2)
				panel_app_manage

				mkdir -p /home/docker && touch /home/docker/appno.txt && (add_app_id)

				;;
			3)
				panel_app_uninstall

				sed -i "/\b${app_id}\b/d" /home/docker/appno.txt
				;;
			*)
				break
				;;
		esac
		break_end
	done
}


##############################
###### Docker类应用管理 ######
##############################

# Docker信息统计
docker_tato() {

	local container_count=$(docker ps -a -q 2>/dev/null | wc -l)
	local image_count=$(docker images -q 2>/dev/null | wc -l)
	local network_count=$(docker network ls -q 2>/dev/null | wc -l)
	local volume_count=$(docker volume ls -q 2>/dev/null | wc -l)

	if command -v docker &> /dev/null; then
		echo -e "${cyan}------------------------${white}"
		echo -e "${green}环境已经安装${white}  容器: ${green}$container_count${white}  镜像: ${green}$image_count${white}  网络: ${green}$network_count${white}  卷: ${green}$volume_count${white}"
	fi
}

# 检查 crontab 是否安装
check_crontab_installed() {
	if ! command -v crontab >/dev/null 2>&1; then
		install_crontab
	fi
}

# 安装 crontab
install_crontab() {

	if [ -f /etc/os-release ]; then
		. /etc/os-release
		case "$ID" in
			ubuntu|debian|kali)
				apt update
				apt install -y cron
				systemctl enable cron
				systemctl start cron
				;;
			centos|rhel|almalinux|rocky|fedora)
				yum install -y cronie
				systemctl enable crond
				systemctl start crond
				;;
			alpine)
				apk add --no-cache cronie
				rc-update add crond
				rc-service crond start
				;;
			arch|manjaro)
				pacman -S --noconfirm cronie
				systemctl enable cronie
				systemctl start cronie
				;;
			opensuse|suse|opensuse-tumbleweed)
				zypper install -y cron
				systemctl enable cron
				systemctl start cron
				;;
			iStoreOS|openwrt|ImmortalWrt|lede)
				opkg update
				opkg install cron
				/etc/init.d/cron enable
				/etc/init.d/cron start
				;;
			FreeBSD)
				pkg install -y cronie
				sysrc cron_enable="YES"
				service cron start
				;;
			*)
				echo "不支持的发行版: $ID"
				return
				;;
		esac
	else
		echo "无法确定操作系统。"
		return
	fi

	echo -e "${green}crontab 已安装且 cron 服务正在运行。${white}"
}

# 保存 iptables 规则
save_iptables_rules() {
	mkdir -p /etc/iptables
	touch /etc/iptables/rules.v4
	iptables-save > /etc/iptables/rules.v4
	check_crontab_installed
	crontab -l | grep -v 'iptables-restore' | crontab - > /dev/null 2>&1
	(crontab -l ; echo '@reboot iptables-restore < /etc/iptables/rules.v4') | crontab - > /dev/null 2>&1

}


# 检查Docker
check_docker() {
	if ! command -v docker &>/dev/null; then
		echo -e "${red}未检测到Docker环境${white}"
		echo -e "${cyan}------------------------"
		echo -e "${cyan}1.   ${white}安装Docker环境"
		echo -e "${cyan}0.   ${white}返回主菜单"
		echo -e "${cyan}------------------------${white}"
		read -e -p "请输入你的选择: " docker_choice
		case $docker_choice in
			1)
				install_add_docker
				break_end
				;;
			0)
				return_to_menu
				;;
			*)
				echo "无效输入!"
				break_end
				;;
		esac
		return
	fi
}

# 检查Docker应用是否安装
check_docker_app() {
	if docker ps -a --format '{{.Names}}' | grep -q "$docker_name" >/dev/null 2>&1 ; then
		check_docker="${gl_lv}已安装${gl_bai}"
	else
		check_docker="${gl_hui}未安装${gl_bai}"
	fi
}

# 检查Docker应用的访问地址
check_docker_app_ip() {
echo -e "${pink}------------------------${white}"
echo "访问地址:"
ip_address

if [ -n "$ipv4_address" ]; then
	echo "http://$ipv4_address:${docker_port}"
fi

if [ -n "$ipv6_address" ]; then
	echo "http://[$ipv6_address]:${docker_port}"
fi

local search_pattern1="$ipv4_address:${docker_port}"
local search_pattern2="127.0.0.1:${docker_port}"

for file in /home/web/conf.d/*; do
	if [ -f "$file" ]; then
		if grep -q "$search_pattern1" "$file" 2>/dev/null || grep -q "$search_pattern2" "$file" 2>/dev/null; then
			echo "https://$(basename "$file" | sed 's/\.conf$//')"
		fi
	fi
done
}

# 检查Docker镜像更新
check_docker_image_update() {
	local container_name=$1
	local country=$(curl -s ipinfo.io/country)
	if [[ "$country" == "CN" ]]; then
		update_status=""
		return
	fi

	# 获取容器的创建时间和镜像名称
	local container_info=$(docker inspect --format='{{.Created}},{{.Config.Image}}' "$container_name" 2>/dev/null)
	local container_created=$(echo "$container_info" | cut -d',' -f1)
	local image_name=$(echo "$container_info" | cut -d',' -f2)

	# 提取镜像仓库和标签
	local image_repo=${image_name%%:*}
	local image_tag=${image_name##*:}

	# 默认标签为 latest
	[[ "$image_repo" == "$image_tag" ]] && image_tag="latest"

	# 添加对官方镜像的支持
	[[ "$image_repo" != */* ]] && image_repo="library/$image_repo"

	# 从 Docker Hub API 获取镜像发布时间
	local hub_info=$(curl -s "https://hub.docker.com/v2/repositories/$image_repo/tags/$image_tag")
	local last_updated=$(echo "$hub_info" | jq -r '.last_updated' 2>/dev/null)

	# 验证获取的时间
	if [[ -n "$last_updated" && "$last_updated" != "null" ]]; then
		local container_created_ts=$(date -d "$container_created" +%s 2>/dev/null)
		local last_updated_ts=$(date -d "$last_updated" +%s 2>/dev/null)

		# 比较时间戳
		if [[ $container_created_ts -lt $last_updated_ts ]]; then
			update_status="${yellow}发现新版本!${white}"
		else
			update_status=""
		fi
	else
		update_status=""
	fi
}

# 检查Docker容器的端口访问
block_container_port() {
	local container_name_or_id=$1
	local allowed_ip=$2

	# 获取容器的 IP 地址
	local container_ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$container_name_or_id")

	if [ -z "$container_ip" ]; then
		return 1
	fi

	install iptables


	# 检查并封禁其他所有 IP
	if ! iptables -C DOCKER-USER -p tcp -d "$container_ip" -j DROP &>/dev/null; then
		iptables -I DOCKER-USER -p tcp -d "$container_ip" -j DROP
	fi

	# 检查并放行指定 IP
	if ! iptables -C DOCKER-USER -p tcp -s "$allowed_ip" -d "$container_ip" -j ACCEPT &>/dev/null; then
		iptables -I DOCKER-USER -p tcp -s "$allowed_ip" -d "$container_ip" -j ACCEPT
	fi

	# 检查并放行本地网络 127.0.0.0/8
	if ! iptables -C DOCKER-USER -p tcp -s 127.0.0.0/8 -d "$container_ip" -j ACCEPT &>/dev/null; then
		iptables -I DOCKER-USER -p tcp -s 127.0.0.0/8 -d "$container_ip" -j ACCEPT
	fi

	# 检查并封禁其他所有 IP
	if ! iptables -C DOCKER-USER -p udp -d "$container_ip" -j DROP &>/dev/null; then
		iptables -I DOCKER-USER -p udp -d "$container_ip" -j DROP
	fi

	# 检查并放行指定 IP
	if ! iptables -C DOCKER-USER -p udp -s "$allowed_ip" -d "$container_ip" -j ACCEPT &>/dev/null; then
		iptables -I DOCKER-USER -p udp -s "$allowed_ip" -d "$container_ip" -j ACCEPT
	fi

	# 检查并放行本地网络 127.0.0.0/8
	if ! iptables -C DOCKER-USER -p udp -s 127.0.0.0/8 -d "$container_ip" -j ACCEPT &>/dev/null; then
		iptables -I DOCKER-USER -p udp -s 127.0.0.0/8 -d "$container_ip" -j ACCEPT
	fi

	if ! iptables -C DOCKER-USER -m state --state ESTABLISHED,RELATED -d "$container_ip" -j ACCEPT &>/dev/null; then
		iptables -I DOCKER-USER -m state --state ESTABLISHED,RELATED -d "$container_ip" -j ACCEPT
	fi

	echo "已阻止IP+端口访问该服务"
	save_iptables_rules
}


# 清除容器的防火墙规则
clear_container_rules() {
	local container_name_or_id=$1
	local allowed_ip=$2

	# 获取容器的 IP 地址
	local container_ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$container_name_or_id")

	if [ -z "$container_ip" ]; then
		return 1
	fi

	install iptables


	# 清除封禁其他所有 IP 的规则
	if iptables -C DOCKER-USER -p tcp -d "$container_ip" -j DROP &>/dev/null; then
		iptables -D DOCKER-USER -p tcp -d "$container_ip" -j DROP
	fi

	# 清除放行指定 IP 的规则
	if iptables -C DOCKER-USER -p tcp -s "$allowed_ip" -d "$container_ip" -j ACCEPT &>/dev/null; then
		iptables -D DOCKER-USER -p tcp -s "$allowed_ip" -d "$container_ip" -j ACCEPT
	fi

	# 清除放行本地网络 127.0.0.0/8 的规则
	if iptables -C DOCKER-USER -p tcp -s 127.0.0.0/8 -d "$container_ip" -j ACCEPT &>/dev/null; then
		iptables -D DOCKER-USER -p tcp -s 127.0.0.0/8 -d "$container_ip" -j ACCEPT
	fi

	# 清除封禁其他所有 IP 的规则
	if iptables -C DOCKER-USER -p udp -d "$container_ip" -j DROP &>/dev/null; then
		iptables -D DOCKER-USER -p udp -d "$container_ip" -j DROP
	fi

	# 清除放行指定 IP 的规则
	if iptables -C DOCKER-USER -p udp -s "$allowed_ip" -d "$container_ip" -j ACCEPT &>/dev/null; then
		iptables -D DOCKER-USER -p udp -s "$allowed_ip" -d "$container_ip" -j ACCEPT
	fi

	# 清除放行本地网络 127.0.0.0/8 的规则
	if iptables -C DOCKER-USER -p udp -s 127.0.0.0/8 -d "$container_ip" -j ACCEPT &>/dev/null; then
		iptables -D DOCKER-USER -p udp -s 127.0.0.0/8 -d "$container_ip" -j ACCEPT
	fi


	if iptables -C DOCKER-USER -m state --state ESTABLISHED,RELATED -d "$container_ip" -j ACCEPT &>/dev/null; then
		iptables -D DOCKER-USER -m state --state ESTABLISHED,RELATED -d "$container_ip" -j ACCEPT
	fi

	echo "已允许IP+端口访问该服务"
	save_iptables_rules
}

# 检查主机的端口访问
block_host_port() {
	local port=$1
	local allowed_ip=$2

	if [[ -z "$port" || -z "$allowed_ip" ]]; then
		echo "错误：请提供端口号和允许访问的 IP。"
		echo "用法: block_host_port <端口号> <允许的IP>"
		return 1
	fi

	install iptables

	# 拒绝其他所有 IP 访问
	if ! iptables -C INPUT -p tcp --dport "$port" -j DROP &>/dev/null; then
		iptables -I INPUT -p tcp --dport "$port" -j DROP
	fi

	# 允许指定 IP 访问
	if ! iptables -C INPUT -p tcp --dport "$port" -s "$allowed_ip" -j ACCEPT &>/dev/null; then
		iptables -I INPUT -p tcp --dport "$port" -s "$allowed_ip" -j ACCEPT
	fi

	# 允许本机访问
	if ! iptables -C INPUT -p tcp --dport "$port" -s 127.0.0.0/8 -j ACCEPT &>/dev/null; then
		iptables -I INPUT -p tcp --dport "$port" -s 127.0.0.0/8 -j ACCEPT
	fi

	# 拒绝其他所有 IP 访问
	if ! iptables -C INPUT -p udp --dport "$port" -j DROP &>/dev/null; then
		iptables -I INPUT -p udp --dport "$port" -j DROP
	fi

	# 允许指定 IP 访问
	if ! iptables -C INPUT -p udp --dport "$port" -s "$allowed_ip" -j ACCEPT &>/dev/null; then
		iptables -I INPUT -p udp --dport "$port" -s "$allowed_ip" -j ACCEPT
	fi

	# 允许本机访问
	if ! iptables -C INPUT -p udp --dport "$port" -s 127.0.0.0/8 -j ACCEPT &>/dev/null; then
		iptables -I INPUT -p udp --dport "$port" -s 127.0.0.0/8 -j ACCEPT
	fi

	# 允许已建立和相关连接的流量
	if ! iptables -C INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT &>/dev/null; then
		iptables -I INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
	fi

	echo "已阻止IP+端口访问该服务"
	save_iptables_rules
}

# 清除主机的端口访问
clear_host_port_rules() {
	local port=$1
	local allowed_ip=$2

	if [[ -z "$port" || -z "$allowed_ip" ]]; then
		echo "错误：请提供端口号和允许访问的 IP。"
		echo "用法: clear_host_port_rules <端口号> <允许的IP>"
		return 1
	fi

	install iptables

	# 清除封禁所有其他 IP 访问的规则
	if iptables -C INPUT -p tcp --dport "$port" -j DROP &>/dev/null; then
		iptables -D INPUT -p tcp --dport "$port" -j DROP
	fi

	# 清除允许本机访问的规则
	if iptables -C INPUT -p tcp --dport "$port" -s 127.0.0.0/8 -j ACCEPT &>/dev/null; then
		iptables -D INPUT -p tcp --dport "$port" -s 127.0.0.0/8 -j ACCEPT
	fi

	# 清除允许指定 IP 访问的规则
	if iptables -C INPUT -p tcp --dport "$port" -s "$allowed_ip" -j ACCEPT &>/dev/null; then
		iptables -D INPUT -p tcp --dport "$port" -s "$allowed_ip" -j ACCEPT
	fi

	# 清除封禁所有其他 IP 访问的规则
	if iptables -C INPUT -p udp --dport "$port" -j DROP &>/dev/null; then
		iptables -D INPUT -p udp --dport "$port" -j DROP
	fi

	# 清除允许本机访问的规则
	if iptables -C INPUT -p udp --dport "$port" -s 127.0.0.0/8 -j ACCEPT &>/dev/null; then
		iptables -D INPUT -p udp --dport "$port" -s 127.0.0.0/8 -j ACCEPT
	fi

	# 清除允许指定 IP 访问的规则
	if iptables -C INPUT -p udp --dport "$port" -s "$allowed_ip" -j ACCEPT &>/dev/null; then
		iptables -D INPUT -p udp --dport "$port" -s "$allowed_ip" -j ACCEPT
	fi

	echo "已允许IP+端口访问该服务"
	save_iptables_rules
}

# 设置 Docker 目录
setup_docker_dir() {

	mkdir -p /home/docker/ 2>/dev/null
	if [ -d "/vol1/1000/" ] && [ ! -d "/vol1/1000/docker" ]; then
		cp -f /home/docker /home/docker1 2>/dev/null
		rm -rf /home/docker 2>/dev/null
		mkdir -p /vol1/1000/docker 2>/dev/null
		ln -s /vol1/1000/docker /home/docker 2>/dev/null
	fi
}

# 添加应用 ID
add_app_id() {
	mkdir -p /home/docker
	touch /home/docker/appno.txt
	grep -qxF "${app_id}" /home/docker/appno.txt || echo "${app_id}" >> /home/docker/appno.txt
}


# Docker 应用管理
docker_app() {

while true; do
	clear
	check_docker_app
	check_docker_image_update $docker_name
	echo -e "$docker_name $check_docker $update_status"
	echo "$docker_describe"
	echo "$docker_url"
	if docker ps -a --format '{{.Names}}' | grep -q "$docker_name" >/dev/null 2>&1; then
		if [ ! -f "/home/docker/${docker_name}_port.conf" ]; then
			local docker_port=$(docker port "$docker_name" | head -n1 | awk -F'[:]' '/->/ {print $NF; exit}')
			docker_port=${docker_port:-0000}
			echo "$docker_port" > "/home/docker/${docker_name}_port.conf"
		fi
		local docker_port=$(cat "/home/docker/${docker_name}_port.conf")
		check_docker_app_ip
	fi
	echo ""
	echo -e "${pink}------------------------${white}"
	echo "1. 安装              2. 更新            3. 卸载"
	echo -e "${pink}------------------------${white}"
	echo "5. 添加域名访问      6. 删除域名访问"
	echo "7. 允许IP+端口访问   8. 阻止IP+端口访问"
	echo -e "${pink}------------------------${white}"
	echo "0. 返回上一级选单"
	echo -e "${pink}------------------------${white}"
	read -e -p "请输入你的选择: " choice
	case $choice in
		1)
			check_disk_space $app_size
			read -e -p "输入应用对外服务端口，回车默认使用${docker_port}端口: " app_port
			local app_port=${app_port:-${docker_port}}
			local docker_port=$app_port

			install jq
			install_docker
			docker_run
			setup_docker_dir
			echo "$docker_port" > "/home/docker/${docker_name}_port.conf"

			mkdir -p /home/docker && touch /home/docker/appno.txt && (add_app_id)

			clear
			echo "$docker_name 已经安装完成"
			check_docker_app_ip
			echo ""
			$docker_use
			$docker_passwd
			;;
		2)
			docker rm -f "$docker_name"
			docker rmi -f "$docker_img"
			docker_run

			mkdir -p /home/docker && touch /home/docker/appno.txt && (add_app_id)

			clear
			echo "$docker_name 已经安装完成"
			check_docker_app_ip
			echo ""
			$docker_use
			$docker_passwd
			;;
		3)
			docker rm -f "$docker_name"
			docker rmi -f "$docker_img"
			rm -rf "/home/docker/$docker_name"
			rm -f /home/docker/${docker_name}_port.conf

			sed -i "/\b${app_id}\b/d" /home/docker/appno.txt
			echo "应用已卸载"
			;;

		5)
			echo "${docker_name}域名访问设置"
			add_yuming
			ldnmp_Proxy ${yuming} 127.0.0.1 ${docker_port}
			block_container_port "$docker_name" "$ipv4_address"
			;;

		6)
			echo "域名格式 example.com 不带https://"
			web_del
			;;

		7)
			clear_container_rules "$docker_name" "$ipv4_address"
			;;

		8)
			block_container_port "$docker_name" "$ipv4_address"
			;;

		*)
			break
			;;
	esac
	break_end
done
}

# Docker 应用管理plus
docker_app_plus() {
	while true; do
		clear
		check_docker_app
		check_docker_image_update $docker_name
		echo -e "$app_name $check_docker $update_status"
		echo "$app_text"
		echo "$app_url"
		if docker ps -a --format '{{.Names}}' | grep -q "$docker_name" >/dev/null 2>&1; then
			if [ ! -f "/home/docker/${docker_name}_port.conf" ]; then
				local docker_port=$(docker port "$docker_name" | head -n1 | awk -F'[:]' '/->/ {print $NF; exit}')
				docker_port=${docker_port:-0000}
				echo "$docker_port" > "/home/docker/${docker_name}_port.conf"
			fi
			local docker_port=$(cat "/home/docker/${docker_name}_port.conf")
			check_docker_app_ip
		fi
		echo ""
		echo -e "${pink}------------------------${white}"
		echo "1. 安装             2. 更新             3. 卸载"
		echo -e "${pink}------------------------${white}"
		echo "5. 添加域名访问     6. 删除域名访问"
		echo "7. 允许IP+端口访问  8. 阻止IP+端口访问"
		echo -e "${pink}------------------------${white}"
		echo "0. 返回上一级选单"
		echo -e "${pink}------------------------${white}"
		read -e -p "输入你的选择: " choice
		case $choice in
			1)
				check_disk_space $app_size
				read -e -p "输入应用对外服务端口，回车默认使用${docker_port}端口: " app_port
				local app_port=${app_port:-${docker_port}}
				local docker_port=$app_port
				install jq
				install_docker
				docker_app_install
				setup_docker_dir
				echo "$docker_port" > "/home/docker/${docker_name}_port.conf"

				mkdir -p /home/docker && touch /home/docker/appno.txt && (add_app_id)
				;;
			2)
				docker_app_update

				mkdir -p /home/docker && touch /home/docker/appno.txt && (add_app_id)
				;;
			3)
				docker_app_uninstall
				rm -f /home/docker/${docker_name}_port.conf

				sed -i "/\b${app_id}\b/d" /home/docker/appno.txt

				;;
			5)
				echo "${docker_name}域名访问设置"
				add_yuming
				ldnmp_Proxy ${yuming} 127.0.0.1 ${docker_port}
				block_container_port "$docker_name" "$ipv4_address"
				;;
			6)
				echo "域名格式 example.com 不带https://"
				web_del
				;;
			7)
				clear_container_rules "$docker_name" "$ipv4_address"
				;;
			8)
				block_container_port "$docker_name" "$ipv4_address"
				;;
			*)
				break
				;;
		esac
		break_end
	done
}

##############################
########## 应用函数 ##########
##############################
# 1panel面板
1panel_app(){
	local app_id="1"
	local panel_path="command -v 1pctl"
	local panelname="1Panel"
	local panelurl="https://1panel.cn/"

	panel_app_install(){
		bash -c "$(curl -sSL https://resource.fit2cloud.com/1panel/package/v2/quick_start.sh)"
	}

	panel_app_manage(){
		1pctl user-info
		1pctl update password
	}

	panel_app_uninstall() {
		1pctl uninstall
	}
	panel_manage
}

# 宝塔面板
bt_app(){
	local app_id="2"
	local panel_path="[ -d "/www/server/panel" ]"
	local panelname="宝塔面板"
	local panelurl="https://www.bt.cn"

	panel_app_install(){
		if [ -f /usr/bin/curl ]; then curl -sSO https://download.bt.cn/install/install_panel.sh; else wget -O install_panel.sh https://download.bt.cn/install/install_panel.sh; fi; bash install_panel.sh ed8484bec
	}

	panel_app_manage(){
		bt
	}

	panel_app_uninstall() {
		curl -o bt-uninstall.sh http://download.bt.cn/install/bt-uninstall.sh > /dev/null 2>&1 && chmod +x bt-uninstall.sh && ./bt-uninstall.sh
		chmod +x bt-uninstall.sh
		./bt-uninstall.sh
	}
	panel_manage
}

# aapanel面板
aapanel_app(){
	local app_id="3"
	local panel_path="[ -d "/www/server/panel" ]"
	local panelname="aapanel"
	local panelurl="https://www.aapanel.com/"

	panel_app_install(){
		URL=https://www.aapanel.com/script/install_pro_en.sh && if [ -f /usr/bin/curl ]; then curl -ksSO $URL ; else wget --no-check-certificate -O install_pro_en.sh $URL; fi; bash install_pro_en.sh aa372544
	}

	panel_app_manage(){
		bt
	}

	panel_app_uninstall() {
		curl -o bt-uninstall.sh http://download.bt.cn/install/bt-uninstall.sh > /dev/null 2>&1 && chmod +x bt-uninstall.sh && ./bt-uninstall.sh
		chmod +x bt-uninstall.sh
		./bt-uninstall.sh
	}
	panel_manage
}

# NginxProxyManager可视化面板
npm_app(){
		local app_id="4"
		local docker_name="npm"
		local docker_img="jc21/nginx-proxy-manager:latest"
		local docker_port=81

		docker_run() {
			docker run -d \
				--name=$docker_name \
				-p ${docker_port}:81 \
				-p 80:80 \
				-p 443:443 \
				-v /home/docker/npm/data:/data \
				-v /home/docker/npm/letsencrypt:/etc/letsencrypt \
				--restart=always \
				$docker_img
		}

		local docker_describe="一个Nginx反向代理工具面板，不支持添加域名访问。"
		local docker_url="官网介绍: https://nginxproxymanager.com/"
		local docker_use="echo \"初始用户名: admin@example.com\""
		local docker_passwd="echo \"初始密码: changeme\""
		local app_size="1"

		docker_app
}

# openlist
openlist_app(){
		local app_id="5"
		local docker_name="openlist"
		local docker_img="openlistteam/openlist:latest-aria2"
		local docker_port=5244

		docker_run() {
			docker run -d \
				--restart=always \
				-v /home/docker/openlist:/opt/openlist/data \
				-p ${docker_port}:5244 \
				-e PUID=0 \
				-e PGID=0 \
				-e UMASK=022 \
				--name="openlist" \
				openlistteam/openlist:latest-aria2
		}

		local docker_describe="一个支持多种存储，支持网页浏览和 WebDAV 的文件列表程序，由 gin 和 Solidjs 驱动"
		local docker_url="官网介绍: https://github.com/OpenListTeam/OpenList"
		local docker_use="docker exec -it openlist ./openlist admin random"
		local docker_passwd=""
		local app_size="1"

		docker_app
}

# webtop(浏览器访问linux系统)
webtop_app(){
		local app_id="6"
		local docker_name="webtop-ubuntu"
		local docker_img="lscr.io/linuxserver/webtop:ubuntu-kde"
		local docker_port=3006

		docker_run() {
			read -e -p "设置登录用户名: " admin
			read -e -p "设置登录用户密码: " admin_password
			docker run -d \
				--name=webtop-ubuntu \
				--security-opt seccomp=unconfined \
				-e PUID=1000 \
				-e PGID=1000 \
				-e TZ=Etc/UTC \
				-e SUBFOLDER=/ \
				-e TITLE=Webtop \
				-e CUSTOM_USER=${admin} \
				-e PASSWORD=${admin_password} \
				-p ${docker_port}:3000 \
				-v /home/docker/webtop/data:/config \
				-v /var/run/docker.sock:/var/run/docker.sock \
				--shm-size="1gb" \
				--restart unless-stopped \
				lscr.io/linuxserver/webtop:ubuntu-kde
		}

		local docker_describe="webtop基于Ubuntu的容器。若IP无法访问，请添加域名访问。"
		local docker_url="官网介绍: https://docs.linuxserver.io/images/docker-webtop/"
		local docker_use=""
		local docker_passwd=""
		local app_size="2"
		docker_app
}

# 哪吒探针面板
nezha_app(){
	clear
	local app_id="7"
	local docker_name="nezha-dashboard"
	local docker_port=8008
	while true; do
		check_docker_app
		check_docker_image_update $docker_name
		clear
		echo -e "哪吒监控 $check_docker $update_status"
		echo "开源、轻量、易用的服务器监控与运维工具"
		echo "官网搭建文档: https://nezha.wiki/guide/dashboard.html"
		if docker ps -a --format '{{.Names}}' | grep -q "$docker_name" >/dev/null 2>&1; then
			local docker_port=$(docker port $docker_name | awk -F'[:]' '/->/ {print $NF}' | uniq)
			check_docker_app_ip
		fi
		echo ""
		echo -e "${pink}------------------------${white}"
		echo "1. 使用"
		echo -e "${pink}------------------------${white}"
		echo "0. 返回上一级选单"
		echo -e "${pink}------------------------${white}"
		read -e -p "输入你的选择: " choice

		case $choice in
			1)
				check_disk_space 1
				install unzip jq
				install_docker
				curl -sL ${url_proxy}raw.githubusercontent.com/nezhahq/scripts/refs/heads/main/install.sh -o nezha.sh && chmod +x nezha.sh && ./nezha.sh
				local docker_port=$(docker port $docker_name | awk -F'[:]' '/->/ {print $NF}' | uniq)
				check_docker_app_ip
				;;

			*)
				break
				;;
		esac
		break_end
	done
}

# qbittorrent
qb_app(){
	local app_id="8"
	local docker_name="qbittorrent"
	local docker_img="lscr.io/linuxserver/qbittorrent:latest"
	local docker_port=8081

	docker_run() {
		docker run -d \
			--name=qbittorrent \
			-e PUID=1000 \
			-e PGID=1000 \
			-e TZ=Etc/UTC \
			-e WEBUI_PORT=${docker_port} \
			-e TORRENTING_PORT=56881 \
			-p ${docker_port}:${docker_port} \
			-p 56881:56881 \
			-p 56881:56881/udp \
			-v /home/docker/qbittorrent/config:/config \
			-v /home/docker/qbittorrent/downloads:/downloads \
			--restart unless-stopped \
			lscr.io/linuxserver/qbittorrent:latest
	}

	local docker_describe="qbittorrent离线BT磁力下载服务"
	local docker_url="官网介绍: https://hub.docker.com/r/linuxserver/qbittorrent"
	local docker_use="sleep 3"
	local docker_passwd="docker logs qbittorrent"
	local app_size="1"
	docker_app
}

# Poste.io邮件服务器程序
poste_mail_app(){
	clear
	install telnet
	local app_id="9"
	local docker_name="mailserver"
	while true; do
		check_docker_app
		check_docker_image_update $docker_name

		clear
		echo -e "邮局服务 $check_docker $update_status"
		echo "poste.io 是一个开源的邮件服务器解决方案，"
		echo "官网: https://poste.io/"

		echo ""
		echo "端口检测"
		port=25
		timeout=3
		if echo "quit" | timeout $timeout telnet smtp.qq.com $port | grep 'Connected'; then
			echo -e "${green}端口 $port 当前可用${white}"
		else
			echo -e "${red}端口 $port 当前不可用${white}"
		fi
		echo ""

		if docker ps -a --format '{{.Names}}' | grep -q "$docker_name" >/dev/null 2>&1; then
			yuming=$(cat /home/docker/mail.txt)
			echo "访问地址: "
			echo "https://$yuming"
		fi

		echo -e "${pink}------------------------${white}"
		echo "1. 安装           2. 更新           3. 卸载"
		echo -e "${pink}------------------------${white}"
		echo "0. 返回上一级选单"
		echo -e "${pink}------------------------${white}"
		read -e -p "输入你的选择: " choice

		case $choice in
			1)
				check_disk_space 2
				read -e -p "请设置邮箱域名 例如 mail.yuming.com : " yuming
				mkdir -p /home/docker
				echo "$yuming" > /home/docker/mail.txt
				echo -e "${pink}------------------------${white}"
				ip_address
				echo "先解析这些DNS记录"
				echo "A           mail            $ipv4_address"
				echo "CNAME       imap            $yuming"
				echo "CNAME       pop             $yuming"
				echo "CNAME       smtp            $yuming"
				echo "MX          @               $yuming"
				echo "TXT         @               v=spf1 mx ~all"
				echo "TXT         ?               ?"
				echo ""
				echo -e "${pink}------------------------${white}"
				echo "按任意键继续..."
				read -n 1 -s -r -p ""

				install jq
				install_docker

				docker run \
					--net=host \
					-e TZ=Europe/Prague \
					-v /home/docker/mail:/data \
					--name "mailserver" \
					-h "$yuming" \
					--restart=always \
					-d analogic/poste.io

				mkdir -p /home/docker && touch /home/docker/appno.txt && (add_app_id)

				clear
				echo "poste.io已经安装完成"
				echo -e "${pink}------------------------${white}"
				echo "您可以使用以下地址访问poste.io:"
				echo "https://$yuming"
				echo ""

				;;

			2)
				docker rm -f mailserver
				docker rmi -f analogic/poste.i
				yuming=$(cat /home/docker/mail.txt)
				docker run \
					--net=host \
					-e TZ=Europe/Prague \
					-v /home/docker/mail:/data \
					--name "mailserver" \
					-h "$yuming" \
					--restart=always \
					-d analogic/poste.i

				mkdir -p /home/docker && touch /home/docker/appno.txt && (add_app_id)

				clear
				echo "poste.io已经安装完成"
				echo -e "${pink}------------------------${white}"
				echo "您可以使用以下地址访问poste.io:"
				echo "https://$yuming"
				echo ""
				;;
			3)
				docker rm -f mailserver
				docker rmi -f analogic/poste.io
				rm /home/docker/mail.txt
				rm -rf /home/docker/mail

				sed -i "/\b${app_id}\b/d" /home/docker/appno.txt
				echo "应用已卸载"
				;;

			*)
				break
				;;
		esac
		break_end
	done
}

# 青龙面板
qinglong_app(){
	local app_id="10"
	local docker_name="qinglong"
	local docker_img="whyour/qinglong:latest"
	local docker_port=5700

	docker_run() {
		docker run -d \
			-v /home/docker/qinglong/data:/ql/data \
			-p ${docker_port}:5700 \
			--name qinglong \
			--hostname qinglong \
			--restart unless-stopped \
			whyour/qinglong:latest
	}

	local docker_describe="青龙面板是一个定时任务管理平台"
	local docker_url="官网介绍: ${url_proxy}github.com/whyour/qinglong"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# vscode网页版(code-server)
code_server_app(){
	local app_id="11"
	local docker_name="code-server"
	local docker_img="codercom/code-server"
	local docker_port=8021

	docker_run() {
		docker run -d -p ${docker_port}:8080 -v /home/docker/vscode-web:/home/coder/.local/share/code-server --name vscode-web --restart always codercom/code-server
	}

	local docker_describe="VScode是一款强大的在线代码编写工具"
	local docker_url="官网介绍: ${url_proxy}github.com/coder/code-server"
	local docker_use="sleep 3"
	local docker_passwd="docker exec vscode-web cat /home/coder/.config/code-server/config.yaml"
	local app_size="1"
	docker_app

}

# Looking Glass测速面板
looking_glass_app(){
		local app_id="12"
		local docker_name="looking-glass"
		local docker_img="wikihostinc/looking-glass-server"
		local docker_port=8016

		docker_run() {
			docker run -d --name looking-glass --restart always -p ${docker_port}:80 wikihostinc/looking-glass-server
		}
		local docker_describe="Looking Glass是一个VPS网速测试工具, 多项测试功能, 还可以实时监控VPS进出站流量"
		local docker_url="官网介绍: ${url_proxy}github.com/wikihost-opensource/als"
		local docker_use=""
		local docker_passwd=""
		local app_size="1"
		docker_app
}

# 雷池WAF防火墙面板
safeline_app(){
	local app_id="13"
	local docker_name=safeline-mgt
	local docker_port=9443
	while true; do
		check_docker_app
		clear
		echo -e "雷池服务 $check_docker"
		echo "雷池是长亭科技开发的WAF站点防火墙程序面板, 可以反代站点进行自动化防御"
		echo "官网: https://waf-ce.chaitin.cn/"
		if docker ps -a --format '{{.Names}}' | grep -q "$docker_name" >/dev/null 2>&1; then
			check_docker_app_ip
		fi
		echo ""
		echo -e "${pink}------------------------${white}"
		echo "1. 安装           2. 更新           3. 重置密码           4. 卸载"
		echo -e "${pink}------------------------${white}"
		echo "0. 返回上一级选单"
		echo -e "${pink}------------------------${white}"
		read -e -p "输入你的选择: " choice

		case $choice in
			1)
				install_docker
				check_disk_space 5
				bash -c "$(curl -fsSLk https://waf-ce.chaitin.cn/release/latest/setup.sh)"

				mkdir -p /home/docker && touch /home/docker/appno.txt && (add_app_id)
				clear
				echo "雷池WAF面板已经安装完成"
				check_docker_app_ip
				docker exec safeline-mgt resetadmin

				;;

			2)
				bash -c "$(curl -fsSLk https://waf-ce.chaitin.cn/release/latest/upgrade.sh)"
				docker rmi $(docker images | grep "safeline" | grep "none" | awk '{print $3}')
				echo ""

				mkdir -p /home/docker && touch /home/docker/appno.txt && (add_app_id)
				clear
				echo "雷池WAF面板已经更新完成"
				check_docker_app_ip
				;;
			3)
				docker exec safeline-mgt resetadmin
				;;
			4)
				cd /data/safeline
				docker compose down --rmi all

				sed -i "/\b${app_id}\b/d" /home/docker/appno.txt
				echo "如果你是默认安装目录那现在项目已经卸载。如果你是自定义安装目录你需要到安装目录下自行执行:"
				echo "docker compose down && docker compose down --rmi all"
				;;
			*)
				break
				;;
		esac
		break_end
	done
}

# onlyoffice在线办公OFFICE
onlyoffice_app(){
	local app_id="14"
	local docker_name="onlyoffice"
	local docker_img="onlyoffice/documentserver"
	local docker_port=8018

	docker_run() {
		docker run -d -p ${docker_port}:80 \
			--restart=always \
			--name onlyoffice \
			-v /home/docker/onlyoffice/DocumentServer/logs:/var/log/onlyoffice  \
			-v /home/docker/onlyoffice/DocumentServer/data:/var/www/onlyoffice/Data  \
				onlyoffice/documentserver
	}

	local docker_describe="onlyoffice是一款开源的在线office工具, 太强大了！"
	local docker_url="官网介绍: https://www.onlyoffice.com/"
	local docker_use=""
	local docker_passwd=""
	local app_size="2"
	docker_app
}

# UptimeKuma监控工具
uptimekuma_app(){
	local app_id="15"
	local docker_name="uptime-kuma"
	local docker_img="louislam/uptime-kuma:latest"
	local docker_port=8022

	docker_run() {
		docker run -d \
			--name=uptime-kuma \
			-p ${docker_port}:3001 \
			-v /home/docker/uptime-kuma/uptime-kuma-data:/app/data \
			--restart=always \
			louislam/uptime-kuma:latest
	}

	local docker_describe="Uptime Kuma 易于使用的自托管监控工具"
	local docker_url="官网介绍: ${url_proxy}github.com/louislam/uptime-kuma"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# Memos网页备忘录
memos_app(){
	local app_id="16"
	local docker_name="memos"
	local docker_img="ghcr.io/usememos/memos:latest"
	local docker_port=8023

	docker_run() {
		docker run -d --name memos -p ${docker_port}:5230 -v /home/docker/memos:/var/opt/memos --restart always ghcr.io/usememos/memos:latest
	}

	local docker_describe="Memos是一款轻量级、自托管的备忘录中心"
	local docker_url="官网介绍: ${url_proxy}github.com/usememos/memos"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# drawio免费的在线图表软件
drawio_app(){
	local app_id="17"
	local docker_name="drawio"
	local docker_img="jgraph/drawio"
	local docker_port=8032

	docker_run() {
		docker run -d --restart=always --name drawio -p ${docker_port}:8080 -v /home/docker/drawio:/var/lib/drawio jgraph/drawio
	}

	local docker_describe="这是一个强大图表绘制软件。思维导图，拓扑图，流程图，都能画"
	local docker_url="官网介绍: https://www.drawio.com/"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# Sun-Panel导航面板
sun_panel_app(){
	local app_id="18"
	local docker_name="sun-panel"
	local docker_img="hslr/sun-panel"
	local docker_port=8033

	docker_run() {
		docker run -d --restart=always -p ${docker_port}:3002 \
			-v /home/docker/sun-panel/conf:/app/conf \
			-v /home/docker/sun-panel/uploads:/app/uploads \
			-v /home/docker/sun-panel/database:/app/database \
			--name sun-panel \
			hslr/sun-panel
	}

	local docker_describe="Sun-Panel服务器、NAS导航面板、Homepage、浏览器首页"
	local docker_url="官网介绍: https://doc.sun-panel.top/zh_cn/"
	local docker_use="echo \"账号: admin@sun.cc  密码: 12345678\""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# webssh网页版SSH连接工具
webssh_app(){
	local app_id="19"
	local docker_name="webssh"
	local docker_img="jrohy/webssh"
	local docker_port=8040
	docker_run() {
		docker run -d -p ${docker_port}:5032 --restart always --name webssh -e TZ=Asia/Shanghai jrohy/webssh
	}

	local docker_describe="简易在线ssh连接工具和sftp工具"
	local docker_url="官网介绍: ${url_proxy}github.com/Jrohy/webssh"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# LobeChatAI聊天聚合网站
lobe_chat(){
	local app_id="20"
	local docker_name="lobe-chat"
	local docker_img="lobehub/lobe-chat:latest"
	local docker_port=8036

	docker_run() {
		docker run -d -p ${docker_port}:3210 \
			--name lobe-chat \
			--restart=always \
			lobehub/lobe-chat
	}

	local docker_describe="LobeChat聚合市面上主流的AI大模型，ChatGPT/Claude/Gemini/Groq/Ollama"
	local docker_url="官网介绍: ${url_proxy}github.com/lobehub/lobe-chat"
	local docker_use=""
	local docker_passwd=""
	local app_size="2"
	docker_app
}

# MyIP工具箱
myip_app(){
	local app_id="21"
	local docker_name="myip"
	local docker_img="jason5ng32/myip:latest"
	local docker_port=8037

	docker_run() {
		docker run -d -p ${docker_port}:18966 --name myip jason5ng32/myip:latest
	}

	local docker_describe="是一个多功能IP工具箱，可以查看自己IP信息及连通性，用网页面板呈现"
	local docker_url="官网介绍: ${url_proxy}github.com/jason5ng32/MyIP/blob/main/README_ZH.md"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# ghproxy(GitHub加速站)
ghproxy_app(){
	local app_id="22"
	local docker_name="ghproxy"
	local docker_img="wjqserver/ghproxy:latest"
	local docker_port=8046

	docker_run() {
		docker run -d \
		--name ghproxy \
		--restart always \
		-p ${docker_port}:8080 \
		-v /home/docker/ghproxy/config:/data/ghproxy/config wjqserver/ghproxy:latest
	}

	local docker_describe="使用Go实现的GHProxy, 用于加速部分地区Github仓库的拉取。"
	local docker_url="官网介绍: https://github.com/WJQSERVER-STUDIO/ghproxy"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# AllinSSL证书管理平台
allinssl_app(){
	local app_id="23"
	local docker_name="allinssl"
	local docker_img="allinssl/allinssl:latest"
	local docker_port=8068

	docker_run() {
		docker run -itd --name allinssl -p ${docker_port}:8888 -v /home/docker/allinssl/data:/www/allinssl/data -e ALLINSSL_USER=allinssl -e ALLINSSL_PWD=allinssldocker -e ALLINSSL_URL=allinssl allinssl/allinssl:latest
	}

	local docker_describe="开源免费的 SSL 证书自动化管理平台"
	local docker_url="官网介绍: https://allinssl.com"
	local docker_use="echo \"安全入口: /allinssl\""
	local docker_passwd="echo \"用户名: allinssl  密码: allinssldocker\""
	local app_size="1"
	docker_app
}

# DDNS-GO
ddnsgo_app(){
	local app_id="24"
	local docker_name="ddns-go"
	local docker_img="jeessy/ddns-go"
	local docker_port=8067

	docker_run() {
		docker run -d \
			--name ddns-go \
			--restart=always \
			-p ${docker_port}:9876 \
			-v /home/docker/ddns-go:/root \
			jeessy/ddns-go
	}

	local docker_describe="自动将你的公网 IP(IPv4/IPv6)实时更新到各大 DNS 服务商，实现动态域名解析。"
	local docker_url="官网介绍: https://github.com/jeessy2/ddns-go"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# Lucky
lucky_app(){
	local app_id="25"
	local docker_name="lucky"
	local docker_img="gdy666/lucky"
	local docker_port=8068

	docker_run() {
		docker run -d \
		--name lucky \
		--restart=always \
		-v /home/docker/lucky:/goodluck \
		gdy666/lucky
	}

	local docker_describe="自动将你的公网 IP(IPv4/IPv6)实时更新到各大 DNS 服务商，实现动态域名解析。"
	local docker_url="官网介绍: https://github.com/gdy666/lucky"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# LibreTV私有影视
libretv_app(){
		local app_id="26"
		local docker_name="libretv"
		local docker_img="bestzwei/libretv:latest"
		local docker_port=8073

		docker_run() {
			read -e -p "设置LibreTV的登录密码: " app_passwd
			docker run -d \
				--name libretv \
				--restart unless-stopped \
				-p ${docker_port}:8080 \
				-e PASSWORD=${app_passwd} \
				bestzwei/libretv:latest
		}

		local docker_describe="免费在线视频搜索与观看平台"
		local docker_url="官网介绍: https://github.com/LibreSpark/LibreTV"
		local docker_use=""
		local docker_passwd=""
		local app_size="1"
		docker_app
}

# MoonTV私有影视
moontv_app(){
	local app_id="27"

	local app_name="moontv私有影视"
	local app_text="免费在线视频搜索与观看平台"
	local app_url="官网介绍: https://github.com/MoonTechLab/LunaTV"
	local docker_name="moontv-core"
	local docker_port="8074"
	local app_size="2"

	docker_app_install() {
		read -e -p "设置登录用户名: " admin
		while true; do
			read -e -p "设置登录用户密码: " admin_password
			if [ ${#admin_password} -ge 8 ]; then
				break
			else
				echo "密码长度必须大于8位, 请重新输入! "
			fi
		done
		read -e -p "输入授权码: " shouquanma


		mkdir -p /home/docker/moontv
		mkdir -p /home/docker/moontv/config
		mkdir -p /home/docker/moontv/data
		cd /home/docker/moontv

		curl -o /home/docker/moontv/docker-compose.yml ${url_proxy}raw.githubusercontent.com/kejilion/docker/main/moontv-docker-compose.yml
		sed -i "s/3000:3000/${docker_port}:3000/g" /home/docker/moontv/docker-compose.yml
		sed -i "s/USERNAME=admin/USERNAME=${admin}/g" /home/docker/moontv/docker-compose.yml
		sed -i "s/PASSWORD=admin_password/PASSWORD=${admin_password}/g" /home/docker/moontv/docker-compose.yml
		sed -i "s/shouquanma/${shouquanma}/g" /home/docker/moontv/docker-compose.yml
		cd /home/docker/moontv/
		docker compose up -d
		clear
		echo "已经安装完成"
		check_docker_app_ip
	}


	docker_app_update() {
		cd /home/docker/moontv/ && docker compose down --rmi all
		cd /home/docker/moontv/ && docker compose up -d
	}


	docker_app_uninstall() {
		cd /home/docker/moontv/ && docker compose down --rmi all
		rm -rf /home/docker/moontv
		echo "应用已卸载"
	}

	docker_app_plus
}

# Melody音乐精灵
melody_app(){
	local app_id="28"
	local docker_name="melody"
	local docker_img="foamzou/melody:latest"
	local docker_port=8075

	docker_run() {
		docker run -d \
			--name melody \
			--restart unless-stopped \
			-p ${docker_port}:5566 \
			-v /home/docker/melody/.profile:/app/backend/.profile \
			foamzou/melody:latest
	}

	local docker_describe="你的音乐精灵，旨在帮助你更好地管理音乐。"
	local docker_url="官网介绍: https://github.com/foamzou/melody"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# Beszel服务器监控
beszel_app(){
	local app_id="29"
	local docker_name="beszel"
	local docker_img="henrygd/beszel"
	local docker_port=8079

	docker_run() {
		mkdir -p /home/docker/beszel && \
		docker run -d \
			--name beszel \
			--restart=unless-stopped \
			-v /home/docker/beszel:/beszel_data \
			-p ${docker_port}:8090 \
			henrygd/beszel
	}

	local docker_describe="Beszel轻量易用的服务器监控"
	local docker_url="官网介绍: https://beszel.dev/zh/"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# SyncTV一起看片神器
synctv_app(){
		local app_id="30"
		local docker_name="synctv"
		local docker_img="synctvorg/synctv"
		local docker_port=8087

		docker_run() {
			docker run -d \
				--name synctv \
				-v /home/docker/synctv:/root/.synctv \
				-p ${docker_port}:8080 \
				--restart=always \
				synctvorg/synctv
		}

		local docker_describe="远程一起观看电影和直播的程序。它提供了同步观影、直播、聊天等功能"
		local docker_url="官网介绍: https://github.com/synctv-org/synctv"
		local docker_use="echo \"初始账号和密码: root  登陆后请及时修改登录密码\""
		local docker_passwd=""
		local app_size="1"
		docker_app
}

# X-UI面板
xui_app(){
	local app_id="31"
	local panel_path="[ -d "/usr/local/x-ui/" ]"
	local panelname="xui"
	local panelurl="https://github.com/FranzKafkaYu/x-ui"

	panel_app_install(){
		bash <(curl -Ls https://raw.githubusercontent.com/FranzKafkaYu/x-ui/master/install.sh)
	}

	panel_app_manage(){
		x-ui
	}

	panel_app_uninstall() {
		echo "请通过管理面板卸载, 谢谢！"
		break_end
	}
	panel_manage
}

# 3X-UI面板
3xui_app(){
	local app_id="32"
	local panel_path="[ -d "/usr/local/x-ui/" ]"
	local panelname="3xui"
	local panelurl="https://github.com/MHSanaei/3x-ui"

	panel_app_install(){
		bash <(curl -Ls https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh)
	}

	panel_app_manage(){
		x-ui
	}

	panel_app_uninstall() {
		echo "请通过管理面板卸载, 谢谢！"
		break_end
	}
	panel_manage
}

# Microsoft 365 E5 Renew X
e5_renew_x_app(){
		local app_id="33"
		local docker_name="angry_ellis"
		local docker_img="mcr.microsoft.com/office/office365"
		local docker_port=1066

		docker_run() {
		read -e -p "请输入发送邮件的服务邮箱: " send_email
		read -e -p "请输入服务邮箱的授权码: " token
		read -e -p "请输入接收邮件的邮箱: " receiver_email
		read -e -p "请输入Web界面管理员登录密码: " admin_pwd

			docker run -d \
				-p ${docker_port}:1066 \
				-e TZ=Asia/Shanghai \
				-e sender="${send_email}" \
				-e pwd="${token}" \
				-e receiver="${receiver_email}" \
				-e adminpwd="${admin_pwd}" \
				hanhongyong/ms365-e5-renew-x:pubemail
		}

		local docker_describe="Microsoft 365 E5 Renew X 一键续订脚本"
		local docker_url="官网介绍: https://github.com/hongyonghan/Docker_Microsoft365_E5_Renew_X"
		local docker_use=""
		local docker_passwd=""
		local app_size="1"
		docker_app
}




##############################
######## 应用中心菜单 #########
##############################
linux_app() {

	while true; do
		clear
		echo -e "应用市场"
		docker_tato
		echo -e "${cyan}------------------------${white}"
		echo -e "${cyan}1.  ${white}1Panel面板             ${cyan}2.  ${white}宝塔面板                 ${cyan}3.  ${white}aaPanel面板"
		echo -e "${cyan}4.  ${white}NginxProxyManager面板  ${cyan}5.  ${white}OpenList面板             ${cyan}6.  ${white}WebTop远程桌面网页版"
		echo -e "${cyan}7.  ${white}哪吒探针               ${cyan}8.  ${white}qbittorrent离线下载      ${cyan}9.  ${white}Poste.io邮件服务器程序"
		echo -e "${cyan}10. ${white}青龙面板               ${cyan}11. ${white}Code-Server(网页vscode)  ${cyan}12. ${white}Looking Glass(测速面板)"
		echo -e "${cyan}13. ${white}雷池WAF防火墙面板      ${cyan}14. ${white}onlyoffice在线办公OFFICE ${cyan}15. ${white}UptimeKuma监控工具"
		echo -e "${cyan}16. ${white}Memos网页备忘录        ${cyan}17. ${white}drawio免费的在线图表软件 ${cyan}18. ${white}Sun-Panel导航面板"
		echo -e "${cyan}19. ${white}webssh网页版SSH连接工具${cyan}20. ${white}LobeChatAI聊天聚合网站   ${cyan}21. ${white}MyIP工具箱"
		echo -e "${cyan}22. ${white}ghproxy(GitHub加速站)  ${cyan}23. ${white}AllinSSL证书管理平台     ${cyan}24. ${white}DDNS-GO"
		echo -e "${cyan}25. ${white}Lucky                  ${cyan}26. ${white}LibreTV私有影视          ${cyan}27. ${white}MoonTV私有影视"
		echo -e "${cyan}28. ${white}Melody音乐精灵         ${cyan}29. ${white}Beszel服务器监控         ${cyan}30. ${white}SyncTV一起看片神器"
		echo -e "${cyan}31. ${white}X-UI面板               ${cyan}32. ${white}3X-UI面板                ${cyan}33. ${white}Microsoft 365 E5 Renew X"
		echo -e "${cyan}------------------------${white}"
		echo -e "${yellow}0.   ${white}返回主菜单"
		echo -e "${cyan}------------------------${white}"
		read -e -p "请输入你的选择: " sub_choice

		case $sub_choice in
		1)
			1panel_app ;;
		2)
			bt_app ;;
		3)
			aapanel_app ;;
		4)
			npm_app ;;
		5)
			openlist_app ;;
		6)
			webtop_app ;;
		7)
			nezha_app ;;
		8)
			qb_app ;;
		9)
			poste_app ;;
		10)
			qinglong_app ;;
		11)
			code_server_app ;;
		12)
			looking_glass_app ;;
		13)
			safeline_app ;;
		14)
			onlyoffice_app ;;
		15)
			uptimekuma_app ;;
		16)
			memos_app ;;
		17)
			drawio_app ;;
		18)
			sun_panel_app ;;
		19)
			webssh_app ;;
		20)
			lobe_chat ;;
		21)
			myip_app ;;
		22)
			ghproxy_app ;;
		23)
			allinssl_app ;;
		24)
			ddnsgo_app ;;
		25)
			lucky_app ;;
		26)
			libretv_app ;;
		27)
			moontv_app ;;
		28)
			melody_app ;;
		29)
			beszel_app ;;
		30)
			synctv_app ;;
		31)
			xui_app ;;
		32)
			3xui_app ;;
		33)
			e5_renew_x_app ;;
		0)
			break
			;;
		*)
			echo -e "${red}无效选择，请重试${white}"
			pause
			;;
		esac
	done
}


#############################################################################
################################# 主菜单 #####################################
main_menu() {
    clear
    while true; do
		clear
		echo -e "${cyan}LinuxBox脚本工具箱 V$version${white}"
        echo -e "命令行输入${yellow} j ${cyan}可快速启动脚本${white}"
		echo -e ""
        echo -e "${cyan}------------------------${white}"
        echo -e "${cyan}1.   ${white}系统信息查询"
		echo -e "${cyan}2.   ${white}系统工具"
        echo -e "${cyan}3.   ${white}测试工具"
        echo -e "${cyan}4.   ${white}Docker容器管理"
        echo -e "${cyan}5.   ${white}LDNMP建站管理"
        echo -e "${cyan}6.   ${white}防火墙配置"
        echo -e "${cyan}7.   ${white}BBR加速管理"
        echo -e "${cyan}8.   ${white}应用市场"
        echo -e "${cyan}9.   ${white}Dev环境管理"
		echo -e "${cyan}------------------------${white}"
		echo -e "${yellow}0.     ${white}退出脚本"
		echo -e "${green}00.    ${white}更新脚本"
		echo -e "${red}555.   ${white}卸载脚本"
        echo -e "${cyan}------------------------${white}"

        read -e -p "请选择功能编号: " choice
        case $choice in
            1) system_info ;;
			2) linux_tools ;;
            3) network_tools ;; 
            4) linux_docker ;;
            5) linux_ldnmp ;;
            6) linux_firewall ;;
            7) linux_bbr ;;
            8) linux_app ;;
            9) echo "Dev环境管理(待实现)"; read -n1 -s -r -p "按任意键继续..." ;;
            0) 	clear 
				exit 0 ;;
			00) update_script ;;
			555) uninstall_script ;;
            *) echo "无效选择"; sleep 1 ;;
        esac
    done
}

os=$(detect_os)
if [ "$os" == "unsupported" ]; then
    error_exit "不支持的系统类型: $os_id"
fi
CheckFirstRun
dependency_check
main_menu
