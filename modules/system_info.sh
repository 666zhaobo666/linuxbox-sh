system_info() {
	clear
    echo -e "${green}=====系统信息查询=====${white}"
    echo -e ""
    echo -e "${cyan}主机名:       ${white}$(hostname)"
    echo -e "${cyan}系统版本:     ${white}$(cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '"')"
    echo -e "${cyan}Linux版本:    ${white}$(uname -r)"
    echo -e "${pink}------------------------------------------------------${white}"
    echo -e "${cyan}CPU架构:      ${white}$(uname -m)"
    echo -e "${cyan}CPU型号:      ${white}$(lscpu | grep 'Model name' | awk -F: '{print $2}' | xargs)"
    echo -e "${cyan}CPU核心数:    ${white}$(nproc)"
    echo -e "${cyan}CPU频率:      ${white}$(lscpu | grep 'MHz' | awk '{print $2/1000 " GHz"}')"
    echo -e "${pink}------------------------------------------------------${white}"
    echo -e "${cyan}CPU占用:      ${white}$(top -bn1 | grep 'Cpu(s)' | awk '{print $2}')%"
    echo -e "${cyan}系统负载:     ${white}$(uptime | awk -F'load average:' '{print $2}' | xargs)"
    echo -e "${cyan}物理内存:     ${white}$(free -m | awk '/Mem:/ {printf "%0.2f/%0.2fM (%0.2f%%)", $3, $2, $3/$2*100}')"
    echo -e "${cyan}虚拟内存:     ${white}$(free -m | awk '/Swap:/ {printf "%0.2f/%0.2fM (%0.2f%%)", $3, $2, ($2==0?0:$3/$2*100)}')"
    echo -e "${cyan}硬盘占用:     ${white}$(df -h / | awk 'NR==2{print $3"/"$2" ("$5")"}')"
    echo -e "${pink}------------------------------------------------------${white}"
    echo -e "${cyan}总接收:       ${white}$(cat /proc/net/dev | awk '/eth|ens|eno|enp|wlan/ {rx+=$2} END {printf "%.2fG", rx/1024/1024/1024}')"
    echo -e "${cyan}总发送:       ${white}$(cat /proc/net/dev | awk '/eth|ens|eno|enp|wlan/ {tx+=$10} END {printf "%.2fG", tx/1024/1024/1024}')"
    echo -e "${pink}------------------------------------------------------${white}"
    echo -e "${cyan}网络算法:     ${white}$(sysctl net.ipv4.tcp_congestion_control | awk -F= '{print $2}' | xargs)"
    echo -e "${pink}------------------------------------------------------${white}"
    echo -e "${cyan}运营商:       ${white}$(curl -s ipinfo.io/org)"
    echo -e "${cyan}IPv4地址:     ${white}$(hostname -I | awk '{print $1}')"
    echo -e "${cyan}DNS地址:      ${white}$(cat /etc/resolv.conf | grep nameserver | awk '{print $2}' | xargs)"
    echo -e "${cyan}地理位置:     ${white}$(curl -s ipinfo.io/city), $(curl -s ipinfo.io/country)"
    echo -e "${cyan}系统时间:     ${white}$(date '+%Z %Y-%m-%d %I:%M %p')"
    echo -e "${pink}------------------------------------------------------${white}"
    echo -e "${cyan}运行时长:     ${white}$(uptime -p | cut -d' ' -f2-)"
    echo -e "${pink}------------------------------------------------------${white}"
    echo -e "${green}操作完成${white}"
    break_end
    clear
}

###########################################################################
########################### 二、系统工具合集 ###############################
# ------------- 功能实现 -------------
# 1. 设置本脚本启动快捷键
set_script_shortcut() {
	clear
	root_use
	
	# 检查原脚本文件是否存在
	if [ ! -f "/usr/local/bin/$key" ]; then
		echo "错误：原脚本文件 /usr/local/bin/$key 不存在! "
		break_end
		return 1
	fi
	
	read -e -p "请输入你的选择(输入0退出): " new_key
	if [ "$new_key" == "0" ]; then
		break_end
		return 0
	fi
	
	# 检查输入是否为空
	if [ -z "$new_key" ]; then
		echo "错误：快捷键不能为空! "
		break_end
		return 1
	fi
	
	# 检查新快捷键是否已存在
	if [ -f "/usr/local/bin/$new_key" ]; then
		read -p "警告：快捷键 $new_key 已存在, 是否覆盖？(y/n) " confirm
		if [ "$confirm" != "y" ]; then
			echo "操作已取消"
			break_end
			return 0
		fi
	fi
	
	# 第一步：先修改原文件中的 key 变量（此时文件仍叫 $key）
	sed -i "s/key=\"$key\"/key=\"$new_key\"/g; s/key='$key'/key='$new_key'/g" "/usr/local/bin/$key"
	
	# 第二步：重命名文件（从 $key 改为 $new_key）
	mv -f "/usr/local/bin/$key" "/usr/local/bin/$new_key"
	
	echo -e "快捷键已设置为: $new_key"
	echo -e "请用新的快捷键进入脚本, 即将退出..."
	exit 0  # 退出当前脚本, 让用户用新快捷键重新启动
}

# 2. 修改登录密码（当前用户）
