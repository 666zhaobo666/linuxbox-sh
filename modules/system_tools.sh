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
    break_end
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
    break_end
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
	echo "端口号范围1到65535之间的数字.(输入0退出)"

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
			echo "端口号无效, 请输入1到65535之间的数字."
			## "输入无效SSH端口"
			break_end
		fi
	else
		echo "输入无效, 请输入数字."
		## "输入无效SSH端口"
		break_end
	fi
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
            echo -e "${green}已关闭SSH密码登录(请确保密钥登录可用)${white}"
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
    break_end
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
    break_end
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
		echo -e "${yellow}0.     ${white}返回上一级菜单"
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
		0)
			break # 返回上一级菜单
			;;
		*)
			echo -e "${red}无效选择, 请重新输入 !${white}"
			sleep 1
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
		echo -e "${yellow}0.     ${white}返回上一级菜单"
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

			0)
				break # 返回上一级菜单
				;;
			*)
				echo -e "${red}无效选择, 请重新输入 !${white}"
				sleep 1
				;;
		esac
	done
}

# 9. 查看端口占用状态
linux_port() {
    clear
	ss -tulnape
	break_end
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
		echo -e "${yellow}0.     ${white}返回上一级菜单"
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

			0)
				break # 返回上一级菜单
				;;
			*)
				echo -e "${red}无效选择, 请重新输入 !${white}"
				sleep 1
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
		echo -e "1. 创建普通账户             2. 创建高级账户"
		echo -e "${pink}------------------------------------------${white}"
		echo -e "3. 赋予最高权限             4. 取消最高权限"
		echo -e "${pink}------------------------------------------${white}"
		echo -e "5. 删除账号"
		echo -e "${pink}------------------------------------------${white}"
		echo -e "${yellow}0.     ${white}返回上一级菜单"
		echo -e "${pink}------------------------------------------${white}"
		read -e -p "请输入你的选择: " sub_choice

		case $sub_choice in
			1)
			# 提示用户输入新用户名
			read -e -p "请输入新用户名: " new_username

			# 创建新用户并设置密码
			useradd -m -s /bin/bash "$new_username"
			passwd "$new_username"

			echo "操作已完成."
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

			echo "操作已完成."

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
				break  # 跳出循环, 退出菜单
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
		echo -e "${yellow}0.     ${white}返回上一级菜单"
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
			0)
				break # 返回上一级菜单
				;;
			*)
				echo -e "${red}无效选择, 请重新输入 !${white}"
				sleep 1
				;;
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
				# 其他系统, 如 Debian, Ubuntu, CentOS 等
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
			echo "已退出, 未更改主机名."
			break
		fi
	done
}

# 14. 切换系统更新源
switch_update_source() {
	while true; do
		root_use
		clear
		echo "选择更新源区域"
		echo "接入LinuxMirrors切换系统更新源"
		echo -e "${pink}------------------------${white}"
		echo "1. 中国大陆【默认】          2. 中国大陆【教育网】          3. 海外地区"
		echo -e "${pink}------------------------${white}"
		echo -e "${yellow}0.     ${white}返回上一级菜单"
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
			0)
				break # 返回上一级菜单
				;;
			*)
				echo -e "${red}无效选择, 请重新输入 !${white}"
				sleep 1
				;;
		esac
	done
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
		echo -e "${yellow}0.     ${white}返回上一级菜单"
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
						read -e -p "选择周几执行任务？ (0-6, 0代表星期日): " weekday
						(crontab -l ; echo "0 0 * * $weekday $newquest") | crontab - > /dev/null 2>&1
						;;
					3)
						read -e -p "选择每天几点执行任务？（小时, 0-23）: " hour
						(crontab -l ; echo "0 $hour * * * $newquest") | crontab - > /dev/null 2>&1
						;;
					4)
						read -e -p "输入每小时的第几分钟执行任务？（分钟, 0-60）: " minute
						(crontab -l ; echo "$minute * * * * $newquest") | crontab - > /dev/null 2>&1
						;;
					0)
						break # 返回上一级菜单
						;;
					*)
						echo -e "${red}无效选择, 请重新输入 !${white}"
						sleep 1
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
			0)
				break # 返回上一级菜单
				;;
			*)
				echo -e "${red}无效选择, 请重新输入 !${white}"
				sleep 1
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
            echo -e "${red}错误：未安装 $tool, 请先安装（例如: sudo apt install $tool 或 sudo yum install $tool）${white}"
            return 1
        fi
        return 0
    }

    while true; do
        clear
        echo -e "${blue}文件管理器 - 当前目录: $current_dir${white}"
        echo -e "${cyan}目录内容:${white}"
        ls -la --color=auto "$current_dir"

        echo -e "\n${green}功能菜单:${white}"
        echo "1. 进入目录		2. 创建目录		3. 重命名目录		4. 删除目录"
        echo "5. 修改目录权限		6. 返回上一级目录"
		echo -e "${pink}--------------------------------------------------------------------------------------${white}"
        echo "7. 创建文件		8. 编辑文件		9. 重命名文件		10. 删除文件"
		echo "11. 修改文件权限"
		echo -e "${pink}--------------------------------------------------------------------------------------${white}"
        echo "12. 压缩文件目录	13. 解压文件目录	14. 复制文件目录	15. 移动文件目录"
        echo "16. 传输文件至远程服务器(scp)"
		echo -e "${pink}--------------------------------------------------------------------------------------${white}"
        echo -e "${yellow}0. 退出文件管理器${white}"
		echo -e "${pink}--------------------------------------------------------------------------------------${white}"

        read -e -p "请选择功能编号: " file_choice
        case $file_choice in
            1)  # 进入目录
                read -p "请输入目录名: " subdir
                if [ -d "$current_dir/$subdir" ]; then
                    current_dir="$current_dir/$subdir"
                else
                    echo -e "${red}目录不存在${white}"; break_end
                fi
                ;;
            2)  # 创建目录
                read -p "请输入新目录名: " newdir
                mkdir -p "$current_dir/$newdir"
                echo -e "${green}目录创建成功${white}"; break_end
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
                break_end
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
                break_end
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
                break_end
                ;;
            6)  # 返回上一级目录
                if [ "$current_dir" != "/" ]; then
                    current_dir=$(dirname "$current_dir")
                else
                    echo -e "${yellow}已在根目录${white}"; break_end
                fi
                ;;
            7)  # 创建文件
                read -p "请输入文件名: " filename
                touch "$current_dir/$filename"
                echo -e "${green}文件创建成功${white}"; break_end
                ;;
            8)  # 编辑文件（nano）
                read -p "请输入文件名: " filename
                if [ -f "$current_dir/$filename" ]; then
                    nano "$current_dir/$filename"
                else
                    echo -e "${red}文件不存在${white}"; break_end
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
                break_end
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
                break_end
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
                break_end
                ;;
            12)  # 压缩文件/目录（多格式选择）
                read -p "请输入要压缩的名称: " src
                if [ ! -e "$current_dir/$src" ]; then
                    echo -e "${red}目标不存在${white}"; break_end; break
                fi
                
                echo -e "\n${cyan}支持的压缩格式:${white}"
                echo "1. tar.gz（推荐, 跨平台）"
                echo "2. zip（Windows兼容）"
                echo "3. 7z（高压缩率）"
                read -p "请选择压缩格式(1-3): " compress_type
                
                read -p "请输入压缩包名（不含后缀）: " dst
                local success=0
                
                case $compress_type in
                    1)
                        # tar.gz 依赖 tar
                        if ! command -v tar &>/dev/null; then
                            echo -e "${cyan}检测到 tar 未安装, 开始安装...${white}"
                            install tar
                        fi
                        tar -zcvf "$current_dir/$dst.tar.gz" -C "$current_dir" "$src"
                        echo -e "${green}压缩完成: $dst.tar.gz${white}"
                        ;;
                    2)
                        # zip 依赖 zip
                        if ! command -v zip &>/dev/null; then
                            echo -e "${cyan}检测到 zip 未安装, 开始安装...${white}"
                            install zip
                        fi
                        zip -r "$current_dir/$dst.zip" "$current_dir/$src"
                        echo -e "${green}压缩完成: $dst.zip${white}"
                        ;;
                    3)
                        # 7z 依赖 7z, 不同系统包名可能有差异, 这里用 7z 作为参数调用 install
                        if ! command -v 7z &>/dev/null; then
                            echo -e "${cyan}检测到 7z 未安装, 开始安装...${white}"
                            install p7zip  # 常见发行版中 7z 一般由 p7zip 包提供, 若不行可根据实际调整
                        fi
                        7z a "$current_dir/$dst.7z" "$current_dir/$src"
                        echo -e "${green}压缩完成: $dst.7z${white}"
                        ;;
                    *)
						echo -e "${red}无效选择, 请重新输入 !${white}"
						sleep 1
						;;
                esac
                break_end
                ;;
            13)  # 解压文件（自动识别格式）
                read -p "请输入要解压的文件名: " archive
                if [ ! -f "$current_dir/$archive" ]; then
                    echo -e "${red}压缩文件不存在${white}"; break_end; break
                fi
                
                local ext="${archive##*.}"
                local success=0
                
                case $ext in
                    gz|tar.gz)
                        if ! command -v tar &>/dev/null; then
                            echo -e "${cyan}检测到 tar 未安装, 开始安装...${white}"
                            install tar
                        fi
                        tar -zxvf "$current_dir/$archive" -C "$current_dir"
                        echo -e "${green}解压完成${white}"
                        ;;
                    zip)
                        if ! command -v unzip &>/dev/null; then
                            echo -e "${cyan}检测到 unzip 未安装, 开始安装...${white}"
                            install unzip
                        fi
                        unzip "$current_dir/$archive" -d "$current_dir"
                        echo -e "${green}解压完成${white}"
                        ;;
                    7z)
                        if ! command -v 7z &>/dev/null; then
                            echo -e "${cyan}检测到 7z 未安装, 开始安装...${white}"
                            install p7zip
                        fi
                        7z x "$current_dir/$archive" -o"$current_dir"
                        echo -e "${green}解压完成${white}"
                        ;;
                    *)
                        echo -e "${red}不支持的压缩格式(仅支持tar.gz/zip/7z)${white}"; success=0
                        ;;
                esac
                break_end
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
                break_end
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
                break_end
                ;;
            16)  # 传输文件至远程服务器（scp）
                read -p "请输入要传输的文件: " file
                if [ -f "$current_dir/$file" ]; then
                    read -p "请输入远程地址(user@host:path): " remote
                    scp "$current_dir/$file" "$remote" && echo -e "${green}传输完成${white}"
                else
                    echo -e "${red}文件不存在${white}"
                fi
                break_end
                ;;
            0)  # 退出文件管理器
                return 0
                ;;
            *)
				echo -e "${red}无效选择, 请重新输入 !${white}"
				sleep 1
				;;
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
				echo -e "${green}系统语言已经修改为: $lang 重新连接SSH生效.${white}"
				hash -r
				break_end

				;;
			centos|rhel|almalinux|rocky|fedora)
				install glibc-langpack-zh
				localectl set-locale LANG=${lang}
				echo "LANG=${lang}" | tee /etc/locale.conf
				echo -e "${green}系统语言已经修改为: $lang 重新连接SSH生效.${white}"
				hash -r
				break_end
				;;
			*)
				echo "不支持的系统: $ID"
				break_end
				;;
		esac
	else
		echo "不支持的系统, 无法识别系统类型."
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
		echo -e "${yellow}0.     ${white}返回上一级菜单"
		echo -e "${pink}------------------------${white}"
		read -e -p "请输入你的选择: " choice

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
		echo -e "启用后rm删除的文件先进入回收站, 防止误删重要文件!"
		echo -e "${pink}------------------------------------------------${white}"
		ls -l --color=auto "$TRASH_DIR" 2>/dev/null || echo "回收站为空"
		echo -e "${pink}------------------------${white}"
		echo "1. 启用回收站          2. 关闭回收站"
		echo "3. 还原内容            4. 清空回收站"
		echo -e "${pink}------------------------${white}"
		echo -e "${yellow}0.     ${white}返回上一级菜单"
		echo -e "${pink}------------------------${white}"
		read -e -p "输入你的选择: " choice

		case $choice in
		1)
			install trash-cli
			sed -i '/alias rm/d' "$bashrc_profile"
			echo "alias rm='trash-put'" >> "$bashrc_profile"
			source "$bashrc_profile"
			echo "回收站已启用, 删除的文件将移至回收站."
			break_end
			;;
		2)
			remove trash-cli
			sed -i '/alias rm/d' "$bashrc_profile"
			echo "alias rm='rm -i'" >> "$bashrc_profile"
			source "$bashrc_profile"
			echo "回收站已关闭, 文件将直接删除."
			break_end
			;;
		3)
			read -e -p "输入要还原的文件名: " file_to_restore
			if [ -e "$TRASH_DIR/$file_to_restore" ]; then
			mv "$TRASH_DIR/$file_to_restore" "$HOME/"
			echo "$file_to_restore 已还原到主目录."
			else
			echo "文件不存在."
			fi
			;;
		4)
			read -e -p "确认清空回收站？[y/n]: " confirm
			if [[ "$confirm" == "y" ]]; then
			trash-empty
			echo "回收站已清空."
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

	# 检查配置文件和密钥目录是否存在, 如果不存在则创建
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
		echo -e "${yellow}0.     ${white}返回上一级菜单"
		echo -e "${pink}------------------------${white}"
		read -e -p "请输入你的选择: " choice
		case $choice in
			1) add_connection ;;
			2) use_connection ;;
			3) delete_connection ;;
			0) break ;;
			*) 
				echo -e "${red}无效选择, 请重新输入 !${white}"
				sleep 1
				;;
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
		echo "分区不存在!"
		return
	fi

	# 检查分区是否已经挂载
	if lsblk -o MOUNTPOINT | grep -w "$PARTITION" > /dev/null; then
		echo "分区已经挂载!"
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
		echo "分区挂载失败!"
		rmdir "$MOUNT_POINT"
	fi
}

# 卸载分区
unmount_partition() {
	read -e -p "请输入要卸载的分区名称（例如 sda1）: " PARTITION

	# 检查分区是否已经挂载
	MOUNT_POINT=$(lsblk -o MOUNTPOINT | grep -w "$PARTITION")
	if [ -z "$MOUNT_POINT" ]; then
		echo "分区未挂载!"
		return
	fi

	# 卸载分区
	umount "/dev/$PARTITION"

	if [ $? -eq 0 ]; then
		echo "分区卸载成功: $MOUNT_POINT"
		rmdir "$MOUNT_POINT"
	else
		echo "分区卸载失败!"
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
		echo "分区不存在!"
		return
	fi

	# 检查分区是否已经挂载
	if lsblk -o MOUNTPOINT | grep -w "$PARTITION" > /dev/null; then
		echo "分区已经挂载, 请先卸载!"
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
		*) 
			echo -e "${red}无效选择, 请重新输入 !${white}"
			return 
			;;
	esac

	# 确认格式化
	read -e -p "确认格式化分区 /dev/$PARTITION 为 $FS_TYPE 吗？(y/n): " CONFIRM
	if [ "$CONFIRM" != "y" ]; then
		echo "操作已取消."
		return
	fi

	# 格式化分区
	echo "正在格式化分区 /dev/$PARTITION 为 $FS_TYPE ..."
	mkfs.$FS_TYPE "/dev/$PARTITION"

	if [ $? -eq 0 ]; then
		echo "分区格式化成功!"
	else
		echo "分区格式化失败!"
	fi
}

# 检查分区状态
check_partition() {
	read -e -p "请输入要检查的分区名称（例如 sda1）: " PARTITION

	# 检查分区是否存在
	if ! lsblk -o NAME | grep -w "$PARTITION" > /dev/null; then
		echo "分区不存在!"
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
		echo -e "${yellow}该功能内部测试阶段, 请勿在生产环境使用.${white}"
		echo -e "${pink}------------------------${white}"
		list_partitions
		echo -e "${pink}------------------------${white}"
		echo "1. 挂载分区        2. 卸载分区        3. 查看已挂载分区"
		echo "4. 格式化分区      5. 检查分区状态"
		echo -e "${pink}------------------------${white}"
		echo -e "${yellow}0.     ${white}返回上一级菜单"
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
echo -e "${green}变更完成.重新连接SSH后可查看变化!${white}"

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
		echo -e "${yellow}0. 返回上一级菜单${white}"
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
        echo -e "${green}===== 系统工具菜单 =====${white}"
		echo ""
        echo -e "${cyan}1.  ${white}设置脚本启动快捷键          ${cyan}2.  ${white}修改用户登录密码"
        echo -e "${cyan}3.  ${white}修改root登录密码            ${cyan}4.  ${white}修改ssh连接端口"
        echo -e "${cyan}5.  ${white}打开/关闭ssh密码登录        ${cyan}6.  ${white}打开/关闭ssh root登录"
        echo -e "${cyan}7.  ${white}优化DNS地址                 ${cyan}8.  ${white}切换优先ipv4/ipv6"
        echo -e "${cyan}9.  ${white}查看端口占用状态            ${cyan}10. ${white}修改虚拟内存大小"
		echo -e "${pink}--------------------------------------------------------${white}"
        echo -e "${cyan}11. ${white}用户管理			${cyan}12. ${white}系统时区调整"
        echo -e "${cyan}13. ${white}修改主机名			${cyan}14. ${white}切换系统更新源"
        echo -e "${cyan}15. ${white}定时任务管理		${cyan}16. ${white}文件管理器"
        echo -e "${cyan}17. ${white}切换系统语言		${cyan}18. ${white}设置系统回收站"
        echo -e "${cyan}19. ${white}ssh远程连接工具		${cyan}20. ${white}硬盘分区管理工具"
		echo -e "${pink}--------------------------------------------------------${white}"
        echo -e "${cyan}21. ${white}命令行历史记录		${cyan}22. ${white}命令收藏夹"
        echo -e "${cyan}23. ${white}命令行美化工具		${cyan}24. ${white}脚本升级管理"
        echo -e "${pink}--------------------------------------------------------${white}"
        echo -e "${yellow}0.${white}  ${white}返回上一级菜单${white}"
		echo -e "${pink}--------------------------------------------------------${white}"
        echo -e "${white}请输入你的选择: ${white}\c"
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
            24) update_management_menu ;;
            0) return ;;
            *) 
				echo -e "${red}无效选择, 请重新输入 !${white}"
				sleep 1
				;;
        esac
    done
}

###########################################################################
########################### 系统工具扩展 ###################################
# 包含升级管理、版本回滚等功能

# 升级管理菜单
update_management_menu() {
    while true; do
        clear
        echo -e "${green}===== 脚本升级管理 =====${white}"
        echo ""
        echo -e "${cyan}当前版本: ${green}${version}${white}"
        echo ""
        echo -e "${pink}------------------------${white}"
        echo -e "${cyan}1.  ${white}检查并更新到最新版本"
        echo -e "${cyan}2.  ${white}查看更新日志"
        echo -e "${cyan}3.  ${white}版本回滚"
        echo -e "${cyan}4.  ${white}查看备份列表"
        echo -e "${cyan}5.  ${white}清理旧备份"
        echo -e "${pink}------------------------${white}"
        echo -e "${yellow}0.  ${white}返回"
        echo -e "${pink}------------------------${white}"
        read -e -p "请选择: " choice

        case $choice in
            1)
                update_script
                ;;
            2)
                view_changelog
                ;;
            3)
                rollback_version
                ;;
            4)
                list_backups
                ;;
            5)
                clean_old_backups
                ;;
            0)
                return
                ;;
            *)
                echo -e "${red}无效选择${white}"
                sleep 1
                ;;
        esac
    done
}

# 列出备份
list_backups() {
    clear
    echo -e "${cyan}===== 备份列表 =====${white}"

    if [ ! -d "${SCRIPT_HOME}/backup" ] || [ -z "$(ls -A "${SCRIPT_HOME}/backup" 2>/dev/null)" ]; then
        echo -e "${yellow}没有可用的备份${white}"
        break_end
        return 1
    fi

    local i=1
    echo -e "${cyan}序号  备份时间              版本           大小${white}"
    echo -e "${pink}------------------------------------------------${white}"

    ls -t "${SCRIPT_HOME}/backup/" | while read -r backup; do
        local backup_path="${SCRIPT_HOME}/backup/${backup}"
        local backup_version="unknown"
        local backup_size="0"

        if [ -f "${backup_path}/LinuxBox.sh" ]; then
            backup_version=$(grep '^version=' "${backup_path}/LinuxBox.sh" | head -n 1 | cut -d '"' -f 2)
        fi

        if [ -d "$backup_path" ]; then
            backup_size=$(du -sh "$backup_path" 2>/dev/null | cut -f1)
        fi

        printf "%-5s %-20s %-14s %s\n" "$i" "$backup" "$backup_version" "$backup_size"
        i=$((i + 1))
    done

    echo ""
    break_end
}

# 清理旧备份
clean_old_backups() {
    clear
    echo -e "${cyan}===== 清理旧备份 =====${white}"

    local backup_count
    backup_count=$(ls -1 "${SCRIPT_HOME}/backup/" 2>/dev/null | wc -l)

    if [ "$backup_count" -eq 0 ]; then
        echo -e "${yellow}没有备份需要清理${white}"
        break_end
        return 1
    fi

    echo -e "当前共有 ${cyan}${backup_count}${white} 个备份"
    echo ""
    read -e -p "保留最近几个备份？(默认保留5个): " keep_count
    keep_count=${keep_count:-5}

    if [ "$keep_count" -lt 1 ]; then
        echo -e "${red}至少需要保留1个备份${white}"
        break_end
        return 1
    fi

    if [ "$backup_count" -le "$keep_count" ]; then
        echo -e "${yellow}备份数量(${backup_count})未超过保留数量(${keep_count})，无需清理${white}"
        break_end
        return 0
    fi

    local delete_count=0
    ls -t "${SCRIPT_HOME}/backup/" | tail -n +$((keep_count + 1)) | while read -r old_backup; do
        rm -rf "${SCRIPT_HOME}/backup/${old_backup}"
        echo -e "${grey}已删除: ${old_backup}${white}"
        delete_count=$((delete_count + 1))
    done

    echo ""
    echo -e "${green}✓ 清理完成，保留了最近 ${keep_count} 个备份${white}"
    break_end
}

# 查看模块版本信息
show_module_info() {
    clear
    echo -e "${cyan}===== 模块信息 =====${white}"
    echo ""
    echo -e "${cyan}脚本版本: ${green}${version}${white}"
    echo -e "${cyan}安装目录: ${LINUXBOX_LIB_DIR}${white}"
    echo -e "${cyan}配置目录: ${SCRIPT_HOME}${white}"
    echo ""

    echo -e "${cyan}Lib 目录文件:${white}"
    for file in "${LINUXBOX_LIB_DIR}"/lib/*.sh; do
        if [ -f "$file" ]; then
            local filename
            filename=$(basename "$file")
            local lines
            lines=$(wc -l < "$file")
            printf "  %-25s %5s 行\n" "$filename" "$lines"
        fi
    done

    echo ""
    echo -e "${cyan}Modules 目录文件:${white}"
    for file in "${LINUXBOX_LIB_DIR}"/modules/*.sh; do
        if [ -f "$file" ]; then
            local filename
            filename=$(basename "$file")
            local lines
            lines=$(wc -l < "$file")
            printf "  %-25s %5s 行\n" "$filename" "$lines"
        fi
    done

    echo ""
    echo -e "${cyan}总代码行数:${white}"
    find "${LINUXBOX_LIB_DIR}" -name "*.sh" -exec wc -l {} + | tail -1

    break_end
}
