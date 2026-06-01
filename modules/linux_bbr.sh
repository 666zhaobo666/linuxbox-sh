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

			echo -e "${green}===== BBR管理 =====${white}"
			echo ""
			echo -e "${pink}------------------------${white}"
			echo "1. 开启BBRv3              2. 关闭BBRv3(会重启)"
			echo -e "${pink}------------------------${white}"
			echo -e "${yellow}0.     ${white}返回上一级菜单"
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
				0)
					break # 返回上一级菜单
					;;
				*)
					echo -e "${red}无效选择, 请重新输入 !${white}"
					sleep 1
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

