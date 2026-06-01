###########################################################################
########################### 三、测试工具合集 ###############################
network_tools() {
	while true; do
		clear
        echo -e "${green}===== 测试脚本菜单 =====${white}"
		echo ""
		echo -e "${yellow}IP及解锁状态检测"
		echo -e "${cyan}1.   ${white}ChatGPT 解锁状态检测"
		echo -e "${cyan}2.   ${white}Region 流媒体解锁测试"
		echo -e "${cyan}3.   ${white}yeahwu 流媒体解锁检测"
		echo -e "${cyan}4.   ${white}xykt IP质量体检脚本 ${yellow}★${white}"

		echo -e "${pink}------------------------------------${white}"
		echo -e "${yellow}网络线路测速"
		echo -e "${cyan}11.  ${white}besttrace 三网回程延迟路由测试"
		echo -e "${cyan}12.  ${white}mtr_trace 三网回程线路测试"
		echo -e "${cyan}13.  ${white}Superspeed 三网测速"
		echo -e "${cyan}14.  ${white}nxtrace 快速回程测试脚本"
		echo -e "${cyan}15.  ${white}nxtrace 指定IP回程测试脚本"
		echo -e "${cyan}16.  ${white}ludashi2020 三网线路测试"
		echo -e "${cyan}17.  ${white}i-abc 多功能测速脚本"
		echo -e "${cyan}18.  ${white}NetQuality 网络质量体检脚本 ${yellow}★${white}"

		echo -e "${pink}------------------------------------${white}"
		echo -e "${yellow}硬件性能测试"
		echo -e "${cyan}21.  ${white}yabs 性能测试"
		echo -e "${cyan}22.  ${white}icu/gb5 CPU性能测试脚本"

		echo -e "${pink}------------------------------------${white}"
		echo -e "${yellow}综合性测试"
		echo -e "${cyan}31.  ${white}bench 性能测试"
		echo -e "${cyan}32.  ${white}spiritysdx 融合怪测评 ${yellow}★${white}"
		echo -e "${pink}------------------------------------${white}"
		echo -e "${yellow}0.   ${white}返回主菜单"
		echo -e "${pink}------------------------------------${white}"
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
				echo -e "${red}无效选择, 请重新输入 !${white}"
				sleep 1
				;;
		esac
	done
}
