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
		echo "${panelname}是一款时下流行且强大的运维管理面板."
		echo "官网介绍: $panelurl "

		# 面板应用: 不走端口表, 只展示官网作为参考入口
		echo ""
		echo -e "${cyan}参考入口${white}:  ${green}$panelurl${white}"

		echo ""
		echo -e "${pink}------------------------${white}"
		echo "1. 安装            2. 管理            3. 卸载"
		echo -e "${pink}------------------------${white}"
		echo -e "${yellow}0.     ${white}返回上一级菜单"
		echo -e "${pink}------------------------${white}"
		read -e -p "请输入你的选择: " choice
		case $choice in
			1)
				check_disk_space 1
				install wget
				iptables_open
				panel_app_install

				add_app_id
				;;
			2)
				# 修复检测 bug: 未装就管理会误标为已装
				check_panel_app
				if [ "$check_panel" = "${green}已安装${white}" ]; then
					panel_app_manage
					add_app_id
				else
					echo -e "${red}面板未安装, 请先安装${white}"
					sleep 1
				fi

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
		echo "无法确定操作系统."
		return
	fi

	echo -e "${green}crontab 已安装且 cron 服务正在运行.${white}"
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
				echo -e "${red}无效选择, 请重新输入 !${white}"
				sleep 1
				;;
		esac
		return
	fi
}

# 检查Docker应用是否安装
check_docker_app() {
	if docker ps -a --format '{{.Names}}' | grep -q "^${docker_name}$" >/dev/null 2>&1 ; then
		check_docker="${green}已安装${white}"
		return 0
	else
		check_docker="${grey}未安装${white}"
		return 1
	fi
}

# 检查Docker应用的访问地址
check_docker_app_ip() {
echo -e "${pink}------------------------${white}"
echo "${access_label:-访问地址}:"
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
		echo "错误：请提供端口号和允许访问的 IP."
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
		echo "错误：请提供端口号和允许访问的 IP."
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


#############################################################################
####################### 多端口注册 + 状态查询框架 ############################
#############################################################################
# 全局端口注册表 (每个 app 函数入口前由 clear_app_ports 清空).
# 应用通过 add_app_port "label" port 注册 1..N 个对外暴露的访问入口.
# 框架在 UI 统一渲染成表格; 兼容老 app 仅声明 docker_port 的情况, 自动派生
# 一个 "访问地址" 入口. port_mode / access_label 旧变量已废弃, 不再读取.
APP_PORTS_LABELS=()
APP_PORTS_NUMBERS=()

# 注册一个访问入口
add_app_port() {
	APP_PORTS_LABELS+=("$1")
	APP_PORTS_NUMBERS+=("$2")
}

# 清空端口注册 (linux_app dispatch 入口调用, 防残留)
clear_app_ports() {
	APP_PORTS_LABELS=()
	APP_PORTS_NUMBERS=()
}

# 获取主端口 (第一个注册的); 若空则回退到 $docker_port 兼容老 app
get_primary_port() {
	if [ ${#APP_PORTS_NUMBERS[@]} -gt 0 ]; then
		echo "${APP_PORTS_NUMBERS[0]}"
	elif [ -n "${docker_port:-}" ]; then
		echo "$docker_port"
	fi
}

# (no-op) 框架不再自动注册, app 必须在 docker_run 里显式 add_app_port
_auto_register_fallback_port() { :; }

# 全局 app 注册表 (供 666 已安装列表展示 app_name)
APP_REGISTRY_IDS=()
APP_REGISTRY_NAMES=()

# 全局显示名映射: sub_choice → 中文显示名 (linux_app 菜单 + 666 列表共用)
# 维护: 与 linux_app() case 语句的顺序一致. 改 case 时同步更新这里.
declare -A APP_DISPLAY_NAMES=(
	[1]="1Panel面板"           [2]="宝塔面板"             [3]="aaPanel面板"
	[4]="NginxProxyManager面板" [5]="OpenList面板"         [6]="WebTop远程桌面网页版"
	[7]="哪吒探针"              [8]="qbittorrent离线下载"  [9]="Poste.io邮件服务器程序"
	[10]="青龙面板"             [11]="Code-Server(网页vscode)" [12]="Looking Glass(测速面板)"
	[13]="雷池WAF防火墙面板"   [14]="onlyoffice在线办公OFFICE" [15]="UptimeKuma监控工具"
	[16]="Memos网页备忘录"      [17]="drawio免费的在线图表软件" [18]="Sun-Panel导航面板"
	[19]="webssh网页版SSH连接工具" [20]="LobeChatAI聊天聚合网站" [21]="MyIP工具箱"
	[22]="ghproxy(GitHub加速站)" [23]="AllinSSL证书管理平台" [24]="DDNS-GO"
	[25]="Lucky"                [26]="LibreTV私有影视"      [27]="MoonTV私有影视"
	[28]="Melody音乐精灵"       [29]="Beszel服务器监控"     [30]="SyncTV一起看片神器"
	[31]="X-UI面板"             [32]="3X-UI面板"            [33]="Microsoft 365 E5 Renew X"
	[34]="DecoTV私有影视"       [35]="Drawnix在线白板"
	[36]="Portainer容器管理"    [37]="Cloudreve网盘"        [38]="Nextcloud私有网盘"
	[39]="emby媒体管理"         [40]="jellyfin媒体管理"     [41]="AdGuardHome去广告"
	[42]="Navidrome音乐服务器"  [43]="Vaultwarden密码管理"  [44]="StirlingPDF工具大全"
	[45]="Speedtest测速面板"    [46]="PhotoPrism私有相册"   [47]="searxng聚合搜索"
	[48]="Pingvin-Share文件分享" [49]="Dockge容器管理"       [50]="it-tools工具箱"
	[51]="n8n自动化工作流"      [52]="OpenWebUI自托管AI"    [53]="Dify大模型知识库"
	[54]="gitea私有代码仓库"    [55]="FileBrowser文件管理"  [56]="FRP内网穿透(服务端)"
	[57]="WireGuard组网(服务端)" [58]="JumpServer堡垒机"     [59]="immich图片视频管理"
	[60]="Syncthing文件同步"    [61]="Umami网站统计"        [62]="思源笔记"
	[63]="SFTPGo文件传输"       [64]="Owncast自托管直播"     [65]="Deepseek AI大模型"
	[66]="RocketChat聊天系统"   [67]="Gopeed高速下载"       [68]="2FAuth二步验证器"
	[69]="ZFile在线网盘"        [70]="Nexterm远程连接"      [71]="JitsiMeet视频会议"
	[72]="Stream四层代理转发"   [73]="FileCodeBox文件快递"  [74]="Matrix去中心化聊天"
	[75]="yt-dlp视频下载"       [76]="paperless文档管理"    [77]="Wallos财务管理"
	[78]="komari服务器监控"     [79]="Dufs静态文件服务器"   [80]="PandaWiki文档管理"
	[81]="linkwarden书签管理"   [82]="VoceChat聊天系统"     [83]="Karakeep书签管理"
	[84]="NewAPI大模型资产管理" [85]="RAGFlow知识库"        [86]="AstrBot聊天机器人"
	[87]="LangBot聊天机器人"    [88]="多格式文件转换"       [89]="LibreSpeed测速"
	[90]="gpt-load AI透明代理"  [91]="补货监控工具"         [92]="PVE虚拟化管理"
	[93]="DSM群晖虚拟机"        [94]="在线DOS老游戏"        [95]="迅雷离线下载"
	[96]="小雅Alist全家桶"      [97]="Bililive直播录制"     [98]="极简朋友圈"
	[99]="PanSou网盘搜索"       [100]="简单图床lskypro"     [101]="禅道项目管理"
	[102]="QD-Today定时任务"    [103]="耗子管理面板"        [104]="AMH建站面板"
	[105]="在线翻译服务器"      [106]="AI视频生成工具"      [107]="RustDesk远程桌面"
	[108]="Firefox浏览器"       [109]="DPanel容器管理"      [110]="普罗米修斯监控"
)

# 注册当前 app 到全局表 (linux_app 入口处统一调一次)
register_app() {
	APP_REGISTRY_IDS+=("$1")
	APP_REGISTRY_NAMES+=("$2")
}

# 清空 app 注册表
clear_app_registry() {
	APP_REGISTRY_IDS=()
	APP_REGISTRY_NAMES=()
}

# 根据 app_id 查找显示名
get_app_name_by_id() {
	local id="$1"
	local i
	for i in "${!APP_REGISTRY_IDS[@]}"; do
		if [ "${APP_REGISTRY_IDS[$i]}" = "$id" ]; then
			echo "${APP_REGISTRY_NAMES[$i]}"
			return
		fi
	done
	echo "app_id=$id"
}

# 判断 app_id 是否已安装 (看 /home/docker/appno.txt)
is_app_installed() {
	local id="$1"
	[ -f /home/docker/appno.txt ] && grep -qxF "$id" /home/docker/appno.txt 2>/dev/null
}

# 获取 docker 容器的运行状态
# 输出: "not_installed" | "running <started_iso>" | "<state>" (exited/paused/...)
get_docker_app_status() {
	if ! docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q "^${docker_name}$"; then
		echo "not_installed"
		return
	fi
	local state started
	state=$(docker inspect --format='{{.State.Status}}' "$docker_name" 2>/dev/null)
	started=$(docker inspect --format='{{.State.StartedAt}}' "$docker_name" 2>/dev/null)
	if [ "$state" = "running" ] && [ -n "$started" ]; then
		echo "running $started"
	else
		echo "$state"
	fi
}

# 把秒数格式化成 "X天Y小时Z分" / "X小时Y分" / "X分Y秒"
format_uptime() {
	local secs=$1
	if [ -z "$secs" ] || ! [[ "$secs" =~ ^[0-9]+$ ]]; then
		echo ""
		return
	fi
	local d=$((secs/86400))
	local h=$(((secs%86400)/3600))
	local m=$(((secs%3600)/60))
	local s=$((secs%60))
	if [ "$d" -gt 0 ]; then
		# 天+小时+分 (分可选, 不显示秒)
		if [ "$m" -gt 0 ]; then
			echo "${d}天${h}小时${m}分"
		elif [ "$h" -gt 0 ]; then
			echo "${d}天${h}小时"
		else
			echo "${d}天"
		fi
	elif [ "$h" -gt 0 ]; then
		echo "${h}小时${m}分"
	elif [ "$m" -gt 0 ]; then
		echo "${m}分${s}秒"
	else
		echo "${s}秒"
	fi
}

# 计算两个 ISO 时间戳之间的秒数
_secs_between() {
	local from="$1" to="$2"
	local from_ts to_ts
	from_ts=$(date -d "$from" +%s 2>/dev/null)
	to_ts=$(date -d "$to" +%s 2>/dev/null)
	if [ -z "$from_ts" ] || [ -z "$to_ts" ]; then
		echo "0"
	else
		echo $((to_ts - from_ts))
	fi
}

# 渲染端口表格 (边框 + 多行单元格: 同一端口 v4 / v6 各占一行)
render_app_ports_table() {
	_auto_register_fallback_port
	if [ ${#APP_PORTS_LABELS[@]} -eq 0 ]; then
		return
	fi

	ip_address
	local ipv4="${ipv4_address:-}"
	local ipv6="${ipv6_address:-}"

	# 列宽
	local LBL_W=22
	local PORT_W=6
	local URL_W=44

	# 绘制表格顶/中/底分隔线
	_hline() {
		printf "${cyan}+%*s+%*s+%*s+${white}\n" \
			$((LBL_W + 2)) '' $((PORT_W + 2)) '' $((URL_W + 2)) '' | tr ' ' '-'
	}

	# 绘制单行
	_row() {
		printf "${cyan}|${white} %-${LBL_W}s ${cyan}|${white} %-${PORT_W}s ${cyan}|${white} %-${URL_W}s ${cyan}|${white}\n" "$1" "$2" "$3"
	}

	_hline
	_row "标签" "端口" "访问地址"
	_hline

	local i label port v4 v6
	for i in "${!APP_PORTS_LABELS[@]}"; do
		label="${APP_PORTS_LABELS[$i]}"
		port="${APP_PORTS_NUMBERS[$i]}"
		v4=""
		v6=""
		[ -n "$ipv4" ] && v4="http://$ipv4:$port"
		[ -n "$ipv6" ] && v6="http://[$ipv6]:$port"
		# 第一行带 label/port
		if [ -n "$v4" ]; then
			_row "$label" "$port" "$v4"
			# v6 单独占一行 (空 label/port)
			[ -n "$v6" ] && _row "" "" "$v6"
		elif [ -n "$v6" ]; then
			_row "$label" "$port" "$v6"
		else
			_row "$label" "$port" "(本机无可用 IP)"
		fi
		_hline
	done
}

# 渲染应用运行状态行 (详情页用)
# 输出: "Docker 状态: running (已运行 3天 4小时)" / "Docker 状态: exited" / ...
render_app_status_line() {
	local status
	status=$(get_docker_app_status)
	case "$status" in
		not_installed)
			echo -e "${red}未安装${white}"
			;;
		running\ *)
			local started="${status#running }"
			local secs
			secs=$(_secs_between "$started" "$(date -Iseconds)")
			local uptime
			uptime=$(format_uptime "$secs")
			echo -e "${green}运行中${white} (已运行 ${uptime})"
			;;
		exited)
			echo -e "${yellow}已停止${white}"
			;;
		paused)
			echo -e "${yellow}已暂停${white}"
			;;
		*)
			echo -e "${yellow}${status}${white}"
			;;
	esac
}

# 检查 /home/web/conf.d/ 下哪些域名 conf 引用了此端口, 输出 https://<domain>
_render_domain_access() {
	local port="$1"
	if [ -z "$port" ]; then return; fi
	ip_address
	local search1="$ipv4_address:$port"
	local search2="127.0.0.1:$port"
	local f
	for f in /home/web/conf.d/*; do
		[ -f "$f" ] || continue
		if grep -q "$search1" "$f" 2>/dev/null || grep -q "$search2" "$f" 2>/dev/null; then
			echo "https://$(basename "$f" | sed 's/\.conf$//')"
		fi
	done
}


# Docker 应用管理 (合并版)
# ----------------------------------------------------------------------------
# 兼容两种应用风格, 通过 compose 标志自动选择路径:
#   1) 单容器风格 (94 个老 app): 调用方定义 docker_run, 框架用默认实现
#      app_id / docker_name / docker_img / docker_port / docker_describe
#      docker_url / docker_use / docker_passwd / app_size
#   2) compose 风格 (8 个老 app): 调用方定义 docker_app_install/update/uninstall
#      app_id / app_name / app_text / app_url / docker_name / docker_port / app_size
# 旧版变量名 (docker_name/docker_describe/docker_url) 与新版 (app_name/app_text/app_url)
# 通过 ${var:-fallback} 兼容, 老的 xxx_app 不用改一行.
# ----------------------------------------------------------------------------

# 单容器风格: 默认安装 (外层已 read app_port → docker_port)
_docker_app_default_install() {
	install jq
	install_docker
	docker_run
	setup_docker_dir
	echo "$docker_port" > "/home/docker/${docker_name}_port.conf"
}

# 单容器风格: 默认更新 (删容器+删镜像+重跑 docker_run)
_docker_app_default_update() {
	docker rm -f "$docker_name"
	docker rmi -f "$docker_img"
	docker_run
}

# 单容器风格: 默认卸载 (删容器+删镜像+清数据目录)
_docker_app_default_uninstall() {
	docker rm -f "$docker_name"
	docker rmi -f "$docker_img"
	rm -rf "/home/docker/$docker_name"
}

# 安装/更新后处理: 优先新式钩子 app_post_install / app_post_install_password,
# 兜底走老式 $docker_use / $docker_passwd (eval 执行)
_docker_app_post_install() {
	if declare -F app_post_install >/dev/null 2>&1; then
		app_post_install
	elif [ -n "${docker_use:-}" ]; then
		eval "$docker_use"
	fi
	if declare -F app_post_install_password >/dev/null 2>&1; then
		app_post_install_password
	elif [ -n "${docker_passwd:-}" ]; then
		eval "$docker_passwd"
	fi
}

# 统一入口: 合并自 docker_app() + docker_app_plus()
# 调用方需在调用前定义好变量, 可选定义 docker_app_install/update/uninstall (compose)
# 或 docker_run (单容器). 由 declare -F 自动检测.
# 显示标题用变量: 优先 app_* 新名, 兼容老 docker_* 命名.
docker_app() {
	# 选路径: 优先 compose 三函数, 否则用单容器默认实现
	local _install_cmd
	if declare -F docker_app_install >/dev/null 2>&1; then
		_install_cmd="docker_app_install"
	else
		_install_cmd="_docker_app_default_install"
	fi
	local _update_cmd
	if declare -F docker_app_update >/dev/null 2>&1; then
		_update_cmd="docker_app_update"
	else
		_update_cmd="_docker_app_default_update"
	fi
	local _uninstall_cmd
	if declare -F docker_app_uninstall >/dev/null 2>&1; then
		_uninstall_cmd="docker_app_uninstall"
	else
		_uninstall_cmd="_docker_app_default_uninstall"
	fi

	# 显示标题用变量: 兼容老 (docker_*) 与新 (app_*) 两种命名
	local _title="${app_name:-$docker_name}"
	local _text="${app_text:-$docker_describe}"
	local _url="${app_url:-$docker_url}"

	while true; do
		clear
		# 先执行检查函数, 确定容器状态
		check_docker_app
		check_docker_image_update "$docker_name"

		# 标题行 + 状态
		echo -e "$_title  $check_docker  $update_status"
		echo "$_text"
		echo "$_url"

		# 已安装时: 状态行 + 访问入口表
		if check_docker_app; then
			# 容器运行状态 (running/exited/...)
			local _status
			_status=$(get_docker_app_status)
			if [ "$_status" != "not_installed" ]; then
				local _line
				_line=$(render_app_status_line)
				echo ""
				echo -e "${cyan}应用状态${white}:  $_line"
			fi

			# 域名访问 (扫 /home/web/conf.d/)
			local _primary
			_primary=$(get_primary_port)
			local _domain
			_domain=$(_render_domain_access "$_primary")
			if [ -n "$_domain" ]; then
				echo -e "${cyan}域名访问${white}:  ${green}$_domain${white}"
			fi

			# 端口表 (支持多端口)
			render_app_ports_table
		fi

		echo ""
		echo -e "${cyan}------------------------------------------------------${white}"

		# 根据容器是否存在显示不同菜单
		if check_docker_app; then  # 容器存在 (返回0)
			echo -e "${green}1. 更新${white}              ${red}2. 卸载${white}"
		else  # 容器不存在 (返回非0)
			echo -e "${green}1. 安装${white}"
		fi

		echo -e "${pink}------------------------------------------------------${white}"

		# 仅当容器存在时显示域名和端口相关操作
		if check_docker_app; then
			echo -e "5. 添加域名访问      6. 删除域名访问"
			echo -e "7. 允许IP+端口访问   8. 阻止IP+端口访问"
			echo -e "${pink}------------------------------------------------------${white}"
		fi

		echo -e "${yellow}0. 返回上一级菜单${white}"
		echo -e "${pink}------------------------------------------------------${white}"

		read -e -p "请输入你的选择: " choice

		# 解析主端口 (供 ldnmp_Proxy 等使用)
		local _primary_port
		_primary_port=$(get_primary_port)

		# 根据容器状态限制可执行的选项
		if check_docker_app; then
			# 容器存在时允许的操作
			case $choice in
				1)  # 更新
					"$_update_cmd"
					add_app_id

					clear
					echo "$docker_name 已经更新完成"
					render_app_ports_table
					echo ""
					_docker_app_post_install
					;;
				2)  # 卸载
					"$_uninstall_cmd"
					rm -f /home/docker/${docker_name}_port.conf
					sed -i "/\b${app_id}\b/d" /home/docker/appno.txt
					echo "应用已卸载"
					;;
				5)  # 添加域名访问
					echo "${docker_name}域名访问设置"
					add_yuming
					ldnmp_Proxy "${yuming}" 127.0.0.1 "${_primary_port}"
					block_container_port "$docker_name" "$ipv4_address"
					;;
				6)  # 删除域名访问
					echo "域名格式 example.com 不带https://"
					web_del
					;;
				7)  # 允许IP+端口访问
					clear_container_rules "$docker_name" "$ipv4_address"
					;;
				8)  # 阻止IP+端口访问
					block_container_port "$docker_name" "$ipv4_address"
					;;
				0)  # 返回上一级
					break
					;;
				*)  # 无效选项
					echo -e "${red}无效选择, 请重新输入 !${white}"
					sleep 1
					;;
			esac
		else
			# 容器不存在时仅允许安装和返回操作
			case $choice in
				1)  # 全新安装
					check_disk_space "$app_size"

					"$_install_cmd"
					add_app_id

					clear
					echo "$docker_name 已经安装完成"
					render_app_ports_table
					echo ""
					_docker_app_post_install
					;;
				0)  # 返回上一级
					break
					;;
				*)  # 无效选项
					echo -e "${red}无效选择, 当前只能选择安装或返回 !${white}"
					sleep 1
					;;
			esac
		fi
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
	local app_name="宝塔面板"
	local app_text="宝塔面板是一款流行的国产 Linux 运维管理面板"
	local app_url="官网介绍: https://www.bt.cn"
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
	local app_name="aaPanel面板"
	local app_text="aaPanel 是宝塔面板的国际版, 界面英文, 适合海外用户"
	local app_url="官网介绍: https://www.aapanel.com/"
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
	local app_name="NginxProxyManager面板"
		local docker_name="npm"
		local docker_img="jc21/nginx-proxy-manager:latest"
		local docker_port=81

		docker_run() {
			# app 自管端口: 让用户输入实际对外服务端口
			read -e -p "服务端口 (默认 81): " _user_port
			_user_port=${_user_port:-81}
			docker_port=$_user_port

			docker run -d \
				--name=$docker_name \
				-p ${docker_port}:81 \
				-p 80:80 \
				-p 443:443 \
				-v /home/docker/npm/data:/data \
				-v /home/docker/npm/letsencrypt:/etc/letsencrypt \
				--restart=always \
				$docker_img

			# 注册到展示表 (app 自定 label)
			add_app_port "Web 端口" "$docker_port"
		}

		local app_text="一个Nginx反向代理工具面板, 不支持添加域名访问."
		local app_url="官网介绍: https://nginxproxymanager.com/"
		local app_size="1"

		docker_app
}

# openlist
openlist_app(){
		local app_id="5"
	local app_name="OpenList面板"
		local docker_name="openlist"
		local docker_img="openlistteam/openlist:latest"
		local docker_port=5244

		docker_run() {
			# app 自管端口: 让用户输入实际对外服务端口
			read -e -p "服务端口 (默认 5244): " _user_port
			_user_port=${_user_port:-5244}
			docker_port=$_user_port

			docker run -d \
				--restart=always \
				-v /home/docker/openlist:/opt/openlist/data \
				-p ${docker_port}:5244 \
				-e PUID=0 \
				-e PGID=0 \
				-e UMASK=022 \
				--name="openlist" \
				--user 0:0 \
				--restart=unless-stopped \
				openlistteam/openlist:latest

			# 注册到展示表 (app 自定 label)
			add_app_port "Web 端口" "$docker_port"
		}

		local app_text="一个支持多种存储, 支持网页浏览和 WebDAV 的文件列表程序, 由 gin 和 Solidjs 驱动"
		local app_url="官网介绍: https://github.com/OpenListTeam/OpenList"
		local app_size="1"

		docker_app
}

# webtop(浏览器访问linux系统)
webtop_app(){
		local app_id="6"
	local app_name="WebTop远程桌面网页版"
		local docker_name="webtop-ubuntu"
		local docker_img="lscr.io/linuxserver/webtop:ubuntu-kde"
		local docker_port=3006

		docker_run() {
			# app 自管端口: 让用户输入实际对外服务端口
			read -e -p "服务端口 (默认 3006): " _user_port
			_user_port=${_user_port:-3006}
			docker_port=$_user_port

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

			# 注册到展示表 (app 自定 label)
			add_app_port "Web 端口" "$docker_port"
		}

		local app_text="webtop基于Ubuntu的容器.若IP无法访问, 请添加域名访问."
		local app_url="官网介绍: https://docs.linuxserver.io/images/docker-webtop/"
		local app_size="2"
		docker_app
}

# 哪吒探针面板
nezha_app(){
	clear
	local app_id="7"
	local app_name="哪吒探针"
	local app_text="开源、轻量、易用的服务器监控与运维工具"
	local app_url="官网搭建文档: https://nezha.wiki/guide/dashboard.html"
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
		echo -e "${yellow}0.     ${white}返回上一级菜单"
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
	local app_name="qbittorrent离线下载"
	local docker_name="qbittorrent"
	local docker_img="lscr.io/linuxserver/qbittorrent:latest"
	local docker_port=8081
	add_app_port "Web管理界面" 8081
	add_app_port "BT下载端口 (TCP+UDP)" 56881

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

	local app_text="qbittorrent离线BT磁力下载服务"
	local app_url="官网介绍: https://hub.docker.com/r/linuxserver/qbittorrent"
	local app_size="1"
	docker_app
}

# Poste.io邮件服务器程序
poste_mail_app(){
	clear
	install telnet
	local app_id="9"
	local app_name="Poste.io邮件服务器程序"
	local app_text="poste.io 是一个开源的邮件服务器解决方案, 支持 Webmail / 反垃圾 / 病毒扫描"
	local app_url="官网介绍: https://poste.io/"
	local docker_name="mailserver"
	while true; do
		check_docker_app
		check_docker_image_update $docker_name

		clear
		echo -e "邮局服务 $check_docker $update_status"
		echo "poste.io 是一个开源的邮件服务器解决方案, "
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
		echo -e "${yellow}0.     ${white}返回上一级菜单"
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

				add_app_id

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

				add_app_id

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
	local app_name="青龙面板"
	local docker_name="qinglong"
	local docker_img="whyour/qinglong:latest"
	local docker_port=5700

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 5700): " _user_port
		_user_port=${_user_port:-5700}
		docker_port=$_user_port

		docker run -d \
			-v /home/docker/qinglong/data:/ql/data \
			-p ${docker_port}:5700 \
			--name qinglong \
			--hostname qinglong \
			--restart unless-stopped \
			whyour/qinglong:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="青龙面板是一个定时任务管理平台"
	local app_url="官网介绍: ${url_proxy}github.com/whyour/qinglong"
	local app_size="1"
	docker_app
}

# vscode网页版(code-server)
code_server_app(){
	local app_id="11"
	local app_name="Code-Server(网页vscode)"
	local docker_name="code-server"
	local docker_img="codercom/code-server"
	local docker_port=8021

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8021): " _user_port
		_user_port=${_user_port:-8021}
		docker_port=$_user_port

		docker run -d -p ${docker_port}:8080 -v /home/docker/vscode-web:/home/coder/.local/share/code-server --name vscode-web --restart always codercom/code-server

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="VScode是一款强大的在线代码编写工具"
	local app_url="官网介绍: ${url_proxy}github.com/coder/code-server"
	local app_size="1"
	docker_app

}

# Looking Glass测速面板
looking_glass_app(){
		local app_id="12"
	local app_name="Looking Glass(测速面板)"
		local docker_name="looking-glass"
		local docker_img="wikihostinc/looking-glass-server"
		local docker_port=8016

		docker_run() {
			# app 自管端口: 让用户输入实际对外服务端口
			read -e -p "服务端口 (默认 8016): " _user_port
			_user_port=${_user_port:-8016}
			docker_port=$_user_port

			docker run -d --name looking-glass --restart always -p ${docker_port}:80 wikihostinc/looking-glass-server

			# 注册到展示表 (app 自定 label)
			add_app_port "Web 端口" "$docker_port"
		}
		local app_text="Looking Glass是一个VPS网速测试工具, 多项测试功能, 还可以实时监控VPS进出站流量"
		local app_url="官网介绍: ${url_proxy}github.com/wikihost-opensource/als"
		local app_size="1"
		docker_app
}

# 雷池WAF防火墙面板
safeline_app(){
	local app_id="13"
	local app_name="雷池WAF防火墙面板"
	local app_text="雷池是长亭科技开发的 WAF 站点防火墙程序面板, 可以反代站点进行自动化防御"
	local app_url="官网介绍: https://waf-ce.chaitin.cn/"
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
		echo -e "${yellow}0.     ${white}返回上一级菜单"
		echo -e "${pink}------------------------${white}"
		read -e -p "输入你的选择: " choice

		case $choice in
			1)
				install_docker
				check_disk_space 5
				bash -c "$(curl -fsSLk https://waf-ce.chaitin.cn/release/latest/setup.sh)"

				add_app_id
				clear
				echo "雷池WAF面板已经安装完成"
				check_docker_app_ip
				docker exec safeline-mgt resetadmin

				;;

			2)
				bash -c "$(curl -fsSLk https://waf-ce.chaitin.cn/release/latest/upgrade.sh)"
				docker rmi $(docker images | grep "safeline" | grep "none" | awk '{print $3}')
				echo ""

				add_app_id
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
				echo "如果你是默认安装目录那现在项目已经卸载.如果你是自定义安装目录你需要到安装目录下自行执行:"
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
	local app_name="onlyoffice在线办公OFFICE"
	local docker_name="onlyoffice"
	local docker_img="onlyoffice/documentserver"
	local docker_port=8018

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8018): " _user_port
		_user_port=${_user_port:-8018}
		docker_port=$_user_port

		docker run -d -p ${docker_port}:80 \
			--restart=always \
			--name onlyoffice \
			-v /home/docker/onlyoffice/DocumentServer/logs:/var/log/onlyoffice  \
			-v /home/docker/onlyoffice/DocumentServer/data:/var/www/onlyoffice/Data  \
				onlyoffice/documentserver

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="onlyoffice是一款开源的在线office工具, 太强大了!"
	local app_url="官网介绍: https://www.onlyoffice.com/"
	local app_size="2"
	docker_app
}

# UptimeKuma监控工具
uptimekuma_app(){
	local app_id="15"
	local app_name="UptimeKuma监控工具"
	local docker_name="uptime-kuma"
	local docker_img="louislam/uptime-kuma:latest"
	local docker_port=8022

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8022): " _user_port
		_user_port=${_user_port:-8022}
		docker_port=$_user_port

		docker run -d \
			--name=uptime-kuma \
			-p ${docker_port}:3001 \
			-v /home/docker/uptime-kuma/uptime-kuma-data:/app/data \
			--restart=always \
			louislam/uptime-kuma:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="Uptime Kuma 易于使用的自托管监控工具"
	local app_url="官网介绍: ${url_proxy}github.com/louislam/uptime-kuma"
	local app_size="1"
	docker_app
}

# Memos网页备忘录
memos_app(){
	local app_id="16"
	local app_name="Memos网页备忘录"
	local docker_name="memos"
	local docker_img="ghcr.io/usememos/memos:latest"
	local docker_port=8023

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8023): " _user_port
		_user_port=${_user_port:-8023}
		docker_port=$_user_port

		docker run -d --name memos -p ${docker_port}:5230 -v /home/docker/memos:/var/opt/memos --restart always ghcr.io/usememos/memos:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="Memos是一款轻量级、自托管的备忘录中心"
	local app_url="官网介绍: ${url_proxy}github.com/usememos/memos"
	local app_size="1"
	docker_app
}

# drawio免费的在线图表软件
drawio_app(){
	local app_id="17"
	local app_name="drawio免费的在线图表软件"
	local docker_name="drawio"
	local docker_img="jgraph/drawio"
	local docker_port=8032

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8032): " _user_port
		_user_port=${_user_port:-8032}
		docker_port=$_user_port

		docker run -d --restart=always --name drawio -p ${docker_port}:8080 -v /home/docker/drawio:/var/lib/drawio jgraph/drawio

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="这是一个强大图表绘制软件.思维导图, 拓扑图, 流程图, 都能画"
	local app_url="官网介绍: https://www.drawio.com/"
	local app_size="1"
	docker_app
}

# Sun-Panel导航面板
sun_panel_app(){
	local app_id="18"
	local app_name="Sun-Panel导航面板"
	local docker_name="sun-panel"
	local docker_img="hslr/sun-panel"
	local docker_port=8033

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8033): " _user_port
		_user_port=${_user_port:-8033}
		docker_port=$_user_port

		docker run -d --restart=always -p ${docker_port}:3002 \
			-v /home/docker/sun-panel/conf:/app/conf \
			-v /home/docker/sun-panel/uploads:/app/uploads \
			-v /home/docker/sun-panel/database:/app/database \
			--name sun-panel \
			hslr/sun-panel

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="Sun-Panel服务器、NAS导航面板、Homepage、浏览器首页"
	local app_url="官网介绍: https://doc.sun-panel.top/zh_cn/"
	local app_size="1"
	docker_app
}

# webssh网页版SSH连接工具
webssh_app(){
	local app_id="19"
	local app_name="webssh网页版SSH连接工具"
	local docker_name="webssh"
	local docker_img="jrohy/webssh"
	local docker_port=8040
	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8040): " _user_port
		_user_port=${_user_port:-8040}
		docker_port=$_user_port

		docker run -d -p ${docker_port}:5032 --restart always --name webssh -e TZ=Asia/Shanghai jrohy/webssh
	}

	local app_text="简易在线ssh连接工具和sftp工具"
	local app_url="官网介绍: ${url_proxy}github.com/Jrohy/webssh"
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

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="LobeChat聚合市面上主流的AI大模型, ChatGPT/Claude/Gemini/Groq/Ollama"
	local app_url="官网介绍: ${url_proxy}github.com/lobehub/lobe-chat"
	local app_size="2"
	docker_app
}

# MyIP工具箱
myip_app(){
	local app_id="21"
	local app_name="MyIP工具箱"
	local docker_name="myip"
	local docker_img="jason5ng32/myip:latest"
	local docker_port=8037

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8037): " _user_port
		_user_port=${_user_port:-8037}
		docker_port=$_user_port

		docker run -d -p ${docker_port}:18966 --name myip jason5ng32/myip:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="是一个多功能IP工具箱, 可以查看自己IP信息及连通性, 用网页面板呈现"
	local app_url="官网介绍: ${url_proxy}github.com/jason5ng32/MyIP/blob/main/README_ZH.md"
	local app_size="1"
	docker_app
}

# ghproxy(GitHub加速站)
ghproxy_app(){
	local app_id="22"
	local app_name="ghproxy(GitHub加速站)"
	local docker_name="ghproxy"
	local docker_img="wjqserver/ghproxy:latest"
	local docker_port=8046

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8046): " _user_port
		_user_port=${_user_port:-8046}
		docker_port=$_user_port

		docker run -d \
		--name ghproxy \
		--restart always \
		-p ${docker_port}:8080 \
		-v /home/docker/ghproxy/config:/data/ghproxy/config wjqserver/ghproxy:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="使用Go实现的GHProxy, 用于加速部分地区Github仓库的拉取."
	local app_url="官网介绍: https://github.com/WJQSERVER-STUDIO/ghproxy"
	local app_size="1"
	docker_app
}

# AllinSSL证书管理平台
allinssl_app(){
	local app_id="23"
	local app_name="AllinSSL证书管理平台"
	local docker_name="allinssl"
	local docker_img="allinssl/allinssl:latest"
	local docker_port=8068

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8068): " _user_port
		_user_port=${_user_port:-8068}
		docker_port=$_user_port

		docker run -itd --name allinssl -p ${docker_port}:8888 -v /home/docker/allinssl/data:/www/allinssl/data -e ALLINSSL_USER=allinssl -e ALLINSSL_PWD=allinssldocker -e ALLINSSL_URL=allinssl allinssl/allinssl:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="开源免费的 SSL 证书自动化管理平台"
	local app_url="官网介绍: https://allinssl.com"
	local app_size="1"
	docker_app
}

# DDNS-GO
ddnsgo_app(){
	local app_id="24"
	local app_name="DDNS-GO"
	local docker_name="ddns-go"
	local docker_img="jeessy/ddns-go"
	local docker_port=8067

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8067): " _user_port
		_user_port=${_user_port:-8067}
		docker_port=$_user_port

		docker run -d \
			--name ddns-go \
			--restart=always \
			-p ${docker_port}:9876 \
			-v /home/docker/ddns-go:/root \
			jeessy/ddns-go

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="自动将你的公网 IP(IPv4/IPv6)实时更新到各大 DNS 服务商, 实现动态域名解析."
	local app_url="官网介绍: https://github.com/jeessy2/ddns-go"
	local app_size="1"
	docker_app
}

# Lucky
lucky_app(){
	local app_id="25"
	local app_name="Lucky"
	local docker_name="lucky"
	local docker_img="gdy666/lucky"
	local docker_port=8068

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8068): " _user_port
		_user_port=${_user_port:-8068}
		docker_port=$_user_port

		docker run -d \
		--name lucky \
		--restart=always \
		-v /home/docker/lucky:/goodluck \
		gdy666/lucky

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="自动将你的公网 IP(IPv4/IPv6)实时更新到各大 DNS 服务商, 实现动态域名解析."
	local app_url="官网介绍: https://github.com/gdy666/lucky"
	local app_size="1"
	docker_app
}

# LibreTV私有影视
libretv_app(){
		local app_id="26"
	local app_name="LibreTV私有影视"
		local docker_name="libretv"
		local docker_img="bestzwei/libretv:latest"
		local docker_port=8073

		docker_run() {
			# app 自管端口: 让用户输入实际对外服务端口
			read -e -p "服务端口 (默认 8073): " _user_port
			_user_port=${_user_port:-8073}
			docker_port=$_user_port

			read -e -p "设置LibreTV的登录密码: " app_passwd
			docker run -d \
				--name libretv \
				--restart unless-stopped \
				-p ${docker_port}:8080 \
				-e PASSWORD=${app_passwd} \
				bestzwei/libretv:latest

			# 注册到展示表 (app 自定 label)
			add_app_port "Web 端口" "$docker_port"
		}

		local app_text="免费在线视频搜索与观看平台"
		local app_url="官网介绍: https://github.com/LibreSpark/LibreTV"
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
	local app_name="Melody音乐精灵"
	local docker_name="melody"
	local docker_img="foamzou/melody:latest"
	local docker_port=8075

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8075): " _user_port
		_user_port=${_user_port:-8075}
		docker_port=$_user_port

		docker run -d \
			--name melody \
			--restart unless-stopped \
			-p ${docker_port}:5566 \
			-v /home/docker/melody/.profile:/app/backend/.profile \
			foamzou/melody:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="你的音乐精灵, 旨在帮助你更好地管理音乐."
	local app_url="官网介绍: https://github.com/foamzou/melody"
	local app_size="1"
	docker_app
}

# Beszel服务器监控
beszel_app(){
	local app_id="29"
	local app_name="Beszel服务器监控"
	local docker_name="beszel"
	local docker_img="henrygd/beszel"
	local docker_port=8079

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8079): " _user_port
		_user_port=${_user_port:-8079}
		docker_port=$_user_port

		mkdir -p /home/docker/beszel && \
		docker run -d \
			--name beszel \
			--restart=unless-stopped \
			-v /home/docker/beszel:/beszel_data \
			-p ${docker_port}:8090 \
			henrygd/beszel

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="Beszel轻量易用的服务器监控"
	local app_url="官网介绍: https://beszel.dev/zh/"
	local app_size="1"
	docker_app
}

# SyncTV一起看片神器
synctv_app(){
		local app_id="30"
	local app_name="SyncTV一起看片神器"
		local docker_name="synctv"
		local docker_img="synctvorg/synctv"
		local docker_port=8087

		docker_run() {
			# app 自管端口: 让用户输入实际对外服务端口
			read -e -p "服务端口 (默认 8087): " _user_port
			_user_port=${_user_port:-8087}
			docker_port=$_user_port

			docker run -d \
				--name synctv \
				-v /home/docker/synctv:/root/.synctv \
				-p ${docker_port}:8080 \
				--restart=always \
				synctvorg/synctv

			# 注册到展示表 (app 自定 label)
			add_app_port "Web 端口" "$docker_port"
		}

		local app_text="远程一起观看电影和直播的程序.它提供了同步观影、直播、聊天等功能"
		local app_url="官网介绍: https://github.com/synctv-org/synctv"
		local app_size="1"
		docker_app
}

# X-UI面板
xui_app(){
	local app_id="31"
	local app_name="X-UI面板"
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
		echo "请通过管理面板卸载, 谢谢!"
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
		echo "请通过管理面板卸载, 谢谢!"
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
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 1066): " _user_port
		_user_port=${_user_port:-1066}
		docker_port=$_user_port

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

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
		}

		local app_text="Microsoft 365 E5 Renew X 一键续订脚本"
		local app_url="官网介绍: https://github.com/hongyonghan/Docker_Microsoft365_E5_Renew_X"
		local app_size="1"
		docker_app
}

# DecoTV私有影视
decotv_app(){
	local app_id="34"

	local app_name="decotv私有影视"
	local app_text="免费在线视频搜索与观看平台"
	local app_url="官网介绍: https://github.com/decohererk/decotv"
	local docker_name="decotv-core"
	local docker_port="8076"
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

		mkdir -p /home/docker/decotv
		cd /home/docker/decotv

		cat > /home/docker/decotv/docker-compose.yml << 'EOF'
services:
  decotv-core:
    image: ghcr.io/decohererk/decotv:latest
    container_name: decotv-core
    restart: on-failure
    ports:
      - '${docker_port}:3000'
    environment:
      - USERNAME=${admin}
      - PASSWORD=${admin_password}
      - NEXT_PUBLIC_STORAGE_TYPE=kvrocks
      - KVROCKS_URL=redis://decotv-kvrocks:6666
    networks:
      - decotv-network
    depends_on:
      - decotv-kvrocks
      
  decotv-kvrocks:
    image: apache/kvrocks
    container_name: decotv-kvrocks
    restart: unless-stopped
    volumes:
      - kvrocks-data:/var/lib/kvrocks
    networks:
      - decotv-network

networks:
  decotv-network:
    driver: bridge

volumes:
  kvrocks-data:
EOF
		
		# 替换变量
		sed -i "s/\${docker_port}/${docker_port}/g" /home/docker/decotv/docker-compose.yml
		sed -i "s/\${admin}/${admin}/g" /home/docker/decotv/docker-compose.yml
		sed -i "s/\${admin_password}/${admin_password}/g" /home/docker/decotv/docker-compose.yml

		cd /home/docker/decotv/
		docker compose up -d
		clear
		echo "已经安装完成"
		check_docker_app_ip
	}


	docker_app_update() {
		cd /home/docker/decotv/ && docker compose down --rmi all
		cd /home/docker/decotv/ && docker compose up -d
	}


	docker_app_uninstall() {
		cd /home/docker/decotv/ && docker compose down --rmi all
		rm -rf /home/docker/decotv
		echo "应用已卸载"
	}

	docker_app_plus
}

# Drawnix在线白板
drawnix_app(){
	local app_id="35"
	local app_name="Drawnix在线白板"
	local docker_name="drawnix"
	local docker_img="pubuzhixing/drawnix:latest"
	local docker_port=8077

	docker_run() {
		docker run -d \
			--name drawnix \
			--restart=always \
			-p ${docker_port}:80 \
			pubuzhixing/drawnix:latest
	}

	local app_text="一款开源的在线白板工具，类似Excalidraw，支持思维导图、流程图和自由绘图。"
	local app_url="官网介绍: https://github.com/pubuzhixing/drawnix"
	local app_size="1"
	docker_app
}

##############################
######## 应用中心菜单 #########
##############################
linux_app() {

	# 已安装 app_id 集合 (O(1) 查表, 用于菜单状态点 + 666 列表)
	declare -A INSTALLED_MAP=()
	INSTALLED_IDS=()
	if [ -f /home/docker/appno.txt ]; then
		while read -r id; do
			[ -n "$id" ] || continue
			INSTALLED_MAP["$id"]=1
			INSTALLED_IDS+=("$id")
		done < /home/docker/appno.txt
	fi

	# 状态点 (单字符, 颜色根据安装状态)
	_dot() {
		if [ "${INSTALLED_MAP[$1]:-0}" = "1" ]; then
			echo "${green}●${white}"
		else
			echo "${red}●${white}"
		fi
	}

	# 渲染已安装应用列表 (666 入口)
	_render_installed_list() {
		clear
		echo -e "${green}===== 已安装应用 =====${white}"
		echo ""
		if [ ${#INSTALLED_IDS[@]} -eq 0 ]; then
			echo -e "${yellow}暂无已安装应用${white}"
			break_end
			return 1
		fi
		# 按 app_id 数字排序
		local sorted
		sorted=$(printf '%s\n' "${INSTALLED_IDS[@]}" | sort -n)
		while read -r id; do
			[ -n "$id" ] || continue
			local name="${APP_DISPLAY_NAMES[$id]:-?未注册}"
			echo -e "  ${cyan}$id. ${white}$name  ${green}●${white}"
		done <<< "$sorted"
		echo ""
		echo -e "${pink}------------------------------------------------------------------------------------${white}"
		echo -e "${yellow}0.   ${white}返回应用市场"
		echo -e "${pink}------------------------------------------------------------------------------------${white}"
		read -e -p "输入编号进入应用详情 (0 返回): " jump_choice
		if [ "$jump_choice" = "0" ] || [ -z "$jump_choice" ]; then
			return 1
		fi
		# 直接跳到该 sub_choice (复用主 case 调度)
		if [ -n "${APP_DISPLAY_NAMES[$jump_choice]:-}" ]; then
			_linux_app_dispatch "$jump_choice"
		else
			echo -e "${red}无效编号 $jump_choice${white}"
			sleep 1
			return 1
		fi
	}

	# sub_choice 调度 (主菜单 + 666 列表共用)
	_linux_app_dispatch() {
		local sub_choice="$1"
		# 清理上一个 app 残留的内嵌函数定义
		unset -f docker_app_install docker_app_update docker_app_uninstall app_post_install app_post_install_password 2>/dev/null
		clear_app_ports

		case $sub_choice in
		1) 1panel_app ;;
		2) bt_app ;;
		3) aapanel_app ;;
		4) npm_app ;;
		5) openlist_app ;;
		6) webtop_app ;;
		7) nezha_app ;;
		8) qb_app ;;
		9) poste_mail_app ;;
		10) qinglong_app ;;
		11) code_server_app ;;
		12) looking_glass_app ;;
		13) safeline_app ;;
		14) onlyoffice_app ;;
		15) uptimekuma_app ;;
		16) memos_app ;;
		17) drawio_app ;;
		18) sun_panel_app ;;
		19) webssh_app ;;
		20) lobe_chat ;;
		21) myip_app ;;
		22) ghproxy_app ;;
		23) allinssl_app ;;
		24) ddnsgo_app ;;
		25) lucky_app ;;
		26) libretv_app ;;
		27) moontv_app ;;
		28) melody_app ;;
		29) beszel_app ;;
		30) synctv_app ;;
		31) xui_app ;;
		32) 3xui_app ;;
		33) e5_renew_x_app ;;
		34) decotv_app ;;
		35) drawnix_app ;;
		36) portainer_app ;;
		37) cloudreve_app ;;
		38) nextcloud_app ;;
		39) emby_app ;;
		40) jellyfin_app ;;
		41) adguardhome_app ;;
		42) navidrome_app ;;
		43) bitwarden_app ;;
		44) stirlingpdf_app ;;
		45) speedtest_app ;;
		46) photoprism_app ;;
		47) searxng_app ;;
		48) pingvinshare_app ;;
		49) dockge_app ;;
		50) ittools_app ;;
		51) n8n_app ;;
		52) openwebui_app ;;
		53) dify_app ;;
		54) gitea_app ;;
		55) filebrowser_app ;;
		56) frp_server_app ;;
		57) wireguard_server_app ;;
		58) jumpserver_app ;;
		59) immich_app ;;
		60) syncthing_app ;;
		61) umami_app ;;
		62) siyuan_app ;;
		63) sftpgp_app ;;
		64) owncast_app ;;
		65) deepseek_app ;;
		66) rocketchat_app ;;
		67) gopeed_app ;;
		68) twofauth_app ;;
		69) zfile_app ;;
		70) nexterm_app ;;
		71) jitsimeet_app ;;
		72) stream_app ;;
		73) filecodebox_app ;;
		74) matrix_app ;;
		75) ytdlp_app ;;
		76) paperless_app ;;
		77) wallos_app ;;
		78) komari_app ;;
		79) dufs_app ;;
		80) pandawiki_app ;;
		81) linkwarden_app ;;
		82) vocechat_app ;;
		83) karakeep_app ;;
		84) newapi_app ;;
		85) ragflow_app ;;
		86) astrbot_app ;;
		87) langbot_app ;;
		88) gotenberg_app ;;
		89) librespeed_app ;;
		90) gptload_app ;;
		91) stockmonitor_app ;;
		92) pve_app ;;
		93) dsm_app ;;
		94) dosgame_app ;;
		95) xunlei_app ;;
		96) xiaoya_app ;;
		97) bililive_app ;;
		98) moments_app ;;
		99) pansou_app ;;
		100) lskypro_app ;;
		101) zentao_app ;;
		102) qdtoday_app ;;
		103) haizi_app ;;
		104) amh_app ;;
		105) libretranslate_app ;;
		106) videogen_app ;;
		107) rustdesk_server_app ;;
		108) firefox_app ;;
		109) dpanel_app ;;
		110) prometheus_app ;;
		esac
	}

	while true; do
		clear
		echo -e "${green}===== 应用市场 =====${white}"
		echo -e "[图例] ${green}●${white} 已安装  ${red}●${white} 未安装"
		echo ""
		docker_tato
		echo -e "${pink}------------------------------------------------------------------------------------${white}"
		echo -e "${cyan}1.  ${white}1Panel面板 $(_dot 1)            ${cyan}2.  ${white}宝塔面板 $(_dot 2)                  ${cyan}3.  ${white}aaPanel面板 $(_dot 3)"
		echo -e "${cyan}4.  ${white}NginxProxyManager面板 $(_dot 4)  ${cyan}5.  ${white}OpenList面板 $(_dot 5)              ${cyan}6.  ${white}WebTop远程桌面网页版 $(_dot 6)"
		echo -e "${cyan}7.  ${white}哪吒探针 $(_dot 7)               ${cyan}8.  ${white}qbittorrent离线下载 $(_dot 8)        ${cyan}9.  ${white}Poste.io邮件服务器程序 $(_dot 9)"
		echo -e "${cyan}10. ${white}青龙面板 $(_dot 10)               ${cyan}11. ${white}Code-Server(网页vscode) $(_dot 11)  ${cyan}12. ${white}Looking Glass(测速面板) $(_dot 12)"
		echo -e "${cyan}13. ${white}雷池WAF防火墙面板 $(_dot 13)      ${cyan}14. ${white}onlyoffice在线办公OFFICE $(_dot 14) ${cyan}15. ${white}UptimeKuma监控工具 $(_dot 15)"
		echo -e "${cyan}16. ${white}Memos网页备忘录 $(_dot 16)        ${cyan}17. ${white}drawio免费的在线图表软件 $(_dot 17) ${cyan}18. ${white}Sun-Panel导航面板 $(_dot 18)"
		echo -e "${cyan}19. ${white}webssh网页版SSH连接工具 $(_dot 19)${cyan}20. ${white}LobeChatAI聊天聚合网站 $(_dot 20)   ${cyan}21. ${white}MyIP工具箱 $(_dot 21)"
		echo -e "${cyan}22. ${white}ghproxy(GitHub加速站) $(_dot 22)  ${cyan}23. ${white}AllinSSL证书管理平台 $(_dot 23)     ${cyan}24. ${white}DDNS-GO $(_dot 24)"
		echo -e "${cyan}25. ${white}Lucky $(_dot 25)                  ${cyan}26. ${white}LibreTV私有影视 $(_dot 26)          ${cyan}27. ${white}MoonTV私有影视 $(_dot 27)"
		echo -e "${cyan}28. ${white}Melody音乐精灵 $(_dot 28)         ${cyan}29. ${white}Beszel服务器监控 $(_dot 29)         ${cyan}30. ${white}SyncTV一起看片神器 $(_dot 30)"
		echo -e "${cyan}31. ${white}X-UI面板 $(_dot 31)               ${cyan}32. ${white}3X-UI面板 $(_dot 32)                  ${cyan}33. ${white}Microsoft 365 E5 Renew X $(_dot 33)"
		echo -e "${cyan}34. ${white}DecoTV私有影视 $(_dot 34)         ${cyan}35. ${white}Drawnix在线白板 $(_dot 35)"
		echo -e "${pink}------------------------------------------------------------------------------------${white}"
		echo -e "${cyan}36. ${white}Portainer容器管理 $(_dot 36)      ${cyan}37. ${white}Cloudreve网盘 $(_dot 37)            ${cyan}38. ${white}Nextcloud私有网盘 $(_dot 38)"
		echo -e "${cyan}39. ${white}emby媒体管理 $(_dot 39)           ${cyan}40. ${white}jellyfin媒体管理 $(_dot 40)         ${cyan}41. ${white}AdGuardHome去广告 $(_dot 41)"
		echo -e "${cyan}42. ${white}Navidrome音乐服务器 $(_dot 42)    ${cyan}43. ${white}Vaultwarden密码管理 $(_dot 43)     ${cyan}44. ${white}StirlingPDF工具大全 $(_dot 44)"
		echo -e "${cyan}45. ${white}Speedtest测速面板 $(_dot 45)      ${cyan}46. ${white}PhotoPrism私有相册 $(_dot 46)       ${cyan}47. ${white}searxng聚合搜索 $(_dot 47)"
		echo -e "${cyan}48. ${white}Pingvin-Share文件分享 $(_dot 48)  ${cyan}49. ${white}Dockge容器管理 $(_dot 49)          ${cyan}50. ${white}it-tools工具箱 $(_dot 50)"
		echo -e "${cyan}51. ${white}n8n自动化工作流 $(_dot 51)       ${cyan}52. ${white}OpenWebUI自托管AI $(_dot 52)        ${cyan}53. ${white}Dify大模型知识库 $(_dot 53)"
		echo -e "${cyan}54. ${white}gitea私有代码仓库 $(_dot 54)      ${cyan}55. ${white}FileBrowser文件管理 $(_dot 55)      ${cyan}56. ${white}FRP内网穿透(服务端) $(_dot 56)"
		echo -e "${cyan}57. ${white}WireGuard组网(服务端) $(_dot 57)  ${cyan}58. ${white}JumpServer堡垒机 $(_dot 58)         ${cyan}59. ${white}immich图片视频管理 $(_dot 59)"
		echo -e "${cyan}60. ${white}Syncthing文件同步 $(_dot 60)       ${cyan}61. ${white}Umami网站统计 $(_dot 61)           ${cyan}62. ${white}思源笔记 $(_dot 62)"
		echo -e "${cyan}63. ${white}SFTPGo文件传输 $(_dot 63)         ${cyan}64. ${white}Owncast自托管直播 $(_dot 64)        ${cyan}65. ${white}Deepseek AI大模型 $(_dot 65)"
		echo -e "${cyan}66. ${white}RocketChat聊天系统 $(_dot 66)     ${cyan}67. ${white}Gopeed高速下载 $(_dot 67)           ${cyan}68. ${white}2FAuth二步验证器 $(_dot 68)"
		echo -e "${cyan}69. ${white}ZFile在线网盘 $(_dot 69)          ${cyan}70. ${white}Nexterm远程连接 $(_dot 70)          ${cyan}71. ${white}JitsiMeet视频会议 $(_dot 71)"
		echo -e "${cyan}72. ${white}Stream四层代理转发 $(_dot 72)     ${cyan}73. ${white}FileCodeBox文件快递 $(_dot 73)      ${cyan}74. ${white}Matrix去中心化聊天 $(_dot 74)"
		echo -e "${cyan}75. ${white}yt-dlp视频下载 $(_dot 75)         ${cyan}76. ${white}paperless文档管理 $(_dot 76)        ${cyan}77. ${white}Wallos财务管理 $(_dot 77)"
		echo -e "${cyan}78. ${white}komari服务器监控 $(_dot 78)       ${cyan}79. ${white}Dufs静态文件服务器 $(_dot 79)      ${cyan}80. ${white}PandaWiki文档管理 $(_dot 80)"
		echo -e "${cyan}81. ${white}linkwarden书签管理 $(_dot 81)     ${cyan}82. ${white}VoceChat聊天系统 $(_dot 82)         ${cyan}83. ${white}Karakeep书签管理 $(_dot 83)"
		echo -e "${cyan}84. ${white}NewAPI大模型资产管理 $(_dot 84)   ${cyan}85. ${white}RAGFlow知识库 $(_dot 85)            ${cyan}86. ${white}AstrBot聊天机器人 $(_dot 86)"
		echo -e "${cyan}87. ${white}LangBot聊天机器人 $(_dot 87)      ${cyan}88. ${white}多格式文件转换 $(_dot 88)           ${cyan}89. ${white}LibreSpeed测速 $(_dot 89)"
		echo -e "${cyan}90. ${white}gpt-load AI透明代理 $(_dot 90)    ${cyan}91. ${white}补货监控工具 $(_dot 91)             ${cyan}92. ${white}PVE虚拟化管理 $(_dot 92)"
		echo -e "${cyan}93. ${white}DSM群晖虚拟机 $(_dot 93)          ${cyan}94. ${white}在线DOS老游戏 $(_dot 94)            ${cyan}95. ${white}迅雷离线下载 $(_dot 95)"
		echo -e "${cyan}96. ${white}小雅Alist全家桶 $(_dot 96)        ${cyan}97. ${white}Bililive直播录制 $(_dot 97)         ${cyan}98. ${white}极简朋友圈 $(_dot 98)"
		echo -e "${cyan}99. ${white}PanSou网盘搜索 $(_dot 99)         ${cyan}100.${white}简单图床lskypro $(_dot 100)          ${cyan}101.${white}禅道项目管理 $(_dot 101)"
		echo -e "${cyan}102.${white}QD-Today定时任务 $(_dot 102)       ${cyan}103.${white}耗子管理面板 $(_dot 103)             ${cyan}104.${white}AMH建站面板 $(_dot 104)"
		echo -e "${cyan}105.${white}在线翻译服务器 $(_dot 105)         ${cyan}106.${white}AI视频生成工具 $(_dot 106)           ${cyan}107.${white}RustDesk远程桌面 $(_dot 107)"
		echo -e "${cyan}108.${white}Firefox浏览器 $(_dot 108)          ${cyan}109.${white}DPanel容器管理 $(_dot 109)           ${cyan}110.${white}普罗米修斯监控 $(_dot 110)"
		echo -e "${pink}------------------------------------------------------------------------------------${white}"
		echo -e "${yellow}0.   ${white}返回主菜单"
		echo -e "${green}666. ${white}查看已安装应用 (当前: ${#INSTALLED_IDS[@]} 个)"
		echo -e "${pink}------------------------------------------------------------------------------------${white}"
		read -e -p "请输入你的选择: " sub_choice

		case $sub_choice in
			0)
				break
				;;
			666)
				_render_installed_list
				;;
			*)
				if [ -n "${APP_DISPLAY_NAMES[$sub_choice]:-}" ]; then
					_linux_app_dispatch "$sub_choice"
				else
					echo -e "${red}无效选择, 请重新输入 !${white}"
					sleep 1
				fi
				;;
		esac
	done
}

#############################################################################
########################### 补充应用 (36-110) #############################

# portainer容器管理面板
portainer_app(){
	local app_id="36"
	local app_name="Portainer容器管理"
	local docker_name="portainer"
	local docker_img="portainer/portainer-ce:latest"
	local docker_port=9000

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 9000): " _user_port
		_user_port=${_user_port:-9000}
		docker_port=$_user_port

		docker volume create portainer_data
		docker run -d \
			--name portainer \
			--restart=always \
			-p ${docker_port}:9000 \
			-p 9443:9443 \
			-v /var/run/docker.sock:/var/run/docker.sock \
			-v portainer_data:/data \
			portainer/portainer-ce:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="轻量级的Docker容器管理UI面板, 支持容器/镜像/网络/卷的可视化管理"
	local app_url="官网介绍: https://www.portainer.io/"
	local app_size="1"
	docker_app
}

# Cloudreve网盘
cloudreve_app(){
	local app_id="37"
	local app_name="Cloudreve网盘"
	local docker_name="cloudreve"
	local docker_img="cloudreve/cloudreve:latest"
	local docker_port=8088

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8088): " _user_port
		_user_port=${_user_port:-8088}
		docker_port=$_user_port

		mkdir -p /home/docker/cloudreve
		docker run -d \
			--name cloudreve \
			--restart=always \
			-p ${docker_port}:5212 \
			-v /home/docker/cloudreve:/cloudreve \
			cloudreve/cloudreve:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="支持多种存储的云盘系统, 支持本地存储/对象存储/S3等"
	local app_url="官网介绍: https://github.com/cloudreve/Cloudreve"
	local app_size="1"
	docker_app
}

# Nextcloud网盘
nextcloud_app(){
	local app_id="38"

	local app_name="Nextcloud私有网盘"
	local app_text="功能强大的私有云存储和协作平台"
	local app_url="官网介绍: https://nextcloud.com/"
	local docker_name="nextcloud-app"
	local docker_port="8089"
	local app_size="2"

	docker_app_install() {
		mkdir -p /home/docker/nextcloud/db
		cd /home/docker/nextcloud

		cat > docker-compose.yml << 'EOF'
services:
  db:
    image: mariadb:10.11
    container_name: nextcloud-db
    restart: always
    environment:
      MYSQL_ROOT_PASSWORD: nextcloud_root_pwd
      MYSQL_DATABASE: nextcloud
      MYSQL_USER: nextcloud
      MYSQL_PASSWORD: nextcloud_pwd
    volumes:
      - db:/var/lib/mysql
    networks:
      - nextcloud-net

  redis:
    image: redis:alpine
    container_name: nextcloud-redis
    restart: always
    networks:
      - nextcloud-net

  app:
    image: nextcloud:apache
    container_name: nextcloud-app
    restart: always
    ports:
      - '${docker_port}:80'
    environment:
      MYSQL_HOST: db
      MYSQL_DATABASE: nextcloud
      MYSQL_USER: nextcloud
      MYSQL_PASSWORD: nextcloud_pwd
      REDIS_HOST: redis
    volumes:
      - app:/var/www/html
    depends_on:
      - db
      - redis
    networks:
      - nextcloud-net

networks:
  nextcloud-net:
    driver: bridge

volumes:
  db:
  app:
EOF
		sed -i "s/\${docker_port}/${docker_port}/g" docker-compose.yml
		docker compose up -d
		clear
		echo "Nextcloud 安装完成"
		check_docker_app_ip
	}

	docker_app_update() {
		cd /home/docker/nextcloud && docker compose down --rmi all
		cd /home/docker/nextcloud && docker compose up -d
	}

	docker_app_uninstall() {
		cd /home/docker/nextcloud && docker compose down --rmi all -v
		rm -rf /home/docker/nextcloud
		echo "Nextcloud 已卸载"
	}

	docker_app_plus
}

# emby多媒体管理系统
emby_app(){
	local app_id="39"
	local app_name="emby媒体管理"
	local docker_name="emby"
	local docker_img="emby/embyserver:latest"
	local docker_port=8096

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8096): " _user_port
		_user_port=${_user_port:-8096}
		docker_port=$_user_port

		mkdir -p /home/docker/emby/config /home/docker/emby/data
		docker run -d \
			--name emby \
			--restart=always \
			-p ${docker_port}:8096 \
			-p 8920:8920 \
			-v /home/docker/emby/config:/config \
			-v /home/docker/emby/data:/data \
			--device=/dev/dri:/dev/dri \
			emby/embyserver:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="功能强大的个人媒体服务器, 支持电影/电视剧/音乐管理和在线播放"
	local app_url="官网介绍: https://emby.media/"
	local app_size="3"
	docker_app
}

# jellyfin媒体管理系统
jellyfin_app(){
	local app_id="40"
	local app_name="jellyfin媒体管理"
	local docker_name="jellyfin"
	local docker_img="jellyfin/jellyfin:latest"
	local docker_port=8097

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8097): " _user_port
		_user_port=${_user_port:-8097}
		docker_port=$_user_port

		mkdir -p /home/docker/jellyfin/config /home/docker/jellyfin/cache
		docker run -d \
			--name jellyfin \
			--restart=always \
			-p ${docker_port}:8096 \
			-v /home/docker/jellyfin/config:/config \
			-v /home/docker/jellyfin/cache:/cache \
			--device=/dev/dri:/dev/dri \
			jellyfin/jellyfin:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="免费开源的媒体服务器, Emby的替代品, 支持电影/电视剧/音乐管理和在线播放"
	local app_url="官网介绍: https://jellyfin.org/"
	local app_size="2"
	docker_app
}

# AdGuardHome去广告软件
adguardhome_app(){
	local app_id="41"
	local app_name="AdGuardHome去广告"
	local docker_name="adguardhome"
	local docker_img="adguard/adguardhome:latest"
	local docker_port=3000
	add_app_port "Web管理界面" 3000
	add_app_port "DNS端口 (TCP+UDP)" 53
	add_app_port "DHCP客户端" 67
	add_app_port "DHCP服务端" 68
	add_app_port "DNS-over-HTTPS" 443
	add_app_port "DNS-over-TLS" 853

	docker_run() {
		mkdir -p /home/docker/adguardhome/work /home/docker/adguardhome/conf
		docker run -d \
			--name adguardhome \
			--restart=always \
			-p ${docker_port}:3000 \
			-p 53:53/tcp \
			-p 53:53/udp \
			-p 67:67/udp \
			-p 68:68/udp \
			-p 443:443/tcp \
			-p 853:853/tcp \
			-v /home/docker/adguardhome/work:/opt/adguardhome/work \
			-v /home/docker/adguardhome/conf:/opt/adguardhome/conf \
			adguard/adguardhome:latest
	}

	local app_text="全网广告拦截与隐私保护DNS服务, 支持DNS-over-HTTPS/TLS"
	local app_url="官网介绍: https://adguard.com/adguard-home/overview.html"
	local app_size="1"
	docker_app
}

# Navidrome私有音乐服务器
navidrome_app(){
	local app_id="42"
	local app_name="Navidrome音乐服务器"
	local docker_name="navidrome"
	local docker_img="deluan/navidrome:latest"
	local docker_port=8098

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8098): " _user_port
		_user_port=${_user_port:-8098}
		docker_port=$_user_port

		mkdir -p /home/docker/navidrome/music /home/docker/navidrome/data
		docker run -d \
			--name navidrome \
			--restart=always \
			-p ${docker_port}:4533 \
			-v /home/docker/navidrome/music:/music \
			-v /home/docker/navidrome/data:/data \
			navidrome/navidrome:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="现代的私人音乐流媒体服务器, 支持多用户, 兼容Subsonic/Airsonic API"
	local app_url="官网介绍: https://github.com/navidrome/navidrome"
	local app_size="1"
	docker_app
}

# bitwarden密码管理器 (使用Vaultwarden轻量替代)
bitwarden_app(){
	local app_id="43"
	local app_name="Vaultwarden密码管理"
	local docker_name="vaultwarden"
	local docker_img="vaultwarden/server:latest"
	local docker_port=8099

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8099): " _user_port
		_user_port=${_user_port:-8099}
		docker_port=$_user_port

		mkdir -p /home/docker/vaultwarden/data
		docker run -d \
			--name vaultwarden \
			--restart=always \
			-p ${docker_port}:80 \
			-e WEBSOCKET_ENABLED=true \
			-v /home/docker/vaultwarden/data:/data \
			vaultwarden/server:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="Bitwarden的轻量级替代(Vaultwarden), 自托管密码管理器"
	local app_url="官网介绍: https://github.com/dani-garcia/vaultwarden"
	local app_size="1"
	docker_app
}

# StirlingPDF工具大全
stirlingpdf_app(){
	local app_id="44"
	local app_name="StirlingPDF工具大全"
	local docker_name="stirlingpdf"
	local docker_img="frooodle/s-pdf:latest"
	local docker_port=8100

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8100): " _user_port
		_user_port=${_user_port:-8100}
		docker_port=$_user_port

		mkdir -p /home/docker/stirlingpdf/config /home/docker/stirlingpdf/logs
		docker run -d \
			--name stirlingpdf \
			--restart=always \
			-p ${docker_port}:8080 \
			-v /home/docker/stirlingpdf/config:/configs \
			-v /home/docker/stirlingpdf/logs:/logs \
			-e DOCKER_ENABLE_SECURITY=false \
			frooodle/s-pdf:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="功能强大的PDF处理工具箱, 支持合并/拆分/转换/压缩/加水印等"
	local app_url="官网介绍: https://github.com/Stirling-Tools/Stirling-PDF"
	local app_size="2"
	docker_app
}

# Speedtest测速面板
speedtest_app(){
	local app_id="45"
	local app_name="Speedtest测速面板"
	local docker_name="speedtest"
	local docker_img="adolfintel/speedtest:latest"
	local docker_port=8101

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8101): " _user_port
		_user_port=${_user_port:-8101}
		docker_port=$_user_port

		docker run -d \
			--name speedtest \
			--restart=always \
			-p ${docker_port}:80 \
			--network host \
			adolfintel/speedtest:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="LibreSpeed测速面板, 自托管的网络测速工具"
	local app_url="官网介绍: https://github.com/librespeed/speedtest"
	local app_size="1"
	docker_app
}

# PhotoPrism私有相册系统
photoprism_app(){
	local app_id="46"

	local app_name="PhotoPrism私有相册"
	local app_text="基于AI的私有照片管理和浏览系统"
	local app_url="官网介绍: https://photoprism.app/"
	local docker_name="photoprism-app"
	local docker_port="8102"
	local app_size="3"

	docker_app_install() {
		mkdir -p /home/docker/photoprism/storage /home/docker/photoprism/originals
		cd /home/docker/photoprism

		cat > docker-compose.yml << 'EOF'
services:
  photoprism:
    image: photoprism/photoprism:latest
    container_name: photoprism-app
    restart: always
    ports:
      - '${docker_port}:2342'
    environment:
      PHOTOPRISM_ADMIN_USER: "admin"
      PHOTOPRISM_ADMIN_PASSWORD: "changeme"
      PHOTOPRISM_AUTH_MODE: "password"
      PHOTOPRISM_SITE_URL: "http://localhost:2342"
    volumes:
      - storage:/photoprism/storage
      - originals:/photoprism/originals
    networks:
      - photoprism-net

networks:
  photoprism-net:
    driver: bridge

volumes:
  storage:
  originals:
EOF
		sed -i "s/\${docker_port}/${docker_port}/g" docker-compose.yml
		docker compose up -d
		clear
		echo "PhotoPrism 安装完成"
		check_docker_app_ip
	}

	docker_app_update() {
		cd /home/docker/photoprism && docker compose down --rmi all
		cd /home/docker/photoprism && docker compose up -d
	}

	docker_app_uninstall() {
		cd /home/docker/photoprism && docker compose down --rmi all -v
		rm -rf /home/docker/photoprism
		echo "PhotoPrism 已卸载"
	}

	docker_app_plus
}

# searxng聚合搜索站
searxng_app(){
	local app_id="47"
	local app_name="searxng聚合搜索"
	local docker_name="searxng"
	local docker_img="searxng/searxng:latest"
	local docker_port=8103

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8103): " _user_port
		_user_port=${_user_port:-8103}
		docker_port=$_user_port

		mkdir -p /home/docker/searxng
		docker run -d \
			--name searxng \
			--restart=always \
			-p ${docker_port}:8080 \
			-v /home/docker/searxng:/etc/searxng \
			-e SEARXNG_BASE_URL: "http://localhost:${docker_port}/" \
			-e SEARXNG_SECRET: "$(openssl rand -hex 32)" \
			searxng/searxng:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="注重隐私的元搜索引擎聚合平台, 不追踪用户"
	local app_url="官网介绍: https://github.com/searxng/searxng"
	local app_size="1"
	docker_app
}

# Pingvin-Share文件分享平台
pingvinshare_app(){
	local app_id="48"
	local app_name="Pingvin-Share文件分享"
	local docker_name="pingvin-share"
	local docker_img="stonith404/pingvin-share:latest"
	local docker_port=8104

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8104): " _user_port
		_user_port=${_user_port:-8104}
		docker_port=$_user_port

		mkdir -p /home/docker/pingvin/data /home/docker/pingvin/images
		docker run -d \
			--name pingvin-share \
			--restart=always \
			-p ${docker_port}:3000 \
			-v /home/docker/pingvin/data:/app/data \
			-v /home/docker/pingvin/images:/app/backend/images \
			stonith404/pingvin-share:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="自托管文件分享平台, 支持创建分享链接和上传文件"
	local app_url="官网介绍: https://github.com/stonith404/pingvin-share"
	local app_size="1"
	docker_app
}

# Dockge容器堆栈管理面板
dockge_app(){
	local app_id="49"
	local app_name="Dockge容器管理"
	local docker_name="dockge"
	local docker_img="louislam/dockge:latest"
	local docker_port=8105

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8105): " _user_port
		_user_port=${_user_port:-8105}
		docker_port=$_user_port

		mkdir -p /home/docker/dockge/stacks
		docker run -d \
			--name dockge \
			--restart=always \
			-p ${docker_port}:5001 \
			-v /var/run/docker.sock:/var/run/docker.sock \
			-v /home/docker/dockge/data:/app/data \
			-v /home/docker/dockge/stacks:/opt/stacks \
			louislam/dockge:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="简洁优雅的Docker Compose堆栈管理面板"
	local app_url="官网介绍: https://github.com/louislam/dockge"
	local app_size="1"
	docker_app
}

# it-tools工具箱
ittools_app(){
	local app_id="50"
	local app_name="it-tools工具箱"
	local docker_name="it-tools"
	local docker_img="corentintho/it-tools:latest"
	local docker_port=8106

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8106): " _user_port
		_user_port=${_user_port:-8106}
		docker_port=$_user_port

		docker run -d \
			--name it-tools \
			--restart=always \
			-p ${docker_port}:80 \
			corentintho/it-tools:latest
	}

	local app_text="开发者常用工具集合, 包含JSON格式化/Base64编解码/UUID生成等数百个工具"
	local app_url="官网介绍: https://github.com/CorentinTh/it-tools"
	local app_size="1"
	docker_app
}

# n8n自动化工作流平台
n8n_app(){
	local app_id="51"
	local docker_name="n8n"
	local docker_img="n8nio/n8n:latest"
	local docker_port=8107

	docker_run() {
		mkdir -p /home/docker/n8n/data
		docker run -d \
			--name n8n \
			--restart=always \
			-p ${docker_port}:5678 \
			-v /home/docker/n8n/data:/home/node/.n8n \
			-e N8N_HOST=0.0.0.0 \
			n8nio/n8n:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="开源的工作流自动化平台, 可视化连接各种API和服务"
	local app_url="官网介绍: https://n8n.io/"
	local app_size="2"
	docker_app
}

# OpenWebUI自托管AI平台
openwebui_app(){
	local app_id="52"
	local app_name="OpenWebUI自托管AI"
	local docker_name="open-webui"
	local docker_img="ghcr.io/open-webui/open-webui:main"
	local docker_port=8108

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8108): " _user_port
		_user_port=${_user_port:-8108}
		docker_port=$_user_port

		mkdir -p /home/docker/open-webui/data
		docker run -d \
			--name open-webui \
			--restart=always \
			-p ${docker_port}:8080 \
			-v /home/docker/open-webui/data:/app/backend/data \
			-e WEBUI_AUTH=true \
			ghcr.io/open-webui/open-webui:main

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="自托管的AI对话界面, 支持Ollama/OpenAI等多种后端"
	local app_url="官网介绍: https://github.com/open-webui/open-webui"
	local app_size="2"
	docker_app
}

# Dify大模型知识库
dify_app(){
	local app_id="53"

	local app_name="Dify大模型知识库"
	local app_text="开源的LLM应用开发平台, 可视化编排AI工作流"
	local app_url="官网介绍: https://dify.ai/"
	local docker_name="dify-app"
	local docker_port="8109"
	local app_size="3"

	docker_app_install() {
		mkdir -p /home/docker/dify
		cd /home/docker/dify

		local compose_url="${gh_proxy}raw.githubusercontent.com/langgenius/dify/main/docker/docker-compose.yaml"
		curl -fsSL "$compose_url" -o docker-compose.yaml

		sed -i "s/- '80:80'/#- '80:80'/g" docker-compose.yaml
		sed -i "s/- '443:443'/#- '443:443'/g" docker-compose.yaml
		sed -i "/EXPOSE/a\      - '${docker_port}:80'" docker-compose.yaml

		docker compose up -d
		clear
		echo "Dify 安装完成"
		check_docker_app_ip
	}

	docker_app_update() {
		cd /home/docker/dify && docker compose pull && docker compose up -d
	}

	docker_app_uninstall() {
		cd /home/docker/dify && docker compose down --rmi all -v
		rm -rf /home/docker/dify
		echo "Dify 已卸载"
	}

	docker_app_plus
}

# gitea私有代码仓库
gitea_app(){
	local app_id="54"
	local app_name="gitea私有代码仓库"
	local docker_name="gitea"
	local docker_img="gitea/gitea:latest"
	local docker_port=8110

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8110): " _user_port
		_user_port=${_user_port:-8110}
		docker_port=$_user_port

		mkdir -p /home/docker/gitea/data /home/docker/gitea/mysql
		docker run -d \
			--name gitea \
			--restart=always \
			-p ${docker_port}:3000 \
			-p 222:22 \
			-v /home/docker/gitea/data:/data \
			-v /etc/timezone:/etc/timezone:ro \
			-v /etc/localtime:/etc/localtime:ro \
			gitea/gitea:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="轻量级的自托管Git服务, 类似GitHub/GitLab"
	local app_url="官网介绍: https://gitea.io/"
	local app_size="2"
	docker_app
}

# FileBrowser文件管理器
filebrowser_app(){
	local app_id="55"
	local app_name="FileBrowser文件管理"
	local docker_name="filebrowser"
	local docker_img="filebrowser/filebrowser:latest"
	local docker_port=8111

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8111): " _user_port
		_user_port=${_user_port:-8111}
		docker_port=$_user_port

		mkdir -p /home/docker/filebrowser/database /home/docker/filebrowser/srv
		docker run -d \
			--name filebrowser \
			--restart=always \
			-p ${docker_port}:80 \
			-v /home/docker/filebrowser/database:/database \
			-v /home/docker/filebrowser/srv:/srv \
			filebrowser/filebrowser:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="轻量级的网页文件管理器, 支持文件上传/下载/编辑/分享"
	local app_url="官网介绍: https://github.com/filebrowser/filebrowser"
	local app_size="1"
	docker_app
}

# FRP内网穿透(服务端)
# 多端口样本: Dashboard 端口 (静态) + Server 端口 (用户安装时输入)
frp_server_app(){
	local app_id="56"
	local app_name="FRP内网穿透(服务端)"
	local docker_name="frps"
	local docker_img="snowdreamtech/frps:latest"
	local docker_port=7500
	local app_text="FRP内网穿透服务端, 让内网服务暴露到公网"
	local app_url="官网介绍: https://github.com/fatedier/frp"
	local app_size="1"

	# 静态端口: Dashboard
	add_app_port "Dashboard访问地址" 7500

	docker_run() {
		mkdir -p /home/docker/frps
		# 让用户输入 Server bindPort (默认 7000)
		read -e -p "设置FRP服务端口 (默认7000): " frp_port
		frp_port=${frp_port:-7000}

		local dash_port=$docker_port
		read -e -p "设置Dashboard密码: " dash_pwd

		cat > /home/docker/frps/frps.toml << EOF
bindPort = $frp_port
webServer.addr = "0.0.0.0"
webServer.port = $dash_port
webServer.user = "admin"
webServer.password = "$dash_pwd"
EOF

		docker run -d \
			--name frps \
			--restart=always \
			-p ${frp_port}:${frp_port} \
			-p ${dash_port}:${dash_port} \
			-v /home/docker/frps/frps.toml:/etc/frp/frps.toml \
			snowdreamtech/frps:latest

		# 动态端口: Server (装完后才注册到展示表)
		add_app_port "Server访问地址" "$frp_port"
	}

	docker_app
}

# WireGuard组网(服务端)
# 多端口样本: Web 管理面板 (静态) + WireGuard UDP 端口 (用户安装时输入)
wireguard_server_app(){
	local app_id="57"
	local app_name="WireGuard组网(服务端)"
	local docker_name="wg-easy"
	local docker_img="ghcr.io/wg-easy/wg-easy:latest"
	local docker_port=8113
	local app_text="WireGuard VPN服务端, 简单易用的虚拟组网工具"
	local app_url="官网介绍: https://github.com/wg-easy/wg-easy"
	local app_size="1"

	# 静态端口: Web 管理面板
	add_app_port "Web管理面板" 8113

	docker_run() {
		mkdir -p /home/docker/wireguard
		local wg_port=${docker_port}
		read -e -p "设置WireGuard端口 (默认51820): " wg_udp_port
		wg_udp_port=${wg_udp_port:-51820}
		read -e -p "设置管理面板密码: " wg_pwd

		docker run -d \
			--name wg-easy \
			--restart=always \
			--cap-add=NET_ADMIN \
			--cap-add=SYS_MODULE \
			-v /lib/modules:/lib/modules:ro \
			-p ${wg_port}:51821 \
			-p ${wg_udp_port}:51820/udp \
			-e WG_HOST=$(get_public_ip) \
			-e PASSWORD_HASH="$(openssl passwd -6 "$wg_pwd")" \
			-e WG_ALLOWED_IPS="0.0.0.0/0,::/0" \
			-v /home/docker/wireguard:/etc/wireguard \
			ghcr.io/wg-easy/wg-easy:latest

		# 动态端口: WireGuard UDP (装完后注册)
		add_app_port "WireGuard端口 (UDP)" "$wg_udp_port"
	}

	docker_app
}

# JumpServer开源堡垒机
jumpserver_app(){
	local app_id="58"

	local app_name="JumpServer堡垒机"
	local app_text="开源的运维安全审计系统, 集中管理SSH/RDP访问"
	local app_url="官网介绍: https://www.jumpserver.org/"
	local docker_name="jms-all"
	local docker_port="8114"
	add_app_port "Web管理界面" 8114
	add_app_port "SSH连接端口" 2222
	local app_size="4"

	docker_app_install() {
		mkdir -p /home/docker/jumpserver/data
		cd /home/docker/jumpserver

		cat > docker-compose.yml << 'EOF'
services:
  mysql:
    image: mysql:8.0
    container_name: jms-mysql
    restart: always
    environment:
      MYSQL_ROOT_PASSWORD: jumpserver_root_pwd
      MYSQL_DATABASE: jumpserver
    volumes:
      - mysql_data:/var/lib/mysql
    networks:
      - jms-net

  redis:
    image: redis:7-alpine
    container_name: jms-redis
    restart: always
    networks:
      - jms-net

  core:
    image: jumpserver/jms_core:v3.10.0
    container_name: jms-core
    restart: always
    environment:
      DB_HOST: mysql
      DB_PORT: 3306
      DB_USER: root
      DB_PASSWORD: jumpserver_root_pwd
      DB_NAME: jumpserver
      REDIS_HOST: redis
      CORE_HOST: 127.0.0.1
    depends_on:
      - mysql
      - redis
    networks:
      - jms-net

  koko:
    image: jumpserver/jms_koko:v3.10.0
    container_name: jms-koko
    restart: always
    ports:
      - '${docker_port}:8080'
      - 2222:2222
    environment:
      CORE_HOST: http://core:8080
    depends_on:
      - core
    networks:
      - jms-net

networks:
  jms-net:
    driver: bridge

volumes:
  mysql_data:
EOF
		sed -i "s/\${docker_port}/${docker_port}/g" docker-compose.yml
		docker compose up -d
		clear
		echo "JumpServer 安装完成"
		echo "默认用户: admin  密码: ChangeMe"
		check_docker_app_ip
	}

	docker_app_update() {
		cd /home/docker/jumpserver && docker compose down --rmi all
		cd /home/docker/jumpserver && docker compose up -d
	}

	docker_app_uninstall() {
		cd /home/docker/jumpserver && docker compose down --rmi all -v
		rm -rf /home/docker/jumpserver
		echo "JumpServer 已卸载"
	}

	docker_app_plus
}

# immich图片视频管理器
immich_app(){
	local app_id="59"

	local app_name="Immich图片视频管理"
	local app_text="高性能的自托管Google Photos替代品"
	local app_url="官网介绍: https://immich.app/"
	local docker_name="immich-server"
	local docker_port="8115"
	local app_size="3"

	docker_app_install() {
		mkdir -p /home/docker/immich
		cd /home/docker/immich

		curl -fsSL "${gh_proxy}raw.githubusercontent.com/immich-app/immich/main/docker-compose.yml" -o docker-compose.yml
		curl -fsSL "${gh_proxy}raw.githubusercontent.com/immich-app/immich/main/.env" -o .env

		sed -i "s/- '2283:2283'/#- '2283:2283'/g" docker-compose.yml
		sed -i "/EXPOSE/a\      - '${docker_port}:2283'" docker-compose.yml

		docker compose up -d
		clear
		echo "Immich 安装完成"
		check_docker_app_ip
	}

	docker_app_update() {
		cd /home/docker/immich && docker compose pull && docker compose up -d
	}

	docker_app_uninstall() {
		cd /home/docker/immich && docker compose down --rmi all -v
		rm -rf /home/docker/immich
		echo "Immich 已卸载"
	}

	docker_app_plus
}

# Syncthing点对点文件同步工具
syncthing_app(){
	local app_id="60"
	local app_name="Syncthing文件同步"
	local docker_name="syncthing"
	local docker_img="syncthing/syncthing:latest"
	local docker_port=8116
	add_app_port "Web管理界面" 8116
	add_app_port "设备同步端口 (TCP+UDP)" 22000

	docker_run() {
		mkdir -p /home/docker/syncthing/config
		docker run -d \
			--name syncthing \
			--restart=always \
			-p ${docker_port}:8384 \
			-p 22000:22000/tcp \
			-p 22000:22000/udp \
			-v /home/docker/syncthing/config:/var/syncthing/config \
			syncthing/syncthing:latest
	}

	local app_text="开源的连续文件同步工具, 支持P2P多设备间文件同步"
	local app_url="官网介绍: https://syncthing.net/"
	local app_size="1"
	docker_app
}

# Umami网站统计工具
umami_app(){
	local app_id="61"
	local app_name="Umami网站统计"
	local docker_name="umami"
	local docker_img="ghcr.io/umami-software/umami:postgresql-latest"
	local docker_port=8117

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8117): " _user_port
		_user_port=${_user_port:-8117}
		docker_port=$_user_port

		mkdir -p /home/docker/umami/data
		docker run -d \
			--name umami \
			--restart=always \
			-p ${docker_port}:3000 \
			-e DATABASE_URL=postgresql://umami:umami_pwd@db:5432/umami \
			-e UMAMI_APP_SECRET="$(openssl rand -hex 32)" \
			umami/umami:postgresql-latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="开源的网站分析统计工具, Google Analytics的隐私友好替代"
	local app_url="官网介绍: https://umami.is/"
	local app_size="1"
	docker_app
}

# 思源笔记
siyuan_app(){
	local app_id="62"
	local app_name="思源笔记"
	local docker_name="siyuan"
	local docker_img="b3log/siyuan:latest"
	local docker_port=8118

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8118): " _user_port
		_user_port=${_user_port:-8118}
		docker_port=$_user_port

		mkdir -p /home/docker/siyuan/workspace
		docker run -d \
			--name siyuan \
			--restart=always \
			-p ${docker_port}:6806 \
			-v /home/docker/siyuan/workspace:/siyuan/workspace \
			b3log/siyuan:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="本地优先的个人知识管理系统, 支持块级引用和双向链接"
	local app_url="官网介绍: https://b3log.org/siyuan/"
	local app_size="2"
	docker_app
}

# SFTPGo文件传输工具
sftpgp_app(){
	local app_id="63"
	local app_name="SFTPGo文件传输"
	local docker_name="sftpgo"
	local docker_img="drakkan/sftpgo:latest"
	local docker_port=8119

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8119): " _user_port
		_user_port=${_user_port:-8119}
		docker_port=$_user_port

		mkdir -p /home/docker/sftpgo/data /home/docker/sftpgo/config
		docker run -d \
			--name sftpgo \
			--restart=always \
			-p ${docker_port}:8080 \
			-p 2022:2022 \
			-v /home/docker/sftpgo/data:/srv/sftpgo \
			-v /home/docker/sftpgo/config:/etc/sftpgo \
			drakkan/sftpgo:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="功能齐全的SFTP/FTP/WebDAV服务器, 支持多种协议"
	local app_url="官网介绍: https://github.com/drakkan/sftpgo"
	local app_size="1"
	docker_app
}

# Owncast自托管直播平台
owncast_app(){
	local app_id="64"
	local app_name="Owncast自托管直播"
	local docker_name="owncast"
	local docker_img="owncast/owncast:latest"
	local docker_port=8120

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8120): " _user_port
		_user_port=${_user_port:-8120}
		docker_port=$_user_port

		mkdir -p /home/docker/owncast/data
		docker run -d \
			--name owncast \
			--restart=always \
			-p ${docker_port}:8080 \
			-p 1935:1935 \
			-v /home/docker/owncast/data:/app/data \
			owncast/owncast:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="自托管的视频直播平台, 支持RTMP推流和Web观看"
	local app_url="官网介绍: https://owncast.online/"
	local app_size="2"
	docker_app
}

# Deepseek聊天AI大模型
deepseek_app(){
	local app_id="65"
	local app_name="Deepseek AI大模型"
	local docker_name="deepseek"
	local docker_img="deepseek-ai/deepseek-coder:6.7b-instruct-q4_0"
	local docker_port=8121

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8121): " _user_port
		_user_port=${_user_port:-8121}
		docker_port=$_user_port

		docker run -d \
			--name deepseek \
			--restart=always \
			-p ${docker_port}:8000 \
			-v /home/docker/deepseek:/root/.ollama \
			deepseek-ai/deepseek-coder:6.7b-instruct-q4_0

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="DeepSeek AI大模型本地部署, 支持代码生成和对话"
	local app_url="官网介绍: https://github.com/deepseek-ai/DeepSeek-Coder"
	local app_size="4"
	docker_app
}

# RocketChat多人在线聊天系统
rocketchat_app(){
	local app_id="66"

	local app_name="RocketChat"
	local app_text="开源的团队协作聊天平台, Slack的替代品"
	local app_url="官网介绍: https://rocket.chat/"
	local docker_name="rocketchat-app"
	local docker_port="8122"
	local app_size="3"

	docker_app_install() {
		mkdir -p /home/docker/rocketchat
		cd /home/docker/rocketchat

		cat > docker-compose.yml << 'EOF'
services:
  mongo:
    image: mongo:6
    container_name: rocketchat-mongo
    restart: always
    volumes:
      - mongo_data:/data/db
    command: mongod --replSet rs0 --oplogSize 128
    networks:
      - rocketchat-net

  mongo-init-replica:
    image: mongo:6
    container_name: rocketchat-mongo-init
    restart: "no"
    depends_on:
      - mongo
    command: >
      mongosh --host mongo --eval "rs.initiate({ _id: 'rs0', members: [{ _id: 0, host: 'mongo:27017' }] })"
    networks:
      - rocketchat-net

  rocketchat:
    image: rocket.chat:latest
    container_name: rocketchat-app
    restart: always
    ports:
      - '${docker_port}:3000'
    environment:
      PORT: "3000"
      ROOT_URL: "http://localhost"
      MONGO_URL: "mongodb://mongo:27017/rocketchat"
      MONGO_OPLOG_URL: "mongodb://mongo:27017/local"
    depends_on:
      - mongo
    networks:
      - rocketchat-net

networks:
  rocketchat-net:
    driver: bridge

volumes:
  mongo_data:
EOF
		sed -i "s/\${docker_port}/${docker_port}/g" docker-compose.yml
		docker compose up -d
		clear
		echo "RocketChat 安装完成"
		check_docker_app_ip
	}

	docker_app_update() {
		cd /home/docker/rocketchat && docker compose down --rmi all
		cd /home/docker/rocketchat && docker compose up -d
	}

	docker_app_uninstall() {
		cd /home/docker/rocketchat && docker compose down --rmi all -v
		rm -rf /home/docker/rocketchat
		echo "RocketChat 已卸载"
	}

	docker_app_plus
}

# Gopeed高速下载工具
gopeed_app(){
	local app_id="67"
	local app_name="Gopeed高速下载"
	local docker_name="gopeed"
	local docker_img="liwei2633/gopeed:latest"
	local docker_port=8123

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8123): " _user_port
		_user_port=${_user_port:-8123}
		docker_port=$_user_port

		mkdir -p /home/docker/gopeed
		docker run -d \
			--name gopeed \
			--restart=always \
			-p ${docker_port}:9999 \
			-v /home/docker/gopeed:/app/data \
			liwei2633/gopeed:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="高速下载工具, 支持HTTP/BitTorrent等协议"
	local app_url="官网介绍: https://github.com/GoproxyFoss/gopeed"
	local app_size="1"
	docker_app
}

# 2FAuth自托管二步验证器
twofauth_app(){
	local app_id="68"
	local app_name="2FAuth二步验证器"
	local docker_name="2fauth"
	local docker_img="2fauth/2fauth:latest"
	local docker_port=8124

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8124): " _user_port
		_user_port=${_user_port:-8124}
		docker_port=$_user_port

		mkdir -p /home/docker/2fauth
		docker run -d \
			--name 2fauth \
			--restart=always \
			-p ${docker_port}:8000 \
			-v /home/docker/2fauth:/app/storage \
			-e APP_ENV=production \
			-e APP_KEY=base64:$(openssl rand -base64 32) \
			2fauth/2fauth:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="自托管的二步验证(2FA)管理器, 管理所有TOTP/HOTP令牌"
	local app_url="官网介绍: https://docs.2fauth.app/"
	local app_size="1"
	docker_app
}

# ZFile在线网盘
zfile_app(){
	local app_id="69"
	local app_name="ZFile在线网盘"
	local docker_name="zfile"
	local docker_img="zhaojun1998/zfile:latest"
	local docker_port=8125

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8125): " _user_port
		_user_port=${_user_port:-8125}
		docker_port=$_user_port

		mkdir -p /home/docker/zfile/data
		docker run -d \
			--name zfile \
			--restart=always \
			-p ${docker_port}:8080 \
			-v /home/docker/zfile/data:/data \
			zhaojun1998/zfile:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="开源的在线网盘系统, 支持多种存储策略"
	local app_url="官网介绍: https://github.com/zhaojun1998/zfile"
	local app_size="1"
	docker_app
}

# Nexterm远程连接
nexterm_app(){
	local app_id="70"
	local app_name="Nexterm远程连接"
	local docker_name="nexterm"
	local docker_img="germannewsmaker/nexterm:latest"
	local docker_port=8126

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8126): " _user_port
		_user_port=${_user_port:-8126}
		docker_port=$_user_port

		mkdir -p /home/docker/nexterm
		docker run -d \
			--name nexterm \
			--restart=always \
			-p ${docker_port}:6989 \
			-v /home/docker/nexterm:/app/data \
			germannewsmaker/nexterm:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="开源的远程连接管理工具, 支持SSH/VNC/RDP"
	local app_url="官网介绍: https://github.com/gnmyt/Nexterm"
	local app_size="1"
	docker_app
}

# JitsiMeet视频会议
jitsimeet_app(){
	local app_id="71"
	local app_name="JitsiMeet视频会议"
	local docker_name="jitsi-meet"
	local docker_img="jitsi/web:latest"
	local docker_port=8127

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8127): " _user_port
		_user_port=${_user_port:-8127}
		docker_port=$_user_port

		mkdir -p /home/docker/jitsi/{web,prosody,jicofo,jvb}
		docker run -d \
			--name jitsi-web \
			--restart=always \
			-p ${docker_port}:80 \
			-v /home/docker/jitsi/web:/config \
			-e ENABLE_LETSENCRYPT=0 \
			jitsi/web:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="开源的视频会议系统, 支持多人视频会议"
	local app_url="官网介绍: https://jitsi.org/"
	local app_size="2"
	docker_app
}

# Stream四层代理转发
stream_app(){
	local app_id="72"
	local app_name="Stream四层代理转发"
	local docker_name="stream"
	local docker_img="nginx:alpine"
	local docker_port=8128

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8128): " _user_port
		_user_port=${_user_port:-8128}
		docker_port=$_user_port

		mkdir -p /home/docker/stream
		cat > /home/docker/stream/nginx.conf << 'EOF'
stream {
    server {
        listen 8128;
        proxy_pass backend;
    }
}
EOF
		docker run -d \
			--name stream \
			--restart=always \
			-p ${docker_port}:8128 \
			-v /home/docker/stream/nginx.conf:/etc/nginx/nginx.conf \
			nginx:alpine

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="四层代理转发服务, 基于Nginx Stream模块"
	local app_url="官网介绍: https://nginx.org/"
	local app_size="1"
	docker_app
}

# FileCodeBox文件快递
filecodebox_app(){
	local app_id="73"
	local app_name="FileCodeBox文件快递"
	local docker_name="filecodebox"
	local docker_img="lanol/filecodebox:latest"
	local docker_port=8129

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8129): " _user_port
		_user_port=${_user_port:-8129}
		docker_port=$_user_port

		mkdir -p /home/docker/filecodebox
		docker run -d \
			--name filecodebox \
			--restart=always \
			-p ${docker_port}:12345 \
			-v /home/docker/filecodebox:/app/data \
			lanol/filecodebox:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="文件快递柜, 匿名口令分享文件"
	local app_url="官网介绍: https://github.com/vastsa/FileCodeBox"
	local app_size="1"
	docker_app
}

# Matrix去中心化聊天
matrix_app(){
	local app_id="74"
	local app_name="Matrix去中心化聊天"
	local docker_name="matrix"
	local docker_img="matrixdotorg/synapse:latest"
	local docker_port=8130

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8130): " _user_port
		_user_port=${_user_port:-8130}
		docker_port=$_user_port

		mkdir -p /home/docker/matrix/data
		docker run -d \
			--name matrix \
			--restart=always \
			-p ${docker_port}:8008 \
			-v /home/docker/matrix/data:/data \
			-e SYNAPSE_SERVER_NAME=matrix.local \
			-e SYNAPSE_REPORT_STATS=no \
			matrixdotorg/synapse:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="去中心化的即时通讯协议, 支持端到端加密"
	local app_url="官网介绍: https://matrix.org/"
	local app_size="2"
	docker_app
}

# yt-dlp视频下载
ytdlp_app(){
	local app_id="75"
	local app_name="yt-dlp视频下载"
	local docker_name="yt-dlp"
	local docker_img="mikenye/yt-dlp:latest"
	local docker_port=8131

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8131): " _user_port
		_user_port=${_user_port:-8131}
		docker_port=$_user_port

		mkdir -p /home/docker/ytdlp/downloads
		docker run -d \
			--name yt-dlp \
			--restart=always \
			-p ${docker_port}:8080 \
			-v /home/docker/ytdlp/downloads:/downloads \
			mikenye/yt-dlp:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="强大的视频下载工具, 支持YouTube等数百个网站"
	local app_url="官网介绍: https://github.com/yt-dlp/yt-dlp"
	local app_size="1"
	docker_app
}

# paperless文档管理
paperless_app(){
	local app_id="76"
	local app_name="paperless文档管理"
	local docker_name="paperless"
	local docker_img="ghcr.io/paperless-ngx/paperless-ngx:latest"
	local docker_port=8132

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8132): " _user_port
		_user_port=${_user_port:-8132}
		docker_port=$_user_port

		mkdir -p /home/docker/paperless/{data,media}
		docker run -d \
			--name paperless \
			--restart=always \
			-p ${docker_port}:8000 \
			-v /home/docker/paperless/data:/usr/src/paperless/data \
			-v /home/docker/paperless/media:/usr/src/paperless/media \
			-e PAPERLESS_REDIS=redis://localhost:6379 \
			ghcr.io/paperless-ngx/paperless-ngx:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="开源的文档管理系统, 支持OCR和全文搜索"
	local app_url="官网介绍: https://docs.paperless-ngx.com/"
	local app_size="2"
	docker_app
}

# Wallos财务管理
wallos_app(){
	local app_id="77"
	local app_name="Wallos财务管理"
	local docker_name="wallos"
	local docker_img="bellamy/wallos:latest"
	local docker_port=8133

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8133): " _user_port
		_user_port=${_user_port:-8133}
		docker_port=$_user_port

		mkdir -p /home/docker/wallos
		docker run -d \
			--name wallos \
			--restart=always \
			-p ${docker_port}:80 \
			-v /home/docker/wallos:/var/www/html \
			bellamy/wallos:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="开源的个人财务管理工具, 追踪订阅和支出"
	local app_url="官网介绍: https://github.com/ellite/Wallos"
	local app_size="1"
	docker_app
}

# komari服务器监控
komari_app(){
	local app_id="78"
	local app_name="komari服务器监控"
	local docker_name="komari"
	local docker_img="komari-server:latest"
	local docker_port=8134

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8134): " _user_port
		_user_port=${_user_port:-8134}
		docker_port=$_user_port

		mkdir -p /home/docker/komari
		docker run -d \
			--name komari \
			--restart=always \
			-p ${docker_port}:8080 \
			-v /home/docker/komari:/data \
			komari-server:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="轻量级服务器监控面板"
	local app_url="官网介绍: https://github.com/komari-server"
	local app_size="1"
	docker_app
}

# Dufs静态文件服务器
dufs_app(){
	local app_id="79"
	local app_name="Dufs静态文件服务器"
	local docker_name="dufs"
	local docker_img="sigoden/dufs:latest"
	local docker_port=8135

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8135): " _user_port
		_user_port=${_user_port:-8135}
		docker_port=$_user_port

		mkdir -p /home/docker/dufs/data
		docker run -d \
			--name dufs \
			--restart=always \
			-p ${docker_port}:5000 \
			-v /home/docker/dufs/data:/data \
			sigoden/dufs:latest /data

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="简单的静态文件服务器, 支持上传下载"
	local app_url="官网介绍: https://github.com/sigoden/dufs"
	local app_size="1"
	docker_app
}

# PandaWiki文档管理
pandawiki_app(){
	local app_id="80"
	local app_name="PandaWiki文档管理"
	local docker_name="pandawiki"
	local docker_img="pandawiki/pandawiki:latest"
	local docker_port=8136

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8136): " _user_port
		_user_port=${_user_port:-8136}
		docker_port=$_user_port

		mkdir -p /home/docker/pandawiki
		docker run -d \
			--name pandawiki \
			--restart=always \
			-p ${docker_port}:80 \
			-v /home/docker/pandawiki:/data \
			pandawiki/pandawiki:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="开源的Wiki文档管理系统"
	local app_url="官网介绍: https://github.com/pandawiki"
	local app_size="1"
	docker_app
}

# linkwarden书签管理
linkwarden_app(){
	local app_id="81"
	local app_name="linkwarden书签管理"
	local docker_name="linkwarden"
	local docker_img="ghcr.io/linkwarden/linkwarden:latest"
	local docker_port=8137

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8137): " _user_port
		_user_port=${_user_port:-8137}
		docker_port=$_user_port

		mkdir -p /home/docker/linkwarden
		docker run -d \
			--name linkwarden \
			--restart=always \
			-p ${docker_port}:3000 \
			-v /home/docker/linkwarden:/data \
			-e NEXTAUTH_SECRET=$(openssl rand -base64 32) \
			ghcr.io/linkwarden/linkwarden:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="开源的书签管理工具, 支持网页归档"
	local app_url="官网介绍: https://github.com/linkwarden/linkwarden"
	local app_size="1"
	docker_app
}

# VoceChat聊天系统
vocechat_app(){
	local app_id="82"
	local app_name="VoceChat聊天系统"
	local docker_name="vocechat"
	local docker_img="privoce/vocechat-server:latest"
	local docker_port=8138

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8138): " _user_port
		_user_port=${_user_port:-8138}
		docker_port=$_user_port

		mkdir -p /home/docker/vocechat
		docker run -d \
			--name vocechat \
			--restart=always \
			-p ${docker_port}:3000 \
			-v /home/docker/vocechat:/home/vocechat-server/data \
			privoce/vocechat-server:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="开源的轻量级聊天系统, 支持自托管"
	local app_url="官网介绍: https://voce.chat/"
	local app_size="1"
	docker_app
}

# Karakeep书签管理
karakeep_app(){
	local app_id="83"
	local app_name="Karakeep书签管理"
	local docker_name="karakeep"
	local docker_img="ghcr.io/karakeep-app/karakeep:latest"
	local docker_port=8139

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8139): " _user_port
		_user_port=${_user_port:-8139}
		docker_port=$_user_port

		mkdir -p /home/docker/karakeep
		docker run -d \
			--name karakeep \
			--restart=always \
			-p ${docker_port}:3000 \
			-v /home/docker/karakeep:/data \
			ghcr.io/karakeep-app/karakeep:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="智能书签管理工具, 支持AI自动标签"
	local app_url="官网介绍: https://github.com/karakeep-app/karakeep"
	local app_size="1"
	docker_app
}

# NewAPI大模型资产管理
newapi_app(){
	local app_id="84"
	local app_name="NewAPI大模型资产管理"
	local docker_name="newapi"
	local docker_img="calciumion/new-api:latest"
	local docker_port=8140

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8140): " _user_port
		_user_port=${_user_port:-8140}
		docker_port=$_user_port

		mkdir -p /home/docker/newapi
		docker run -d \
			--name newapi \
			--restart=always \
			-p ${docker_port}:3000 \
			-v /home/docker/newapi:/data \
			calciumion/new-api:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="大模型API管理和分发系统"
	local app_url="官网介绍: https://github.com/Calcium-Ion/new-api"
	local app_size="1"
	docker_app
}

# RAGFlow知识库
ragflow_app(){
	local app_id="85"
	local app_name="RAGFlow知识库"
	local docker_name="ragflow"
	local docker_img="infiniflow/ragflow:latest"
	local docker_port=8141

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8141): " _user_port
		_user_port=${_user_port:-8141}
		docker_port=$_user_port

		mkdir -p /home/docker/ragflow
		docker run -d \
			--name ragflow \
			--restart=always \
			-p ${docker_port}:80 \
			-v /home/docker/ragflow:/ragflow \
			infiniflow/ragflow:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="开源的RAG引擎, 构建企业知识库"
	local app_url="官网介绍: https://github.com/infiniflow/ragflow"
	local app_size="3"
	docker_app
}

# AstrBot聊天机器人
astrbot_app(){
	local app_id="86"
	local app_name="AstrBot聊天机器人"
	local docker_name="astrbot"
	local docker_img="soulter/astrbot:latest"
	local docker_port=8142

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8142): " _user_port
		_user_port=${_user_port:-8142}
		docker_port=$_user_port

		mkdir -p /home/docker/astrbot
		docker run -d \
			--name astrbot \
			--restart=always \
			-p ${docker_port}:6185 \
			-v /home/docker/astrbot:/AstrBot/data \
			soulter/astrbot:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="多平台聊天机器人框架, 支持QQ/微信/飞书"
	local app_url="官网介绍: https://github.com/Soulter/AstrBot"
	local app_size="1"
	docker_app
}

# LangBot聊天机器人
langbot_app(){
	local app_id="87"
	local app_name="LangBot聊天机器人"
	local docker_name="langbot"
	local docker_img="rockchin/langbot:latest"
	local docker_port=8143

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8143): " _user_port
		_user_port=${_user_port:-8143}
		docker_port=$_user_port

		mkdir -p /home/docker/langbot
		docker run -d \
			--name langbot \
			--restart=always \
			-p ${docker_port}:2280 \
			-v /home/docker/langbot:/app \
			rockchin/langbot:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="大模型原生即时通信机器人平台"
	local app_url="官网介绍: https://github.com/RockChinQ/LangBot"
	local app_size="1"
	docker_app
}

# 多格式文件转换
gotenberg_app(){
	local app_id="88"
	local app_name="多格式文件转换"
	local docker_name="gotenberg"
	local docker_img="gotenberg/gotenberg:latest"
	local docker_port=8144

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8144): " _user_port
		_user_port=${_user_port:-8144}
		docker_port=$_user_port

		docker run -d \
			--name gotenberg \
			--restart=always \
			-p ${docker_port}:3000 \
			gotenberg/gotenberg:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="开源的文档转换服务, 支持多种格式互转"
	local app_url="官网介绍: https://github.com/gotenberg/gotenberg"
	local app_size="1"
	docker_app
}

# LibreSpeed测速
librespeed_app(){
	local app_id="89"
	local app_name="LibreSpeed测速"
	local docker_name="librespeed"
	local docker_img="adolfintel/speedtest:latest"
	local docker_port=8145

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8145): " _user_port
		_user_port=${_user_port:-8145}
		docker_port=$_user_port

		docker run -d \
			--name librespeed \
			--restart=always \
			-p ${docker_port}:80 \
			adolfintel/speedtest:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="开源的网络测速工具, 类似Speedtest"
	local app_url="官网介绍: https://github.com/librespeed/speedtest"
	local app_size="1"
	docker_app
}

# gpt-load AI透明代理
gptload_app(){
	local app_id="90"
	local app_name="gpt-load AI透明代理"
	local docker_name="gpt-load"
	local docker_img="ghcr.io/gpt-load/gpt-load:latest"
	local docker_port=8146

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8146): " _user_port
		_user_port=${_user_port:-8146}
		docker_port=$_user_port

		mkdir -p /home/docker/gptload
		docker run -d \
			--name gpt-load \
			--restart=always \
			-p ${docker_port}:8080 \
			-v /home/docker/gptload:/data \
			ghcr.io/gpt-load/gpt-load:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="AI服务透明代理工具"
	local app_url="官网介绍: https://github.com/gpt-load"
	local app_size="1"
	docker_app
}

# 补货监控工具
stockmonitor_app(){
	local app_id="91"
	local app_name="补货监控工具"
	local docker_name="stockmonitor"
	local docker_img="stock-monitor:latest"
	local docker_port=8147

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8147): " _user_port
		_user_port=${_user_port:-8147}
		docker_port=$_user_port

		mkdir -p /home/docker/stockmonitor
		docker run -d \
			--name stockmonitor \
			--restart=always \
			-p ${docker_port}:8080 \
			-v /home/docker/stockmonitor:/data \
			stock-monitor:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="商品库存监控和补货提醒工具"
	local app_url="官网介绍: https://github.com/stock-monitor"
	local app_size="1"
	docker_app
}

# PVE虚拟化管理
pve_app(){
	local app_id="92"
	local app_name="PVE虚拟化管理"
	local docker_name="pve"
	local docker_img="pve-manager:latest"
	local docker_port=8148

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8148): " _user_port
		_user_port=${_user_port:-8148}
		docker_port=$_user_port

		mkdir -p /home/docker/pve
		docker run -d \
			--name pve \
			--restart=always \
			-p ${docker_port}:8006 \
			--privileged \
			-v /home/docker/pve:/data \
			pve-manager:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="Proxmox VE虚拟化管理平台"
	local app_url="官网介绍: https://www.proxmox.com/"
	local app_size="3"
	docker_app
}

# DSM群晖虚拟机
dsm_app(){
	local app_id="93"
	local app_name="DSM群晖虚拟机"
	local docker_name="dsm"
	local docker_img="kroese/virtual-dsm:latest"
	local docker_port=8149

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8149): " _user_port
		_user_port=${_user_port:-8149}
		docker_port=$_user_port

		mkdir -p /home/docker/dsm
		docker run -d \
			--name dsm \
			--restart=always \
			-p ${docker_port}:5000 \
			--privileged \
			-v /home/docker/dsm:/storage \
			kroese/virtual-dsm:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="在Docker中运行群晖DSM系统"
	local app_url="官网介绍: https://github.com/kroese/virtual-dsm"
	local app_size="3"
	docker_app
}

# 在线DOS老游戏
dosgame_app(){
	local app_id="94"
	local app_name="在线DOS老游戏"
	local docker_name="dosgame"
	local docker_img="oldiy/dosgame-web-docker:latest"
	local docker_port=8150

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8150): " _user_port
		_user_port=${_user_port:-8150}
		docker_port=$_user_port

		docker run -d \
			--name dosgame \
			--restart=always \
			-p ${docker_port}:262 \
			oldiy/dosgame-web-docker:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="在线DOS游戏合集, 怀旧经典游戏"
	local app_url="官网介绍: https://github.com/rwv/dosgame"
	local app_size="1"
	docker_app
}

# 迅雷离线下载
xunlei_app(){
	local app_id="95"
	local app_name="迅雷离线下载"
	local docker_name="xunlei"
	local docker_img="cnk3x/xunlei:latest"
	local docker_port=8151

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8151): " _user_port
		_user_port=${_user_port:-8151}
		docker_port=$_user_port

		mkdir -p /home/docker/xunlei/downloads
		docker run -d \
			--name xunlei \
			--restart=always \
			-p ${docker_port}:2345 \
			-v /home/docker/xunlei:/xunlei \
			-v /home/docker/xunlei/downloads:/downloads \
			cnk3x/xunlei:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="迅雷离线下载服务, 支持远程下载"
	local app_url="官网介绍: https://github.com/cnk3x/xunlei"
	local app_size="1"
	docker_app
}

# 小雅Alist全家桶
xiaoya_app(){
	local app_id="96"
	local app_name="小雅Alist全家桶"
	local docker_name="xiaoya"
	local docker_img="xiaoyaliu/alist:latest"
	local docker_port=8152

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8152): " _user_port
		_user_port=${_user_port:-8152}
		docker_port=$_user_port

		mkdir -p /home/docker/xiaoya
		docker run -d \
			--name xiaoya \
			--restart=always \
			-p ${docker_port}:5244 \
			-v /home/docker/xiaoya:/data \
			xiaoyaliu/alist:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="小雅Alist, 整合多网盘资源"
	local app_url="官网介绍: https://github.com/xiaoyaliu/alist"
	local app_size="1"
	docker_app
}

# Bililive直播录制
bililive_app(){
	local app_id="97"
	local app_name="Bililive直播录制"
	local docker_name="bililive"
	local docker_img="bililive/recorder:latest"
	local docker_port=8153

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8153): " _user_port
		_user_port=${_user_port:-8153}
		docker_port=$_user_port

		mkdir -p /home/docker/bililive
		docker run -d \
			--name bililive \
			--restart=always \
			-p ${docker_port}:2356 \
			-v /home/docker/bililive:/rec \
			bililive/recorder:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="B站直播录制工具, 自动录制直播间"
	local app_url="官网介绍: https://github.com/BililiveRecorder/BililiveRecorder"
	local app_size="1"
	docker_app
}

# 极简朋友圈
moments_app(){
	local app_id="98"
	local app_name="极简朋友圈"
	local docker_name="moments"
	local docker_img="moments-app:latest"
	local docker_port=8154

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8154): " _user_port
		_user_port=${_user_port:-8154}
		docker_port=$_user_port

		mkdir -p /home/docker/moments
		docker run -d \
			--name moments \
			--restart=always \
			-p ${docker_port}:3000 \
			-v /home/docker/moments:/data \
			moments-app:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="极简风格的朋友圈/微博系统"
	local app_url="官网介绍: https://github.com/moments-app"
	local app_size="1"
	docker_app
}

# PanSou网盘搜索
pansou_app(){
	local app_id="99"
	local app_name="PanSou网盘搜索"
	local docker_name="pansou"
	local docker_img="pansou-search:latest"
	local docker_port=8155

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8155): " _user_port
		_user_port=${_user_port:-8155}
		docker_port=$_user_port

		mkdir -p /home/docker/pansou
		docker run -d \
			--name pansou \
			--restart=always \
			-p ${docker_port}:8080 \
			-v /home/docker/pansou:/data \
			pansou-search:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="网盘资源搜索引擎"
	local app_url="官网介绍: https://github.com/pansou"
	local app_size="1"
	docker_app
}

# 简单图床lskypro
lskypro_app(){
	local app_id="100"
	local app_name="简单图床lskypro"
	local docker_name="lskypro"
	local docker_img="halcyonazure/lsky-pro-docker:latest"
	local docker_port=8156

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8156): " _user_port
		_user_port=${_user_port:-8156}
		docker_port=$_user_port

		mkdir -p /home/docker/lskypro
		docker run -d \
			--name lskypro \
			--restart=always \
			-p ${docker_port}:8089 \
			-v /home/docker/lskypro:/var/www/html \
			halcyonazure/lsky-pro-docker:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="简单图床系统, 支持多存储策略"
	local app_url="官网介绍: https://github.com/lsky-org/lsky-pro"
	local app_size="1"
	docker_app
}

# 禅道项目管理
zentao_app(){
	local app_id="101"
	local app_name="禅道项目管理"
	local docker_name="zentao"
	local docker_img="idoop/zentao:latest"
	local docker_port=8157

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8157): " _user_port
		_user_port=${_user_port:-8157}
		docker_port=$_user_port

		mkdir -p /home/docker/zentao
		docker run -d \
			--name zentao \
			--restart=always \
			-p ${docker_port}:80 \
			-v /home/docker/zentao:/www/zentaopms \
			idoop/zentao:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="开源的项目管理软件, 支持敏捷开发"
	local app_url="官网介绍: https://www.zentao.net/"
	local app_size="2"
	docker_app
}

# QD-Today定时任务
qdtoday_app(){
	local app_id="102"
	local app_name="QD-Today定时任务"
	local docker_name="qdtoday"
	local docker_img="qdtoday/qd:latest"
	local docker_port=8158

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8158): " _user_port
		_user_port=${_user_port:-8158}
		docker_port=$_user_port

		mkdir -p /home/docker/qdtoday
		docker run -d \
			--name qdtoday \
			--restart=always \
			-p ${docker_port}:80 \
			-v /home/docker/qdtoday:/usr/src/app \
			qdtoday/qd:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="HTTP请求定时任务框架, 自动签到"
	local app_url="官网介绍: https://github.com/qd-today/qd"
	local app_size="1"
	docker_app
}

# 耗子管理面板
haizi_app(){
	local app_id="103"
	local app_name="耗子管理面板"
	local docker_name="haizi"
	local docker_img="haizi-panel:latest"
	local docker_port=8159

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8159): " _user_port
		_user_port=${_user_port:-8159}
		docker_port=$_user_port

		mkdir -p /home/docker/haizi
		docker run -d \
			--name haizi \
			--restart=always \
			-p ${docker_port}:8080 \
			-v /home/docker/haizi:/data \
			haizi-panel:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="耗子管理面板, 轻量级服务器管理"
	local app_url="官网介绍: https://github.com/haizi-panel"
	local app_size="1"
	docker_app
}

# AMH建站面板
amh_app(){
	local app_id="104"
	local app_name="AMH建站面板"
	local docker_name="amh"
	local docker_img="amh-panel:latest"
	local docker_port=8160

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8160): " _user_port
		_user_port=${_user_port:-8160}
		docker_port=$_user_port

		mkdir -p /home/docker/amh
		docker run -d \
			--name amh \
			--restart=always \
			-p ${docker_port}:8888 \
			-v /home/docker/amh:/data \
			amh-panel:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="AMH云主机面板, 建站管理工具"
	local app_url="官网介绍: https://amh.sh/"
	local app_size="2"
	docker_app
}

# 在线翻译服务器
libretranslate_app(){
	local app_id="105"
	local app_name="在线翻译服务器"
	local docker_name="libretranslate"
	local docker_img="libretranslate/libretranslate:latest"
	local docker_port=8161

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8161): " _user_port
		_user_port=${_user_port:-8161}
		docker_port=$_user_port

		docker run -d \
			--name libretranslate \
			--restart=always \
			-p ${docker_port}:5000 \
			libretranslate/libretranslate:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="开源的神经网络翻译API服务"
	local app_url="官网介绍: https://github.com/LibreTranslate/LibreTranslate"
	local app_size="2"
	docker_app
}

# AI视频生成工具
videogen_app(){
	local app_id="106"
	local app_name="AI视频生成工具"
	local docker_name="videogen"
	local docker_img="videogen-ai:latest"
	local docker_port=8162

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8162): " _user_port
		_user_port=${_user_port:-8162}
		docker_port=$_user_port

		mkdir -p /home/docker/videogen
		docker run -d \
			--name videogen \
			--restart=always \
			-p ${docker_port}:8080 \
			-v /home/docker/videogen:/data \
			--gpus all \
			videogen-ai:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="AI视频生成工具, 文本生成视频"
	local app_url="官网介绍: https://github.com/videogen-ai"
	local app_size="3"
	docker_app
}

# RustDesk远程桌面
rustdesk_server_app(){
	local app_id="107"
	local app_name="RustDesk远程桌面"
	local docker_name="rustdesk-server"
	local docker_img="rustdesk/rustdesk-server:latest"
	local docker_port=8163
	add_app_port "Web客户端/API" 8163
	add_app_port "中继服务 (TCP)" 21115
	add_app_port "中继服务 (TCP+UDP)" 21116
	add_app_port "心跳服务" 21117
	add_app_port "服务端口" 21118

	docker_run() {
		mkdir -p /home/docker/rustdesk-server
		docker run -d \
			--name rustdesk-server \
			--restart=always \
			-p 21115:21115 \
			-p 21116:21116 \
			-p 21116:21116/udp \
			-p 21117:21117 \
			-p ${docker_port}:21118 \
			-v /home/docker/rustdesk-server:/data \
			rustdesk/rustdesk-server:latest
	}

	local app_text="开源的远程桌面软件服务端"
	local app_url="官网介绍: https://github.com/rustdesk/rustdesk"
	local app_size="1"
	docker_app
}

# Firefox浏览器
firefox_app(){
	local app_id="108"
	local app_name="Firefox浏览器"
	local docker_name="firefox"
	local docker_img="jlesage/firefox:latest"
	local docker_port=8164

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8164): " _user_port
		_user_port=${_user_port:-8164}
		docker_port=$_user_port

		mkdir -p /home/docker/firefox
		docker run -d \
			--name firefox \
			--restart=always \
			-p ${docker_port}:5800 \
			-v /home/docker/firefox:/config \
			jlesage/firefox:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="在浏览器中运行的Firefox浏览器"
	local app_url="官网介绍: https://github.com/jlesage/docker-firefox"
	local app_size="2"
	docker_app
}

# DPanel容器管理
dpanel_app(){
	local app_id="109"
	local app_name="DPanel容器管理"
	local docker_name="dpanel"
	local docker_img="dpanel/dpanel:latest"
	local docker_port=8165

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8165): " _user_port
		_user_port=${_user_port:-8165}
		docker_port=$_user_port

		mkdir -p /home/docker/dpanel
		docker run -d \
			--name dpanel \
			--restart=always \
			-p ${docker_port}:8080 \
			-v /var/run/docker.sock:/var/run/docker.sock \
			-v /home/docker/dpanel:/dpanel \
			dpanel/dpanel:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="Docker容器可视化管理面板"
	local app_url="官网介绍: https://github.com/dpanel-io/dpanel"
	local app_size="1"
	docker_app
}

# 普罗米修斯监控
prometheus_app(){
	local app_id="110"
	local app_name="普罗米修斯监控"
	local docker_name="prometheus"
	local docker_img="prom/prometheus:latest"
	local docker_port=8166

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8166): " _user_port
		_user_port=${_user_port:-8166}
		docker_port=$_user_port

		mkdir -p /home/docker/prometheus
		cat > /home/docker/prometheus/prometheus.yml << 'EOF'
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']
EOF
		docker run -d \
			--name prometheus \
			--restart=always \
			-p ${docker_port}:9090 \
			-v /home/docker/prometheus:/etc/prometheus \
			prom/prometheus:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="开源的系统监控和报警工具"
	local app_url="官网介绍: https://prometheus.io/"
	local app_size="2"
	docker_app
}