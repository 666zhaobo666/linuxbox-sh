#############################################################################
################################# 鍏€佸簲鐢ㄥ競鍦?###############################

###########################
###### 闈㈡澘绫诲簲鐢ㄧ鐞?######
###########################
# 妫€鏌anel鏄惁瀹夎
check_panel_app() {
	if $panel_path > /dev/null 2>&1; then
		check_panel="${green}宸插畨瑁?{white}"
	else
		check_panel="${white}鏈畨瑁?{white}"
	fi
}
# 闈㈡澘绠＄悊
panel_manage() {
	while true; do
		clear
		check_panel_app
		echo -e "$panelname $check_panel"
		echo "${panelname}鏄竴娆炬椂涓嬫祦琛屼笖寮哄ぇ鐨勮繍缁寸鐞嗛潰鏉?"
		echo "瀹樼綉浠嬬粛: $panelurl "

		# 闈㈡澘搴旂敤: 涓嶈蛋绔彛琛? 鍙睍绀哄畼缃戜綔涓哄弬鑰冨叆鍙?		echo ""
		echo -e "${cyan}鍙傝€冨叆鍙?{white}:  ${green}$panelurl${white}"

		echo ""
		echo -e "${pink}------------------------${white}"
		echo "1. 瀹夎            2. 绠＄悊            3. 鍗歌浇"
		echo -e "${pink}------------------------${white}"
		echo -e "${yellow}0.     ${white}杩斿洖涓婁竴绾ц彍鍗?
		echo -e "${pink}------------------------${white}"
		read -e -p "璇疯緭鍏ヤ綘鐨勯€夋嫨: " choice
		case $choice in
			1)
				check_disk_space 1
				install wget
				iptables_open
				panel_app_install

				check_panel_app
				if [ "$check_panel" = "${green}宸插畨瑁?{white}" ]; then
					add_app_id
				fi
				;;
			2)
				# 淇妫€娴?bug: 鏈灏辩鐞嗕細璇爣涓哄凡瑁?				check_panel_app
				if [ "$check_panel" = "${green}宸插畨瑁?{white}" ]; then
					panel_app_manage
					add_app_id
				else
					echo -e "${red}闈㈡澘鏈畨瑁? 璇峰厛瀹夎${white}"
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
###### Docker绫诲簲鐢ㄧ鐞?######
##############################

# Docker淇℃伅缁熻
docker_tato() {

	local container_count=$(docker ps -a -q 2>/dev/null | wc -l)
	local image_count=$(docker images -q 2>/dev/null | wc -l)
	local network_count=$(docker network ls -q 2>/dev/null | wc -l)
	local volume_count=$(docker volume ls -q 2>/dev/null | wc -l)

	if command -v docker &> /dev/null; then
		echo -e "${green}鐜宸茬粡瀹夎${white}  瀹瑰櫒: ${green}$container_count${white}  闀滃儚: ${green}$image_count${white}  缃戠粶: ${green}$network_count${white}  鍗? ${green}$volume_count${white}"
	fi
}

# 妫€鏌?crontab 鏄惁瀹夎
check_crontab_installed() {
	if ! command -v crontab >/dev/null 2>&1; then
		install_crontab
	fi
}

# 瀹夎 crontab
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
				echo "涓嶆敮鎸佺殑鍙戣鐗? $ID"
				return
				;;
		esac
	else
		echo "鏃犳硶纭畾鎿嶄綔绯荤粺."
		return
	fi

	echo -e "${green}crontab 宸插畨瑁呬笖 cron 鏈嶅姟姝ｅ湪杩愯.${white}"
}

# 淇濆瓨 iptables 瑙勫垯
save_iptables_rules() {
	mkdir -p /etc/iptables
	touch /etc/iptables/rules.v4
	iptables-save > /etc/iptables/rules.v4
	check_crontab_installed
	crontab -l | grep -v 'iptables-restore' | crontab - > /dev/null 2>&1
	(crontab -l ; echo '@reboot iptables-restore < /etc/iptables/rules.v4') | crontab - > /dev/null 2>&1

}


# 妫€鏌ocker
check_docker() {
	if ! command -v docker &>/dev/null; then
		echo -e "${red}鏈娴嬪埌Docker鐜${white}"
		echo -e "${cyan}------------------------"
		echo -e "${cyan}1.   ${white}瀹夎Docker鐜"
		echo -e "${cyan}0.   ${white}杩斿洖涓昏彍鍗?
		echo -e "${cyan}------------------------${white}"
		read -e -p "璇疯緭鍏ヤ綘鐨勯€夋嫨: " docker_choice
		case $docker_choice in
			1)
				install_add_docker
				break_end
				;;
			0)
				return_to_menu
				;;
			*)
				echo -e "${red}鏃犳晥閫夋嫨, 璇烽噸鏂拌緭鍏?!${white}"
				sleep 1
				;;
		esac
		return
	fi
}

# 妫€鏌ocker搴旂敤鏄惁瀹夎
check_docker_app() {
	if docker ps -a --format '{{.Names}}' | grep -q "^${docker_name}$" >/dev/null 2>&1 ; then
		check_docker="${green}宸插畨瑁?{white}"
		return 0
	else
		check_docker="${grey}鏈畨瑁?{white}"
		return 1
	fi
}

# 妫€鏌ocker搴旂敤鐨勮闂湴鍧€
check_docker_app_ip() {
echo -e "${pink}------------------------${white}"
echo "${access_label:-璁块棶鍦板潃}:"
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

# 妫€鏌ocker闀滃儚鏇存柊
check_docker_image_update() {
	local container_name=$1
	local country=$(curl -s ipinfo.io/country)
	if [[ "$country" == "CN" ]]; then
		update_status=""
		return
	fi

	# 鑾峰彇瀹瑰櫒鐨勫垱寤烘椂闂村拰闀滃儚鍚嶇О
	local container_info=$(docker inspect --format='{{.Created}},{{.Config.Image}}' "$container_name" 2>/dev/null)
	local container_created=$(echo "$container_info" | cut -d',' -f1)
	local image_name=$(echo "$container_info" | cut -d',' -f2)

	# 鎻愬彇闀滃儚浠撳簱鍜屾爣绛?	local image_repo=${image_name%%:*}
	local image_tag=${image_name##*:}

	# 榛樿鏍囩涓?latest
	[[ "$image_repo" == "$image_tag" ]] && image_tag="latest"

	# 娣诲姞瀵瑰畼鏂归暅鍍忕殑鏀寔
	[[ "$image_repo" != */* ]] && image_repo="library/$image_repo"

	# 浠?Docker Hub API 鑾峰彇闀滃儚鍙戝竷鏃堕棿
	local hub_info=$(curl -s "https://hub.docker.com/v2/repositories/$image_repo/tags/$image_tag")
	local last_updated=$(echo "$hub_info" | jq -r '.last_updated' 2>/dev/null)

	# 楠岃瘉鑾峰彇鐨勬椂闂?	if [[ -n "$last_updated" && "$last_updated" != "null" ]]; then
		local container_created_ts=$(date -d "$container_created" +%s 2>/dev/null)
		local last_updated_ts=$(date -d "$last_updated" +%s 2>/dev/null)

		# 姣旇緝鏃堕棿鎴?		if [[ $container_created_ts -lt $last_updated_ts ]]; then
			update_status="${yellow}鍙戠幇鏂扮増鏈?${white}"
		else
			update_status=""
		fi
	else
		update_status=""
	fi
}

# 妫€鏌ocker瀹瑰櫒鐨勭鍙ｈ闂?block_container_port() {
	local container_name_or_id=$1
	local allowed_ip=$2

	# 鑾峰彇瀹瑰櫒鐨?IP 鍦板潃
	local container_ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$container_name_or_id")

	if [ -z "$container_ip" ]; then
		return 1
	fi

	install iptables


	# 妫€鏌ュ苟灏佺鍏朵粬鎵€鏈?IP
	if ! iptables -C DOCKER-USER -p tcp -d "$container_ip" -j DROP &>/dev/null; then
		iptables -I DOCKER-USER -p tcp -d "$container_ip" -j DROP
	fi

	# 妫€鏌ュ苟鏀捐鎸囧畾 IP
	if ! iptables -C DOCKER-USER -p tcp -s "$allowed_ip" -d "$container_ip" -j ACCEPT &>/dev/null; then
		iptables -I DOCKER-USER -p tcp -s "$allowed_ip" -d "$container_ip" -j ACCEPT
	fi

	# 妫€鏌ュ苟鏀捐鏈湴缃戠粶 127.0.0.0/8
	if ! iptables -C DOCKER-USER -p tcp -s 127.0.0.0/8 -d "$container_ip" -j ACCEPT &>/dev/null; then
		iptables -I DOCKER-USER -p tcp -s 127.0.0.0/8 -d "$container_ip" -j ACCEPT
	fi

	# 妫€鏌ュ苟灏佺鍏朵粬鎵€鏈?IP
	if ! iptables -C DOCKER-USER -p udp -d "$container_ip" -j DROP &>/dev/null; then
		iptables -I DOCKER-USER -p udp -d "$container_ip" -j DROP
	fi

	# 妫€鏌ュ苟鏀捐鎸囧畾 IP
	if ! iptables -C DOCKER-USER -p udp -s "$allowed_ip" -d "$container_ip" -j ACCEPT &>/dev/null; then
		iptables -I DOCKER-USER -p udp -s "$allowed_ip" -d "$container_ip" -j ACCEPT
	fi

	# 妫€鏌ュ苟鏀捐鏈湴缃戠粶 127.0.0.0/8
	if ! iptables -C DOCKER-USER -p udp -s 127.0.0.0/8 -d "$container_ip" -j ACCEPT &>/dev/null; then
		iptables -I DOCKER-USER -p udp -s 127.0.0.0/8 -d "$container_ip" -j ACCEPT
	fi

	if ! iptables -C DOCKER-USER -m state --state ESTABLISHED,RELATED -d "$container_ip" -j ACCEPT &>/dev/null; then
		iptables -I DOCKER-USER -m state --state ESTABLISHED,RELATED -d "$container_ip" -j ACCEPT
	fi

	echo "宸查樆姝P+绔彛璁块棶璇ユ湇鍔?
	save_iptables_rules
}


# 娓呴櫎瀹瑰櫒鐨勯槻鐏瑙勫垯
clear_container_rules() {
	local container_name_or_id=$1
	local allowed_ip=$2

	# 鑾峰彇瀹瑰櫒鐨?IP 鍦板潃
	local container_ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$container_name_or_id")

	if [ -z "$container_ip" ]; then
		return 1
	fi

	install iptables


	# 娓呴櫎灏佺鍏朵粬鎵€鏈?IP 鐨勮鍒?	if iptables -C DOCKER-USER -p tcp -d "$container_ip" -j DROP &>/dev/null; then
		iptables -D DOCKER-USER -p tcp -d "$container_ip" -j DROP
	fi

	# 娓呴櫎鏀捐鎸囧畾 IP 鐨勮鍒?	if iptables -C DOCKER-USER -p tcp -s "$allowed_ip" -d "$container_ip" -j ACCEPT &>/dev/null; then
		iptables -D DOCKER-USER -p tcp -s "$allowed_ip" -d "$container_ip" -j ACCEPT
	fi

	# 娓呴櫎鏀捐鏈湴缃戠粶 127.0.0.0/8 鐨勮鍒?	if iptables -C DOCKER-USER -p tcp -s 127.0.0.0/8 -d "$container_ip" -j ACCEPT &>/dev/null; then
		iptables -D DOCKER-USER -p tcp -s 127.0.0.0/8 -d "$container_ip" -j ACCEPT
	fi

	# 娓呴櫎灏佺鍏朵粬鎵€鏈?IP 鐨勮鍒?	if iptables -C DOCKER-USER -p udp -d "$container_ip" -j DROP &>/dev/null; then
		iptables -D DOCKER-USER -p udp -d "$container_ip" -j DROP
	fi

	# 娓呴櫎鏀捐鎸囧畾 IP 鐨勮鍒?	if iptables -C DOCKER-USER -p udp -s "$allowed_ip" -d "$container_ip" -j ACCEPT &>/dev/null; then
		iptables -D DOCKER-USER -p udp -s "$allowed_ip" -d "$container_ip" -j ACCEPT
	fi

	# 娓呴櫎鏀捐鏈湴缃戠粶 127.0.0.0/8 鐨勮鍒?	if iptables -C DOCKER-USER -p udp -s 127.0.0.0/8 -d "$container_ip" -j ACCEPT &>/dev/null; then
		iptables -D DOCKER-USER -p udp -s 127.0.0.0/8 -d "$container_ip" -j ACCEPT
	fi


	if iptables -C DOCKER-USER -m state --state ESTABLISHED,RELATED -d "$container_ip" -j ACCEPT &>/dev/null; then
		iptables -D DOCKER-USER -m state --state ESTABLISHED,RELATED -d "$container_ip" -j ACCEPT
	fi

	echo "宸插厑璁窱P+绔彛璁块棶璇ユ湇鍔?
	save_iptables_rules
}

# 妫€鏌ヤ富鏈虹殑绔彛璁块棶
block_host_port() {
	local port=$1
	local allowed_ip=$2

	if [[ -z "$port" || -z "$allowed_ip" ]]; then
		echo "閿欒锛氳鎻愪緵绔彛鍙峰拰鍏佽璁块棶鐨?IP."
		echo "鐢ㄦ硶: block_host_port <绔彛鍙? <鍏佽鐨処P>"
		return 1
	fi

	install iptables

	# 鎷掔粷鍏朵粬鎵€鏈?IP 璁块棶
	if ! iptables -C INPUT -p tcp --dport "$port" -j DROP &>/dev/null; then
		iptables -I INPUT -p tcp --dport "$port" -j DROP
	fi

	# 鍏佽鎸囧畾 IP 璁块棶
	if ! iptables -C INPUT -p tcp --dport "$port" -s "$allowed_ip" -j ACCEPT &>/dev/null; then
		iptables -I INPUT -p tcp --dport "$port" -s "$allowed_ip" -j ACCEPT
	fi

	# 鍏佽鏈満璁块棶
	if ! iptables -C INPUT -p tcp --dport "$port" -s 127.0.0.0/8 -j ACCEPT &>/dev/null; then
		iptables -I INPUT -p tcp --dport "$port" -s 127.0.0.0/8 -j ACCEPT
	fi

	# 鎷掔粷鍏朵粬鎵€鏈?IP 璁块棶
	if ! iptables -C INPUT -p udp --dport "$port" -j DROP &>/dev/null; then
		iptables -I INPUT -p udp --dport "$port" -j DROP
	fi

	# 鍏佽鎸囧畾 IP 璁块棶
	if ! iptables -C INPUT -p udp --dport "$port" -s "$allowed_ip" -j ACCEPT &>/dev/null; then
		iptables -I INPUT -p udp --dport "$port" -s "$allowed_ip" -j ACCEPT
	fi

	# 鍏佽鏈満璁块棶
	if ! iptables -C INPUT -p udp --dport "$port" -s 127.0.0.0/8 -j ACCEPT &>/dev/null; then
		iptables -I INPUT -p udp --dport "$port" -s 127.0.0.0/8 -j ACCEPT
	fi

	# 鍏佽宸插缓绔嬪拰鐩稿叧杩炴帴鐨勬祦閲?	if ! iptables -C INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT &>/dev/null; then
		iptables -I INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
	fi

	echo "宸查樆姝P+绔彛璁块棶璇ユ湇鍔?
	save_iptables_rules
}

# 娓呴櫎涓绘満鐨勭鍙ｈ闂?clear_host_port_rules() {
	local port=$1
	local allowed_ip=$2

	if [[ -z "$port" || -z "$allowed_ip" ]]; then
		echo "閿欒锛氳鎻愪緵绔彛鍙峰拰鍏佽璁块棶鐨?IP."
		echo "鐢ㄦ硶: clear_host_port_rules <绔彛鍙? <鍏佽鐨処P>"
		return 1
	fi

	install iptables

	# 娓呴櫎灏佺鎵€鏈夊叾浠?IP 璁块棶鐨勮鍒?	if iptables -C INPUT -p tcp --dport "$port" -j DROP &>/dev/null; then
		iptables -D INPUT -p tcp --dport "$port" -j DROP
	fi

	# 娓呴櫎鍏佽鏈満璁块棶鐨勮鍒?	if iptables -C INPUT -p tcp --dport "$port" -s 127.0.0.0/8 -j ACCEPT &>/dev/null; then
		iptables -D INPUT -p tcp --dport "$port" -s 127.0.0.0/8 -j ACCEPT
	fi

	# 娓呴櫎鍏佽鎸囧畾 IP 璁块棶鐨勮鍒?	if iptables -C INPUT -p tcp --dport "$port" -s "$allowed_ip" -j ACCEPT &>/dev/null; then
		iptables -D INPUT -p tcp --dport "$port" -s "$allowed_ip" -j ACCEPT
	fi

	# 娓呴櫎灏佺鎵€鏈夊叾浠?IP 璁块棶鐨勮鍒?	if iptables -C INPUT -p udp --dport "$port" -j DROP &>/dev/null; then
		iptables -D INPUT -p udp --dport "$port" -j DROP
	fi

	# 娓呴櫎鍏佽鏈満璁块棶鐨勮鍒?	if iptables -C INPUT -p udp --dport "$port" -s 127.0.0.0/8 -j ACCEPT &>/dev/null; then
		iptables -D INPUT -p udp --dport "$port" -s 127.0.0.0/8 -j ACCEPT
	fi

	# 娓呴櫎鍏佽鎸囧畾 IP 璁块棶鐨勮鍒?	if iptables -C INPUT -p udp --dport "$port" -s "$allowed_ip" -j ACCEPT &>/dev/null; then
		iptables -D INPUT -p udp --dport "$port" -s "$allowed_ip" -j ACCEPT
	fi

	echo "宸插厑璁窱P+绔彛璁块棶璇ユ湇鍔?
	save_iptables_rules
}

# 璁剧疆 Docker 鐩綍
setup_docker_dir() {

	mkdir -p /home/docker/ 2>/dev/null
	if [ -d "/vol1/1000/" ] && [ ! -d "/vol1/1000/docker" ]; then
		cp -f /home/docker /home/docker1 2>/dev/null
		rm -rf /home/docker 2>/dev/null
		mkdir -p /vol1/1000/docker 2>/dev/null
		ln -s /vol1/1000/docker /home/docker 2>/dev/null
	fi
}

# 娣诲姞搴旂敤 ID
add_app_id() {
	mkdir -p /home/docker
	touch /home/docker/appno.txt
	grep -qxF "${app_id}" /home/docker/appno.txt || echo "${app_id}" >> /home/docker/appno.txt
}


#############################################################################
####################### 澶氱鍙ｆ敞鍐?+ 鐘舵€佹煡璇㈡鏋?############################
#############################################################################
# 鍏ㄥ眬绔彛娉ㄥ唽琛?(姣忎釜 app 鍑芥暟鍏ュ彛鍓嶇敱 clear_app_ports 娓呯┖).
# 搴旂敤閫氳繃 add_app_port "label" port 娉ㄥ唽 1..N 涓澶栨毚闇茬殑璁块棶鍏ュ彛.
# 妗嗘灦鍦?UI 缁熶竴娓叉煋鎴愯〃鏍? 鍏煎鑰?app 浠呭０鏄?docker_port 鐨勬儏鍐? 鑷姩娲剧敓
# 涓€涓?"璁块棶鍦板潃" 鍏ュ彛. port_mode / access_label 鏃у彉閲忓凡搴熷純, 涓嶅啀璇诲彇.
APP_PORTS_LABELS=()
APP_PORTS_NUMBERS=()

# 娉ㄥ唽涓€涓闂叆鍙?add_app_port() {
	APP_PORTS_LABELS+=("$1")
	APP_PORTS_NUMBERS+=("$2")
}

# 娓呯┖绔彛娉ㄥ唽 (linux_app dispatch 鍏ュ彛璋冪敤, 闃叉畫鐣?
clear_app_ports() {
	APP_PORTS_LABELS=()
	APP_PORTS_NUMBERS=()
}

# 淇濆瓨褰撳墠宸叉敞鍐岀殑绔彛鍒版枃浠讹紙鏀寔澶氱鍙ｏ紝绗簩娆¤繘鍏ヨ鎯呴〉鎭㈠鐢級
save_app_ports() {
	[ -z "${docker_name:-}" ] && return
	mkdir -p /home/docker
	> "/home/docker/${docker_name}_ports.txt"
	for i in "${!APP_PORTS_LABELS[@]}"; do
		echo "${APP_PORTS_LABELS[$i]}|${APP_PORTS_NUMBERS[$i]}" >> "/home/docker/${docker_name}_ports.txt"
	done
}

# 浠庢枃浠跺姞杞界鍙ｏ紙绗簩娆¤繘鍏ヨ鎯呴〉鏃朵娇鐢級
load_app_ports() {
	[ -z "${docker_name:-}" ] && return
	local port_file="/home/docker/${docker_name}_ports.txt"
	[ ! -f "$port_file" ] && return

	APP_PORTS_LABELS=()
	APP_PORTS_NUMBERS=()
	while IFS='|' read -r label port; do
		[ -n "$label" ] && [ -n "$port" ] && {
			APP_PORTS_LABELS+=("$label")
			APP_PORTS_NUMBERS+=("$port")
		}
	done < "$port_file"
}

# 鑾峰彇涓荤鍙?(绗竴涓敞鍐岀殑); 鑻ョ┖鍒欏洖閫€鍒?$docker_port 鍏煎鑰?app
get_primary_port() {
	if [ ${#APP_PORTS_NUMBERS[@]} -gt 0 ]; then
		echo "${APP_PORTS_NUMBERS[0]}"
	elif [ -n "${docker_port:-}" ]; then
		echo "$docker_port"
	fi
}

# (no-op) 妗嗘灦涓嶅啀鑷姩娉ㄥ唽, app 蹇呴』鍦?docker_run 閲屾樉寮?add_app_port
_auto_register_fallback_port() { :; }

# 鍏ㄥ眬 app 娉ㄥ唽琛?(渚?666 宸插畨瑁呭垪琛ㄥ睍绀?app_name)
APP_REGISTRY_IDS=()
APP_REGISTRY_NAMES=()

# 鍏ㄥ眬鏄剧ず鍚嶆槧灏? sub_choice 鈫?涓枃鏄剧ず鍚?(linux_app 鑿滃崟 + 666 鍒楄〃鍏辩敤)
# 缁存姢: 涓?linux_app() case 璇彞鐨勯『搴忎竴鑷? 鏀?case 鏃跺悓姝ユ洿鏂拌繖閲?
declare -A APP_DISPLAY_NAMES=(
	[1]="1Panel闈㈡澘"           [2]="瀹濆闈㈡澘"             [3]="aaPanel闈㈡澘"
	[4]="NginxProxyManager闈㈡澘" [5]="OpenList闈㈡澘"         [6]="WebTop杩滅▼妗岄潰缃戦〉鐗?
	[7]="Komari鐩戞帶"            [8]="qbittorrent绂荤嚎涓嬭浇"  [9]="Poste.io閭欢鏈嶅姟鍣ㄧ▼搴?
	[10]="闈掗緳闈㈡澘"             [11]="Code-Server(缃戦〉vscode)" [12]="Looking Glass(娴嬮€熼潰鏉?"
	[13]="闆锋睜WAF闃茬伀澧欓潰鏉?   [14]="onlyoffice鍦ㄧ嚎鍔炲叕OFFICE" [15]="UptimeKuma鐩戞帶宸ュ叿"
	[16]="Memos缃戦〉澶囧繕褰?      [17]="drawio鍏嶈垂鐨勫湪绾垮浘琛ㄨ蒋浠? [18]="Sun-Panel瀵艰埅闈㈡澘"
	[19]="webssh缃戦〉鐗圫SH杩炴帴宸ュ叿" [20]="LobeChatAI鑱婂ぉ鑱氬悎缃戠珯" [21]="MyIP宸ュ叿绠?
	[22]="ghproxy(GitHub鍔犻€熺珯)" [23]="AllinSSL璇佷功绠＄悊骞冲彴" [24]="DDNS-GO"
	[25]="Lucky"                [26]="LibreTV绉佹湁褰辫"      [27]="MoonTV绉佹湁褰辫"
	[28]="Melody闊充箰绮剧伒"       [29]="Beszel鏈嶅姟鍣ㄧ洃鎺?     [30]="SyncTV涓€璧风湅鐗囩鍣?
	[31]="X-UI闈㈡澘"             [32]="3X-UI闈㈡澘"            [33]="Microsoft 365 E5 Renew X"
	[34]="DecoTV绉佹湁褰辫"       [35]="Drawnix鍦ㄧ嚎鐧芥澘"
	[36]="Portainer瀹瑰櫒绠＄悊"    [37]="Cloudreve缃戠洏"        [38]="Nextcloud绉佹湁缃戠洏"
	[39]="emby濯掍綋绠＄悊"         [40]="jellyfin濯掍綋绠＄悊"     [41]="AdGuardHome鍘诲箍鍛?
	[42]="Navidrome闊充箰鏈嶅姟鍣?  [43]="Vaultwarden瀵嗙爜绠＄悊"  [44]="StirlingPDF宸ュ叿澶у叏"
	[45]="Speedtest娴嬮€熼潰鏉?    [46]="PhotoPrism绉佹湁鐩稿唽"   [47]="searxng鑱氬悎鎼滅储"
	[48]="Pingvin-Share鏂囦欢鍒嗕韩" [49]="Dockge瀹瑰櫒绠＄悊"       [50]="it-tools宸ュ叿绠?
	[51]="n8n鑷姩鍖栧伐浣滄祦"      [52]="OpenWebUI鑷墭绠I"    [53]="Dify澶фā鍨嬬煡璇嗗簱"
	[54]="gitea绉佹湁浠ｇ爜浠撳簱"    [55]="FileBrowser鏂囦欢绠＄悊"  [56]="FRP鍐呯綉绌块€?鏈嶅姟绔?"
	[57]="WireGuard缁勭綉(鏈嶅姟绔?" [58]="JumpServer鍫″瀿鏈?     [59]="immich鍥剧墖瑙嗛绠＄悊"
	[60]="Syncthing鏂囦欢鍚屾"    [61]="Umami缃戠珯缁熻"        [62]="鎬濇簮绗旇"
	[63]="SFTPGo鏂囦欢浼犺緭"       [64]="Owncast鑷墭绠＄洿鎾?     [65]="Deepseek AI澶фā鍨?
	[66]="RocketChat鑱婂ぉ绯荤粺"   [67]="Gopeed楂橀€熶笅杞?       [68]="2FAuth浜屾楠岃瘉鍣?
	[69]="ZFile鍦ㄧ嚎缃戠洏"        [70]="Nexterm杩滅▼杩炴帴"      [71]="JitsiMeet瑙嗛浼氳"
	[72]="Stream鍥涘眰浠ｇ悊杞彂"   [73]="FileCodeBox鏂囦欢蹇€?  [74]="Matrix鍘讳腑蹇冨寲鑱婂ぉ"
	[75]="yt-dlp瑙嗛涓嬭浇"       [76]="paperless鏂囨。绠＄悊"    [77]="Wallos璐㈠姟绠＄悊"
	[78]="PairDrop鏂囦欢浼犺緭"      [79]="Dufs闈欐€佹枃浠舵湇鍔″櫒"   [80]="PandaWiki鏂囨。绠＄悊"
	[81]="linkwarden涔︾绠＄悊"   [82]="VoceChat鑱婂ぉ绯荤粺"     [83]="Karakeep涔︾绠＄悊"
	[84]="NewAPI澶фā鍨嬭祫浜х鐞? [85]="RAGFlow鐭ヨ瘑搴?        [86]="AstrBot鑱婂ぉ鏈哄櫒浜?
	[87]="LangBot鑱婂ぉ鏈哄櫒浜?    [88]="澶氭牸寮忔枃浠惰浆鎹?       [89]="LibreSpeed娴嬮€?
	[90]="gpt-load AI閫忔槑浠ｇ悊"  [91]="琛ヨ揣鐩戞帶宸ュ叿"         [92]="PVE铏氭嫙鍖栫鐞?
	[93]="DSM缇ゆ櫀铏氭嫙鏈?        [94]="鍦ㄧ嚎DOS鑰佹父鎴?        [95]="杩呴浄绂荤嚎涓嬭浇"
	[96]="灏忛泤Alist鍏ㄥ妗?      [97]="Bililive鐩存挱褰曞埗"     [98]="鏋佺畝鏈嬪弸鍦?
	[99]="PanSou缃戠洏鎼滅储"       [100]="绠€鍗曞浘搴妉skypro"     [101]="绂呴亾椤圭洰绠＄悊"
	[102]="QD-Today瀹氭椂浠诲姟"    [103]="鑰楀瓙绠＄悊闈㈡澘"        [104]="AMH寤虹珯闈㈡澘"
	[105]="鍦ㄧ嚎缈昏瘧鏈嶅姟鍣?      [106]="AI瑙嗛鐢熸垚宸ュ叿"      [107]="RustDesk杩滅▼妗岄潰"
	[108]="Firefox娴忚鍣?       [109]="DPanel瀹瑰櫒绠＄悊"      [110]="鏅綏绫充慨鏂洃鎺?
)

# 娉ㄥ唽褰撳墠 app 鍒板叏灞€琛?(linux_app 鍏ュ彛澶勭粺涓€璋冧竴娆?
register_app() {
	APP_REGISTRY_IDS+=("$1")
	APP_REGISTRY_NAMES+=("$2")
}

# 娓呯┖ app 娉ㄥ唽琛?clear_app_registry() {
	APP_REGISTRY_IDS=()
	APP_REGISTRY_NAMES=()
}

# 鏍规嵁 app_id 鏌ユ壘鏄剧ず鍚?get_app_name_by_id() {
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

# 鍒ゆ柇 app_id 鏄惁宸插畨瑁?(鐪?/home/docker/appno.txt)
is_app_installed() {
	local id="$1"
	[ -f /home/docker/appno.txt ] && grep -qxF "$id" /home/docker/appno.txt 2>/dev/null
}

# 鑾峰彇 docker 瀹瑰櫒鐨勮繍琛岀姸鎬?# 杈撳嚭: "not_installed" | "running <started_iso>" | "<state>" (exited/paused/...)
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

# 鎶婄鏁版牸寮忓寲鎴?"X澶℡灏忔椂Z鍒? / "X灏忔椂Y鍒? / "X鍒哬绉?
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
		# 澶?灏忔椂+鍒?(鍒嗗彲閫? 涓嶆樉绀虹)
		if [ "$m" -gt 0 ]; then
			echo "${d}澶?{h}灏忔椂${m}鍒?
		elif [ "$h" -gt 0 ]; then
			echo "${d}澶?{h}灏忔椂"
		else
			echo "${d}澶?
		fi
	elif [ "$h" -gt 0 ]; then
		echo "${h}灏忔椂${m}鍒?
	elif [ "$m" -gt 0 ]; then
		echo "${m}鍒?{s}绉?
	else
		echo "${s}绉?
	fi
}

# 璁＄畻涓や釜 ISO 鏃堕棿鎴充箣闂寸殑绉掓暟
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

# 娓叉煋绔彛琛ㄦ牸 (杈规 + 澶氳鍗曞厓鏍? 鍚屼竴绔彛 v4 / v6 鍚勫崰涓€琛?
render_app_ports_table() {
	_auto_register_fallback_port
	if [ ${#APP_PORTS_LABELS[@]} -eq 0 ]; then
		load_app_ports
	fi
	if [ ${#APP_PORTS_LABELS[@]} -eq 0 ]; then
		return
	fi

	ip_address
	local ipv4="${ipv4_address:-}"
	local ipv6="${ipv6_address:-}"

	# 鍒楀
	local LBL_W=22
	local PORT_W=6
	local URL_W=44

	# 缁樺埗琛ㄦ牸椤?涓?搴曞垎闅旂嚎
	_hline() {
		printf "${cyan}+%*s+%*s+%*s+${white}\n" \
			$((LBL_W + 2)) '' $((PORT_W + 2)) '' $((URL_W + 2)) '' | tr ' ' '-'
	}

	# 缁樺埗鍗曡
	_row() {
		printf "${cyan}|${white} %-${LBL_W}s ${cyan}|${white} %-${PORT_W}s ${cyan}|${white} %-${URL_W}s ${cyan}|${white}\n" "$1" "$2" "$3"
	}

	_hline
	_row "鏍囩" "绔彛" "璁块棶鍦板潃"
	_hline

	local i label port v4 v6
	for i in "${!APP_PORTS_LABELS[@]}"; do
		label="${APP_PORTS_LABELS[$i]}"
		port="${APP_PORTS_NUMBERS[$i]}"
		v4=""
		v6=""
		[ -n "$ipv4" ] && v4="http://$ipv4:$port"
		[ -n "$ipv6" ] && v6="http://[$ipv6]:$port"
		# 绗竴琛屽甫 label/port
		if [ -n "$v4" ]; then
			_row "$label" "$port" "$v4"
			# v6 鍗曠嫭鍗犱竴琛?(绌?label/port)
			[ -n "$v6" ] && _row "" "" "$v6"
		elif [ -n "$v6" ]; then
			_row "$label" "$port" "$v6"
		else
			_row "$label" "$port" "(鏈満鏃犲彲鐢?IP)"
		fi
		_hline
	done
}

# 娓叉煋搴旂敤杩愯鐘舵€佽 (璇︽儏椤电敤)
# 杈撳嚭: "Docker 鐘舵€? running (宸茶繍琛?3澶?4灏忔椂)" / "Docker 鐘舵€? exited" / ...
render_app_status_line() {
	local status
	status=$(get_docker_app_status)
	case "$status" in
		not_installed)
			echo -e "${red}鏈畨瑁?{white}"
			;;
		running\ *)
			local started="${status#running }"
			local secs
			secs=$(_secs_between "$started" "$(date -Iseconds)")
			local uptime
			uptime=$(format_uptime "$secs")
			echo -e "${green}杩愯涓?{white} (宸茶繍琛?${uptime})"
			;;
		exited)
			echo -e "${yellow}宸插仠姝?{white}"
			;;
		paused)
			echo -e "${yellow}宸叉殏鍋?{white}"
			;;
		*)
			echo -e "${yellow}${status}${white}"
			;;
	esac
}

# 妫€鏌?/home/web/conf.d/ 涓嬪摢浜涘煙鍚?conf 寮曠敤浜嗘绔彛, 杈撳嚭 https://<domain>
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


# Docker 搴旂敤绠＄悊 (鍚堝苟鐗?
# ----------------------------------------------------------------------------
# 鍏煎涓ょ搴旂敤椋庢牸, 閫氳繃 compose 鏍囧織鑷姩閫夋嫨璺緞:
#   1) 鍗曞鍣ㄩ鏍?(94 涓€?app): 璋冪敤鏂瑰畾涔?docker_run, 妗嗘灦鐢ㄩ粯璁ゅ疄鐜?#      app_id / docker_name / docker_img / docker_port / docker_describe
#      docker_url / docker_use / docker_passwd / app_size
#   2) compose 椋庢牸 (8 涓€?app): 璋冪敤鏂瑰畾涔?docker_app_install/update/uninstall
#      app_id / app_name / app_text / app_url / docker_name / docker_port / app_size
# 鏃х増鍙橀噺鍚?(docker_name/docker_describe/docker_url) 涓庢柊鐗?(app_name/app_text/app_url)
# 閫氳繃 ${var:-fallback} 鍏煎, 鑰佺殑 xxx_app 涓嶇敤鏀逛竴琛?
# ----------------------------------------------------------------------------

# 鍗曞鍣ㄩ鏍? 榛樿瀹夎 (澶栧眰宸?read app_port 鈫?docker_port)
_docker_app_default_install() {
	install jq
	install_docker
	docker_run
	setup_docker_dir
	echo "$docker_port" > "/home/docker/${docker_name}_port.conf"
}

# 鍗曞鍣ㄩ鏍? 榛樿鏇存柊 (鍒犲鍣?鍒犻暅鍍?閲嶈窇 docker_run)
_docker_app_default_update() {
	docker rm -f "$docker_name"
	docker rmi -f "$docker_img"
	docker_run
}

# 鍗曞鍣ㄩ鏍? 榛樿鍗歌浇 (鍒犲鍣?鍒犻暅鍍?娓呮暟鎹洰褰?
_docker_app_default_uninstall() {
	docker rm -f "$docker_name"
	docker rmi -f "$docker_img"
	rm -rf "/home/docker/$docker_name"
}

# 瀹夎/鏇存柊鍚庡鐞? 浼樺厛鏂板紡閽╁瓙 app_post_install / app_post_install_password,
# 鍏滃簳璧拌€佸紡 $docker_use / $docker_passwd (eval 鎵ц)
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

# 缁熶竴鍏ュ彛
# 璋冪敤鏂归渶鍦ㄨ皟鐢ㄥ墠瀹氫箟濂藉彉閲? 鍙€夊畾涔?docker_app_install/update/uninstall (compose)
# 鎴?docker_run (鍗曞鍣?. 鐢?declare -F 鑷姩妫€娴?
# 鏄剧ず鏍囬鐢ㄥ彉閲? 浼樺厛 app_* 鏂板悕, 鍏煎鑰?docker_* 鍛藉悕.
docker_app() {
	# 閫夎矾寰? 浼樺厛 compose 涓夊嚱鏁? 鍚﹀垯鐢ㄥ崟瀹瑰櫒榛樿瀹炵幇
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

	# 鏄剧ず鏍囬鐢ㄥ彉閲? 鍏煎鑰?(docker_*) 涓庢柊 (app_*) 涓ょ鍛藉悕
	local _title="${app_name:-$docker_name}"
	local _text="${app_text:-$docker_describe}"
	local _url="${app_url:-$docker_url}"

	while true; do
		clear
		# 鍏堟墽琛屾鏌ュ嚱鏁? 纭畾瀹瑰櫒鐘舵€?		check_docker_app
		check_docker_image_update "$docker_name"

		# 鏍囬琛?+ 鐘舵€?		echo -e "$_title  $check_docker  $update_status"
		echo "$_text"
		echo "$_url"

		# 宸插畨瑁呮椂: 鐘舵€佽 + 璁块棶鍏ュ彛琛?		if check_docker_app; then
			# 瀹瑰櫒杩愯鐘舵€?(running/exited/...)
			local _status
			_status=$(get_docker_app_status)
			if [ "$_status" != "not_installed" ]; then
				local _line
				_line=$(render_app_status_line)
				echo ""
				echo -e "${cyan}搴旂敤鐘舵€?{white}:  $_line"
			fi

			# 鍩熷悕璁块棶 (鎵?/home/web/conf.d/)
			local _primary
			_primary=$(get_primary_port)
			local _domain
			_domain=$(_render_domain_access "$_primary")
			if [ -n "$_domain" ]; then
				echo -e "${cyan}鍩熷悕璁块棶${white}:  ${green}$_domain${white}"
			fi

			# 绔彛琛?(鏀寔澶氱鍙?
			render_app_ports_table
		fi

		echo ""
		echo -e "${cyan}------------------------------------------------------${white}"

		# 鏍规嵁瀹瑰櫒鏄惁瀛樺湪鏄剧ず涓嶅悓鑿滃崟
		if check_docker_app; then  # 瀹瑰櫒瀛樺湪 (杩斿洖0)
			echo -e "${green}1. 鏇存柊${white}              ${red}2. 鍗歌浇${white}"
		else  # 瀹瑰櫒涓嶅瓨鍦?(杩斿洖闈?)
			echo -e "${green}1. 瀹夎${white}"
		fi

		echo -e "${pink}------------------------------------------------------${white}"

		# 浠呭綋瀹瑰櫒瀛樺湪鏃舵樉绀哄煙鍚嶅拰绔彛鐩稿叧鎿嶄綔
		if check_docker_app; then
			echo -e "5. 娣诲姞鍩熷悕璁块棶      6. 鍒犻櫎鍩熷悕璁块棶"
			echo -e "7. 鍏佽IP+绔彛璁块棶   8. 闃绘IP+绔彛璁块棶"
			echo -e "${pink}------------------------------------------------------${white}"
		fi

		echo -e "${yellow}0. 杩斿洖涓婁竴绾ц彍鍗?{white}"
		echo -e "${pink}------------------------------------------------------${white}"

		read -e -p "璇疯緭鍏ヤ綘鐨勯€夋嫨: " choice

		# 瑙ｆ瀽涓荤鍙?(渚?ldnmp_Proxy 绛変娇鐢?
		local _primary_port
		_primary_port=$(get_primary_port)

		# 鏍规嵁瀹瑰櫒鐘舵€侀檺鍒跺彲鎵ц鐨勯€夐」
		if check_docker_app; then
			# 瀹瑰櫒瀛樺湪鏃跺厑璁哥殑鎿嶄綔
			case $choice in
				1)  # 鏇存柊
					"$_update_cmd"
					if check_docker_app; then
						add_app_id
						save_app_ports
					fi

					clear
					echo "$docker_name 宸茬粡鏇存柊瀹屾垚"
					render_app_ports_table
					echo ""
					_docker_app_post_install
					;;
				2)  # 鍗歌浇
					"$_uninstall_cmd"
					rm -f /home/docker/${docker_name}_port.conf
					rm -f /home/docker/${docker_name}_ports.txt
					sed -i "/\b${app_id}\b/d" /home/docker/appno.txt
					echo "搴旂敤宸插嵏杞?
					;;
				5)  # 娣诲姞鍩熷悕璁块棶
					echo "${docker_name}鍩熷悕璁块棶璁剧疆"
					add_yuming
					ldnmp_Proxy "${yuming}" 127.0.0.1 "${_primary_port}"
					block_container_port "$docker_name" "$ipv4_address"
					;;
				6)  # 鍒犻櫎鍩熷悕璁块棶
					echo "鍩熷悕鏍煎紡 example.com 涓嶅甫https://"
					web_del
					;;
				7)  # 鍏佽IP+绔彛璁块棶
					clear_container_rules "$docker_name" "$ipv4_address"
					;;
				8)  # 闃绘IP+绔彛璁块棶
					block_container_port "$docker_name" "$ipv4_address"
					;;
				0)  # 杩斿洖涓婁竴绾?					break
					;;
				*)  # 鏃犳晥閫夐」
					echo -e "${red}鏃犳晥閫夋嫨, 璇烽噸鏂拌緭鍏?!${white}"
					sleep 1
					;;
			esac
		else
			# 瀹瑰櫒涓嶅瓨鍦ㄦ椂浠呭厑璁稿畨瑁呭拰杩斿洖鎿嶄綔
			case $choice in
				1)  # 鍏ㄦ柊瀹夎
					check_disk_space "$app_size"

					"$_install_cmd"
					if check_docker_app; then
						add_app_id
						save_app_ports
					fi

					clear
					echo "$docker_name 宸茬粡瀹夎瀹屾垚"
					render_app_ports_table
					echo ""
					_docker_app_post_install
					;;
				0)  # 杩斿洖涓婁竴绾?					break
					;;
				*)  # 鏃犳晥閫夐」
					echo -e "${red}鏃犳晥閫夋嫨, 褰撳墠鍙兘閫夋嫨瀹夎鎴栬繑鍥?!${white}"
					sleep 1
					;;
			esac
		fi
		break_end
	done
}

##############################
########## 搴旂敤鍑芥暟 ##########
##############################
# 1panel闈㈡澘
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

# 瀹濆闈㈡澘
bt_app(){
	local app_id="2"
	local app_name="瀹濆闈㈡澘"
	local app_text="瀹濆闈㈡澘鏄竴娆炬祦琛岀殑鍥戒骇 Linux 杩愮淮绠＄悊闈㈡澘"
	local app_url="瀹樼綉浠嬬粛: https://www.bt.cn"
	local panel_path="[ -d "/www/server/panel" ]"
	local panelname="瀹濆闈㈡澘"
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

# aapanel闈㈡澘
aapanel_app(){
	local app_id="3"
	local app_name="aaPanel闈㈡澘"
	local app_text="aaPanel 鏄疂濉旈潰鏉跨殑鍥介檯鐗? 鐣岄潰鑻辨枃, 閫傚悎娴峰鐢ㄦ埛"
	local app_url="瀹樼綉浠嬬粛: https://www.aapanel.com/"
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

# NginxProxyManager鍙鍖栭潰鏉?npm_app(){
		local app_id="4"
	local app_name="NginxProxyManager闈㈡澘"
		local docker_name="npm"
		local docker_img="jc21/nginx-proxy-manager:latest"
		local docker_port=81

		docker_run() {
			# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?			read -e -p "鏈嶅姟绔彛 (榛樿 81): " _user_port
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

			# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
			add_app_port "Web 绔彛" "$docker_port"
		}

		local app_text="涓€涓狽ginx鍙嶅悜浠ｇ悊宸ュ叿闈㈡澘, 涓嶆敮鎸佹坊鍔犲煙鍚嶈闂?"
		local app_url="瀹樼綉浠嬬粛: https://nginxproxymanager.com/"
		local app_size="1"

		docker_app
}

# openlist
openlist_app(){
		local app_id="5"
	local app_name="OpenList闈㈡澘"
		local docker_name="openlist"
		local docker_img="openlistteam/openlist:latest"
		local docker_port=5244

		docker_run() {
			# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?			read -e -p "鏈嶅姟绔彛 (榛樿 5244): " _user_port
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

			# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
			add_app_port "Web 绔彛" "$docker_port"
		}

		local app_text="涓€涓敮鎸佸绉嶅瓨鍌? 鏀寔缃戦〉娴忚鍜?WebDAV 鐨勬枃浠跺垪琛ㄧ▼搴? 鐢?gin 鍜?Solidjs 椹卞姩"
		local app_url="瀹樼綉浠嬬粛: https://github.com/OpenListTeam/OpenList"
		local app_size="1"

		docker_app
}

# webtop(娴忚鍣ㄨ闂甽inux绯荤粺)
webtop_app(){
		local app_id="6"
	local app_name="WebTop杩滅▼妗岄潰缃戦〉鐗?
		local docker_name="webtop-ubuntu"
		local docker_img="lscr.io/linuxserver/webtop:ubuntu-kde"
		local docker_port=3006

		docker_run() {
			# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?			read -e -p "鏈嶅姟绔彛 (榛樿 3006): " _user_port
			_user_port=${_user_port:-3006}
			docker_port=$_user_port

			read -e -p "璁剧疆鐧诲綍鐢ㄦ埛鍚? " admin
			read -e -p "璁剧疆鐧诲綍鐢ㄦ埛瀵嗙爜: " admin_password
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

			# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
			add_app_port "Web 绔彛" "$docker_port"
		}

		local app_text="webtop鍩轰簬Ubuntu鐨勫鍣?鑻P鏃犳硶璁块棶, 璇锋坊鍔犲煙鍚嶈闂?"
		local app_url="瀹樼綉浠嬬粛: https://docs.linuxserver.io/images/docker-webtop/"
		local app_size="2"
		docker_app
}

# PairDrop文件传输
pairdrop_app(){
	local app_id="78"
	local app_name="PairDrop文件传输"
	local docker_name="pairdrop"
	local docker_img="lscr.io/linuxserver/pairdrop:latest"
	local docker_port=3000

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 3000): " _user_port
		_user_port=${_user_port:-3000}
		docker_port=$_user_port

		mkdir -p /home/docker/pairdrop && \
		docker run -d \
			--name pairdrop \
			--restart=unless-stopped \
			-v /home/docker/pairdrop:/config \
			-p ${docker_port}:3000 \
			lscr.io/linuxserver/pairdrop:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="PairDrop - 浏览器内的 AirDrop 替代品, 跨设备文件/消息/链接分享 (P2P 传输, 文件不经服务器)"
	local app_url="官网介绍: https://github.com/schlagmichdoch/PairDrop"
	local app_size="1"
	docker_app
}

# Komari鐩戞帶
komari_app(){
	local app_id="7"
	local app_name="Komari鐩戞帶"
	local docker_name="komari"
	local docker_img="ghcr.io/komari-monitor/komari:latest"
	local docker_port=25774

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 25774): " _user_port
		_user_port=${_user_port:-25774}
		docker_port=$_user_port

		mkdir -p /home/docker/komari && \
		docker run -d \
			--name komari \
			--restart=unless-stopped \
			-v /home/docker/komari:/app/data \
			-p ${docker_port}:25774 \
			ghcr.io/komari-monitor/komari:latest

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="Komari - 杞婚噺鑷墭绠＄殑鏈嶅姟鍣ㄧ洃鎺т笌鍛婅骞冲彴"
	local app_url="瀹樼綉浠嬬粛: https://github.com/komari-monitor/komari"
	local app_size="1"
	docker_app
}



# qbittorrent
qb_app(){
	local app_id="8"
	local app_name="qbittorrent绂荤嚎涓嬭浇"
	local docker_name="qbittorrent"
	local docker_img="lscr.io/linuxserver/qbittorrent:latest"
	docker_run() {
		# 璁╃敤鎴疯緭鍏?Web绠＄悊鐣岄潰 绔彛 (榛樿 8081)
		read -e -p "璁剧疆Web绠＄悊鐣岄潰绔彛 (榛樿8081): " web_port
		web_port=${web_port:-8081}

		docker run -d \
			--name=qbittorrent \
			-e PUID=1000 \
			-e PGID=1000 \
			-e TZ=Etc/UTC \
			-e WEBUI_PORT=${web_port} \
			-e TORRENTING_PORT=56881 \
			-p ${web_port}:${web_port} \
			-p 56881:56881 \
			-p 56881:56881/udp \
			-v /home/docker/qbittorrent/config:/config \
			-v /home/docker/qbittorrent/downloads:/downloads \
			--restart unless-stopped \
			lscr.io/linuxserver/qbittorrent:latest

		# Web闈㈡澘绔彛
		add_app_port "Web绠＄悊鐣岄潰" "$web_port"
		# BT 绔彛淇濇寔纭紪鐮?(鏆備笉鏀?
		add_app_port "BT涓嬭浇绔彛 (TCP+UDP)" 56881
	}

	local app_text="qbittorrent绂荤嚎BT纾佸姏涓嬭浇鏈嶅姟"
	local app_url="瀹樼綉浠嬬粛: https://hub.docker.com/r/linuxserver/qbittorrent"
	local app_size="1"
	docker_app
}

# Poste.io閭欢鏈嶅姟鍣ㄧ▼搴?poste_mail_app(){
	clear
	install telnet
	local app_id="9"
	local app_name="Poste.io閭欢鏈嶅姟鍣ㄧ▼搴?
	local app_text="poste.io 鏄竴涓紑婧愮殑閭欢鏈嶅姟鍣ㄨВ鍐虫柟妗? 鏀寔 Webmail / 鍙嶅瀮鍦?/ 鐥呮瘨鎵弿"
	local app_url="瀹樼綉浠嬬粛: https://poste.io/"
	local docker_name="mailserver"
	while true; do
		check_docker_app
		check_docker_image_update $docker_name

		clear
		echo -e "閭眬鏈嶅姟 $check_docker $update_status"
		echo "poste.io 鏄竴涓紑婧愮殑閭欢鏈嶅姟鍣ㄨВ鍐虫柟妗? "
		echo "瀹樼綉: https://poste.io/"

		echo ""
		echo "绔彛妫€娴?
		port=25
		timeout=3
		if echo "quit" | timeout $timeout telnet smtp.qq.com $port | grep 'Connected'; then
			echo -e "${green}绔彛 $port 褰撳墠鍙敤${white}"
		else
			echo -e "${red}绔彛 $port 褰撳墠涓嶅彲鐢?{white}"
		fi
		echo ""

		if docker ps -a --format '{{.Names}}' | grep -q "$docker_name" >/dev/null 2>&1; then
			yuming=$(cat /home/docker/mail.txt)
			echo "璁块棶鍦板潃: "
			echo "https://$yuming"
		fi

		echo -e "${pink}------------------------${white}"
		echo "1. 瀹夎           2. 鏇存柊           3. 鍗歌浇"
		echo -e "${pink}------------------------${white}"
		echo -e "${yellow}0.     ${white}杩斿洖涓婁竴绾ц彍鍗?
		echo -e "${pink}------------------------${white}"
		read -e -p "杈撳叆浣犵殑閫夋嫨: " choice

		case $choice in
			1)
				check_disk_space 2
				read -e -p "璇疯缃偖绠卞煙鍚?渚嬪 mail.yuming.com : " yuming
				mkdir -p /home/docker
				echo "$yuming" > /home/docker/mail.txt
				echo -e "${pink}------------------------${white}"
				ip_address
				echo "鍏堣В鏋愯繖浜汥NS璁板綍"
				echo "A           mail            $ipv4_address"
				echo "CNAME       imap            $yuming"
				echo "CNAME       pop             $yuming"
				echo "CNAME       smtp            $yuming"
				echo "MX          @               $yuming"
				echo "TXT         @               v=spf1 mx ~all"
				echo "TXT         ?               ?"
				echo ""
				echo -e "${pink}------------------------${white}"
				echo "鎸変换鎰忛敭缁х画..."
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
				echo "poste.io宸茬粡瀹夎瀹屾垚"
				echo -e "${pink}------------------------${white}"
				echo "鎮ㄥ彲浠ヤ娇鐢ㄤ互涓嬪湴鍧€璁块棶poste.io:"
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
				echo "poste.io宸茬粡瀹夎瀹屾垚"
				echo -e "${pink}------------------------${white}"
				echo "鎮ㄥ彲浠ヤ娇鐢ㄤ互涓嬪湴鍧€璁块棶poste.io:"
				echo "https://$yuming"
				echo ""
				;;
			3)
				docker rm -f mailserver
				docker rmi -f analogic/poste.io
				rm /home/docker/mail.txt
				rm -rf /home/docker/mail

				sed -i "/\b${app_id}\b/d" /home/docker/appno.txt
				echo "搴旂敤宸插嵏杞?
				;;

			*)
				break
				;;
		esac
		break_end
	done
}

# 闈掗緳闈㈡澘
qinglong_app(){
	local app_id="10"
	local app_name="闈掗緳闈㈡澘"
	local docker_name="qinglong"
	local docker_img="whyour/qinglong:latest"
	local docker_port=5700

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 5700): " _user_port
		_user_port=${_user_port:-5700}
		docker_port=$_user_port

		docker run -d \
			-v /home/docker/qinglong/data:/ql/data \
			-p ${docker_port}:5700 \
			--name qinglong \
			--hostname qinglong \
			--restart unless-stopped \
			whyour/qinglong:latest

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="闈掗緳闈㈡澘鏄竴涓畾鏃朵换鍔＄鐞嗗钩鍙?
	local app_url="瀹樼綉浠嬬粛: ${url_proxy}github.com/whyour/qinglong"
	local app_size="1"
	docker_app
}

# vscode缃戦〉鐗?code-server)
code_server_app(){
	local app_id="11"
	local app_name="Code-Server(缃戦〉vscode)"
	local docker_name="code-server"
	local docker_img="codercom/code-server"
	local docker_port=8021

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8021): " _user_port
		_user_port=${_user_port:-8021}
		docker_port=$_user_port

		docker run -d -p ${docker_port}:8080 -v /home/docker/vscode-web:/home/coder/.local/share/code-server --name vscode-web --restart always codercom/code-server

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="VScode鏄竴娆惧己澶х殑鍦ㄧ嚎浠ｇ爜缂栧啓宸ュ叿"
	local app_url="瀹樼綉浠嬬粛: ${url_proxy}github.com/coder/code-server"
	local app_size="1"
	docker_app

}

# Looking Glass娴嬮€熼潰鏉?looking_glass_app(){
		local app_id="12"
	local app_name="Looking Glass(娴嬮€熼潰鏉?"
		local docker_name="looking-glass"
		local docker_img="wikihostinc/looking-glass-server"
		local docker_port=8016

		docker_run() {
			# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?			read -e -p "鏈嶅姟绔彛 (榛樿 8016): " _user_port
			_user_port=${_user_port:-8016}
			docker_port=$_user_port

			docker run -d --name looking-glass --restart always -p ${docker_port}:80 wikihostinc/looking-glass-server

			# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
			add_app_port "Web 绔彛" "$docker_port"
		}
		local app_text="Looking Glass鏄竴涓猇PS缃戦€熸祴璇曞伐鍏? 澶氶」娴嬭瘯鍔熻兘, 杩樺彲浠ュ疄鏃剁洃鎺PS杩涘嚭绔欐祦閲?
		local app_url="瀹樼綉浠嬬粛: ${url_proxy}github.com/wikihost-opensource/als"
		local app_size="1"
		docker_app
}

# 闆锋睜WAF闃茬伀澧欓潰鏉?safeline_app(){
	local app_id="13"
	local app_name="闆锋睜WAF闃茬伀澧欓潰鏉?
	local app_text="闆锋睜鏄暱浜鎶€寮€鍙戠殑 WAF 绔欑偣闃茬伀澧欑▼搴忛潰鏉? 鍙互鍙嶄唬绔欑偣杩涜鑷姩鍖栭槻寰?
	local app_url="瀹樼綉浠嬬粛: https://waf-ce.chaitin.cn/"
	local docker_name=safeline-mgt
	local docker_port=9443
	while true; do
		check_docker_app
		clear
		echo -e "闆锋睜鏈嶅姟 $check_docker"
		echo "闆锋睜鏄暱浜鎶€寮€鍙戠殑WAF绔欑偣闃茬伀澧欑▼搴忛潰鏉? 鍙互鍙嶄唬绔欑偣杩涜鑷姩鍖栭槻寰?
		echo "瀹樼綉: https://waf-ce.chaitin.cn/"
		if docker ps -a --format '{{.Names}}' | grep -q "$docker_name" >/dev/null 2>&1; then
			check_docker_app_ip
		fi
		echo ""
		echo -e "${pink}------------------------${white}"
		echo "1. 瀹夎           2. 鏇存柊           3. 閲嶇疆瀵嗙爜           4. 鍗歌浇"
		echo -e "${pink}------------------------${white}"
		echo -e "${yellow}0.     ${white}杩斿洖涓婁竴绾ц彍鍗?
		echo -e "${pink}------------------------${white}"
		read -e -p "杈撳叆浣犵殑閫夋嫨: " choice

		case $choice in
			1)
				install_docker
				check_disk_space 5
				bash -c "$(curl -fsSLk https://waf-ce.chaitin.cn/release/latest/setup.sh)"

				add_app_id
				clear
				echo "闆锋睜WAF闈㈡澘宸茬粡瀹夎瀹屾垚"
				check_docker_app_ip
				docker exec safeline-mgt resetadmin

				;;

			2)
				bash -c "$(curl -fsSLk https://waf-ce.chaitin.cn/release/latest/upgrade.sh)"
				docker rmi $(docker images | grep "safeline" | grep "none" | awk '{print $3}')
				echo ""

				add_app_id
				clear
				echo "闆锋睜WAF闈㈡澘宸茬粡鏇存柊瀹屾垚"
				check_docker_app_ip
				;;
			3)
				docker exec safeline-mgt resetadmin
				;;
			4)
				cd /data/safeline
				docker compose down --rmi all

				sed -i "/\b${app_id}\b/d" /home/docker/appno.txt
				echo "濡傛灉浣犳槸榛樿瀹夎鐩綍閭ｇ幇鍦ㄩ」鐩凡缁忓嵏杞?濡傛灉浣犳槸鑷畾涔夊畨瑁呯洰褰曚綘闇€瑕佸埌瀹夎鐩綍涓嬭嚜琛屾墽琛?"
				echo "docker compose down && docker compose down --rmi all"
				;;
			*)
				break
				;;
		esac
		break_end
	done
}

# onlyoffice鍦ㄧ嚎鍔炲叕OFFICE
onlyoffice_app(){
	local app_id="14"
	local app_name="onlyoffice鍦ㄧ嚎鍔炲叕OFFICE"
	local docker_name="onlyoffice"
	local docker_img="onlyoffice/documentserver"
	local docker_port=8018

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8018): " _user_port
		_user_port=${_user_port:-8018}
		docker_port=$_user_port

		docker run -d -p ${docker_port}:80 \
			--restart=always \
			--name onlyoffice \
			-v /home/docker/onlyoffice/DocumentServer/logs:/var/log/onlyoffice  \
			-v /home/docker/onlyoffice/DocumentServer/data:/var/www/onlyoffice/Data  \
				onlyoffice/documentserver

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="onlyoffice鏄竴娆惧紑婧愮殑鍦ㄧ嚎office宸ュ叿, 澶己澶т簡!"
	local app_url="瀹樼綉浠嬬粛: https://www.onlyoffice.com/"
	local app_size="2"
	docker_app
}

# UptimeKuma鐩戞帶宸ュ叿
uptimekuma_app(){
	local app_id="15"
	local app_name="UptimeKuma鐩戞帶宸ュ叿"
	local docker_name="uptime-kuma"
	local docker_img="louislam/uptime-kuma:latest"
	local docker_port=8022

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8022): " _user_port
		_user_port=${_user_port:-8022}
		docker_port=$_user_port

		docker run -d \
			--name=uptime-kuma \
			-p ${docker_port}:3001 \
			-v /home/docker/uptime-kuma/uptime-kuma-data:/app/data \
			--restart=always \
			louislam/uptime-kuma:latest

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="Uptime Kuma 鏄撲簬浣跨敤鐨勮嚜鎵樼鐩戞帶宸ュ叿"
	local app_url="瀹樼綉浠嬬粛: ${url_proxy}github.com/louislam/uptime-kuma"
	local app_size="1"
	docker_app
}

# Memos缃戦〉澶囧繕褰?memos_app(){
	local app_id="16"
	local app_name="Memos缃戦〉澶囧繕褰?
	local docker_name="memos"
	local docker_img="ghcr.io/usememos/memos:latest"
	local docker_port=8023

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8023): " _user_port
		_user_port=${_user_port:-8023}
		docker_port=$_user_port

		docker run -d --name memos -p ${docker_port}:5230 -v /home/docker/memos:/var/opt/memos --restart always ghcr.io/usememos/memos:latest

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="Memos鏄竴娆捐交閲忕骇銆佽嚜鎵樼鐨勫蹇樺綍涓績"
	local app_url="瀹樼綉浠嬬粛: ${url_proxy}github.com/usememos/memos"
	local app_size="1"
	docker_app
}

# drawio鍏嶈垂鐨勫湪绾垮浘琛ㄨ蒋浠?drawio_app(){
	local app_id="17"
	local app_name="drawio鍏嶈垂鐨勫湪绾垮浘琛ㄨ蒋浠?
	local docker_name="drawio"
	local docker_img="jgraph/drawio"
	local docker_port=8032

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8032): " _user_port
		_user_port=${_user_port:-8032}
		docker_port=$_user_port

		docker run -d --restart=always --name drawio -p ${docker_port}:8080 -v /home/docker/drawio:/var/lib/drawio jgraph/drawio

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="杩欐槸涓€涓己澶у浘琛ㄧ粯鍒惰蒋浠?鎬濈淮瀵煎浘, 鎷撴墤鍥? 娴佺▼鍥? 閮借兘鐢?
	local app_url="瀹樼綉浠嬬粛: https://www.drawio.com/"
	local app_size="1"
	docker_app
}

# Sun-Panel瀵艰埅闈㈡澘
sun_panel_app(){
	local app_id="18"
	local app_name="Sun-Panel瀵艰埅闈㈡澘"
	local docker_name="sun-panel"
	local docker_img="hslr/sun-panel"
	local docker_port=8033

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8033): " _user_port
		_user_port=${_user_port:-8033}
		docker_port=$_user_port

		docker run -d --restart=always -p ${docker_port}:3002 \
			-v /home/docker/sun-panel/conf:/app/conf \
			-v /home/docker/sun-panel/uploads:/app/uploads \
			-v /home/docker/sun-panel/database:/app/database \
			--name sun-panel \
			hslr/sun-panel

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="Sun-Panel鏈嶅姟鍣ㄣ€丯AS瀵艰埅闈㈡澘銆丠omepage銆佹祻瑙堝櫒棣栭〉"
	local app_url="瀹樼綉浠嬬粛: https://doc.sun-panel.top/zh_cn/"
	local app_size="1"
	docker_app
}

# webssh缃戦〉鐗圫SH杩炴帴宸ュ叿
webssh_app(){
	local app_id="19"
	local app_name="webssh缃戦〉鐗圫SH杩炴帴宸ュ叿"
	local docker_name="webssh"
	local docker_img="jrohy/webssh"
	local docker_port=8040
	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8040): " _user_port
		_user_port=${_user_port:-8040}
		docker_port=$_user_port

		docker run -d -p ${docker_port}:5032 --restart always --name webssh -e TZ=Asia/Shanghai jrohy/webssh
	}

	local app_text="绠€鏄撳湪绾縮sh杩炴帴宸ュ叿鍜宻ftp宸ュ叿"
	local app_url="瀹樼綉浠嬬粛: ${url_proxy}github.com/Jrohy/webssh"
	local app_size="1"
	docker_app
}

# LobeChatAI鑱婂ぉ鑱氬悎缃戠珯
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

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="LobeChat鑱氬悎甯傞潰涓婁富娴佺殑AI澶фā鍨? ChatGPT/Claude/Gemini/Groq/Ollama"
	local app_url="瀹樼綉浠嬬粛: ${url_proxy}github.com/lobehub/lobe-chat"
	local app_size="2"
	docker_app
}

# MyIP宸ュ叿绠?myip_app(){
	local app_id="21"
	local app_name="MyIP宸ュ叿绠?
	local docker_name="myip"
	local docker_img="jason5ng32/myip:latest"
	local docker_port=8037

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8037): " _user_port
		_user_port=${_user_port:-8037}
		docker_port=$_user_port

		docker run -d -p ${docker_port}:18966 --name myip jason5ng32/myip:latest

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="鏄竴涓鍔熻兘IP宸ュ叿绠? 鍙互鏌ョ湅鑷繁IP淇℃伅鍙婅繛閫氭€? 鐢ㄧ綉椤甸潰鏉垮憟鐜?
	local app_url="瀹樼綉浠嬬粛: ${url_proxy}github.com/jason5ng32/MyIP/blob/main/README_ZH.md"
	local app_size="1"
	docker_app
}

# ghproxy(GitHub鍔犻€熺珯)
ghproxy_app(){
	local app_id="22"
	local app_name="ghproxy(GitHub鍔犻€熺珯)"
	local docker_name="ghproxy"
	local docker_img="wjqserver/ghproxy:latest"
	local docker_port=8046

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8046): " _user_port
		_user_port=${_user_port:-8046}
		docker_port=$_user_port

		docker run -d \
		--name ghproxy \
		--restart always \
		-p ${docker_port}:8080 \
		-v /home/docker/ghproxy/config:/data/ghproxy/config wjqserver/ghproxy:latest

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="浣跨敤Go瀹炵幇鐨凣HProxy, 鐢ㄤ簬鍔犻€熼儴鍒嗗湴鍖篏ithub浠撳簱鐨勬媺鍙?"
	local app_url="瀹樼綉浠嬬粛: https://github.com/WJQSERVER-STUDIO/ghproxy"
	local app_size="1"
	docker_app
}

# AllinSSL璇佷功绠＄悊骞冲彴
allinssl_app(){
	local app_id="23"
	local app_name="AllinSSL璇佷功绠＄悊骞冲彴"
	local docker_name="allinssl"
	local docker_img="allinssl/allinssl:latest"
	local docker_port=8068

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8068): " _user_port
		_user_port=${_user_port:-8068}
		docker_port=$_user_port

		docker run -itd --name allinssl -p ${docker_port}:8888 -v /home/docker/allinssl/data:/www/allinssl/data -e ALLINSSL_USER=allinssl -e ALLINSSL_PWD=allinssldocker -e ALLINSSL_URL=allinssl allinssl/allinssl:latest

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="寮€婧愬厤璐圭殑 SSL 璇佷功鑷姩鍖栫鐞嗗钩鍙?
	local app_url="瀹樼綉浠嬬粛: https://allinssl.com"
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
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8067): " _user_port
		_user_port=${_user_port:-8067}
		docker_port=$_user_port

		docker run -d \
			--name ddns-go \
			--restart=always \
			-p ${docker_port}:9876 \
			-v /home/docker/ddns-go:/root \
			jeessy/ddns-go

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="鑷姩灏嗕綘鐨勫叕缃?IP(IPv4/IPv6)瀹炴椂鏇存柊鍒板悇澶?DNS 鏈嶅姟鍟? 瀹炵幇鍔ㄦ€佸煙鍚嶈В鏋?"
	local app_url="瀹樼綉浠嬬粛: https://github.com/jeessy2/ddns-go"
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
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8068): " _user_port
		_user_port=${_user_port:-8068}
		docker_port=$_user_port

		docker run -d \
		--name lucky \
		--restart=always \
		-v /home/docker/lucky:/goodluck \
		gdy666/lucky

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="鑷姩灏嗕綘鐨勫叕缃?IP(IPv4/IPv6)瀹炴椂鏇存柊鍒板悇澶?DNS 鏈嶅姟鍟? 瀹炵幇鍔ㄦ€佸煙鍚嶈В鏋?"
	local app_url="瀹樼綉浠嬬粛: https://github.com/gdy666/lucky"
	local app_size="1"
	docker_app
}

# LibreTV绉佹湁褰辫
libretv_app(){
		local app_id="26"
	local app_name="LibreTV绉佹湁褰辫"
		local docker_name="libretv"
		local docker_img="bestzwei/libretv:latest"
		local docker_port=8073

		docker_run() {
			# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?			read -e -p "鏈嶅姟绔彛 (榛樿 8073): " _user_port
			_user_port=${_user_port:-8073}
			docker_port=$_user_port

			read -e -p "璁剧疆LibreTV鐨勭櫥褰曞瘑鐮? " app_passwd
			docker run -d \
				--name libretv \
				--restart unless-stopped \
				-p ${docker_port}:8080 \
				-e PASSWORD=${app_passwd} \
				bestzwei/libretv:latest

			# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
			add_app_port "Web 绔彛" "$docker_port"
		}

		local app_text="鍏嶈垂鍦ㄧ嚎瑙嗛鎼滅储涓庤鐪嬪钩鍙?
		local app_url="瀹樼綉浠嬬粛: https://github.com/LibreSpark/LibreTV"
		local app_size="1"
		docker_app
}

# MoonTV绉佹湁褰辫
moontv_app(){
	local app_id="27"

	local app_name="moontv绉佹湁褰辫"
	local app_text="鍏嶈垂鍦ㄧ嚎瑙嗛鎼滅储涓庤鐪嬪钩鍙?
	local app_url="瀹樼綉浠嬬粛: https://github.com/MoonTechLab/LunaTV"
	local docker_name="moontv-core"
	local docker_port="8074"
	local app_size="2"

	docker_app_install() {
		read -e -p "璁剧疆鐧诲綍鐢ㄦ埛鍚? " admin
		while true; do
			read -e -p "璁剧疆鐧诲綍鐢ㄦ埛瀵嗙爜: " admin_password
			if [ ${#admin_password} -ge 8 ]; then
				break
			else
				echo "瀵嗙爜闀垮害蹇呴』澶т簬8浣? 璇烽噸鏂拌緭鍏? "
			fi
		done
		read -e -p "杈撳叆鎺堟潈鐮? " shouquanma


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
		echo "宸茬粡瀹夎瀹屾垚"
		check_docker_app_ip
	}


	docker_app_update() {
		cd /home/docker/moontv/ && docker compose down --rmi all
		cd /home/docker/moontv/ && docker compose up -d
	}


	docker_app_uninstall() {
		cd /home/docker/moontv/ && docker compose down --rmi all
		rm -rf /home/docker/moontv
		echo "搴旂敤宸插嵏杞?
	}

	docker_app
}

# Melody闊充箰绮剧伒
melody_app(){
	local app_id="28"
	local app_name="Melody闊充箰绮剧伒"
	local docker_name="melody"
	local docker_img="foamzou/melody:latest"
	local docker_port=8075

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8075): " _user_port
		_user_port=${_user_port:-8075}
		docker_port=$_user_port

		docker run -d \
			--name melody \
			--restart unless-stopped \
			-p ${docker_port}:5566 \
			-v /home/docker/melody/.profile:/app/backend/.profile \
			foamzou/melody:latest

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="浣犵殑闊充箰绮剧伒, 鏃ㄥ湪甯姪浣犳洿濂藉湴绠＄悊闊充箰."
	local app_url="瀹樼綉浠嬬粛: https://github.com/foamzou/melody"
	local app_size="1"
	docker_app
}

# Beszel鏈嶅姟鍣ㄧ洃鎺?beszel_app(){
	local app_id="29"
	local app_name="Beszel鏈嶅姟鍣ㄧ洃鎺?
	local docker_name="beszel"
	local docker_img="henrygd/beszel"
	local docker_port=8079

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8079): " _user_port
		_user_port=${_user_port:-8079}
		docker_port=$_user_port

		mkdir -p /home/docker/beszel && \
		docker run -d \
			--name beszel \
			--restart=unless-stopped \
			-v /home/docker/beszel:/beszel_data \
			-p ${docker_port}:8090 \
			henrygd/beszel

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="Beszel杞婚噺鏄撶敤鐨勬湇鍔″櫒鐩戞帶"
	local app_url="瀹樼綉浠嬬粛: https://beszel.dev/zh/"
	local app_size="1"
	docker_app
}

# SyncTV涓€璧风湅鐗囩鍣?synctv_app(){
		local app_id="30"
	local app_name="SyncTV涓€璧风湅鐗囩鍣?
		local docker_name="synctv"
		local docker_img="synctvorg/synctv"
		local docker_port=8087

		docker_run() {
			# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?			read -e -p "鏈嶅姟绔彛 (榛樿 8087): " _user_port
			_user_port=${_user_port:-8087}
			docker_port=$_user_port

			docker run -d \
				--name synctv \
				-v /home/docker/synctv:/root/.synctv \
				-p ${docker_port}:8080 \
				--restart=always \
				synctvorg/synctv

			# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
			add_app_port "Web 绔彛" "$docker_port"
		}

		local app_text="杩滅▼涓€璧疯鐪嬬數褰卞拰鐩存挱鐨勭▼搴?瀹冩彁渚涗簡鍚屾瑙傚奖銆佺洿鎾€佽亰澶╃瓑鍔熻兘"
		local app_url="瀹樼綉浠嬬粛: https://github.com/synctv-org/synctv"
		local app_size="1"
		docker_app
}

# X-UI闈㈡澘
xui_app(){
	local app_id="31"
	local app_name="X-UI闈㈡澘"
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
		echo "璇烽€氳繃绠＄悊闈㈡澘鍗歌浇, 璋㈣阿!"
		break_end
	}
	panel_manage
}

# 3X-UI闈㈡澘
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
		echo "璇烽€氳繃绠＄悊闈㈡澘鍗歌浇, 璋㈣阿!"
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
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 1066): " _user_port
		_user_port=${_user_port:-1066}
		docker_port=$_user_port

		read -e -p "璇疯緭鍏ュ彂閫侀偖浠剁殑鏈嶅姟閭: " send_email
		read -e -p "璇疯緭鍏ユ湇鍔￠偖绠辩殑鎺堟潈鐮? " token
		read -e -p "璇疯緭鍏ユ帴鏀堕偖浠剁殑閭: " receiver_email
		read -e -p "璇疯緭鍏eb鐣岄潰绠＄悊鍛樼櫥褰曞瘑鐮? " admin_pwd

			docker run -d \
				-p ${docker_port}:1066 \
				-e TZ=Asia/Shanghai \
				-e sender="${send_email}" \
				-e pwd="${token}" \
				-e receiver="${receiver_email}" \
				-e adminpwd="${admin_pwd}" \
				hanhongyong/ms365-e5-renew-x:pubemail

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
		}

		local app_text="Microsoft 365 E5 Renew X 涓€閿画璁㈣剼鏈?
		local app_url="瀹樼綉浠嬬粛: https://github.com/hongyonghan/Docker_Microsoft365_E5_Renew_X"
		local app_size="1"
		docker_app
}

# DecoTV绉佹湁褰辫
decotv_app(){
	local app_id="34"

	local app_name="decotv绉佹湁褰辫"
	local app_text="鍏嶈垂鍦ㄧ嚎瑙嗛鎼滅储涓庤鐪嬪钩鍙?
	local app_url="瀹樼綉浠嬬粛: https://github.com/decohererk/decotv"
	local docker_name="decotv-core"
	local docker_port="8076"
	local app_size="2"

	docker_app_install() {
		read -e -p "璁剧疆鐧诲綍鐢ㄦ埛鍚? " admin
		while true; do
			read -e -p "璁剧疆鐧诲綍鐢ㄦ埛瀵嗙爜: " admin_password
			if [ ${#admin_password} -ge 8 ]; then
				break
			else
				echo "瀵嗙爜闀垮害蹇呴』澶т簬8浣? 璇烽噸鏂拌緭鍏? "
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
		
		# 鏇挎崲鍙橀噺
		sed -i "s/\${docker_port}/${docker_port}/g" /home/docker/decotv/docker-compose.yml
		sed -i "s/\${admin}/${admin}/g" /home/docker/decotv/docker-compose.yml
		sed -i "s/\${admin_password}/${admin_password}/g" /home/docker/decotv/docker-compose.yml

		cd /home/docker/decotv/
		docker compose up -d
		clear
		echo "宸茬粡瀹夎瀹屾垚"
		check_docker_app_ip
	}


	docker_app_update() {
		cd /home/docker/decotv/ && docker compose down --rmi all
		cd /home/docker/decotv/ && docker compose up -d
	}


	docker_app_uninstall() {
		cd /home/docker/decotv/ && docker compose down --rmi all
		rm -rf /home/docker/decotv
		echo "搴旂敤宸插嵏杞?
	}

	docker_app
}

# Drawnix鍦ㄧ嚎鐧芥澘
drawnix_app(){
	local app_id="35"
	local app_name="Drawnix鍦ㄧ嚎鐧芥澘"
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

	local app_text="涓€娆惧紑婧愮殑鍦ㄧ嚎鐧芥澘宸ュ叿锛岀被浼糆xcalidraw锛屾敮鎸佹€濈淮瀵煎浘銆佹祦绋嬪浘鍜岃嚜鐢辩粯鍥俱€?
	local app_url="瀹樼綉浠嬬粛: https://github.com/pubuzhixing/drawnix"
	local app_size="1"
	docker_app
}

##############################
######## 搴旂敤涓績鑿滃崟 #########
##############################
linux_app() {

	# 鐘舵€佺偣 (鍗曞瓧绗? 棰滆壊鏍规嵁瀹夎鐘舵€?
	_dot() {
		if [ "${INSTALLED_MAP[$1]:-0}" = "1" ]; then
			echo "${green}鈼?{white}"
		else
			echo "${red}鈼?{white}"
		fi
	}

	# 娓叉煋宸插畨瑁呭簲鐢ㄥ垪琛?(666 鍏ュ彛)
	_render_installed_list() {
		clear
		echo -e "${green}===== 宸插畨瑁呭簲鐢?=====${white}"
		echo ""
		if [ ${#INSTALLED_IDS[@]} -eq 0 ]; then
			echo -e "${yellow}鏆傛棤宸插畨瑁呭簲鐢?{white}"
			break_end
			return 1
		fi
		# 鎸?app_id 鏁板瓧鎺掑簭
		local sorted
		sorted=$(printf '%s\n' "${INSTALLED_IDS[@]}" | sort -n)
		while read -r id; do
			[ -n "$id" ] || continue
			local name="${APP_DISPLAY_NAMES[$id]:-?鏈敞鍐寎"
			echo -e "  ${cyan}$id. ${white}$name  ${green}鈼?{white}"
		done <<< "$sorted"
		echo ""
		echo -e "${pink}------------------------------------------------------------------------------------${white}"
		echo -e "${yellow}0.   ${white}杩斿洖搴旂敤甯傚満"
		echo -e "${pink}------------------------------------------------------------------------------------${white}"
		read -e -p "杈撳叆缂栧彿杩涘叆搴旂敤璇︽儏 (0 杩斿洖): " jump_choice
		if [ "$jump_choice" = "0" ] || [ -z "$jump_choice" ]; then
			return 1
		fi
		# 鐩存帴璺冲埌璇?sub_choice (澶嶇敤涓?case 璋冨害)
		if [ -n "${APP_DISPLAY_NAMES[$jump_choice]:-}" ]; then
			_linux_app_dispatch "$jump_choice"
		else
			echo -e "${red}鏃犳晥缂栧彿 $jump_choice${white}"
			sleep 1
			return 1
		fi
	}

	# sub_choice 璋冨害 (涓昏彍鍗?+ 666 鍒楄〃鍏辩敤)
	_linux_app_dispatch() {
		local sub_choice="$1"
		# 娓呯悊涓婁竴涓?app 娈嬬暀鐨勫唴宓屽嚱鏁板畾涔?		unset -f docker_app_install docker_app_update docker_app_uninstall app_post_install app_post_install_password 2>/dev/null
		clear_app_ports

		case $sub_choice in
		1) 1panel_app ;;
		2) bt_app ;;
		3) aapanel_app ;;
		4) npm_app ;;
		5) openlist_app ;;
		6) webtop_app ;;
		7) komari_app ;;
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
		78) pairdrop_app ;;
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
		# 姣忔娓叉煋鑿滃崟鍓嶅埛鏂板凡瀹夎鐘舵€侊紙瑙ｅ喅瀹夎鍚庝富鐣岄潰涓嶅埛鏂颁负缁胯壊鐨勯棶棰橈級
		declare -A INSTALLED_MAP=()
		INSTALLED_IDS=()
		if [ -f /home/docker/appno.txt ]; then
			while read -r id; do
				[ -n "$id" ] || continue
				INSTALLED_MAP["$id"]=1
				INSTALLED_IDS+=("$id")
			done < /home/docker/appno.txt
		fi

		clear
		echo -e "${green}===== 搴旂敤甯傚満 =====${white}"
		echo -e "[鍥句緥] ${green}鈼?{white} 宸插畨瑁? ${red}鈼?{white} 鏈畨瑁?
		echo ""
		docker_tato
		echo -e "${pink}------------------------------------------------------------------------------------${white}"
		echo -e "${cyan}1.  ${white}1Panel闈㈡澘 $(_dot 1)            ${cyan}2.  ${white}瀹濆闈㈡澘 $(_dot 2)                  ${cyan}3.  ${white}aaPanel闈㈡澘 $(_dot 3)"
		echo -e "${cyan}4.  ${white}NginxProxyManager闈㈡澘 $(_dot 4)  ${cyan}5.  ${white}OpenList闈㈡澘 $(_dot 5)              ${cyan}6.  ${white}WebTop杩滅▼妗岄潰缃戦〉鐗?$(_dot 6)"
		echo -e "${cyan}7.  ${white}Komari鐩戞帶 $(_dot 7)             ${cyan}8.  ${white}qbittorrent绂荤嚎涓嬭浇 $(_dot 8)        ${cyan}9.  ${white}Poste.io閭欢鏈嶅姟鍣ㄧ▼搴?$(_dot 9)"
		echo -e "${cyan}10. ${white}闈掗緳闈㈡澘 $(_dot 10)               ${cyan}11. ${white}Code-Server(缃戦〉vscode) $(_dot 11)  ${cyan}12. ${white}Looking Glass(娴嬮€熼潰鏉? $(_dot 12)"
		echo -e "${cyan}13. ${white}闆锋睜WAF闃茬伀澧欓潰鏉?$(_dot 13)      ${cyan}14. ${white}onlyoffice鍦ㄧ嚎鍔炲叕OFFICE $(_dot 14) ${cyan}15. ${white}UptimeKuma鐩戞帶宸ュ叿 $(_dot 15)"
		echo -e "${cyan}16. ${white}Memos缃戦〉澶囧繕褰?$(_dot 16)        ${cyan}17. ${white}drawio鍏嶈垂鐨勫湪绾垮浘琛ㄨ蒋浠?$(_dot 17) ${cyan}18. ${white}Sun-Panel瀵艰埅闈㈡澘 $(_dot 18)"
		echo -e "${cyan}19. ${white}webssh缃戦〉鐗圫SH杩炴帴宸ュ叿 $(_dot 19)${cyan}20. ${white}LobeChatAI鑱婂ぉ鑱氬悎缃戠珯 $(_dot 20)   ${cyan}21. ${white}MyIP宸ュ叿绠?$(_dot 21)"
		echo -e "${cyan}22. ${white}ghproxy(GitHub鍔犻€熺珯) $(_dot 22)  ${cyan}23. ${white}AllinSSL璇佷功绠＄悊骞冲彴 $(_dot 23)     ${cyan}24. ${white}DDNS-GO $(_dot 24)"
		echo -e "${cyan}25. ${white}Lucky $(_dot 25)                  ${cyan}26. ${white}LibreTV绉佹湁褰辫 $(_dot 26)          ${cyan}27. ${white}MoonTV绉佹湁褰辫 $(_dot 27)"
		echo -e "${cyan}28. ${white}Melody闊充箰绮剧伒 $(_dot 28)         ${cyan}29. ${white}Beszel鏈嶅姟鍣ㄧ洃鎺?$(_dot 29)         ${cyan}30. ${white}SyncTV涓€璧风湅鐗囩鍣?$(_dot 30)"
		echo -e "${cyan}31. ${white}X-UI闈㈡澘 $(_dot 31)               ${cyan}32. ${white}3X-UI闈㈡澘 $(_dot 32)                  ${cyan}33. ${white}Microsoft 365 E5 Renew X $(_dot 33)"
		echo -e "${cyan}34. ${white}DecoTV绉佹湁褰辫 $(_dot 34)         ${cyan}35. ${white}Drawnix鍦ㄧ嚎鐧芥澘 $(_dot 35)"
		echo -e "${pink}------------------------------------------------------------------------------------${white}"
		echo -e "${cyan}36. ${white}Portainer瀹瑰櫒绠＄悊 $(_dot 36)      ${cyan}37. ${white}Cloudreve缃戠洏 $(_dot 37)            ${cyan}38. ${white}Nextcloud绉佹湁缃戠洏 $(_dot 38)"
		echo -e "${cyan}39. ${white}emby濯掍綋绠＄悊 $(_dot 39)           ${cyan}40. ${white}jellyfin濯掍綋绠＄悊 $(_dot 40)         ${cyan}41. ${white}AdGuardHome鍘诲箍鍛?$(_dot 41)"
		echo -e "${cyan}42. ${white}Navidrome闊充箰鏈嶅姟鍣?$(_dot 42)    ${cyan}43. ${white}Vaultwarden瀵嗙爜绠＄悊 $(_dot 43)     ${cyan}44. ${white}StirlingPDF宸ュ叿澶у叏 $(_dot 44)"
		echo -e "${cyan}45. ${white}Speedtest娴嬮€熼潰鏉?$(_dot 45)      ${cyan}46. ${white}PhotoPrism绉佹湁鐩稿唽 $(_dot 46)       ${cyan}47. ${white}searxng鑱氬悎鎼滅储 $(_dot 47)"
		echo -e "${cyan}48. ${white}Pingvin-Share鏂囦欢鍒嗕韩 $(_dot 48)  ${cyan}49. ${white}Dockge瀹瑰櫒绠＄悊 $(_dot 49)          ${cyan}50. ${white}it-tools宸ュ叿绠?$(_dot 50)"
		echo -e "${cyan}51. ${white}n8n鑷姩鍖栧伐浣滄祦 $(_dot 51)       ${cyan}52. ${white}OpenWebUI鑷墭绠I $(_dot 52)        ${cyan}53. ${white}Dify澶фā鍨嬬煡璇嗗簱 $(_dot 53)"
		echo -e "${cyan}54. ${white}gitea绉佹湁浠ｇ爜浠撳簱 $(_dot 54)      ${cyan}55. ${white}FileBrowser鏂囦欢绠＄悊 $(_dot 55)      ${cyan}56. ${white}FRP鍐呯綉绌块€?鏈嶅姟绔? $(_dot 56)"
		echo -e "${cyan}57. ${white}WireGuard缁勭綉(鏈嶅姟绔? $(_dot 57)  ${cyan}58. ${white}JumpServer鍫″瀿鏈?$(_dot 58)         ${cyan}59. ${white}immich鍥剧墖瑙嗛绠＄悊 $(_dot 59)"
		echo -e "${cyan}60. ${white}Syncthing鏂囦欢鍚屾 $(_dot 60)       ${cyan}61. ${white}Umami缃戠珯缁熻 $(_dot 61)           ${cyan}62. ${white}鎬濇簮绗旇 $(_dot 62)"
		echo -e "${cyan}63. ${white}SFTPGo鏂囦欢浼犺緭 $(_dot 63)         ${cyan}64. ${white}Owncast鑷墭绠＄洿鎾?$(_dot 64)        ${cyan}65. ${white}Deepseek AI澶фā鍨?$(_dot 65)"
		echo -e "${cyan}66. ${white}RocketChat鑱婂ぉ绯荤粺 $(_dot 66)     ${cyan}67. ${white}Gopeed楂橀€熶笅杞?$(_dot 67)           ${cyan}68. ${white}2FAuth浜屾楠岃瘉鍣?$(_dot 68)"
		echo -e "${cyan}69. ${white}ZFile鍦ㄧ嚎缃戠洏 $(_dot 69)          ${cyan}70. ${white}Nexterm杩滅▼杩炴帴 $(_dot 70)          ${cyan}71. ${white}JitsiMeet瑙嗛浼氳 $(_dot 71)"
		echo -e "${cyan}72. ${white}Stream鍥涘眰浠ｇ悊杞彂 $(_dot 72)     ${cyan}73. ${white}FileCodeBox鏂囦欢蹇€?$(_dot 73)      ${cyan}74. ${white}Matrix鍘讳腑蹇冨寲鑱婂ぉ $(_dot 74)"
		echo -e "${cyan}75. ${white}yt-dlp瑙嗛涓嬭浇 $(_dot 75)         ${cyan}76. ${white}paperless鏂囨。绠＄悊 $(_dot 76)        ${cyan}77. ${white}Wallos璐㈠姟绠＄悊 $(_dot 77)"
		echo -e "${cyan}78.  ${white}PairDrop文件传输 $(_dot 78)        ${cyan}79.  ${white}Dufs静态文件服务器 $(_dot 79)         ${cyan}80.  ${white}PandaWiki文档管理 $(_dot 80)"
		echo -e "${cyan}81. ${white}linkwarden涔︾绠＄悊 $(_dot 81)     ${cyan}82. ${white}VoceChat鑱婂ぉ绯荤粺 $(_dot 82)         ${cyan}83. ${white}Karakeep涔︾绠＄悊 $(_dot 83)"
		echo -e "${cyan}84. ${white}NewAPI澶фā鍨嬭祫浜х鐞?$(_dot 84)   ${cyan}85. ${white}RAGFlow鐭ヨ瘑搴?$(_dot 85)            ${cyan}86. ${white}AstrBot鑱婂ぉ鏈哄櫒浜?$(_dot 86)"
		echo -e "${cyan}87. ${white}LangBot鑱婂ぉ鏈哄櫒浜?$(_dot 87)      ${cyan}88. ${white}澶氭牸寮忔枃浠惰浆鎹?$(_dot 88)           ${cyan}89. ${white}LibreSpeed娴嬮€?$(_dot 89)"
		echo -e "${cyan}90. ${white}gpt-load AI閫忔槑浠ｇ悊 $(_dot 90)    ${cyan}91. ${white}琛ヨ揣鐩戞帶宸ュ叿 $(_dot 91)             ${cyan}92. ${white}PVE铏氭嫙鍖栫鐞?$(_dot 92)"
		echo -e "${cyan}93. ${white}DSM缇ゆ櫀铏氭嫙鏈?$(_dot 93)          ${cyan}94. ${white}鍦ㄧ嚎DOS鑰佹父鎴?$(_dot 94)            ${cyan}95. ${white}杩呴浄绂荤嚎涓嬭浇 $(_dot 95)"
		echo -e "${cyan}96. ${white}灏忛泤Alist鍏ㄥ妗?$(_dot 96)        ${cyan}97. ${white}Bililive鐩存挱褰曞埗 $(_dot 97)         ${cyan}98. ${white}鏋佺畝鏈嬪弸鍦?$(_dot 98)"
		echo -e "${cyan}99. ${white}PanSou缃戠洏鎼滅储 $(_dot 99)         ${cyan}100.${white}绠€鍗曞浘搴妉skypro $(_dot 100)          ${cyan}101.${white}绂呴亾椤圭洰绠＄悊 $(_dot 101)"
		echo -e "${cyan}102.${white}QD-Today瀹氭椂浠诲姟 $(_dot 102)       ${cyan}103.${white}鑰楀瓙绠＄悊闈㈡澘 $(_dot 103)             ${cyan}104.${white}AMH寤虹珯闈㈡澘 $(_dot 104)"
		echo -e "${cyan}105.${white}鍦ㄧ嚎缈昏瘧鏈嶅姟鍣?$(_dot 105)         ${cyan}106.${white}AI瑙嗛鐢熸垚宸ュ叿 $(_dot 106)           ${cyan}107.${white}RustDesk杩滅▼妗岄潰 $(_dot 107)"
		echo -e "${cyan}108.${white}Firefox娴忚鍣?$(_dot 108)          ${cyan}109.${white}DPanel瀹瑰櫒绠＄悊 $(_dot 109)           ${cyan}110.${white}鏅綏绫充慨鏂洃鎺?$(_dot 110)"
		echo -e "${pink}------------------------------------------------------------------------------------${white}"
		echo -e "${yellow}0.   ${white}杩斿洖涓昏彍鍗?
		echo -e "${green}666. ${white}鏌ョ湅宸插畨瑁呭簲鐢?(褰撳墠: ${#INSTALLED_IDS[@]} 涓?"
		echo -e "${pink}------------------------------------------------------------------------------------${white}"
		read -e -p "璇疯緭鍏ヤ綘鐨勯€夋嫨: " sub_choice

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
					echo -e "${red}鏃犳晥閫夋嫨, 璇烽噸鏂拌緭鍏?!${white}"
					sleep 1
				fi
				;;
		esac
	done
}

#############################################################################
########################### 琛ュ厖搴旂敤 (36-110) #############################

# portainer瀹瑰櫒绠＄悊闈㈡澘
portainer_app(){
	local app_id="36"
	local app_name="Portainer瀹瑰櫒绠＄悊"
	local docker_name="portainer"
	local docker_img="portainer/portainer-ce:latest"
	local docker_port=9000

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 9000): " _user_port
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

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="杞婚噺绾х殑Docker瀹瑰櫒绠＄悊UI闈㈡澘, 鏀寔瀹瑰櫒/闀滃儚/缃戠粶/鍗风殑鍙鍖栫鐞?
	local app_url="瀹樼綉浠嬬粛: https://www.portainer.io/"
	local app_size="1"
	docker_app
}

# Cloudreve缃戠洏
cloudreve_app(){
	local app_id="37"
	local app_name="Cloudreve缃戠洏"
	local docker_name="cloudreve"
	local docker_img="cloudreve/cloudreve:latest"
	local docker_port=8088

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8088): " _user_port
		_user_port=${_user_port:-8088}
		docker_port=$_user_port

		mkdir -p /home/docker/cloudreve
		docker run -d \
			--name cloudreve \
			--restart=always \
			-p ${docker_port}:5212 \
			-v /home/docker/cloudreve:/cloudreve \
			cloudreve/cloudreve:latest

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="鏀寔澶氱瀛樺偍鐨勪簯鐩樼郴缁? 鏀寔鏈湴瀛樺偍/瀵硅薄瀛樺偍/S3绛?
	local app_url="瀹樼綉浠嬬粛: https://github.com/cloudreve/Cloudreve"
	local app_size="1"
	docker_app
}

# Nextcloud缃戠洏
nextcloud_app(){
	local app_id="38"

	local app_name="Nextcloud绉佹湁缃戠洏"
	local app_text="鍔熻兘寮哄ぇ鐨勭鏈変簯瀛樺偍鍜屽崗浣滃钩鍙?
	local app_url="瀹樼綉浠嬬粛: https://nextcloud.com/"
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
		echo "Nextcloud 瀹夎瀹屾垚"
		check_docker_app_ip
	}

	docker_app_update() {
		cd /home/docker/nextcloud && docker compose down --rmi all
		cd /home/docker/nextcloud && docker compose up -d
	}

	docker_app_uninstall() {
		cd /home/docker/nextcloud && docker compose down --rmi all -v
		rm -rf /home/docker/nextcloud
		echo "Nextcloud 宸插嵏杞?
	}

	docker_app
}

# emby澶氬獟浣撶鐞嗙郴缁?emby_app(){
	local app_id="39"
	local app_name="emby濯掍綋绠＄悊"
	local docker_name="emby"
	local docker_img="emby/embyserver:latest"
	local docker_port=8096

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8096): " _user_port
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

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="鍔熻兘寮哄ぇ鐨勪釜浜哄獟浣撴湇鍔″櫒, 鏀寔鐢靛奖/鐢佃鍓?闊充箰绠＄悊鍜屽湪绾挎挱鏀?
	local app_url="瀹樼綉浠嬬粛: https://emby.media/"
	local app_size="3"
	docker_app
}

# jellyfin濯掍綋绠＄悊绯荤粺
jellyfin_app(){
	local app_id="40"
	local app_name="jellyfin濯掍綋绠＄悊"
	local docker_name="jellyfin"
	local docker_img="jellyfin/jellyfin:latest"
	local docker_port=8097

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8097): " _user_port
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

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="鍏嶈垂寮€婧愮殑濯掍綋鏈嶅姟鍣? Emby鐨勬浛浠ｅ搧, 鏀寔鐢靛奖/鐢佃鍓?闊充箰绠＄悊鍜屽湪绾挎挱鏀?
	local app_url="瀹樼綉浠嬬粛: https://jellyfin.org/"
	local app_size="2"
	docker_app
}

# AdGuardHome鍘诲箍鍛婅蒋浠?adguardhome_app(){
	local app_id="41"
	local app_name="AdGuardHome鍘诲箍鍛?
	local docker_name="adguardhome"
	local docker_img="adguard/adguardhome:latest"
	docker_run() {
		mkdir -p /home/docker/adguardhome/work /home/docker/adguardhome/conf
		# 璁╃敤鎴疯緭鍏?Web绠＄悊鐣岄潰 绔彛 (榛樿 3000)
		read -e -p "璁剧疆Web绠＄悊鐣岄潰绔彛 (榛樿3000): " web_port
		web_port=${web_port:-3000}

		docker run -d \
			--name adguardhome \
			--restart=always \
			-p ${web_port}:3000 \
			-p 53:53/tcp \
			-p 53:53/udp \
			-p 67:67/udp \
			-p 68:68/udp \
			-p 443:443/tcp \
			-p 853:853/tcp \
			-v /home/docker/adguardhome/work:/opt/adguardhome/work \
			-v /home/docker/adguardhome/conf:/opt/adguardhome/conf \
			adguard/adguardhome:latest

		# Web闈㈡澘绔彛
		add_app_port "Web绠＄悊鐣岄潰" "$web_port"
		# 鍏朵粬 DNS/DHCP 绔彛淇濇寔纭紪鐮?(鏆備笉鏀?
		add_app_port "DNS绔彛 (TCP+UDP)" 53
		add_app_port "DHCP瀹㈡埛绔? 67
		add_app_port "DHCP鏈嶅姟绔? 68
		add_app_port "DNS-over-HTTPS" 443
		add_app_port "DNS-over-TLS" 853
	}

	local app_text="鍏ㄧ綉骞垮憡鎷︽埅涓庨殣绉佷繚鎶NS鏈嶅姟, 鏀寔DNS-over-HTTPS/TLS"
	local app_url="瀹樼綉浠嬬粛: https://adguard.com/adguard-home/overview.html"
	local app_size="1"
	docker_app
}

# Navidrome绉佹湁闊充箰鏈嶅姟鍣?navidrome_app(){
	local app_id="42"
	local app_name="Navidrome闊充箰鏈嶅姟鍣?
	local docker_name="navidrome"
	local docker_img="deluan/navidrome:latest"
	local docker_port=8098

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8098): " _user_port
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

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="鐜颁唬鐨勭浜洪煶涔愭祦濯掍綋鏈嶅姟鍣? 鏀寔澶氱敤鎴? 鍏煎Subsonic/Airsonic API"
	local app_url="瀹樼綉浠嬬粛: https://github.com/navidrome/navidrome"
	local app_size="1"
	docker_app
}

# bitwarden瀵嗙爜绠＄悊鍣?(浣跨敤Vaultwarden杞婚噺鏇夸唬)
bitwarden_app(){
	local app_id="43"
	local app_name="Vaultwarden瀵嗙爜绠＄悊"
	local docker_name="vaultwarden"
	local docker_img="vaultwarden/server:latest"
	local docker_port=8099

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8099): " _user_port
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

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="Bitwarden鐨勮交閲忕骇鏇夸唬(Vaultwarden), 鑷墭绠″瘑鐮佺鐞嗗櫒"
	local app_url="瀹樼綉浠嬬粛: https://github.com/dani-garcia/vaultwarden"
	local app_size="1"
	docker_app
}

# StirlingPDF宸ュ叿澶у叏
stirlingpdf_app(){
	local app_id="44"
	local app_name="StirlingPDF宸ュ叿澶у叏"
	local docker_name="stirlingpdf"
	local docker_img="frooodle/s-pdf:latest"
	local docker_port=8100

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8100): " _user_port
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

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="鍔熻兘寮哄ぇ鐨凱DF澶勭悊宸ュ叿绠? 鏀寔鍚堝苟/鎷嗗垎/杞崲/鍘嬬缉/鍔犳按鍗扮瓑"
	local app_url="瀹樼綉浠嬬粛: https://github.com/Stirling-Tools/Stirling-PDF"
	local app_size="2"
	docker_app
}

# Speedtest娴嬮€熼潰鏉?speedtest_app(){
	local app_id="45"
	local app_name="Speedtest娴嬮€熼潰鏉?
	local docker_name="speedtest"
	local docker_img="adolfintel/speedtest:latest"
	local docker_port=8101

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8101): " _user_port
		_user_port=${_user_port:-8101}
		docker_port=$_user_port

		docker run -d \
			--name speedtest \
			--restart=always \
			-p ${docker_port}:80 \
			--network host \
			adolfintel/speedtest:latest

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="LibreSpeed娴嬮€熼潰鏉? 鑷墭绠＄殑缃戠粶娴嬮€熷伐鍏?
	local app_url="瀹樼綉浠嬬粛: https://github.com/librespeed/speedtest"
	local app_size="1"
	docker_app
}

# PhotoPrism绉佹湁鐩稿唽绯荤粺
photoprism_app(){
	local app_id="46"

	local app_name="PhotoPrism绉佹湁鐩稿唽"
	local app_text="鍩轰簬AI鐨勭鏈夌収鐗囩鐞嗗拰娴忚绯荤粺"
	local app_url="瀹樼綉浠嬬粛: https://photoprism.app/"
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
		echo "PhotoPrism 瀹夎瀹屾垚"
		check_docker_app_ip
	}

	docker_app_update() {
		cd /home/docker/photoprism && docker compose down --rmi all
		cd /home/docker/photoprism && docker compose up -d
	}

	docker_app_uninstall() {
		cd /home/docker/photoprism && docker compose down --rmi all -v
		rm -rf /home/docker/photoprism
		echo "PhotoPrism 宸插嵏杞?
	}

	docker_app
}

# searxng鑱氬悎鎼滅储绔?searxng_app(){
	local app_id="47"
	local app_name="searxng鑱氬悎鎼滅储"
	local docker_name="searxng"
	local docker_img="searxng/searxng:latest"
	local docker_port=8103

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8103): " _user_port
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

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="娉ㄩ噸闅愮鐨勫厓鎼滅储寮曟搸鑱氬悎骞冲彴, 涓嶈拷韪敤鎴?
	local app_url="瀹樼綉浠嬬粛: https://github.com/searxng/searxng"
	local app_size="1"
	docker_app
}

# Pingvin-Share鏂囦欢鍒嗕韩骞冲彴
pingvinshare_app(){
	local app_id="48"
	local app_name="Pingvin-Share鏂囦欢鍒嗕韩"
	local docker_name="pingvin-share"
	local docker_img="stonith404/pingvin-share:latest"
	local docker_port=8104

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8104): " _user_port
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

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="鑷墭绠℃枃浠跺垎浜钩鍙? 鏀寔鍒涘缓鍒嗕韩閾炬帴鍜屼笂浼犳枃浠?
	local app_url="瀹樼綉浠嬬粛: https://github.com/stonith404/pingvin-share"
	local app_size="1"
	docker_app
}

# Dockge瀹瑰櫒鍫嗘爤绠＄悊闈㈡澘
dockge_app(){
	local app_id="49"
	local app_name="Dockge瀹瑰櫒绠＄悊"
	local docker_name="dockge"
	local docker_img="louislam/dockge:latest"
	local docker_port=8105

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8105): " _user_port
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

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="绠€娲佷紭闆呯殑Docker Compose鍫嗘爤绠＄悊闈㈡澘"
	local app_url="瀹樼綉浠嬬粛: https://github.com/louislam/dockge"
	local app_size="1"
	docker_app
}

# it-tools宸ュ叿绠?ittools_app(){
	local app_id="50"
	local app_name="it-tools宸ュ叿绠?
	local docker_name="it-tools"
	local docker_img="corentintho/it-tools:latest"
	local docker_port=8106

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8106): " _user_port
		_user_port=${_user_port:-8106}
		docker_port=$_user_port

		docker run -d \
			--name it-tools \
			--restart=always \
			-p ${docker_port}:80 \
			corentintho/it-tools:latest
	}

	local app_text="寮€鍙戣€呭父鐢ㄥ伐鍏烽泦鍚? 鍖呭惈JSON鏍煎紡鍖?Base64缂栬В鐮?UUID鐢熸垚绛夋暟鐧句釜宸ュ叿"
	local app_url="瀹樼綉浠嬬粛: https://github.com/CorentinTh/it-tools"
	local app_size="1"
	docker_app
}

# n8n鑷姩鍖栧伐浣滄祦骞冲彴
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

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="寮€婧愮殑宸ヤ綔娴佽嚜鍔ㄥ寲骞冲彴, 鍙鍖栬繛鎺ュ悇绉岮PI鍜屾湇鍔?
	local app_url="瀹樼綉浠嬬粛: https://n8n.io/"
	local app_size="2"
	docker_app
}

# OpenWebUI鑷墭绠I骞冲彴
openwebui_app(){
	local app_id="52"
	local app_name="OpenWebUI鑷墭绠I"
	local docker_name="open-webui"
	local docker_img="ghcr.io/open-webui/open-webui:main"
	local docker_port=8108

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8108): " _user_port
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

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="鑷墭绠＄殑AI瀵硅瘽鐣岄潰, 鏀寔Ollama/OpenAI绛夊绉嶅悗绔?
	local app_url="瀹樼綉浠嬬粛: https://github.com/open-webui/open-webui"
	local app_size="2"
	docker_app
}

# Dify澶фā鍨嬬煡璇嗗簱
dify_app(){
	local app_id="53"

	local app_name="Dify澶фā鍨嬬煡璇嗗簱"
	local app_text="寮€婧愮殑LLM搴旂敤寮€鍙戝钩鍙? 鍙鍖栫紪鎺扐I宸ヤ綔娴?
	local app_url="瀹樼綉浠嬬粛: https://dify.ai/"
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
		echo "Dify 瀹夎瀹屾垚"
		check_docker_app_ip
	}

	docker_app_update() {
		cd /home/docker/dify && docker compose pull && docker compose up -d
	}

	docker_app_uninstall() {
		cd /home/docker/dify && docker compose down --rmi all -v
		rm -rf /home/docker/dify
		echo "Dify 宸插嵏杞?
	}

	docker_app
}

# gitea绉佹湁浠ｇ爜浠撳簱
gitea_app(){
	local app_id="54"
	local app_name="gitea绉佹湁浠ｇ爜浠撳簱"
	local docker_name="gitea"
	local docker_img="gitea/gitea:latest"
	local docker_port=8110

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8110): " _user_port
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

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="杞婚噺绾х殑鑷墭绠it鏈嶅姟, 绫讳技GitHub/GitLab"
	local app_url="瀹樼綉浠嬬粛: https://gitea.io/"
	local app_size="2"
	docker_app
}

# FileBrowser鏂囦欢绠＄悊鍣?filebrowser_app(){
	local app_id="55"
	local app_name="FileBrowser鏂囦欢绠＄悊"
	local docker_name="filebrowser"
	local docker_img="filebrowser/filebrowser:latest"
	local docker_port=8111

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8111): " _user_port
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

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="杞婚噺绾х殑缃戦〉鏂囦欢绠＄悊鍣? 鏀寔鏂囦欢涓婁紶/涓嬭浇/缂栬緫/鍒嗕韩"
	local app_url="瀹樼綉浠嬬粛: https://github.com/filebrowser/filebrowser"
	local app_size="1"
	docker_app
}

# FRP鍐呯綉绌块€?鏈嶅姟绔?
# 澶氱鍙ｆ牱鏈? Dashboard + Server 绔彛
frp_server_app(){
	local app_id="56"
	local app_name="FRP鍐呯綉绌块€?鏈嶅姟绔?"
	local docker_name="frps"
	local docker_img="snowdreamtech/frps:latest"
	local app_text="FRP鍐呯綉绌块€忔湇鍔＄, 璁╁唴缃戞湇鍔℃毚闇插埌鍏綉"
	local app_url="瀹樼綉浠嬬粛: https://github.com/fatedier/frp"
	local app_size="1"

	docker_run() {
		mkdir -p /home/docker/frps

		# 1. 鏀堕泦闈㈡澘涓庢湇鍔＄鍙?		read -e -p "璁剧疆FRP闈㈡澘绔彛 (榛樿7500): " dash_port
		dash_port=${dash_port:-7500}

		read -e -p "璁剧疆FRP鏈嶅姟绔彛 (榛樿7000): " frp_port
		frp_port=${frp_port:-7000}

		# 2. 鏀堕泦瀹㈡埛绔繛鎺ョ殑璁よ瘉 Token
        read -e -p "璁剧疆FRP瀹㈡埛绔繛鎺ヨ璇乀oken(閫氫俊瀵嗙爜, 榛樿12345678): " auth_token
        auth_token=${auth_token:-12345678}

		# 3. 鏀堕泦闈㈡澘瀵嗙爜
		read -e -p "璁剧疆Dashboard瀵嗙爜: " dash_pwd

		# 4. 鐢熸垚 frps.toml 閰嶇疆鏂囦欢
		cat > /home/docker/frps/frps.toml << EOF
bindPort = $frp_port

webServer.addr = "0.0.0.0"
webServer.port = $dash_port
webServer.user = "admin"
webServer.password = "$dash_pwd"

# 寮€鍚?Token 璁よ瘉淇濇姢鏈嶅姟绔?auth.method = "token"
auth.token = "$auth_token"
EOF

		docker run -d \
			--name frps \
			--restart=always \
			--network host \
			-v /home/docker/frps/frps.toml:/etc/frp/frps.toml \
			snowdreamtech/frps:latest
		
		# Dashboard绔彛
		add_app_port "Dashboard璁块棶鍦板潃" "$dash_port"
		# Server绔彛
		add_app_port "Server璁块棶鍦板潃" "$frp_port"
	}

	docker_app
}

# WireGuard缁勭綉(鏈嶅姟绔?
# 澶氱鍙ｆ牱鏈? Web 绠＄悊闈㈡澘 + WireGuard UDP 绔彛
wireguard_server_app(){
	local app_id="57"
	local app_name="WireGuard缁勭綉(鏈嶅姟绔?"
	local docker_name="wg-easy"
	local docker_img="ghcr.io/wg-easy/wg-easy:latest"
	local app_text="WireGuard VPN鏈嶅姟绔? 绠€鍗曟槗鐢ㄧ殑铏氭嫙缁勭綉宸ュ叿"
	local app_url="瀹樼綉浠嬬粛: https://github.com/wg-easy/wg-easy"
	local app_size="1"

	docker_run() {
		mkdir -p /home/docker/wireguard
		read -e -p "璁剧疆闈㈡澘绔彛 (榛樿8113): " dash_port
		dash_port=${dash_port:-8113}
		read -e -p "璁剧疆WireGuard绔彛 (榛樿51820): " wg_udp_port
		wg_udp_port=${wg_udp_port:-51820}
		read -e -p "璁剧疆绠＄悊闈㈡澘瀵嗙爜: " wg_pwd

		docker run -d \
			--name wg-easy \
			--restart=always \
			--cap-add=NET_ADMIN \
			--cap-add=SYS_MODULE \
			-v /lib/modules:/lib/modules:ro \
			-p ${dash_port}:51821 \
			-p ${wg_udp_port}:51820/udp \
			-e WG_HOST=$(get_public_ip) \
			-e PASSWORD_HASH="$(openssl passwd -6 "$wg_pwd")" \
			-e WG_ALLOWED_IPS="0.0.0.0/0,::/0" \
			-v /home/docker/wireguard:/etc/wireguard \
			ghcr.io/wg-easy/wg-easy:latest


		# Web 绠＄悊闈㈡澘绔彛
		add_app_port "Web绠＄悊闈㈡澘" "$dash_port"
		# WireGuard UDP绔彛
		add_app_port "WireGuard绔彛 (UDP)" "$wg_udp_port"
	}

	docker_app
}

# JumpServer寮€婧愬牎鍨掓満
jumpserver_app(){
	local app_id="58"

	local app_name="JumpServer鍫″瀿鏈?
	local app_text="寮€婧愮殑杩愮淮瀹夊叏瀹¤绯荤粺, 闆嗕腑绠＄悊SSH/RDP璁块棶"
	local app_url="瀹樼綉浠嬬粛: https://www.jumpserver.org/"
	local docker_name="jms-all"
	local docker_port="8114"
	add_app_port "Web绠＄悊鐣岄潰" 8114
	add_app_port "SSH杩炴帴绔彛" 2222
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
		echo "JumpServer 瀹夎瀹屾垚"
		echo "榛樿鐢ㄦ埛: admin  瀵嗙爜: ChangeMe"
		check_docker_app_ip
	}

	docker_app_update() {
		cd /home/docker/jumpserver && docker compose down --rmi all
		cd /home/docker/jumpserver && docker compose up -d
	}

	docker_app_uninstall() {
		cd /home/docker/jumpserver && docker compose down --rmi all -v
		rm -rf /home/docker/jumpserver
		echo "JumpServer 宸插嵏杞?
	}

	docker_app
}

# immich鍥剧墖瑙嗛绠＄悊鍣?immich_app(){
	local app_id="59"

	local app_name="Immich鍥剧墖瑙嗛绠＄悊"
	local app_text="楂樻€ц兘鐨勮嚜鎵樼Google Photos鏇夸唬鍝?
	local app_url="瀹樼綉浠嬬粛: https://immich.app/"
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
		echo "Immich 瀹夎瀹屾垚"
		check_docker_app_ip
	}

	docker_app_update() {
		cd /home/docker/immich && docker compose pull && docker compose up -d
	}

	docker_app_uninstall() {
		cd /home/docker/immich && docker compose down --rmi all -v
		rm -rf /home/docker/immich
		echo "Immich 宸插嵏杞?
	}

	docker_app
}

# Syncthing鐐瑰鐐规枃浠跺悓姝ュ伐鍏?syncthing_app(){
	local app_id="60"
	local app_name="Syncthing鏂囦欢鍚屾"
	local docker_name="syncthing"
	local docker_img="syncthing/syncthing:latest"
	docker_run() {
		mkdir -p /home/docker/syncthing/config
		# 璁╃敤鎴疯緭鍏?Web绠＄悊鐣岄潰 绔彛 (榛樿 8116)
		read -e -p "璁剧疆Web绠＄悊鐣岄潰绔彛 (榛樿8116): " web_port
		web_port=${web_port:-8116}

		docker run -d \
			--name syncthing \
			--restart=always \
			-p ${web_port}:8384 \
			-p 22000:22000/tcp \
			-p 22000:22000/udp \
			-v /home/docker/syncthing/config:/var/syncthing/config \
			syncthing/syncthing:latest

		# Web闈㈡澘绔彛
		add_app_port "Web绠＄悊鐣岄潰" "$web_port"
		# TCP/UDP 鍚屾绔彛淇濇寔纭紪鐮?(鏆備笉鏀?
		add_app_port "璁惧鍚屾绔彛 (TCP+UDP)" 22000
	}

	local app_text="寮€婧愮殑杩炵画鏂囦欢鍚屾宸ュ叿, 鏀寔P2P澶氳澶囬棿鏂囦欢鍚屾"
	local app_url="瀹樼綉浠嬬粛: https://syncthing.net/"
	local app_size="1"
	docker_app
}

# Umami缃戠珯缁熻宸ュ叿
umami_app(){
	local app_id="61"
	local app_name="Umami缃戠珯缁熻"
	local docker_name="umami"
	local docker_img="ghcr.io/umami-software/umami:postgresql-latest"
	local docker_port=8117

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8117): " _user_port
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

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="寮€婧愮殑缃戠珯鍒嗘瀽缁熻宸ュ叿, Google Analytics鐨勯殣绉佸弸濂芥浛浠?
	local app_url="瀹樼綉浠嬬粛: https://umami.is/"
	local app_size="1"
	docker_app
}

# 鎬濇簮绗旇
siyuan_app(){
	local app_id="62"
	local app_name="鎬濇簮绗旇"
	local docker_name="siyuan"
	local docker_img="b3log/siyuan:latest"
	local docker_port=8118

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8118): " _user_port
		_user_port=${_user_port:-8118}
		docker_port=$_user_port

		mkdir -p /home/docker/siyuan/workspace
		docker run -d \
			--name siyuan \
			--restart=always \
			-p ${docker_port}:6806 \
			-v /home/docker/siyuan/workspace:/siyuan/workspace \
			b3log/siyuan:latest

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="鏈湴浼樺厛鐨勪釜浜虹煡璇嗙鐞嗙郴缁? 鏀寔鍧楃骇寮曠敤鍜屽弻鍚戦摼鎺?
	local app_url="瀹樼綉浠嬬粛: https://b3log.org/siyuan/"
	local app_size="2"
	docker_app
}

# SFTPGo鏂囦欢浼犺緭宸ュ叿
sftpgp_app(){
	local app_id="63"
	local app_name="SFTPGo鏂囦欢浼犺緭"
	local docker_name="sftpgo"
	local docker_img="drakkan/sftpgo:latest"
	local docker_port=8119

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8119): " _user_port
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

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="鍔熻兘榻愬叏鐨凷FTP/FTP/WebDAV鏈嶅姟鍣? 鏀寔澶氱鍗忚"
	local app_url="瀹樼綉浠嬬粛: https://github.com/drakkan/sftpgo"
	local app_size="1"
	docker_app
}

# Owncast鑷墭绠＄洿鎾钩鍙?owncast_app(){
	local app_id="64"
	local app_name="Owncast鑷墭绠＄洿鎾?
	local docker_name="owncast"
	local docker_img="owncast/owncast:latest"
	local docker_port=8120

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8120): " _user_port
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

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="鑷墭绠＄殑瑙嗛鐩存挱骞冲彴, 鏀寔RTMP鎺ㄦ祦鍜學eb瑙傜湅"
	local app_url="瀹樼綉浠嬬粛: https://owncast.online/"
	local app_size="2"
	docker_app
}

# Deepseek鑱婂ぉAI澶фā鍨?deepseek_app(){
	local app_id="65"
	local app_name="Deepseek AI澶фā鍨?
	local docker_name="deepseek"
	local docker_img="deepseek-ai/deepseek-coder:6.7b-instruct-q4_0"
	local docker_port=8121

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8121): " _user_port
		_user_port=${_user_port:-8121}
		docker_port=$_user_port

		docker run -d \
			--name deepseek \
			--restart=always \
			-p ${docker_port}:8000 \
			-v /home/docker/deepseek:/root/.ollama \
			deepseek-ai/deepseek-coder:6.7b-instruct-q4_0

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="DeepSeek AI澶фā鍨嬫湰鍦伴儴缃? 鏀寔浠ｇ爜鐢熸垚鍜屽璇?
	local app_url="瀹樼綉浠嬬粛: https://github.com/deepseek-ai/DeepSeek-Coder"
	local app_size="4"
	docker_app
}

# RocketChat澶氫汉鍦ㄧ嚎鑱婂ぉ绯荤粺
rocketchat_app(){
	local app_id="66"

	local app_name="RocketChat"
	local app_text="寮€婧愮殑鍥㈤槦鍗忎綔鑱婂ぉ骞冲彴, Slack鐨勬浛浠ｅ搧"
	local app_url="瀹樼綉浠嬬粛: https://rocket.chat/"
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
		echo "RocketChat 瀹夎瀹屾垚"
		check_docker_app_ip
	}

	docker_app_update() {
		cd /home/docker/rocketchat && docker compose down --rmi all
		cd /home/docker/rocketchat && docker compose up -d
	}

	docker_app_uninstall() {
		cd /home/docker/rocketchat && docker compose down --rmi all -v
		rm -rf /home/docker/rocketchat
		echo "RocketChat 宸插嵏杞?
	}

	docker_app
}

# Gopeed楂橀€熶笅杞藉伐鍏?gopeed_app(){
	local app_id="67"
	local app_name="Gopeed楂橀€熶笅杞?
	local docker_name="gopeed"
	local docker_img="liwei2633/gopeed:latest"
	local docker_port=8123

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8123): " _user_port
		_user_port=${_user_port:-8123}
		docker_port=$_user_port

		mkdir -p /home/docker/gopeed
		docker run -d \
			--name gopeed \
			--restart=always \
			-p ${docker_port}:9999 \
			-v /home/docker/gopeed:/app/data \
			liwei2633/gopeed:latest

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="楂橀€熶笅杞藉伐鍏? 鏀寔HTTP/BitTorrent绛夊崗璁?
	local app_url="瀹樼綉浠嬬粛: https://github.com/GoproxyFoss/gopeed"
	local app_size="1"
	docker_app
}

# 2FAuth鑷墭绠′簩姝ラ獙璇佸櫒
twofauth_app(){
	local app_id="68"
	local app_name="2FAuth浜屾楠岃瘉鍣?
	local docker_name="2fauth"
	local docker_img="2fauth/2fauth:latest"
	local docker_port=8124

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8124): " _user_port
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

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="鑷墭绠＄殑浜屾楠岃瘉(2FA)绠＄悊鍣? 绠＄悊鎵€鏈塗OTP/HOTP浠ょ墝"
	local app_url="瀹樼綉浠嬬粛: https://docs.2fauth.app/"
	local app_size="1"
	docker_app
}

# ZFile鍦ㄧ嚎缃戠洏
zfile_app(){
	local app_id="69"
	local app_name="ZFile鍦ㄧ嚎缃戠洏"
	local docker_name="zfile"
	local docker_img="zhaojun1998/zfile:latest"
	local docker_port=8125

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8125): " _user_port
		_user_port=${_user_port:-8125}
		docker_port=$_user_port

		mkdir -p /home/docker/zfile/data
		docker run -d \
			--name zfile \
			--restart=always \
			-p ${docker_port}:8080 \
			-v /home/docker/zfile/data:/data \
			zhaojun1998/zfile:latest

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="寮€婧愮殑鍦ㄧ嚎缃戠洏绯荤粺, 鏀寔澶氱瀛樺偍绛栫暐"
	local app_url="瀹樼綉浠嬬粛: https://github.com/zhaojun1998/zfile"
	local app_size="1"
	docker_app
}

# Nexterm杩滅▼杩炴帴
nexterm_app(){
	local app_id="70"
	local app_name="Nexterm杩滅▼杩炴帴"
	local docker_name="nexterm"
	local docker_img="germannewsmaker/nexterm:latest"
	local docker_port=8126

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8126): " _user_port
		_user_port=${_user_port:-8126}
		docker_port=$_user_port

		mkdir -p /home/docker/nexterm
		docker run -d \
			--name nexterm \
			--restart=always \
			-p ${docker_port}:6989 \
			-v /home/docker/nexterm:/app/data \
			germannewsmaker/nexterm:latest

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="寮€婧愮殑杩滅▼杩炴帴绠＄悊宸ュ叿, 鏀寔SSH/VNC/RDP"
	local app_url="瀹樼綉浠嬬粛: https://github.com/gnmyt/Nexterm"
	local app_size="1"
	docker_app
}

# JitsiMeet瑙嗛浼氳
jitsimeet_app(){
	local app_id="71"
	local app_name="JitsiMeet瑙嗛浼氳"
	local docker_name="jitsi-meet"
	local docker_img="jitsi/web:latest"
	local docker_port=8127

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8127): " _user_port
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

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="寮€婧愮殑瑙嗛浼氳绯荤粺, 鏀寔澶氫汉瑙嗛浼氳"
	local app_url="瀹樼綉浠嬬粛: https://jitsi.org/"
	local app_size="2"
	docker_app
}

# Stream鍥涘眰浠ｇ悊杞彂
stream_app(){
	local app_id="72"
	local app_name="Stream鍥涘眰浠ｇ悊杞彂"
	local docker_name="stream"
	local docker_img="nginx:alpine"
	local docker_port=8128

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8128): " _user_port
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

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="鍥涘眰浠ｇ悊杞彂鏈嶅姟, 鍩轰簬Nginx Stream妯″潡"
	local app_url="瀹樼綉浠嬬粛: https://nginx.org/"
	local app_size="1"
	docker_app
}

# FileCodeBox鏂囦欢蹇€?filecodebox_app(){
	local app_id="73"
	local app_name="FileCodeBox鏂囦欢蹇€?
	local docker_name="filecodebox"
	local docker_img="lanol/filecodebox:latest"
	local docker_port=8129

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8129): " _user_port
		_user_port=${_user_port:-8129}
		docker_port=$_user_port

		mkdir -p /home/docker/filecodebox
		docker run -d \
			--name filecodebox \
			--restart=always \
			-p ${docker_port}:12345 \
			-v /home/docker/filecodebox:/app/data \
			lanol/filecodebox:latest

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="鏂囦欢蹇€掓煖, 鍖垮悕鍙ｄ护鍒嗕韩鏂囦欢"
	local app_url="瀹樼綉浠嬬粛: https://github.com/vastsa/FileCodeBox"
	local app_size="1"
	docker_app
}

# Matrix鍘讳腑蹇冨寲鑱婂ぉ
matrix_app(){
	local app_id="74"
	local app_name="Matrix鍘讳腑蹇冨寲鑱婂ぉ"
	local docker_name="matrix"
	local docker_img="matrixdotorg/synapse:latest"
	local docker_port=8130

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8130): " _user_port
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

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="鍘讳腑蹇冨寲鐨勫嵆鏃堕€氳鍗忚, 鏀寔绔埌绔姞瀵?
	local app_url="瀹樼綉浠嬬粛: https://matrix.org/"
	local app_size="2"
	docker_app
}

# yt-dlp瑙嗛涓嬭浇
ytdlp_app(){
	local app_id="75"
	local app_name="yt-dlp瑙嗛涓嬭浇"
	local docker_name="yt-dlp"
	local docker_img="mikenye/yt-dlp:latest"
	local docker_port=8131

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8131): " _user_port
		_user_port=${_user_port:-8131}
		docker_port=$_user_port

		mkdir -p /home/docker/ytdlp/downloads
		docker run -d \
			--name yt-dlp \
			--restart=always \
			-p ${docker_port}:8080 \
			-v /home/docker/ytdlp/downloads:/downloads \
			mikenye/yt-dlp:latest

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="寮哄ぇ鐨勮棰戜笅杞藉伐鍏? 鏀寔YouTube绛夋暟鐧句釜缃戠珯"
	local app_url="瀹樼綉浠嬬粛: https://github.com/yt-dlp/yt-dlp"
	local app_size="1"
	docker_app
}

# paperless鏂囨。绠＄悊
paperless_app(){
	local app_id="76"
	local app_name="paperless鏂囨。绠＄悊"
	local docker_name="paperless"
	local docker_img="ghcr.io/paperless-ngx/paperless-ngx:latest"
	local docker_port=8132

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8132): " _user_port
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

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="寮€婧愮殑鏂囨。绠＄悊绯荤粺, 鏀寔OCR鍜屽叏鏂囨悳绱?
	local app_url="瀹樼綉浠嬬粛: https://docs.paperless-ngx.com/"
	local app_size="2"
	docker_app
}

# Wallos璐㈠姟绠＄悊
wallos_app(){
	local app_id="77"
	local app_name="Wallos璐㈠姟绠＄悊"
	local docker_name="wallos"
	local docker_img="bellamy/wallos:latest"
	local docker_port=8133

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8133): " _user_port
		_user_port=${_user_port:-8133}
		docker_port=$_user_port

		mkdir -p /home/docker/wallos
		docker run -d \
			--name wallos \
			--restart=always \
			-p ${docker_port}:80 \
			-v /home/docker/wallos:/var/www/html \
			bellamy/wallos:latest

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="寮€婧愮殑涓汉璐㈠姟绠＄悊宸ュ叿, 杩借釜璁㈤槄鍜屾敮鍑?
	local app_url="瀹樼綉浠嬬粛: https://github.com/ellite/Wallos"
	local app_size="1"
	docker_app
}


# Dufs闈欐€佹枃浠舵湇鍔″櫒
dufs_app(){
	local app_id="79"
	local app_name="Dufs闈欐€佹枃浠舵湇鍔″櫒"
	local docker_name="dufs"
	local docker_img="sigoden/dufs:latest"
	local docker_port=8135

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8135): " _user_port
		_user_port=${_user_port:-8135}
		docker_port=$_user_port

		mkdir -p /home/docker/dufs/data
		docker run -d \
			--name dufs \
			--restart=always \
			-p ${docker_port}:5000 \
			-v /home/docker/dufs/data:/data \
			sigoden/dufs:latest /data

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="绠€鍗曠殑闈欐€佹枃浠舵湇鍔″櫒, 鏀寔涓婁紶涓嬭浇"
	local app_url="瀹樼綉浠嬬粛: https://github.com/sigoden/dufs"
	local app_size="1"
	docker_app
}

# PandaWiki鏂囨。绠＄悊
pandawiki_app(){
	local app_id="80"
	local app_name="PandaWiki鏂囨。绠＄悊"
	local docker_name="pandawiki"
	local docker_img="pandawiki/pandawiki:latest"
	local docker_port=8136

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8136): " _user_port
		_user_port=${_user_port:-8136}
		docker_port=$_user_port

		mkdir -p /home/docker/pandawiki
		docker run -d \
			--name pandawiki \
			--restart=always \
			-p ${docker_port}:80 \
			-v /home/docker/pandawiki:/data \
			pandawiki/pandawiki:latest

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="寮€婧愮殑Wiki鏂囨。绠＄悊绯荤粺"
	local app_url="瀹樼綉浠嬬粛: https://github.com/pandawiki"
	local app_size="1"
	docker_app
}

# linkwarden涔︾绠＄悊
linkwarden_app(){
	local app_id="81"
	local app_name="linkwarden涔︾绠＄悊"
	local docker_name="linkwarden"
	local docker_img="ghcr.io/linkwarden/linkwarden:latest"
	local docker_port=8137

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8137): " _user_port
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

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="寮€婧愮殑涔︾绠＄悊宸ュ叿, 鏀寔缃戦〉褰掓。"
	local app_url="瀹樼綉浠嬬粛: https://github.com/linkwarden/linkwarden"
	local app_size="1"
	docker_app
}

# VoceChat鑱婂ぉ绯荤粺
vocechat_app(){
	local app_id="82"
	local app_name="VoceChat鑱婂ぉ绯荤粺"
	local docker_name="vocechat"
	local docker_img="privoce/vocechat-server:latest"
	local docker_port=8138

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8138): " _user_port
		_user_port=${_user_port:-8138}
		docker_port=$_user_port

		mkdir -p /home/docker/vocechat
		docker run -d \
			--name vocechat \
			--restart=always \
			-p ${docker_port}:3000 \
			-v /home/docker/vocechat:/home/vocechat-server/data \
			privoce/vocechat-server:latest

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="寮€婧愮殑杞婚噺绾ц亰澶╃郴缁? 鏀寔鑷墭绠?
	local app_url="瀹樼綉浠嬬粛: https://voce.chat/"
	local app_size="1"
	docker_app
}

# Karakeep涔︾绠＄悊
karakeep_app(){
	local app_id="83"
	local app_name="Karakeep涔︾绠＄悊"
	local docker_name="karakeep"
	local docker_img="ghcr.io/karakeep-app/karakeep:latest"
	local docker_port=8139

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8139): " _user_port
		_user_port=${_user_port:-8139}
		docker_port=$_user_port

		mkdir -p /home/docker/karakeep
		docker run -d \
			--name karakeep \
			--restart=always \
			-p ${docker_port}:3000 \
			-v /home/docker/karakeep:/data \
			ghcr.io/karakeep-app/karakeep:latest

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="鏅鸿兘涔︾绠＄悊宸ュ叿, 鏀寔AI鑷姩鏍囩"
	local app_url="瀹樼綉浠嬬粛: https://github.com/karakeep-app/karakeep"
	local app_size="1"
	docker_app
}

# NewAPI澶фā鍨嬭祫浜х鐞?newapi_app(){
	local app_id="84"
	local app_name="NewAPI澶фā鍨嬭祫浜х鐞?
	local docker_name="newapi"
	local docker_img="calciumion/new-api:latest"
	local docker_port=8140

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8140): " _user_port
		_user_port=${_user_port:-8140}
		docker_port=$_user_port

		mkdir -p /home/docker/newapi
		docker run -d \
			--name newapi \
			--restart=always \
			-p ${docker_port}:3000 \
			-v /home/docker/newapi:/data \
			calciumion/new-api:latest

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="澶фā鍨婣PI绠＄悊鍜屽垎鍙戠郴缁?
	local app_url="瀹樼綉浠嬬粛: https://github.com/Calcium-Ion/new-api"
	local app_size="1"
	docker_app
}

# RAGFlow鐭ヨ瘑搴?ragflow_app(){
	local app_id="85"
	local app_name="RAGFlow鐭ヨ瘑搴?
	local docker_name="ragflow"
	local docker_img="infiniflow/ragflow:latest"
	local docker_port=8141

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8141): " _user_port
		_user_port=${_user_port:-8141}
		docker_port=$_user_port

		mkdir -p /home/docker/ragflow
		docker run -d \
			--name ragflow \
			--restart=always \
			-p ${docker_port}:80 \
			-v /home/docker/ragflow:/ragflow \
			infiniflow/ragflow:latest

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="寮€婧愮殑RAG寮曟搸, 鏋勫缓浼佷笟鐭ヨ瘑搴?
	local app_url="瀹樼綉浠嬬粛: https://github.com/infiniflow/ragflow"
	local app_size="3"
	docker_app
}

# AstrBot鑱婂ぉ鏈哄櫒浜?astrbot_app(){
	local app_id="86"
	local app_name="AstrBot鑱婂ぉ鏈哄櫒浜?
	local docker_name="astrbot"
	local docker_img="soulter/astrbot:latest"
	local docker_port=8142

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8142): " _user_port
		_user_port=${_user_port:-8142}
		docker_port=$_user_port

		mkdir -p /home/docker/astrbot
		docker run -d \
			--name astrbot \
			--restart=always \
			-p ${docker_port}:6185 \
			-v /home/docker/astrbot:/AstrBot/data \
			soulter/astrbot:latest

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="澶氬钩鍙拌亰澶╂満鍣ㄤ汉妗嗘灦, 鏀寔QQ/寰俊/椋炰功"
	local app_url="瀹樼綉浠嬬粛: https://github.com/Soulter/AstrBot"
	local app_size="1"
	docker_app
}

# LangBot鑱婂ぉ鏈哄櫒浜?langbot_app(){
	local app_id="87"
	local app_name="LangBot鑱婂ぉ鏈哄櫒浜?
	local docker_name="langbot"
	local docker_img="rockchin/langbot:latest"
	local docker_port=8143

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8143): " _user_port
		_user_port=${_user_port:-8143}
		docker_port=$_user_port

		mkdir -p /home/docker/langbot
		docker run -d \
			--name langbot \
			--restart=always \
			-p ${docker_port}:2280 \
			-v /home/docker/langbot:/app \
			rockchin/langbot:latest

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="澶фā鍨嬪師鐢熷嵆鏃堕€氫俊鏈哄櫒浜哄钩鍙?
	local app_url="瀹樼綉浠嬬粛: https://github.com/RockChinQ/LangBot"
	local app_size="1"
	docker_app
}

# 澶氭牸寮忔枃浠惰浆鎹?gotenberg_app(){
	local app_id="88"
	local app_name="澶氭牸寮忔枃浠惰浆鎹?
	local docker_name="gotenberg"
	local docker_img="gotenberg/gotenberg:latest"
	local docker_port=8144

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8144): " _user_port
		_user_port=${_user_port:-8144}
		docker_port=$_user_port

		docker run -d \
			--name gotenberg \
			--restart=always \
			-p ${docker_port}:3000 \
			gotenberg/gotenberg:latest

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="寮€婧愮殑鏂囨。杞崲鏈嶅姟, 鏀寔澶氱鏍煎紡浜掕浆"
	local app_url="瀹樼綉浠嬬粛: https://github.com/gotenberg/gotenberg"
	local app_size="1"
	docker_app
}

# LibreSpeed娴嬮€?librespeed_app(){
	local app_id="89"
	local app_name="LibreSpeed娴嬮€?
	local docker_name="librespeed"
	local docker_img="adolfintel/speedtest:latest"
	local docker_port=8145

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8145): " _user_port
		_user_port=${_user_port:-8145}
		docker_port=$_user_port

		docker run -d \
			--name librespeed \
			--restart=always \
			-p ${docker_port}:80 \
			adolfintel/speedtest:latest

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="寮€婧愮殑缃戠粶娴嬮€熷伐鍏? 绫讳技Speedtest"
	local app_url="瀹樼綉浠嬬粛: https://github.com/librespeed/speedtest"
	local app_size="1"
	docker_app
}

# gpt-load AI閫忔槑浠ｇ悊
gptload_app(){
	local app_id="90"
	local app_name="gpt-load AI閫忔槑浠ｇ悊"
	local docker_name="gpt-load"
	local docker_img="ghcr.io/gpt-load/gpt-load:latest"
	local docker_port=8146

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8146): " _user_port
		_user_port=${_user_port:-8146}
		docker_port=$_user_port

		mkdir -p /home/docker/gptload
		docker run -d \
			--name gpt-load \
			--restart=always \
			-p ${docker_port}:8080 \
			-v /home/docker/gptload:/data \
			ghcr.io/gpt-load/gpt-load:latest

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="AI鏈嶅姟閫忔槑浠ｇ悊宸ュ叿"
	local app_url="瀹樼綉浠嬬粛: https://github.com/gpt-load"
	local app_size="1"
	docker_app
}

# 琛ヨ揣鐩戞帶宸ュ叿
stockmonitor_app(){
	local app_id="91"
	local app_name="琛ヨ揣鐩戞帶宸ュ叿"
	local docker_name="stockmonitor"
	local docker_img="stock-monitor:latest"
	local docker_port=8147

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8147): " _user_port
		_user_port=${_user_port:-8147}
		docker_port=$_user_port

		mkdir -p /home/docker/stockmonitor
		docker run -d \
			--name stockmonitor \
			--restart=always \
			-p ${docker_port}:8080 \
			-v /home/docker/stockmonitor:/data \
			stock-monitor:latest

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="鍟嗗搧搴撳瓨鐩戞帶鍜岃ˉ璐ф彁閱掑伐鍏?
	local app_url="瀹樼綉浠嬬粛: https://github.com/stock-monitor"
	local app_size="1"
	docker_app
}

# PVE铏氭嫙鍖栫鐞?pve_app(){
	local app_id="92"
	local app_name="PVE铏氭嫙鍖栫鐞?
	local docker_name="pve"
	local docker_img="pve-manager:latest"
	local docker_port=8148

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8148): " _user_port
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

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="Proxmox VE铏氭嫙鍖栫鐞嗗钩鍙?
	local app_url="瀹樼綉浠嬬粛: https://www.proxmox.com/"
	local app_size="3"
	docker_app
}

# DSM缇ゆ櫀铏氭嫙鏈?dsm_app(){
	local app_id="93"
	local app_name="DSM缇ゆ櫀铏氭嫙鏈?
	local docker_name="dsm"
	local docker_img="kroese/virtual-dsm:latest"
	local docker_port=8149

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8149): " _user_port
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

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="鍦―ocker涓繍琛岀兢鏅朌SM绯荤粺"
	local app_url="瀹樼綉浠嬬粛: https://github.com/kroese/virtual-dsm"
	local app_size="3"
	docker_app
}

# 鍦ㄧ嚎DOS鑰佹父鎴?dosgame_app(){
	local app_id="94"
	local app_name="鍦ㄧ嚎DOS鑰佹父鎴?
	local docker_name="dosgame"
	local docker_img="oldiy/dosgame-web-docker:latest"
	local docker_port=8150

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8150): " _user_port
		_user_port=${_user_port:-8150}
		docker_port=$_user_port

		docker run -d \
			--name dosgame \
			--restart=always \
			-p ${docker_port}:262 \
			oldiy/dosgame-web-docker:latest

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="鍦ㄧ嚎DOS娓告垙鍚堥泦, 鎬€鏃х粡鍏告父鎴?
	local app_url="瀹樼綉浠嬬粛: https://github.com/rwv/dosgame"
	local app_size="1"
	docker_app
}

# 杩呴浄绂荤嚎涓嬭浇
xunlei_app(){
	local app_id="95"
	local app_name="杩呴浄绂荤嚎涓嬭浇"
	local docker_name="xunlei"
	local docker_img="cnk3x/xunlei:latest"
	local docker_port=8151

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8151): " _user_port
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

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="杩呴浄绂荤嚎涓嬭浇鏈嶅姟, 鏀寔杩滅▼涓嬭浇"
	local app_url="瀹樼綉浠嬬粛: https://github.com/cnk3x/xunlei"
	local app_size="1"
	docker_app
}

# 灏忛泤Alist鍏ㄥ妗?xiaoya_app(){
	local app_id="96"
	local app_name="灏忛泤Alist鍏ㄥ妗?
	local docker_name="xiaoya"
	local docker_img="xiaoyaliu/alist:latest"
	local docker_port=8152

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8152): " _user_port
		_user_port=${_user_port:-8152}
		docker_port=$_user_port

		mkdir -p /home/docker/xiaoya
		docker run -d \
			--name xiaoya \
			--restart=always \
			-p ${docker_port}:5244 \
			-v /home/docker/xiaoya:/data \
			xiaoyaliu/alist:latest

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="灏忛泤Alist, 鏁村悎澶氱綉鐩樿祫婧?
	local app_url="瀹樼綉浠嬬粛: https://github.com/xiaoyaliu/alist"
	local app_size="1"
	docker_app
}

# Bililive鐩存挱褰曞埗
bililive_app(){
	local app_id="97"
	local app_name="Bililive鐩存挱褰曞埗"
	local docker_name="bililive"
	local docker_img="bililive/recorder:latest"
	local docker_port=8153

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8153): " _user_port
		_user_port=${_user_port:-8153}
		docker_port=$_user_port

		mkdir -p /home/docker/bililive
		docker run -d \
			--name bililive \
			--restart=always \
			-p ${docker_port}:2356 \
			-v /home/docker/bililive:/rec \
			bililive/recorder:latest

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="B绔欑洿鎾綍鍒跺伐鍏? 鑷姩褰曞埗鐩存挱闂?
	local app_url="瀹樼綉浠嬬粛: https://github.com/BililiveRecorder/BililiveRecorder"
	local app_size="1"
	docker_app
}

# 鏋佺畝鏈嬪弸鍦?moments_app(){
	local app_id="98"
	local app_name="鏋佺畝鏈嬪弸鍦?
	local docker_name="moments"
	local docker_img="moments-app:latest"
	local docker_port=8154

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8154): " _user_port
		_user_port=${_user_port:-8154}
		docker_port=$_user_port

		mkdir -p /home/docker/moments
		docker run -d \
			--name moments \
			--restart=always \
			-p ${docker_port}:3000 \
			-v /home/docker/moments:/data \
			moments-app:latest

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="鏋佺畝椋庢牸鐨勬湅鍙嬪湀/寰崥绯荤粺"
	local app_url="瀹樼綉浠嬬粛: https://github.com/moments-app"
	local app_size="1"
	docker_app
}

# PanSou缃戠洏鎼滅储
pansou_app(){
	local app_id="99"
	local app_name="PanSou缃戠洏鎼滅储"
	local docker_name="pansou"
	local docker_img="pansou-search:latest"
	local docker_port=8155

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8155): " _user_port
		_user_port=${_user_port:-8155}
		docker_port=$_user_port

		mkdir -p /home/docker/pansou
		docker run -d \
			--name pansou \
			--restart=always \
			-p ${docker_port}:8080 \
			-v /home/docker/pansou:/data \
			pansou-search:latest

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="缃戠洏璧勬簮鎼滅储寮曟搸"
	local app_url="瀹樼綉浠嬬粛: https://github.com/pansou"
	local app_size="1"
	docker_app
}

# 绠€鍗曞浘搴妉skypro
lskypro_app(){
	local app_id="100"
	local app_name="绠€鍗曞浘搴妉skypro"
	local docker_name="lskypro"
	local docker_img="halcyonazure/lsky-pro-docker:latest"
	local docker_port=8156

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8156): " _user_port
		_user_port=${_user_port:-8156}
		docker_port=$_user_port

		mkdir -p /home/docker/lskypro
		docker run -d \
			--name lskypro \
			--restart=always \
			-p ${docker_port}:8089 \
			-v /home/docker/lskypro:/var/www/html \
			halcyonazure/lsky-pro-docker:latest

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="绠€鍗曞浘搴婄郴缁? 鏀寔澶氬瓨鍌ㄧ瓥鐣?
	local app_url="瀹樼綉浠嬬粛: https://github.com/lsky-org/lsky-pro"
	local app_size="1"
	docker_app
}

# 绂呴亾椤圭洰绠＄悊
zentao_app(){
	local app_id="101"
	local app_name="绂呴亾椤圭洰绠＄悊"
	local docker_name="zentao"
	local docker_img="idoop/zentao:latest"
	local docker_port=8157

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8157): " _user_port
		_user_port=${_user_port:-8157}
		docker_port=$_user_port

		mkdir -p /home/docker/zentao
		docker run -d \
			--name zentao \
			--restart=always \
			-p ${docker_port}:80 \
			-v /home/docker/zentao:/www/zentaopms \
			idoop/zentao:latest

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="寮€婧愮殑椤圭洰绠＄悊杞欢, 鏀寔鏁忔嵎寮€鍙?
	local app_url="瀹樼綉浠嬬粛: https://www.zentao.net/"
	local app_size="2"
	docker_app
}

# QD-Today瀹氭椂浠诲姟
qdtoday_app(){
	local app_id="102"
	local app_name="QD-Today瀹氭椂浠诲姟"
	local docker_name="qdtoday"
	local docker_img="qdtoday/qd:latest"
	local docker_port=8158

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8158): " _user_port
		_user_port=${_user_port:-8158}
		docker_port=$_user_port

		mkdir -p /home/docker/qdtoday
		docker run -d \
			--name qdtoday \
			--restart=always \
			-p ${docker_port}:80 \
			-v /home/docker/qdtoday:/usr/src/app \
			qdtoday/qd:latest

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="HTTP璇锋眰瀹氭椂浠诲姟妗嗘灦, 鑷姩绛惧埌"
	local app_url="瀹樼綉浠嬬粛: https://github.com/qd-today/qd"
	local app_size="1"
	docker_app
}

# 鑰楀瓙绠＄悊闈㈡澘
haizi_app(){
	local app_id="103"
	local app_name="鑰楀瓙绠＄悊闈㈡澘"
	local docker_name="haizi"
	local docker_img="haizi-panel:latest"
	local docker_port=8159

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8159): " _user_port
		_user_port=${_user_port:-8159}
		docker_port=$_user_port

		mkdir -p /home/docker/haizi
		docker run -d \
			--name haizi \
			--restart=always \
			-p ${docker_port}:8080 \
			-v /home/docker/haizi:/data \
			haizi-panel:latest

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="鑰楀瓙绠＄悊闈㈡澘, 杞婚噺绾ф湇鍔″櫒绠＄悊"
	local app_url="瀹樼綉浠嬬粛: https://github.com/haizi-panel"
	local app_size="1"
	docker_app
}

# AMH寤虹珯闈㈡澘
amh_app(){
	local app_id="104"
	local app_name="AMH寤虹珯闈㈡澘"
	local docker_name="amh"
	local docker_img="amh-panel:latest"
	local docker_port=8160

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8160): " _user_port
		_user_port=${_user_port:-8160}
		docker_port=$_user_port

		mkdir -p /home/docker/amh
		docker run -d \
			--name amh \
			--restart=always \
			-p ${docker_port}:8888 \
			-v /home/docker/amh:/data \
			amh-panel:latest

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="AMH浜戜富鏈洪潰鏉? 寤虹珯绠＄悊宸ュ叿"
	local app_url="瀹樼綉浠嬬粛: https://amh.sh/"
	local app_size="2"
	docker_app
}

# 鍦ㄧ嚎缈昏瘧鏈嶅姟鍣?libretranslate_app(){
	local app_id="105"
	local app_name="鍦ㄧ嚎缈昏瘧鏈嶅姟鍣?
	local docker_name="libretranslate"
	local docker_img="libretranslate/libretranslate:latest"
	local docker_port=8161

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8161): " _user_port
		_user_port=${_user_port:-8161}
		docker_port=$_user_port

		docker run -d \
			--name libretranslate \
			--restart=always \
			-p ${docker_port}:5000 \
			libretranslate/libretranslate:latest

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="寮€婧愮殑绁炵粡缃戠粶缈昏瘧API鏈嶅姟"
	local app_url="瀹樼綉浠嬬粛: https://github.com/LibreTranslate/LibreTranslate"
	local app_size="2"
	docker_app
}

# AI瑙嗛鐢熸垚宸ュ叿
videogen_app(){
	local app_id="106"
	local app_name="AI瑙嗛鐢熸垚宸ュ叿"
	local docker_name="videogen"
	local docker_img="videogen-ai:latest"
	local docker_port=8162

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8162): " _user_port
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

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="AI瑙嗛鐢熸垚宸ュ叿, 鏂囨湰鐢熸垚瑙嗛"
	local app_url="瀹樼綉浠嬬粛: https://github.com/videogen-ai"
	local app_size="3"
	docker_app
}

# RustDesk杩滅▼妗岄潰
rustdesk_server_app(){
	local app_id="107"
	local app_name="RustDesk杩滅▼妗岄潰"
	local docker_name="rustdesk-server"
	local docker_img="rustdesk/rustdesk-server:latest"
	local app_text="寮€婧愮殑杩滅▼妗岄潰杞欢鏈嶅姟绔?
	local app_url="瀹樼綉浠嬬粛: https://github.com/rustdesk/rustdesk"
	local app_size="1"

	docker_run() {
		mkdir -p /home/docker/rustdesk-server
		# 璁╃敤鎴疯緭鍏?Web 瀹㈡埛绔?API 绔彛 (榛樿 8163)
		read -e -p "璁剧疆Web瀹㈡埛绔?API绔彛 (榛樿8163): " web_port
		web_port=${web_port:-8163}

		docker run -d \
			--name rustdesk-server \
			--restart=always \
			-p 21115:21115 \
			-p 21116:21116 \
			-p 21116:21116/udp \
			-p 21117:21117 \
			-p ${web_port}:21118 \
			-v /home/docker/rustdesk-server:/data \
			rustdesk/rustdesk-server:latest

		# Web闈㈡澘绔彛
		add_app_port "Web瀹㈡埛绔?API" "$web_port"
		# TCP/UDP 鏈嶅姟绔彛淇濇寔纭紪鐮?(鏆備笉鏀?
		add_app_port "涓户鏈嶅姟 (TCP)" 21115
		add_app_port "涓户鏈嶅姟 (TCP+UDP)" 21116
		add_app_port "蹇冭烦鏈嶅姟" 21117
		add_app_port "鏈嶅姟绔彛" 21118
	}

	docker_app
}

# Firefox娴忚鍣?firefox_app(){
	local app_id="108"
	local app_name="Firefox娴忚鍣?
	local docker_name="firefox"
	local docker_img="jlesage/firefox:latest"
	local docker_port=8164

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8164): " _user_port
		_user_port=${_user_port:-8164}
		docker_port=$_user_port

		mkdir -p /home/docker/firefox
		docker run -d \
			--name firefox \
			--restart=always \
			-p ${docker_port}:5800 \
			-v /home/docker/firefox:/config \
			jlesage/firefox:latest

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="鍦ㄦ祻瑙堝櫒涓繍琛岀殑Firefox娴忚鍣?
	local app_url="瀹樼綉浠嬬粛: https://github.com/jlesage/docker-firefox"
	local app_size="2"
	docker_app
}

# DPanel瀹瑰櫒绠＄悊
dpanel_app(){
	local app_id="109"
	local app_name="DPanel瀹瑰櫒绠＄悊"
	local docker_name="dpanel"
	local docker_img="dpanel/dpanel:latest"
	local docker_port=8165

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8165): " _user_port
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

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="Docker瀹瑰櫒鍙鍖栫鐞嗛潰鏉?
	local app_url="瀹樼綉浠嬬粛: https://github.com/dpanel-io/dpanel"
	local app_size="1"
	docker_app
}

# 鏅綏绫充慨鏂洃鎺?prometheus_app(){
	local app_id="110"
	local app_name="鏅綏绫充慨鏂洃鎺?
	local docker_name="prometheus"
	local docker_img="prom/prometheus:latest"
	local docker_port=8166

	docker_run() {
		# app 鑷绔彛: 璁╃敤鎴疯緭鍏ュ疄闄呭澶栨湇鍔＄鍙?		read -e -p "鏈嶅姟绔彛 (榛樿 8166): " _user_port
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

		# 娉ㄥ唽鍒板睍绀鸿〃 (app 鑷畾 label)
		add_app_port "Web 绔彛" "$docker_port"
	}

	local app_text="寮€婧愮殑绯荤粺鐩戞帶鍜屾姤璀﹀伐鍏?
	local app_url="瀹樼綉浠嬬粛: https://prometheus.io/"
	local app_size="2"
	docker_app
}
