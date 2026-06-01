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


# Docker 应用管理
docker_app() {
    while true; do
        clear
        # 先执行检查函数, 确定容器状态
        check_docker_app
        check_docker_image_update "$docker_name"
        
        echo -e "$docker_name $check_docker $update_status"
        echo "$docker_describe"
        echo "$docker_url"
        
        # 处理端口信息（保持不变）
        if docker ps -a --format '{{.Names}}' | grep -q "^${docker_name}$" >/dev/null 2>&1; then
            if [ ! -f "/home/docker/${docker_name}_port.conf" ]; then
                local docker_port=$(docker port "$docker_name" | head -n1 | awk -F'[:]' '/->/ {print $NF; exit}')
                docker_port=${docker_port:-0000}
                echo "$docker_port" > "/home/docker/${docker_name}_port.conf"
            fi
            local docker_port=$(cat "/home/docker/${docker_name}_port.conf")
            check_docker_app_ip
        fi
        
        echo ""
        echo -e "${cyan}------------------------------------------------------${white}"

		# 根据容器是否存在显示不同菜单
        if check_docker_app; then  # 容器存在（返回0）
            echo -e "${green}1. 更新${white}              ${red}2. 卸载${white}"
        else  # 容器不存在（返回非0）
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
        
        # 根据容器状态限制可执行的选项
        if check_docker_app; then
            # 容器存在时允许的操作
            case $choice in
                1)  # 更新
                    docker rm -f "$docker_name"
                    docker rmi -f "$docker_img"
                    docker_run

                    mkdir -p /home/docker && touch /home/docker/appno.txt && (add_app_id)

                    clear
                    echo "$docker_name 已经更新完成"
                    check_docker_app_ip
                    echo ""
                    $docker_use
                    $docker_passwd
                    ;;
                2)  # 卸载
                    docker rm -f "$docker_name"
                    docker rmi -f "$docker_img"
                    rm -rf "/home/docker/$docker_name"
                    rm -f /home/docker/${docker_name}_port.conf

                    sed -i "/\b${app_id}\b/d" /home/docker/appno.txt
                    echo "应用已卸载"
                    ;;
                5)  # 添加域名访问
                    echo "${docker_name}域名访问设置"
                    add_yuming
                    ldnmp_Proxy "${yuming}" 127.0.0.1 "${docker_port}"
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
                    read -e -p "输入应用对外服务端口: " app_port
                    local app_port=${app_port:-8080}  # 提供默认端口
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


# Docker 应用管理 compose
docker_app_plus() {
    while true; do
        clear
        # 先执行检查函数, 确定容器状态
        check_docker_app
        check_docker_image_update "$docker_name"
        
        echo -e "$app_name $check_docker $update_status"
        echo "$app_text"
        echo "$app_url"
        
        # 处理端口信息（保持不变）
        if docker ps -a --format '{{.Names}}' | grep -q "^${docker_name}$" >/dev/null 2>&1; then
            if [ ! -f "/home/docker/${docker_name}_port.conf" ]; then
                local docker_port=$(docker port "$docker_name" | head -n1 | awk -F'[:]' '/->/ {print $NF; exit}')
                docker_port=${docker_port:-0000}
                echo "$docker_port" > "/home/docker/${docker_name}_port.conf"
            fi
            local docker_port=$(cat "/home/docker/${docker_name}_port.conf")
            check_docker_app_ip
        fi
        
        echo ""
        echo -e "${cyan}------------------------------------------------------${white}"
        
		# 根据容器是否存在显示不同菜单
        if check_docker_app; then  # 容器存在（返回0）
            echo -e "${green}1. 更新${white}              ${red}2. 卸载${white}"
        else  # 容器不存在（返回非0）
            echo -e "${green}1. 安装${white}"
        fi
        
        echo -e "${pink}------------------------------------------------------${white}"
        
        # 仅当容器存在时显示域名和端口相关操作
        if check_docker_app; then
            echo "5. 添加域名访问      6. 删除域名访问"
            echo "7. 允许IP+端口访问   8. 阻止IP+端口访问"
            echo -e "${pink}------------------------------------------------------${white}"
        fi
        
        echo -e "${yellow}0. 返回上一级菜单${white}"
        echo -e "${pink}------------------------------------------------------${white}"
        
        read -e -p "输入你的选择: " choice
        
        # 根据容器状态限制可执行的选项
        if check_docker_app; then
            # 容器存在时允许的操作
            case $choice in
                1)  # 更新
                    docker_app_update
                    mkdir -p /home/docker && touch /home/docker/appno.txt && (add_app_id)
                    ;;
                2)  # 卸载
                    docker_app_uninstall
                    rm -f /home/docker/${docker_name}_port.conf
                    sed -i "/\b${app_id}\b/d" /home/docker/appno.txt
                    ;;
                5)  # 添加域名访问
                    echo "${docker_name}域名访问设置"
                    add_yuming
                    ldnmp_Proxy "${yuming}" 127.0.0.1 "${docker_port}"
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
                    read -e -p "输入应用对外服务端口: " app_port
                    local app_port=${app_port:-8080}  # 提供默认端口（避免未定义）
                    local docker_port=$app_port

                    install jq
                    install_docker
                    docker_app_install
                    setup_docker_dir
                    echo "$docker_port" > "/home/docker/${docker_name}_port.conf"

                    mkdir -p /home/docker && touch /home/docker/appno.txt && (add_app_id)
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

		local docker_describe="一个Nginx反向代理工具面板, 不支持添加域名访问."
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
		local docker_img="openlistteam/openlist:latest"
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
				--user 0:0 \
				--restart=unless-stopped \
				openlistteam/openlist:latest
		}

		local docker_describe="一个支持多种存储, 支持网页浏览和 WebDAV 的文件列表程序, 由 gin 和 Solidjs 驱动"
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

		local docker_describe="webtop基于Ubuntu的容器.若IP无法访问, 请添加域名访问."
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
		echo -e "${yellow}0.     ${white}返回上一级菜单"
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

	local docker_describe="onlyoffice是一款开源的在线office工具, 太强大了!"
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

	local docker_describe="这是一个强大图表绘制软件.思维导图, 拓扑图, 流程图, 都能画"
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

	local docker_describe="LobeChat聚合市面上主流的AI大模型, ChatGPT/Claude/Gemini/Groq/Ollama"
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

	local docker_describe="是一个多功能IP工具箱, 可以查看自己IP信息及连通性, 用网页面板呈现"
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

	local docker_describe="使用Go实现的GHProxy, 用于加速部分地区Github仓库的拉取."
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

	local docker_describe="自动将你的公网 IP(IPv4/IPv6)实时更新到各大 DNS 服务商, 实现动态域名解析."
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

	local docker_describe="自动将你的公网 IP(IPv4/IPv6)实时更新到各大 DNS 服务商, 实现动态域名解析."
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

	local docker_describe="你的音乐精灵, 旨在帮助你更好地管理音乐."
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

		local docker_describe="远程一起观看电影和直播的程序.它提供了同步观影、直播、聊天等功能"
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

	local docker_describe="一款开源的在线白板工具，类似Excalidraw，支持思维导图、流程图和自由绘图。"
	local docker_url="官网介绍: https://github.com/pubuzhixing/drawnix"
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
		echo -e "${green}===== 应用市场 =====${white}"
		echo ""
		docker_tato
		echo -e "${pink}------------------------------------------------------------------------------------${white}"
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
		echo -e "${cyan}34. ${white}DecoTV私有影视         ${cyan}35. ${white}Drawnix在线白板"
		echo -e "${pink}------------------------------------------------------------------------------------${white}"
		echo -e "${cyan}36. ${white}Portainer容器管理      ${cyan}37. ${white}Cloudreve网盘            ${cyan}38. ${white}Nextcloud私有网盘"
		echo -e "${cyan}39. ${white}emby媒体管理           ${cyan}40. ${white}jellyfin媒体管理         ${cyan}41. ${white}AdGuardHome去广告"
		echo -e "${cyan}42. ${white}Navidrome音乐服务器    ${cyan}43. ${white}Vaultwarden密码管理     ${cyan}44. ${white}StirlingPDF工具大全"
		echo -e "${cyan}45. ${white}Speedtest测速面板      ${cyan}46. ${white}PhotoPrism私有相册       ${cyan}47. ${white}searxng聚合搜索"
		echo -e "${cyan}48. ${white}Pingvin-Share文件分享  ${cyan}49. ${white}Dockge容器管理          ${cyan}50. ${white}it-tools工具箱"
		echo -e "${cyan}51. ${white}n8n自动化工作流       ${cyan}52. ${white}OpenWebUI自托管AI        ${cyan}53. ${white}Dify大模型知识库"
		echo -e "${cyan}54. ${white}gitea私有代码仓库      ${cyan}55. ${white}FileBrowser文件管理      ${cyan}56. ${white}FRP内网穿透(服务端)"
		echo -e "${cyan}57. ${white}WireGuard组网(服务端)  ${cyan}58. ${white}JumpServer堡垒机         ${cyan}59. ${white}immich图片视频管理"
		echo -e "${cyan}60. ${white}Syncthing文件同步       ${cyan}61. ${white}Umami网站统计           ${cyan}62. ${white}思源笔记"
		echo -e "${cyan}63. ${white}SFTPGo文件传输         ${cyan}64. ${white}Owncast自托管直播        ${cyan}65. ${white}Deepseek AI大模型"
		echo -e "${cyan}66. ${white}RocketChat聊天系统     ${cyan}67. ${white}Gopeed高速下载           ${cyan}68. ${white}2FAuth二步验证器"
		echo -e "${cyan}69. ${white}ZFile在线网盘          ${cyan}70. ${white}Nexterm远程连接          ${cyan}71. ${white}JitsiMeet视频会议"
		echo -e "${cyan}72. ${white}Stream四层代理转发     ${cyan}73. ${white}FileCodeBox文件快递      ${cyan}74. ${white}Matrix去中心化聊天"
		echo -e "${cyan}75. ${white}yt-dlp视频下载         ${cyan}76. ${white}paperless文档管理        ${cyan}77. ${white}Wallos财务管理"
		echo -e "${cyan}78. ${white}komari服务器监控       ${cyan}79. ${white}Dufs静态文件服务器      ${cyan}80. ${white}PandaWiki文档管理"
		echo -e "${cyan}81. ${white}linkwarden书签管理     ${cyan}82. ${white}VoceChat聊天系统         ${cyan}83. ${white}Karakeep书签管理"
		echo -e "${cyan}84. ${white}NewAPI大模型资产管理   ${cyan}85. ${white}RAGFlow知识库            ${cyan}86. ${white}AstrBot聊天机器人"
		echo -e "${cyan}87. ${white}LangBot聊天机器人      ${cyan}88. ${white}多格式文件转换           ${cyan}89. ${white}LibreSpeed测速"
		echo -e "${cyan}90. ${white}gpt-load AI透明代理    ${cyan}91. ${white}补货监控工具             ${cyan}92. ${white}PVE虚拟化管理"
		echo -e "${cyan}93. ${white}DSM群晖虚拟机          ${cyan}94. ${white}在线DOS老游戏            ${cyan}95. ${white}迅雷离线下载"
		echo -e "${cyan}96. ${white}小雅Alist全家桶        ${cyan}97. ${white}Bililive直播录制         ${cyan}98. ${white}极简朋友圈"
		echo -e "${cyan}99. ${white}PanSou网盘搜索         ${cyan}100.${white}简单图床lskypro          ${cyan}101.${white}禅道项目管理"
		echo -e "${cyan}102.${white}QD-Today定时任务       ${cyan}103.${white}耗子管理面板             ${cyan}104.${white}AMH建站面板"
		echo -e "${cyan}105.${white}在线翻译服务器         ${cyan}106.${white}AI视频生成工具           ${cyan}107.${white}RustDesk远程桌面"
		echo -e "${cyan}108.${white}Firefox浏览器          ${cyan}109.${white}DPanel容器管理           ${cyan}110.${white}普罗米修斯监控"
		echo -e "${pink}------------------------------------------------------------------------------------${white}"
		echo -e "${yellow}0.   ${white}返回主菜单"
		echo -e "${pink}------------------------------------------------------------------------------------${white}"
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
			poste_mail_app ;;
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
		34)
			decotv_app ;;
		35)
			drawnix_app ;;
		36)
			portainer_app ;;
		37)
			cloudreve_app ;;
		38)
			nextcloud_app ;;
		39)
			emby_app ;;
		40)
			jellyfin_app ;;
		41)
			adguardhome_app ;;
		42)
			navidrome_app ;;
		43)
			bitwarden_app ;;
		44)
			stirlingpdf_app ;;
		45)
			speedtest_app ;;
		46)
			photoprism_app ;;
		47)
			searxng_app ;;
		48)
			pingvinshare_app ;;
		49)
			dockge_app ;;
		50)
			ittools_app ;;
		51)
			n8n_app ;;
		52)
			openwebui_app ;;
		53)
			dify_app ;;
		54)
			gitea_app ;;
		55)
			filebrowser_app ;;
		56)
			frp_server_app ;;
		57)
			wireguard_server_app ;;
		58)
			jumpserver_app ;;
		59)
			immich_app ;;
		60)
			syncthing_app ;;
		61)
			umami_app ;;
		62)
			siyuan_app ;;
		63)
			sftpgp_app ;;
		64)
			owncast_app ;;
		65)
			deepseek_app ;;
		66)
			rocketchat_app ;;
		67)
			gopeed_app ;;
		68)
			twofauth_app ;;
		69)
			zfile_app ;;
		70)
			nexterm_app ;;
		71)
			jitsimeet_app ;;
		72)
			stream_app ;;
		73)
			filecodebox_app ;;
		74)
			matrix_app ;;
		75)
			ytdlp_app ;;
		76)
			paperless_app ;;
		77)
			wallos_app ;;
		78)
			komari_app ;;
		79)
			dufs_app ;;
		80)
			pandawiki_app ;;
		81)
			linkwarden_app ;;
		82)
			vocechat_app ;;
		83)
			karakeep_app ;;
		84)
			newapi_app ;;
		85)
			ragflow_app ;;
		86)
			astrbot_app ;;
		87)
			langbot_app ;;
		88)
			gotenberg_app ;;
		89)
			librespeed_app ;;
		90)
			gptload_app ;;
		91)
			stockmonitor_app ;;
		92)
			pve_app ;;
		93)
			dsm_app ;;
		94)
			dosgame_app ;;
		95)
			xunlei_app ;;
		96)
			xiaoya_app ;;
		97)
			bililive_app ;;
		98)
			moments_app ;;
		99)
			pansou_app ;;
		100)
			lskypro_app ;;
		101)
			zentao_app ;;
		102)
			qdtoday_app ;;
		103)
			haizi_app ;;
		104)
			amh_app ;;
		105)
			libretranslate_app ;;
		106)
			videogen_app ;;
		107)
			rustdesk_server_app ;;
		108)
			firefox_app ;;
		109)
			dpanel_app ;;
		110)
			prometheus_app ;;
		0)
			break
			;;
		*)
			echo -e "${red}无效选择, 请重新输入 !${white}"
			sleep 1
			;;
		esac
	done
}
