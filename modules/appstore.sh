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

        show_docker_app_menu()
        # 旧菜单逻辑已迁移至公共函数 show_docker_app_menu()
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
                    read -e -p "确认卸载 ${docker_name}？(y/N): " confirm
                    if [[ "$confirm" =~ ^[Yy]$ ]]; then
                        docker rm -f "$docker_name"
                        docker rmi -f "$docker_img"
                        rm -rf "/home/docker/$docker_name"
                        rm -f /home/docker/${docker_name}_port.conf

                        sed -i "/\b${app_id}\b/d" /home/docker/appno.txt
                        echo "应用已卸载"
                    else
                        echo "已取消卸载"
                    fi
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
                    local docker_port=$(read_docker_port 8080)

                    install jq
                    install_docker
                    docker_run
                    docker_app_post_install "$docker_name" "$docker_port" "$docker_use" "$docker_passwd"
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
        
        show_docker_app_menu()
        # 旧菜单逻辑已迁移至公共函数 show_docker_app_menu()
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
                    docker rm -f "$docker_name"
                    docker rmi -f "$docker_img"
                    docker_run

                    mkdir -p /home/docker && touch /home/docker/appno.txt && (add_app_id)
                    ;;
                2)  # 卸载
                    read -e -p "确认卸载 ${docker_name}？(y/N): " confirm
                    if [[ "$confirm" =~ ^[Yy]$ ]]; then
                        docker rm -f "$docker_name"
                        docker rmi -f "$docker_img"
                        rm -rf "/home/docker/$docker_name"
                        rm -f /home/docker/${docker_name}_port.conf

                        sed -i "/\b${app_id}\b/d" /home/docker/appno.txt
                        echo "应用已卸载"
                    else
                        echo "已取消卸载"
                    fi
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
                    local docker_port=$(read_docker_port 8080)

                    install jq
                    install_docker
                    docker_run
                    docker_app_post_install "$docker_name" "$docker_port" "$docker_use" "$docker_passwd"
                    ;;
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

	1panel_app_install(){
		local tmp_script="/tmp/1panel_install.sh"
		curl -sSL https://resource.fit2cloud.com/1panel/package/v2/quick_start.sh -o "$tmp_script" && bash "$tmp_script"
		rm -f "$tmp_script"
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

	bt_app_install(){
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

	aapanel_app_install(){
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
                    docker_run
                    docker_app_post_install "$docker_name" "$docker_port" "$docker_use" "$docker_passwd"
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
				local tmp_script="/tmp/waf_setup.sh" && curl -fsSLk https://waf-ce.chaitin.cn/release/latest/setup.sh -o "$tmp_script" && bash "$tmp_script" && rm -f "$tmp_script"

				mkdir -p /home/docker && touch /home/docker/appno.txt && (add_app_id)
				clear
				echo "雷池WAF面板已经安装完成"
				check_docker_app_ip
				docker exec safeline-mgt resetadmin

				;;

			2)
				local tmp_script="/tmp/waf_upgrade.sh" && curl -fsSLk https://waf-ce.chaitin.cn/release/latest/upgrade.sh -o "$tmp_script" && bash "$tmp_script" && rm -f "$tmp_script"
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

	xui_app_install(){
		local tmp_script="/tmp/xui_install.sh" && curl -Ls https://raw.githubusercontent.com/FranzKafkaYu/x-ui/master/install.sh -o "$tmp_script" && bash "$tmp_script" && rm -f "$tmp_script"
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

	x3ui_app_install(){
		local tmp_script="/tmp/x3ui_install.sh" && curl -Ls https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh -o "$tmp_script" && bash "$tmp_script" && rm -f "$tmp_script"
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

#############################################################################
########################### 补充应用 (36-110) #############################

# portainer容器管理面板
portainer_app(){
	local app_id="36"
	local docker_name="portainer"
	local docker_img="portainer/portainer-ce:latest"
	local docker_port=9000

	docker_run() {
		docker volume create portainer_data
		docker run -d \
			--name portainer \
			--restart=always \
			-p ${docker_port}:9000 \
			-p 9443:9443 \
			-v /var/run/docker.sock:/var/run/docker.sock \
			-v portainer_data:/data \
			portainer/portainer-ce:latest
	}

	local docker_describe="轻量级的Docker容器管理UI面板, 支持容器/镜像/网络/卷的可视化管理"
	local docker_url="官网介绍: https://www.portainer.io/"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# Cloudreve网盘
cloudreve_app(){
	local app_id="37"
	local docker_name="cloudreve"
	local docker_img="cloudreve/cloudreve:latest"
	local docker_port=8088

	docker_run() {
		mkdir -p /home/docker/cloudreve
		docker run -d \
			--name cloudreve \
			--restart=always \
			-p ${docker_port}:5212 \
			-v /home/docker/cloudreve:/cloudreve \
			cloudreve/cloudreve:latest
	}

	local docker_describe="支持多种存储的云盘系统, 支持本地存储/对象存储/S3等"
	local docker_url="官网介绍: https://github.com/cloudreve/Cloudreve"
	local docker_use=""
	local docker_passwd=""
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
	local docker_name="emby"
	local docker_img="emby/embyserver:latest"
	local docker_port=8096

	docker_run() {
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
	}

	local docker_describe="功能强大的个人媒体服务器, 支持电影/电视剧/音乐管理和在线播放"
	local docker_url="官网介绍: https://emby.media/"
	local docker_use=""
	local docker_passwd=""
	local app_size="3"
	docker_app
}

# jellyfin媒体管理系统
jellyfin_app(){
	local app_id="40"
	local docker_name="jellyfin"
	local docker_img="jellyfin/jellyfin:latest"
	local docker_port=8097

	docker_run() {
		mkdir -p /home/docker/jellyfin/config /home/docker/jellyfin/cache
		docker run -d \
			--name jellyfin \
			--restart=always \
			-p ${docker_port}:8096 \
			-v /home/docker/jellyfin/config:/config \
			-v /home/docker/jellyfin/cache:/cache \
			--device=/dev/dri:/dev/dri \
			jellyfin/jellyfin:latest
	}

	local docker_describe="免费开源的媒体服务器, Emby的替代品, 支持电影/电视剧/音乐管理和在线播放"
	local docker_url="官网介绍: https://jellyfin.org/"
	local docker_use=""
	local docker_passwd=""
	local app_size="2"
	docker_app
}

# AdGuardHome去广告软件
adguardhome_app(){
	local app_id="41"
	local docker_name="adguardhome"
	local docker_img="adguard/adguardhome:latest"
	local docker_port=3000

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

	local docker_describe="全网广告拦截与隐私保护DNS服务, 支持DNS-over-HTTPS/TLS"
	local docker_url="官网介绍: https://adguard.com/adguard-home/overview.html"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# Navidrome私有音乐服务器
navidrome_app(){
	local app_id="42"
	local docker_name="navidrome"
	local docker_img="deluan/navidrome:latest"
	local docker_port=8098

	docker_run() {
		mkdir -p /home/docker/navidrome/music /home/docker/navidrome/data
		docker run -d \
			--name navidrome \
			--restart=always \
			-p ${docker_port}:4533 \
			-v /home/docker/navidrome/music:/music \
			-v /home/docker/navidrome/data:/data \
			navidrome/navidrome:latest
	}

	local docker_describe="现代的私人音乐流媒体服务器, 支持多用户, 兼容Subsonic/Airsonic API"
	local docker_url="官网介绍: https://github.com/navidrome/navidrome"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# bitwarden密码管理器 (使用Vaultwarden轻量替代)
bitwarden_app(){
	local app_id="43"
	local docker_name="vaultwarden"
	local docker_img="vaultwarden/server:latest"
	local docker_port=8099

	docker_run() {
		mkdir -p /home/docker/vaultwarden/data
		docker run -d \
			--name vaultwarden \
			--restart=always \
			-p ${docker_port}:80 \
			-e WEBSOCKET_ENABLED=true \
			-v /home/docker/vaultwarden/data:/data \
			vaultwarden/server:latest
	}

	local docker_describe="Bitwarden的轻量级替代(Vaultwarden), 自托管密码管理器"
	local docker_url="官网介绍: https://github.com/dani-garcia/vaultwarden"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# StirlingPDF工具大全
stirlingpdf_app(){
	local app_id="44"
	local docker_name="stirlingpdf"
	local docker_img="frooodle/s-pdf:latest"
	local docker_port=8100

	docker_run() {
		mkdir -p /home/docker/stirlingpdf/config /home/docker/stirlingpdf/logs
		docker run -d \
			--name stirlingpdf \
			--restart=always \
			-p ${docker_port}:8080 \
			-v /home/docker/stirlingpdf/config:/configs \
			-v /home/docker/stirlingpdf/logs:/logs \
			-e DOCKER_ENABLE_SECURITY=false \
			frooodle/s-pdf:latest
	}

	local docker_describe="功能强大的PDF处理工具箱, 支持合并/拆分/转换/压缩/加水印等"
	local docker_url="官网介绍: https://github.com/Stirling-Tools/Stirling-PDF"
	local docker_use=""
	local docker_passwd=""
	local app_size="2"
	docker_app
}

# Speedtest测速面板
speedtest_app(){
	local app_id="45"
	local docker_name="speedtest"
	local docker_img="adolfintel/speedtest:latest"
	local docker_port=8101

	docker_run() {
		docker run -d \
			--name speedtest \
			--restart=always \
			-p ${docker_port}:80 \
			--network host \
			adolfintel/speedtest:latest
	}

	local docker_describe="LibreSpeed测速面板, 自托管的网络测速工具"
	local docker_url="官网介绍: https://github.com/librespeed/speedtest"
	local docker_use=""
	local docker_passwd=""
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
	local docker_name="searxng"
	local docker_img="searxng/searxng:latest"
	local docker_port=8103

	docker_run() {
		mkdir -p /home/docker/searxng
		docker run -d \
			--name searxng \
			--restart=always \
			-p ${docker_port}:8080 \
			-v /home/docker/searxng:/etc/searxng \
			-e SEARXNG_BASE_URL: "http://localhost:${docker_port}/" \
			-e SEARXNG_SECRET: "$(openssl rand -hex 32)" \
			searxng/searxng:latest
	}

	local docker_describe="注重隐私的元搜索引擎聚合平台, 不追踪用户"
	local docker_url="官网介绍: https://github.com/searxng/searxng"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# Pingvin-Share文件分享平台
pingvinshare_app(){
	local app_id="48"
	local docker_name="pingvin-share"
	local docker_img="stonith404/pingvin-share:latest"
	local docker_port=8104

	docker_run() {
		mkdir -p /home/docker/pingvin/data /home/docker/pingvin/images
		docker run -d \
			--name pingvin-share \
			--restart=always \
			-p ${docker_port}:3000 \
			-v /home/docker/pingvin/data:/app/data \
			-v /home/docker/pingvin/images:/app/backend/images \
			stonith404/pingvin-share:latest
	}

	local docker_describe="自托管文件分享平台, 支持创建分享链接和上传文件"
	local docker_url="官网介绍: https://github.com/stonith404/pingvin-share"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# Dockge容器堆栈管理面板
dockge_app(){
	local app_id="49"
	local docker_name="dockge"
	local docker_img="louislam/dockge:latest"
	local docker_port=8105

	docker_run() {
		mkdir -p /home/docker/dockge/stacks
		docker run -d \
			--name dockge \
			--restart=always \
			-p ${docker_port}:5001 \
			-v /var/run/docker.sock:/var/run/docker.sock \
			-v /home/docker/dockge/data:/app/data \
			-v /home/docker/dockge/stacks:/opt/stacks \
			louislam/dockge:latest
	}

	local docker_describe="简洁优雅的Docker Compose堆栈管理面板"
	local docker_url="官网介绍: https://github.com/louislam/dockge"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# it-tools工具箱
ittools_app(){
	local app_id="50"
	local docker_name="it-tools"
	local docker_img="corentintho/it-tools:latest"
	local docker_port=8106

	docker_run() {
		docker run -d \
			--name it-tools \
			--restart=always \
			-p ${docker_port}:80 \
			corentintho/it-tools:latest
	}

	local docker_describe="开发者常用工具集合, 包含JSON格式化/Base64编解码/UUID生成等数百个工具"
	local docker_url="官网介绍: https://github.com/CorentinTh/it-tools"
	local docker_use=""
	local docker_passwd=""
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
	}

	local docker_describe="开源的工作流自动化平台, 可视化连接各种API和服务"
	local docker_url="官网介绍: https://n8n.io/"
	local docker_use=""
	local docker_passwd=""
	local app_size="2"
	docker_app
}

# OpenWebUI自托管AI平台
openwebui_app(){
	local app_id="52"
	local docker_name="open-webui"
	local docker_img="ghcr.io/open-webui/open-webui:main"
	local docker_port=8108

	docker_run() {
		mkdir -p /home/docker/open-webui/data
		docker run -d \
			--name open-webui \
			--restart=always \
			-p ${docker_port}:8080 \
			-v /home/docker/open-webui/data:/app/backend/data \
			-e WEBUI_AUTH=true \
			ghcr.io/open-webui/open-webui:main
	}

	local docker_describe="自托管的AI对话界面, 支持Ollama/OpenAI等多种后端"
	local docker_url="官网介绍: https://github.com/open-webui/open-webui"
	local docker_use=""
	local docker_passwd=""
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
	local docker_name="gitea"
	local docker_img="gitea/gitea:latest"
	local docker_port=8110

	docker_run() {
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
	}

	local docker_describe="轻量级的自托管Git服务, 类似GitHub/GitLab"
	local docker_url="官网介绍: https://gitea.io/"
	local docker_use=""
	local docker_passwd=""
	local app_size="2"
	docker_app
}

# FileBrowser文件管理器
filebrowser_app(){
	local app_id="55"
	local docker_name="filebrowser"
	local docker_img="filebrowser/filebrowser:latest"
	local docker_port=8111

	docker_run() {
		mkdir -p /home/docker/filebrowser/database /home/docker/filebrowser/srv
		docker run -d \
			--name filebrowser \
			--restart=always \
			-p ${docker_port}:80 \
			-v /home/docker/filebrowser/database:/database \
			-v /home/docker/filebrowser/srv:/srv \
			filebrowser/filebrowser:latest
	}

	local docker_describe="轻量级的网页文件管理器, 支持文件上传/下载/编辑/分享"
	local docker_url="官网介绍: https://github.com/filebrowser/filebrowser"
	local docker_use="echo \"默认用户名: admin  密码: admin\""
	local docker_passwd="echo \"请在首次登录后修改密码\""
	local app_size="1"
	docker_app
}

# FRP内网穿透(服务端)
frp_server_app(){
	local app_id="56"
	local docker_name="frps"
	local docker_img="snowdreamtech/frps:latest"
	local docker_port=8112

	docker_run() {
		mkdir -p /home/docker/frps
		read -e -p "设置FRP服务端端口 (默认7000): " frp_port
		frp_port=${frp_port:-7000}
		read -e -p "设置Dashboard端口: " dash_port
		dash_port=${dash_port:-7500}
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
	}

	local docker_describe="FRP内网穿透服务端, 让内网服务暴露到公网"
	local docker_url="官网介绍: https://github.com/fatedier/frp"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# WireGuard组网(服务端)
wireguard_server_app(){
	local app_id="57"
	local docker_name="wg-easy"
	local docker_img="ghcr.io/wg-easy/wg-easy:latest"
	local docker_port=8113

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
	}

	local docker_describe="WireGuard VPN服务端, 简单易用的虚拟组网工具"
	local docker_url="官网介绍: https://github.com/wg-easy/wg-easy"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
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
	local docker_name="syncthing"
	local docker_img="syncthing/syncthing:latest"
	local docker_port=8116

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

	local docker_describe="开源的连续文件同步工具, 支持P2P多设备间文件同步"
	local docker_url="官网介绍: https://syncthing.net/"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# Umami网站统计工具
umami_app(){
	local app_id="61"
	local docker_name="umami"
	local docker_img="ghcr.io/umami-software/umami:postgresql-latest"
	local docker_port=8117

	docker_run() {
		mkdir -p /home/docker/umami/data
		docker run -d \
			--name umami \
			--restart=always \
			-p ${docker_port}:3000 \
			-e DATABASE_URL=postgresql://umami:umami_pwd@db:5432/umami \
			-e UMAMI_APP_SECRET="$(openssl rand -hex 32)" \
			umami/umami:postgresql-latest
	}

	local docker_describe="开源的网站分析统计工具, Google Analytics的隐私友好替代"
	local docker_url="官网介绍: https://umami.is/"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# 思源笔记
siyuan_app(){
	local app_id="62"
	local docker_name="siyuan"
	local docker_img="b3log/siyuan:latest"
	local docker_port=8118

	docker_run() {
		mkdir -p /home/docker/siyuan/workspace
		docker run -d \
			--name siyuan \
			--restart=always \
			-p ${docker_port}:6806 \
			-v /home/docker/siyuan/workspace:/siyuan/workspace \
			b3log/siyuan:latest
	}

	local docker_describe="本地优先的个人知识管理系统, 支持块级引用和双向链接"
	local docker_url="官网介绍: https://b3log.org/siyuan/"
	local docker_use=""
	local docker_passwd=""
	local app_size="2"
	docker_app
}

# SFTPGo文件传输工具
sftpgp_app(){
	local app_id="63"
	local docker_name="sftpgo"
	local docker_img="drakkan/sftpgo:latest"
	local docker_port=8119

	docker_run() {
		mkdir -p /home/docker/sftpgo/data /home/docker/sftpgo/config
		docker run -d \
			--name sftpgo \
			--restart=always \
			-p ${docker_port}:8080 \
			-p 2022:2022 \
			-v /home/docker/sftpgo/data:/srv/sftpgo \
			-v /home/docker/sftpgo/config:/etc/sftpgo \
			drakkan/sftpgo:latest
	}

	local docker_describe="功能齐全的SFTP/FTP/WebDAV服务器, 支持多种协议"
	local docker_url="官网介绍: https://github.com/drakkan/sftpgo"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# Owncast自托管直播平台
owncast_app(){
	local app_id="64"
	local docker_name="owncast"
	local docker_img="owncast/owncast:latest"
	local docker_port=8120

	docker_run() {
		mkdir -p /home/docker/owncast/data
		docker run -d \
			--name owncast \
			--restart=always \
			-p ${docker_port}:8080 \
			-p 1935:1935 \
			-v /home/docker/owncast/data:/app/data \
			owncast/owncast:latest
	}

	local docker_describe="自托管的视频直播平台, 支持RTMP推流和Web观看"
	local docker_url="官网介绍: https://owncast.online/"
	local docker_use=""
	local docker_passwd=""
	local app_size="2"
	docker_app
}

# Deepseek聊天AI大模型
deepseek_app(){
	local app_id="65"
	local docker_name="deepseek"
	local docker_img="deepseek-ai/deepseek-coder:6.7b-instruct-q4_0"
	local docker_port=8121

	docker_run() {
		docker run -d \
			--name deepseek \
			--restart=always \
			-p ${docker_port}:8000 \
			-v /home/docker/deepseek:/root/.ollama \
			deepseek-ai/deepseek-coder:6.7b-instruct-q4_0
	}

	local docker_describe="DeepSeek AI大模型本地部署, 支持代码生成和对话"
	local docker_url="官网介绍: https://github.com/deepseek-ai/DeepSeek-Coder"
	local docker_use=""
	local docker_passwd=""
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
	local docker_name="gopeed"
	local docker_img="liwei2633/gopeed:latest"
	local docker_port=8123

	docker_run() {
		mkdir -p /home/docker/gopeed
		docker run -d \
			--name gopeed \
			--restart=always \
			-p ${docker_port}:9999 \
			-v /home/docker/gopeed:/app/data \
			liwei2633/gopeed:latest
	}

	local docker_describe="高速下载工具, 支持HTTP/BitTorrent等协议"
	local docker_url="官网介绍: https://github.com/GoproxyFoss/gopeed"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# 2FAuth自托管二步验证器
twofauth_app(){
	local app_id="68"
	local docker_name="2fauth"
	local docker_img="2fauth/2fauth:latest"
	local docker_port=8124

	docker_run() {
		mkdir -p /home/docker/2fauth
		docker run -d \
			--name 2fauth \
			--restart=always \
			-p ${docker_port}:8000 \
			-v /home/docker/2fauth:/app/storage \
			-e APP_ENV=production \
			-e APP_KEY=base64:$(openssl rand -base64 32) \
			2fauth/2fauth:latest
	}

	local docker_describe="自托管的二步验证(2FA)管理器, 管理所有TOTP/HOTP令牌"
	local docker_url="官网介绍: https://docs.2fauth.app/"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# ZFile在线网盘
zfile_app(){
	local app_id="69"
	local docker_name="zfile"
	local docker_img="zhaojun1998/zfile:latest"
	local docker_port=8125

	docker_run() {
		mkdir -p /home/docker/zfile/data
		docker run -d \
			--name zfile \
			--restart=always \
			-p ${docker_port}:8080 \
			-v /home/docker/zfile/data:/data \
			zhaojun1998/zfile:latest
	}

	local docker_describe="开源的在线网盘系统, 支持多种存储策略"
	local docker_url="官网介绍: https://github.com/zhaojun1998/zfile"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# Nexterm远程连接
nexterm_app(){
	local app_id="70"
	local docker_name="nexterm"
	local docker_img="germannewsmaker/nexterm:latest"
	local docker_port=8126

	docker_run() {
		mkdir -p /home/docker/nexterm
		docker run -d \
			--name nexterm \
			--restart=always \
			-p ${docker_port}:6989 \
			-v /home/docker/nexterm:/app/data \
			germannewsmaker/nexterm:latest
	}

	local docker_describe="开源的远程连接管理工具, 支持SSH/VNC/RDP"
	local docker_url="官网介绍: https://github.com/gnmyt/Nexterm"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# JitsiMeet视频会议
jitsimeet_app(){
	local app_id="71"
	local docker_name="jitsi-meet"
	local docker_img="jitsi/web:latest"
	local docker_port=8127

	docker_run() {
		mkdir -p /home/docker/jitsi/{web,prosody,jicofo,jvb}
		docker run -d \
			--name jitsi-web \
			--restart=always \
			-p ${docker_port}:80 \
			-v /home/docker/jitsi/web:/config \
			-e ENABLE_LETSENCRYPT=0 \
			jitsi/web:latest
	}

	local docker_describe="开源的视频会议系统, 支持多人视频会议"
	local docker_url="官网介绍: https://jitsi.org/"
	local docker_use=""
	local docker_passwd=""
	local app_size="2"
	docker_app
}

# Stream四层代理转发
stream_app(){
	local app_id="72"
	local docker_name="stream"
	local docker_img="nginx:alpine"
	local docker_port=8128

	docker_run() {
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
	}

	local docker_describe="四层代理转发服务, 基于Nginx Stream模块"
	local docker_url="官网介绍: https://nginx.org/"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# FileCodeBox文件快递
filecodebox_app(){
	local app_id="73"
	local docker_name="filecodebox"
	local docker_img="lanol/filecodebox:latest"
	local docker_port=8129

	docker_run() {
		mkdir -p /home/docker/filecodebox
		docker run -d \
			--name filecodebox \
			--restart=always \
			-p ${docker_port}:12345 \
			-v /home/docker/filecodebox:/app/data \
			lanol/filecodebox:latest
	}

	local docker_describe="文件快递柜, 匿名口令分享文件"
	local docker_url="官网介绍: https://github.com/vastsa/FileCodeBox"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# Matrix去中心化聊天
matrix_app(){
	local app_id="74"
	local docker_name="matrix"
	local docker_img="matrixdotorg/synapse:latest"
	local docker_port=8130

	docker_run() {
		mkdir -p /home/docker/matrix/data
		docker run -d \
			--name matrix \
			--restart=always \
			-p ${docker_port}:8008 \
			-v /home/docker/matrix/data:/data \
			-e SYNAPSE_SERVER_NAME=matrix.local \
			-e SYNAPSE_REPORT_STATS=no \
			matrixdotorg/synapse:latest
	}

	local docker_describe="去中心化的即时通讯协议, 支持端到端加密"
	local docker_url="官网介绍: https://matrix.org/"
	local docker_use=""
	local docker_passwd=""
	local app_size="2"
	docker_app
}

# yt-dlp视频下载
ytdlp_app(){
	local app_id="75"
	local docker_name="yt-dlp"
	local docker_img="mikenye/yt-dlp:latest"
	local docker_port=8131

	docker_run() {
		mkdir -p /home/docker/ytdlp/downloads
		docker run -d \
			--name yt-dlp \
			--restart=always \
			-p ${docker_port}:8080 \
			-v /home/docker/ytdlp/downloads:/downloads \
			mikenye/yt-dlp:latest
	}

	local docker_describe="强大的视频下载工具, 支持YouTube等数百个网站"
	local docker_url="官网介绍: https://github.com/yt-dlp/yt-dlp"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# paperless文档管理
paperless_app(){
	local app_id="76"
	local docker_name="paperless"
	local docker_img="ghcr.io/paperless-ngx/paperless-ngx:latest"
	local docker_port=8132

	docker_run() {
		mkdir -p /home/docker/paperless/{data,media}
		docker run -d \
			--name paperless \
			--restart=always \
			-p ${docker_port}:8000 \
			-v /home/docker/paperless/data:/usr/src/paperless/data \
			-v /home/docker/paperless/media:/usr/src/paperless/media \
			-e PAPERLESS_REDIS=redis://localhost:6379 \
			ghcr.io/paperless-ngx/paperless-ngx:latest
	}

	local docker_describe="开源的文档管理系统, 支持OCR和全文搜索"
	local docker_url="官网介绍: https://docs.paperless-ngx.com/"
	local docker_use=""
	local docker_passwd=""
	local app_size="2"
	docker_app
}

# Wallos财务管理
wallos_app(){
	local app_id="77"
	local docker_name="wallos"
	local docker_img="bellamy/wallos:latest"
	local docker_port=8133

	docker_run() {
		mkdir -p /home/docker/wallos
		docker run -d \
			--name wallos \
			--restart=always \
			-p ${docker_port}:80 \
			-v /home/docker/wallos:/var/www/html \
			bellamy/wallos:latest
	}

	local docker_describe="开源的个人财务管理工具, 追踪订阅和支出"
	local docker_url="官网介绍: https://github.com/ellite/Wallos"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# komari服务器监控
komari_app(){
	local app_id="78"
	local docker_name="komari"
	local docker_img="komari-server:latest"
	local docker_port=8134

	docker_run() {
		mkdir -p /home/docker/komari
		docker run -d \
			--name komari \
			--restart=always \
			-p ${docker_port}:8080 \
			-v /home/docker/komari:/data \
			komari-server:latest
	}

	local docker_describe="轻量级服务器监控面板"
	local docker_url="官网介绍: https://github.com/komari-server"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# Dufs静态文件服务器
dufs_app(){
	local app_id="79"
	local docker_name="dufs"
	local docker_img="sigoden/dufs:latest"
	local docker_port=8135

	docker_run() {
		mkdir -p /home/docker/dufs/data
		docker run -d \
			--name dufs \
			--restart=always \
			-p ${docker_port}:5000 \
			-v /home/docker/dufs/data:/data \
			sigoden/dufs:latest /data
	}

	local docker_describe="简单的静态文件服务器, 支持上传下载"
	local docker_url="官网介绍: https://github.com/sigoden/dufs"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# PandaWiki文档管理
pandawiki_app(){
	local app_id="80"
	local docker_name="pandawiki"
	local docker_img="pandawiki/pandawiki:latest"
	local docker_port=8136

	docker_run() {
		mkdir -p /home/docker/pandawiki
		docker run -d \
			--name pandawiki \
			--restart=always \
			-p ${docker_port}:80 \
			-v /home/docker/pandawiki:/data \
			pandawiki/pandawiki:latest
	}

	local docker_describe="开源的Wiki文档管理系统"
	local docker_url="官网介绍: https://github.com/pandawiki"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# linkwarden书签管理
linkwarden_app(){
	local app_id="81"
	local docker_name="linkwarden"
	local docker_img="ghcr.io/linkwarden/linkwarden:latest"
	local docker_port=8137

	docker_run() {
		mkdir -p /home/docker/linkwarden
		docker run -d \
			--name linkwarden \
			--restart=always \
			-p ${docker_port}:3000 \
			-v /home/docker/linkwarden:/data \
			-e NEXTAUTH_SECRET=$(openssl rand -base64 32) \
			ghcr.io/linkwarden/linkwarden:latest
	}

	local docker_describe="开源的书签管理工具, 支持网页归档"
	local docker_url="官网介绍: https://github.com/linkwarden/linkwarden"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# VoceChat聊天系统
vocechat_app(){
	local app_id="82"
	local docker_name="vocechat"
	local docker_img="privoce/vocechat-server:latest"
	local docker_port=8138

	docker_run() {
		mkdir -p /home/docker/vocechat
		docker run -d \
			--name vocechat \
			--restart=always \
			-p ${docker_port}:3000 \
			-v /home/docker/vocechat:/home/vocechat-server/data \
			privoce/vocechat-server:latest
	}

	local docker_describe="开源的轻量级聊天系统, 支持自托管"
	local docker_url="官网介绍: https://voce.chat/"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# Karakeep书签管理
karakeep_app(){
	local app_id="83"
	local docker_name="karakeep"
	local docker_img="ghcr.io/karakeep-app/karakeep:latest"
	local docker_port=8139

	docker_run() {
		mkdir -p /home/docker/karakeep
		docker run -d \
			--name karakeep \
			--restart=always \
			-p ${docker_port}:3000 \
			-v /home/docker/karakeep:/data \
			ghcr.io/karakeep-app/karakeep:latest
	}

	local docker_describe="智能书签管理工具, 支持AI自动标签"
	local docker_url="官网介绍: https://github.com/karakeep-app/karakeep"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# NewAPI大模型资产管理
newapi_app(){
	local app_id="84"
	local docker_name="newapi"
	local docker_img="calciumion/new-api:latest"
	local docker_port=8140

	docker_run() {
		mkdir -p /home/docker/newapi
		docker run -d \
			--name newapi \
			--restart=always \
			-p ${docker_port}:3000 \
			-v /home/docker/newapi:/data \
			calciumion/new-api:latest
	}

	local docker_describe="大模型API管理和分发系统"
	local docker_url="官网介绍: https://github.com/Calcium-Ion/new-api"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# RAGFlow知识库
ragflow_app(){
	local app_id="85"
	local docker_name="ragflow"
	local docker_img="infiniflow/ragflow:latest"
	local docker_port=8141

	docker_run() {
		mkdir -p /home/docker/ragflow
		docker run -d \
			--name ragflow \
			--restart=always \
			-p ${docker_port}:80 \
			-v /home/docker/ragflow:/ragflow \
			infiniflow/ragflow:latest
	}

	local docker_describe="开源的RAG引擎, 构建企业知识库"
	local docker_url="官网介绍: https://github.com/infiniflow/ragflow"
	local docker_use=""
	local docker_passwd=""
	local app_size="3"
	docker_app
}

# AstrBot聊天机器人
astrbot_app(){
	local app_id="86"
	local docker_name="astrbot"
	local docker_img="soulter/astrbot:latest"
	local docker_port=8142

	docker_run() {
		mkdir -p /home/docker/astrbot
		docker run -d \
			--name astrbot \
			--restart=always \
			-p ${docker_port}:6185 \
			-v /home/docker/astrbot:/AstrBot/data \
			soulter/astrbot:latest
	}

	local docker_describe="多平台聊天机器人框架, 支持QQ/微信/飞书"
	local docker_url="官网介绍: https://github.com/Soulter/AstrBot"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# LangBot聊天机器人
langbot_app(){
	local app_id="87"
	local docker_name="langbot"
	local docker_img="rockchin/langbot:latest"
	local docker_port=8143

	docker_run() {
		mkdir -p /home/docker/langbot
		docker run -d \
			--name langbot \
			--restart=always \
			-p ${docker_port}:2280 \
			-v /home/docker/langbot:/app \
			rockchin/langbot:latest
	}

	local docker_describe="大模型原生即时通信机器人平台"
	local docker_url="官网介绍: https://github.com/RockChinQ/LangBot"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# 多格式文件转换
gotenberg_app(){
	local app_id="88"
	local docker_name="gotenberg"
	local docker_img="gotenberg/gotenberg:latest"
	local docker_port=8144

	docker_run() {
		docker run -d \
			--name gotenberg \
			--restart=always \
			-p ${docker_port}:3000 \
			gotenberg/gotenberg:latest
	}

	local docker_describe="开源的文档转换服务, 支持多种格式互转"
	local docker_url="官网介绍: https://github.com/gotenberg/gotenberg"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# LibreSpeed测速
librespeed_app(){
	local app_id="89"
	local docker_name="librespeed"
	local docker_img="adolfintel/speedtest:latest"
	local docker_port=8145

	docker_run() {
		docker run -d \
			--name librespeed \
			--restart=always \
			-p ${docker_port}:80 \
			adolfintel/speedtest:latest
	}

	local docker_describe="开源的网络测速工具, 类似Speedtest"
	local docker_url="官网介绍: https://github.com/librespeed/speedtest"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# gpt-load AI透明代理
gptload_app(){
	local app_id="90"
	local docker_name="gpt-load"
	local docker_img="ghcr.io/gpt-load/gpt-load:latest"
	local docker_port=8146

	docker_run() {
		mkdir -p /home/docker/gptload
		docker run -d \
			--name gpt-load \
			--restart=always \
			-p ${docker_port}:8080 \
			-v /home/docker/gptload:/data \
			ghcr.io/gpt-load/gpt-load:latest
	}

	local docker_describe="AI服务透明代理工具"
	local docker_url="官网介绍: https://github.com/gpt-load"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# 补货监控工具
stockmonitor_app(){
	local app_id="91"
	local docker_name="stockmonitor"
	local docker_img="stock-monitor:latest"
	local docker_port=8147

	docker_run() {
		mkdir -p /home/docker/stockmonitor
		docker run -d \
			--name stockmonitor \
			--restart=always \
			-p ${docker_port}:8080 \
			-v /home/docker/stockmonitor:/data \
			stock-monitor:latest
	}

	local docker_describe="商品库存监控和补货提醒工具"
	local docker_url="官网介绍: https://github.com/stock-monitor"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# PVE虚拟化管理
pve_app(){
	local app_id="92"
	local docker_name="pve"
	local docker_img="pve-manager:latest"
	local docker_port=8148

	docker_run() {
		mkdir -p /home/docker/pve
		docker run -d \
			--name pve \
			--restart=always \
			-p ${docker_port}:8006 \
			--privileged \
			-v /home/docker/pve:/data \
			pve-manager:latest
	}

	local docker_describe="Proxmox VE虚拟化管理平台"
	local docker_url="官网介绍: https://www.proxmox.com/"
	local docker_use=""
	local docker_passwd=""
	local app_size="3"
	docker_app
}

# DSM群晖虚拟机
dsm_app(){
	local app_id="93"
	local docker_name="dsm"
	local docker_img="kroese/virtual-dsm:latest"
	local docker_port=8149

	docker_run() {
		mkdir -p /home/docker/dsm
		docker run -d \
			--name dsm \
			--restart=always \
			-p ${docker_port}:5000 \
			--privileged \
			-v /home/docker/dsm:/storage \
			kroese/virtual-dsm:latest
	}

	local docker_describe="在Docker中运行群晖DSM系统"
	local docker_url="官网介绍: https://github.com/kroese/virtual-dsm"
	local docker_use=""
	local docker_passwd=""
	local app_size="3"
	docker_app
}

# 在线DOS老游戏
dosgame_app(){
	local app_id="94"
	local docker_name="dosgame"
	local docker_img="oldiy/dosgame-web-docker:latest"
	local docker_port=8150

	docker_run() {
		docker run -d \
			--name dosgame \
			--restart=always \
			-p ${docker_port}:262 \
			oldiy/dosgame-web-docker:latest
	}

	local docker_describe="在线DOS游戏合集, 怀旧经典游戏"
	local docker_url="官网介绍: https://github.com/rwv/dosgame"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# 迅雷离线下载
xunlei_app(){
	local app_id="95"
	local docker_name="xunlei"
	local docker_img="cnk3x/xunlei:latest"
	local docker_port=8151

	docker_run() {
		mkdir -p /home/docker/xunlei/downloads
		docker run -d \
			--name xunlei \
			--restart=always \
			-p ${docker_port}:2345 \
			-v /home/docker/xunlei:/xunlei \
			-v /home/docker/xunlei/downloads:/downloads \
			cnk3x/xunlei:latest
	}

	local docker_describe="迅雷离线下载服务, 支持远程下载"
	local docker_url="官网介绍: https://github.com/cnk3x/xunlei"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# 小雅Alist全家桶
xiaoya_app(){
	local app_id="96"
	local docker_name="xiaoya"
	local docker_img="xiaoyaliu/alist:latest"
	local docker_port=8152

	docker_run() {
		mkdir -p /home/docker/xiaoya
		docker run -d \
			--name xiaoya \
			--restart=always \
			-p ${docker_port}:5244 \
			-v /home/docker/xiaoya:/data \
			xiaoyaliu/alist:latest
	}

	local docker_describe="小雅Alist, 整合多网盘资源"
	local docker_url="官网介绍: https://github.com/xiaoyaliu/alist"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# Bililive直播录制
bililive_app(){
	local app_id="97"
	local docker_name="bililive"
	local docker_img="bililive/recorder:latest"
	local docker_port=8153

	docker_run() {
		mkdir -p /home/docker/bililive
		docker run -d \
			--name bililive \
			--restart=always \
			-p ${docker_port}:2356 \
			-v /home/docker/bililive:/rec \
			bililive/recorder:latest
	}

	local docker_describe="B站直播录制工具, 自动录制直播间"
	local docker_url="官网介绍: https://github.com/BililiveRecorder/BililiveRecorder"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# 极简朋友圈
moments_app(){
	local app_id="98"
	local docker_name="moments"
	local docker_img="moments-app:latest"
	local docker_port=8154

	docker_run() {
		mkdir -p /home/docker/moments
		docker run -d \
			--name moments \
			--restart=always \
			-p ${docker_port}:3000 \
			-v /home/docker/moments:/data \
			moments-app:latest
	}

	local docker_describe="极简风格的朋友圈/微博系统"
	local docker_url="官网介绍: https://github.com/moments-app"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# PanSou网盘搜索
pansou_app(){
	local app_id="99"
	local docker_name="pansou"
	local docker_img="pansou-search:latest"
	local docker_port=8155

	docker_run() {
		mkdir -p /home/docker/pansou
		docker run -d \
			--name pansou \
			--restart=always \
			-p ${docker_port}:8080 \
			-v /home/docker/pansou:/data \
			pansou-search:latest
	}

	local docker_describe="网盘资源搜索引擎"
	local docker_url="官网介绍: https://github.com/pansou"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# 简单图床lskypro
lskypro_app(){
	local app_id="100"
	local docker_name="lskypro"
	local docker_img="halcyonazure/lsky-pro-docker:latest"
	local docker_port=8156

	docker_run() {
		mkdir -p /home/docker/lskypro
		docker run -d \
			--name lskypro \
			--restart=always \
			-p ${docker_port}:8089 \
			-v /home/docker/lskypro:/var/www/html \
			halcyonazure/lsky-pro-docker:latest
	}

	local docker_describe="简单图床系统, 支持多存储策略"
	local docker_url="官网介绍: https://github.com/lsky-org/lsky-pro"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# 禅道项目管理
zentao_app(){
	local app_id="101"
	local docker_name="zentao"
	local docker_img="idoop/zentao:latest"
	local docker_port=8157

	docker_run() {
		mkdir -p /home/docker/zentao
		docker run -d \
			--name zentao \
			--restart=always \
			-p ${docker_port}:80 \
			-v /home/docker/zentao:/www/zentaopms \
			idoop/zentao:latest
	}

	local docker_describe="开源的项目管理软件, 支持敏捷开发"
	local docker_url="官网介绍: https://www.zentao.net/"
	local docker_use=""
	local docker_passwd=""
	local app_size="2"
	docker_app
}

# QD-Today定时任务
qdtoday_app(){
	local app_id="102"
	local docker_name="qdtoday"
	local docker_img="qdtoday/qd:latest"
	local docker_port=8158

	docker_run() {
		mkdir -p /home/docker/qdtoday
		docker run -d \
			--name qdtoday \
			--restart=always \
			-p ${docker_port}:80 \
			-v /home/docker/qdtoday:/usr/src/app \
			qdtoday/qd:latest
	}

	local docker_describe="HTTP请求定时任务框架, 自动签到"
	local docker_url="官网介绍: https://github.com/qd-today/qd"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# 耗子管理面板
haizi_app(){
	local app_id="103"
	local docker_name="haizi"
	local docker_img="haizi-panel:latest"
	local docker_port=8159

	docker_run() {
		mkdir -p /home/docker/haizi
		docker run -d \
			--name haizi \
			--restart=always \
			-p ${docker_port}:8080 \
			-v /home/docker/haizi:/data \
			haizi-panel:latest
	}

	local docker_describe="耗子管理面板, 轻量级服务器管理"
	local docker_url="官网介绍: https://github.com/haizi-panel"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# AMH建站面板
amh_app(){
	local app_id="104"
	local docker_name="amh"
	local docker_img="amh-panel:latest"
	local docker_port=8160

	docker_run() {
		mkdir -p /home/docker/amh
		docker run -d \
			--name amh \
			--restart=always \
			-p ${docker_port}:8888 \
			-v /home/docker/amh:/data \
			amh-panel:latest
	}

	local docker_describe="AMH云主机面板, 建站管理工具"
	local docker_url="官网介绍: https://amh.sh/"
	local docker_use=""
	local docker_passwd=""
	local app_size="2"
	docker_app
}

# 在线翻译服务器
libretranslate_app(){
	local app_id="105"
	local docker_name="libretranslate"
	local docker_img="libretranslate/libretranslate:latest"
	local docker_port=8161

	docker_run() {
		docker run -d \
			--name libretranslate \
			--restart=always \
			-p ${docker_port}:5000 \
			libretranslate/libretranslate:latest
	}

	local docker_describe="开源的神经网络翻译API服务"
	local docker_url="官网介绍: https://github.com/LibreTranslate/LibreTranslate"
	local docker_use=""
	local docker_passwd=""
	local app_size="2"
	docker_app
}

# AI视频生成工具
videogen_app(){
	local app_id="106"
	local docker_name="videogen"
	local docker_img="videogen-ai:latest"
	local docker_port=8162

	docker_run() {
		mkdir -p /home/docker/videogen
		docker run -d \
			--name videogen \
			--restart=always \
			-p ${docker_port}:8080 \
			-v /home/docker/videogen:/data \
			--gpus all \
			videogen-ai:latest
	}

	local docker_describe="AI视频生成工具, 文本生成视频"
	local docker_url="官网介绍: https://github.com/videogen-ai"
	local docker_use=""
	local docker_passwd=""
	local app_size="3"
	docker_app
}

# RustDesk远程桌面
rustdesk_server_app(){
	local app_id="107"
	local docker_name="rustdesk-server"
	local docker_img="rustdesk/rustdesk-server:latest"
	local docker_port=8163

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

	local docker_describe="开源的远程桌面软件服务端"
	local docker_url="官网介绍: https://github.com/rustdesk/rustdesk"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# Firefox浏览器
firefox_app(){
	local app_id="108"
	local docker_name="firefox"
	local docker_img="jlesage/firefox:latest"
	local docker_port=8164

	docker_run() {
		mkdir -p /home/docker/firefox
		docker run -d \
			--name firefox \
			--restart=always \
			-p ${docker_port}:5800 \
			-v /home/docker/firefox:/config \
			jlesage/firefox:latest
	}

	local docker_describe="在浏览器中运行的Firefox浏览器"
	local docker_url="官网介绍: https://github.com/jlesage/docker-firefox"
	local docker_use=""
	local docker_passwd=""
	local app_size="2"
	docker_app
}

# DPanel容器管理
dpanel_app(){
	local app_id="109"
	local docker_name="dpanel"
	local docker_img="dpanel/dpanel:latest"
	local docker_port=8165

	docker_run() {
		mkdir -p /home/docker/dpanel
		docker run -d \
			--name dpanel \
			--restart=always \
			-p ${docker_port}:8080 \
			-v /var/run/docker.sock:/var/run/docker.sock \
			-v /home/docker/dpanel:/dpanel \
			dpanel/dpanel:latest
	}

	local docker_describe="Docker容器可视化管理面板"
	local docker_url="官网介绍: https://github.com/dpanel-io/dpanel"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# 普罗米修斯监控
prometheus_app(){
	local app_id="110"
	local docker_name="prometheus"
	local docker_img="prom/prometheus:latest"
	local docker_port=8166

	docker_run() {
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
	}

	local docker_describe="开源的系统监控和报警工具"
	local docker_url="官网介绍: https://prometheus.io/"
	local docker_use=""
	local docker_passwd=""
	local app_size="2"
	docker_app
}
# Phase 2/4: 公共 Docker 安装后处理函数
docker_app_post_install() {
    local docker_name=$1
    local docker_port=$2
    local docker_use=$3
    local docker_passwd=$4

    if docker ps -a --format '{{.Names}}' | grep -q "^${docker_name}$"; then
        setup_docker_dir
        echo "$docker_port" > "/home/docker/${docker_name}_port.conf"

        mkdir -p /home/docker && touch /home/docker/appno.txt && (add_app_id)

        clear
        echo "$docker_name 已安装完成"
        echo "访问端口: $docker_port"
        check_docker_app_ip
        echo ""
        $docker_use
        $docker_passwd
    else
        echo "安装失败，请检查 Docker 运行状态"
    fi
}

# Phase 6.2: 公共端口输入函数（带校验）
read_docker_port() {
    local default_port=${1:-8080}
    while true; do
        read -e -p "输入应用对外服务端口 (1-65535): " port
        port=${port:-$default_port}
        if [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]; then
            echo "$port"
            return 0
        else
            echo -e "${red}端口无效，请输入 1-65535 之间的数字${white}"
        fi
    done
}


# Phase 6.2: Docker 应用菜单显示
show_docker_app_menu() {
    echo ""
    echo -e "${cyan}------------------------------------------------------${white}"

    if check_docker_app; then
        echo -e "${green}1. 更新${white}              ${red}2. 卸载${white}"
    else
        echo -e "${green}1. 安装${white}"
    fi

    echo -e "${pink}------------------------------------------------------${white}"

    if check_docker_app; then
        echo -e "5. 添加域名访问      6. 删除域名访问"
        echo -e "7. 允许IP+端口访问   8. 阻止IP+端口访问"
        echo -e "${pink}------------------------------------------------------${white}"
    fi

    echo -e "${yellow}0. 返回上一级菜单${white}"
    echo -e "${pink}------------------------------------------------------${white}"
}
