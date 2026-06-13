#############################################################################
########################### 四、Docker管理模块 ###############################
## 1. Docker容器管理
docker_ps() {
while true; do
	clear
	echo -e "${green}Docker容器列表${white}"
	docker ps -a --format "table {{.ID}}\t{{.Names}}\t{{.Status}}\t{{.Ports}}"
	echo ""
	echo -e "${yellow}容器操作${white}"
	echo -e "${pink}-------------------------------------------${white}"
	echo "1. 创建新的容器"
	echo -e "${pink}-------------------------------------------${white}"
	echo -e "${cyan}2.${white}  启动指定容器            ${cyan}6.${white} 启动所有容器"
	echo -e "${cyan}3.${white}  停止指定容器            ${cyan}7.${white} 停止所有容器"
	echo -e "${cyan}4.${white}  删除指定容器            ${cyan}8.${white} 删除所有容器"
	echo -e "${cyan}5.${white}  重启指定容器            ${cyan}9.${white} 重启所有容器"
	echo -e "${pink}-------------------------------------------${white}"
	echo -e "${cyan}11.${white} 进入指定容器           ${cyan}12.${white} 查看容器日志"
	echo -e "${cyan}13.${white} 查看容器网络           ${cyan}14.${white} 查看容器占用"
	echo -e "${pink}-------------------------------------------${white}"
	echo -e "${cyan}15.${white} 开启容器端口访问       ${cyan}16.${white} 关闭容器端口访问"
	echo -e "${pink}-------------------------------------------${white}"
	echo -e "${yellow}0.${white} 返回上一级菜单"
	echo -e "${pink}-------------------------------------------${white}"
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
				echo -e "${red}无效选择, 请重新输入 !${white}"
				sleep 1
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
		0)
			break ;;
		*)
			echo -e "${red}请输入正确的选项! ${white}"
			;;
	esac
done
}

## 2. Docker镜像管理
docker_image() {
while true; do
	clear
	## "Docker镜像管理"
	echo -e "${green}Docker镜像列表${white}"
	docker image ls
	echo ""
	echo -e "${yellow}镜像操作${white}"
	echo -e "${pink}-------------------------------------------${white}"
	echo -e "${cyan}1.${white} 获取指定镜像            ${cyan}3.${white} 删除指定镜像"
	echo -e "${cyan}2.${white} 更新指定镜像            ${cyan}4.${white} 删除所有镜像"
	echo -e "${pink}-------------------------------------------${white}"
	echo -e "${yellow}0.${white} 返回上一级菜单"
	echo -e "${pink}-------------------------------------------${white}"
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
				echo -e "${red}无效选择, 请输入Y或N !${white}"
				;;
			esac
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

## 3. 打开Docker IPv6
docker_ipv6_on() {
	root_use || return 1
	install jq

	local CONFIG_FILE="/etc/docker/daemon.json"
	local REQUIred_IPV6_CONFIG='{"ipv6": true, "fixed-cidr-v6": "2001:db8:1::/64"}'

	# 检查配置文件是否存在, 如果不存在则创建文件并写入默认设置
	if [ ! -f "$CONFIG_FILE" ]; then
		echo "$REQUIred_IPV6_CONFIG" | jq . > "$CONFIG_FILE"
		restart docker
	else
		# 使用jq处理配置文件的更新
		local ORIGINAL_CONFIG=$(<"$CONFIG_FILE")

		# 检查当前配置是否已经有 ipv6 设置
		local CURRENT_IPV6=$(echo "$ORIGINAL_CONFIG" | jq '.ipv6 // false')

		# 更新配置, 开启 IPv6
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
	root_use || return 1
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
        # Safe merge to daemon.json
        mkdir -p /etc/docker
        if [ ! -f /etc/docker/daemon.json ]; then
            echo '{}' > /etc/docker/daemon.json
        fi
        local tmp_json=$(mktemp)
        # Use jq to merge the mirrors list safely without wiping out other settings
        jq '. + {"registry-mirrors": ["https://docker.mirrors.ustc.edu.cn", "https://hub-mirror.c.163.com", "https://mirror.baidubce.com"]}' /etc/docker/daemon.json > "$tmp_json"
        mv "$tmp_json" /etc/docker/daemon.json
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
    
    # 统一处理依赖（以 Debian/Ubuntu 为例, 其他系统需适配）
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
        echo -e "${yellow}Docker 已安装, 跳过安装流程${white}"
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
            echo -e "${red}无效的选择, 请输入 Y 或 N${white}"
            ;;
    esac
}

# 10. Docker管理界面
linux_docker() {

	while true; do
		clear
		check_docker || return
		echo -e "${green}===== Docker管理菜单 =====${white}"
		docker_tato
		echo -e "${pink}---------------------------------------------${white}"
		echo -e "${cyan}1.  ${white}安装更新Docker环境 ${yellow}★${white}"
		echo -e "${pink}---------------------------------------------${white}"
		echo -e "${cyan}2.  ${white}查看Docker全局状态 ${yellow}★${white}"
		echo -e "${pink}---------------------------------------------${white}"
		echo -e "${cyan}3.  ${white}Docker容器管理 ${yellow}★${white}"
		echo -e "${cyan}4.  ${white}Docker镜像管理"
		echo -e "${cyan}5.  ${white}Docker网络管理"
		echo -e "${cyan}6.  ${white}Docker卷管理"
		echo -e "${pink}---------------------------------------------${white}"
		echo -e "${cyan}7.  ${white}清理无用的docker容器和镜像网络数据卷"
		echo -e "${pink}---------------------------------------------${white}"
		echo -e "${cyan}8.  ${white}更换Docker源"
		echo -e "${cyan}9.  ${white}编辑daemon.json文件"
		echo -e "${pink}---------------------------------------------${white}"
		echo -e "${cyan}11. ${white}开启Docker-ipv6访问"
		echo -e "${cyan}12. ${white}关闭Docker-ipv6访问"
		echo -e "${pink}---------------------------------------------${white}"
		echo -e "${cyan}20. ${white}卸载Docker环境"
		echo -e "${pink}---------------------------------------------${white}"
		echo -e "${yellow}0.  ${white}返回主菜单"
		echo -e "${pink}---------------------------------------------${white}"
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
					echo -e "${green}Docker网络列表${white}"
					echo -e "${pink}------------------------------------------------------------${white}"
					docker network ls
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
					echo -e "${yellow}网络操作${white}"
					echo -e "${pink}------------------------${white}"
					echo -e "${cyan}1.${white} 创建网络"
					echo -e "${cyan}2.${white} 加入网络"
					echo -e "${cyan}3.${white} 退出网络"
					echo -e "${cyan}4.${white} 删除网络"
					echo -e "${pink}------------------------${white}"
					echo -e "${yellow}0.${white} 返回上一级菜单"
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

						0)
							break # 返回上一级菜单
							;;
						*)
							echo -e "${red}无效选择, 请重新输入 !${white}"
							sleep 1
							;;
					esac
				done
				;;

			6)
				while true; do
					clear
					## "Docker卷管理"
					echo -e "${green}Docker卷列表${white}"
					docker volume ls
					echo ""
					echo -e "${yellow}卷操作${white}"
					echo -e "${pink}------------------------${white}"
					echo -e "${cyan}1.${white} 创建新卷"
					echo -e "${cyan}2.${white} 删除指定卷"
					echo -e "${cyan}3.${white} 删除所有卷"
					echo -e "${pink}------------------------${white}"
					echo -e "${yellow}0.${white} 返回上一级菜单"
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
								echo "无效的选择, 请输入 Y 或 N."
								;;
							esac
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
				;;
			7)
				clear
				## "Docker清理"
				read -e -p "$(echo -e "${yellow}提示: ${white}将清理无用的镜像容器网络, 包括停止的容器, 确定清理吗？(Y/N): ")" choice
				case "$choice" in
				[Yy])
					docker system prune -af --volumes
					;;
				[Nn])
					;;
				*)
					echo "无效的选择, 请输入 Y 或 N."
					sleep 1
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
				install vim
				mkdir -p /etc/docker && sudo vim /etc/docker/daemon.json
				sudo systemctl restart docker
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
				return
				;;
			*)
				echo -e "${red}无效选择, 请重新输入 !${white}"
				sleep 1
				;;
		esac
	done
}
