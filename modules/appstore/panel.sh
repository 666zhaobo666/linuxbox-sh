#!/usr/bin/env bash
# LinuxBox AppStore Category: panel

# [1] 1Panel面板
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

# [2] 宝塔面板
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

# [3] aaPanel面板
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

# [4] NginxProxyManager面板
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

# [5] OpenList面板
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

			# 可选: 挂载本机目录到容器 /mnt, 供 OpenList 本地存储驱动读取 (留空跳过)
			local _mount_opt=""
			read -e -p "挂载本机目录到容器 /mnt (可选, 留空跳过, 填绝对路径如 /opt/downloads): " _host_path
			if [ -n "$_host_path" ]; then
				if [ "${_host_path:0:1}" = "/" ]; then
					_mount_opt="-v ${_host_path}:/mnt"
				else
					echo -e "${red}路径不是绝对路径, 已跳过该挂载${white}"
				fi
			fi

			docker run -d \
				--restart=always \
				-v /home/docker/openlist:/opt/openlist/data \
				$_mount_opt \
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

		# 安装/更新后: 从容器日志提取 OpenList 首次启动生成的初始管理员账号密码并打印.
		# OpenList 仅在首次创建 admin 时于日志(stdout)打印一次密码, 之后仅存哈希, 无法反查.
		app_post_install() {
			local _log _pwd
			echo -e "${cyan}正在获取 OpenList 初始管理员账号信息...${white}"
			for _ in $(seq 1 30); do
				_log=$(docker logs "$docker_name" 2>&1)
				_pwd=$(printf '%s\n' "$_log" | tr -d '\r' | grep "initial password is:" | tail -1 | awk '{print $NF}')
				if [ -n "$_pwd" ] || printf '%s\n' "$_log" | grep -q "start HTTP server"; then
					break
				fi
				# 容器已退出(启动失败)则不再等待
				if [ "$(docker inspect -f '{{.State.Running}}' "$docker_name" 2>/dev/null)" = "false" ]; then
					break
				fi
				sleep 1
			done

			echo ""
			if [ -n "$_pwd" ]; then
				echo -e "${green}OpenList 初始管理员账号:${white}"
				echo -e "  ${cyan}用户名${white}: admin"
				echo -e "  ${cyan}密码${white}:   ${_pwd}"
				echo ""
				echo -e "${yellow}密码仅在首次启动时显示一次, 请立即登录并在面板中修改!${white}"
			else
				echo -e "${yellow}本次未打印初始密码 (仅首次安装会显示, 升级/重装保留数据时不会再次出现).${white}"
				echo -e "${yellow}如忘记密码可随机重置: docker exec $docker_name openlist admin random${white}"
				echo -e "${yellow}或手动查看日志: docker logs $docker_name${white}"
			fi
			echo ""
		}

		local app_text="一个支持多种存储, 支持网页浏览和 WebDAV 的文件列表程序, 由 gin 和 Solidjs 驱动"
		local app_url="官网介绍: https://github.com/OpenListTeam/OpenList"
		local app_size="1"

		docker_app
}

# [10] 青龙面板
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

# [12] Looking Glass(测速面板)
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

# [13] 雷池WAF防火墙面板
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

				remove_app_id
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

# [18] Sun-Panel导航面板
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

# [31] X-UI面板
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

# [32] 3X-UI面板
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

# [45] Speedtest测速面板
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

# [49] Dockge容器管理
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

# [58] JumpServer堡垒机
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

	docker_app
}

# [103] 耗子管理面板
haizi_panel_app() {
	app_unavailable "耗子管理面板" "该应用镜像已失效或停止维护，现已下线"
}

# [104] AMH建站面板
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

# [109] DPanel容器管理
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

