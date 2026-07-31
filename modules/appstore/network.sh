#!/usr/bin/env bash
# LinuxBox AppStore Category: network

# [9] Poste.io邮件服务器程序
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
				if ! check_watchtower_installed; then
					echo -e "${red}未安装 Watchtower，请先安装${white}"
					sleep 1.5
				else
					run_watchtower_update "mailserver"
					yuming=$(cat /home/docker/mail.txt 2>/dev/null || echo "")
					add_app_id
					clear
					echo "poste.io已经更新完成"
					echo -e "${pink}------------------------${white}"
					echo "您可以使用以下地址访问poste.io:"
					echo "https://$yuming"
					echo ""
				fi
				;;
			3)
				docker rm -f mailserver
				docker rmi -f analogic/poste.io
				rm /home/docker/mail.txt
				rm -rf /home/docker/mail

				remove_app_id
				echo "应用已卸载"
				;;

			*)
				break
				;;
		esac
		break_end
	done
}

# [22] ghproxy(GitHub加速站)
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

# [24] DDNS-GO
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

# [25] Lucky
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

# [41] AdGuardHome去广告
adguardhome_app(){
	local app_id="41"
	local app_name="AdGuardHome去广告"
	local docker_name="adguardhome"
	local docker_img="adguard/adguardhome:latest"
	docker_run() {
		mkdir -p /home/docker/adguardhome/work /home/docker/adguardhome/conf
		# 让用户输入 Web管理界面 端口 (默认 3000)
		read -e -p "设置Web管理界面端口 (默认3000): " web_port
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

		# Web面板端口
		add_app_port "Web管理界面" "$web_port"
		# 其他 DNS/DHCP 端口保持硬编码 (暂不改)
		add_app_port "DNS端口 (TCP+UDP)" 53
		add_app_port "DHCP客户端" 67
		add_app_port "DHCP服务端" 68
		add_app_port "DNS-over-HTTPS" 443
		add_app_port "DNS-over-TLS" 853
	}

	local app_text="全网广告拦截与隐私保护DNS服务, 支持DNS-over-HTTPS/TLS"
	local app_url="官网介绍: https://adguard.com/adguard-home/overview.html"
	local app_size="1"
	docker_app
}

# [56] FRP内网穿透(服务端)
frp_server_app(){
	local app_id="56"
	local app_name="FRP内网穿透(服务端)"
	local docker_name="frps"
	local docker_img="snowdreamtech/frps:latest"
	local app_text="FRP内网穿透服务端, 让内网服务暴露到公网"
	local app_url="官网介绍: https://github.com/fatedier/frp"
	local app_size="1"

	docker_run() {
		mkdir -p /home/docker/frps

		# 1. 收集面板与服务端口
		read -e -p "设置FRP面板端口 (默认7500): " dash_port
		dash_port=${dash_port:-7500}

		read -e -p "设置FRP服务端口 (默认7000): " frp_port
		frp_port=${frp_port:-7000}

		# 2. 收集客户端连接的认证 Token
        read -e -p "设置FRP客户端连接认证Token(通信密码, 默认12345678): " auth_token
        auth_token=${auth_token:-12345678}

		# 3. 收集面板密码
		read -e -p "设置Dashboard密码: " dash_pwd

		# 4. 生成 frps.toml 配置文件
		cat > /home/docker/frps/frps.toml << EOF
bindPort = $frp_port

webServer.addr = "0.0.0.0"
webServer.port = $dash_port
webServer.user = "admin"
webServer.password = "$dash_pwd"

# 开启 Token 认证保护服务端
auth.method = "token"
auth.token = "$auth_token"
EOF

		docker run -d \
			--name frps \
			--restart=always \
			--network host \
			-v /home/docker/frps/frps.toml:/etc/frp/frps.toml \
			snowdreamtech/frps:latest
		
		# Dashboard端口
		add_app_port "Dashboard访问地址" "$dash_port"
		# Server端口
		add_app_port "Server访问地址" "$frp_port"
	}

	docker_app
}

# [57] WireGuard组网(服务端)
wireguard_server_app(){
	local app_id="57"
	local app_name="WireGuard组网(服务端)"
	local docker_name="wg-easy"
	local docker_img="ghcr.io/wg-easy/wg-easy:latest"
	local app_text="WireGuard VPN服务端, 简单易用的虚拟组网工具"
	local app_url="官网介绍: https://github.com/wg-easy/wg-easy"
	local app_size="1"

	docker_run() {
		mkdir -p /home/docker/wireguard
		read -e -p "设置面板端口 (默认8113): " dash_port
		dash_port=${dash_port:-8113}
		read -e -p "设置WireGuard端口 (默认51820): " wg_udp_port
		wg_udp_port=${wg_udp_port:-51820}
		read -e -p "设置管理面板密码: " wg_pwd

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


		# Web 管理面板端口
		add_app_port "Web管理面板" "$dash_port"
		# WireGuard UDP端口
		add_app_port "WireGuard端口 (UDP)" "$wg_udp_port"
	}

	docker_app
}

# [66] RocketChat聊天系统
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
		run_watchtower_update "$docker_name"
	}

	docker_app_uninstall() {
		cd /home/docker/rocketchat && docker compose down --rmi all -v
		rm -rf /home/docker/rocketchat
		echo "RocketChat 已卸载"
	}

	docker_app
}

# [71] JitsiMeet视频会议
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

# [72] Stream四层代理转发
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

# [74] Matrix去中心化聊天
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

# [82] VoceChat聊天系统
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

# [91] TG下载归档Bot
tg_download_bot_app(){
	local app_id="91"
	local app_name="TG下载归档Bot"
	local app_text="Telegram 消息/媒体归档 Bot，支持频道历史消息、单条消息与评论区下载归档"
	local app_url="官网介绍: https://github.com/666zhaobo666/TG_dowload_bot"
	local install_script="/tmp/TG_dowload.sh"
	local service_name="tg-download-bot"

	check_tg_download_bot() {
		if command -v tgd >/dev/null 2>&1 || systemctl list-unit-files 2>/dev/null | grep -q "^${service_name}\\.service"; then
			check_panel="${green}已安装${white}"
		else
			check_panel="${white}未安装${white}"
		fi
	}

	tg_download_bot_install() {
		install curl
		install wget
		install sudo
		install git
		install python3
		install python3-venv

		rm -f "${install_script}"
		if [ "$country" = "CN" ]; then
			curl -fsSL "https://proxy.cccg.top/raw.githubusercontent.com/666zhaobo666/TG_dowload_bot/master/TG_dowload.sh" -o "${install_script}"
		else
			curl -fsSL "https://raw.githubusercontent.com/666zhaobo666/TG_dowload_bot/master/TG_dowload.sh" -o "${install_script}"
		fi
		chmod +x "${install_script}"
		bash "${install_script}"
	}

	tg_download_bot_manage() {
		if command -v tgd >/dev/null 2>&1; then
			tgd
		elif [ -x /usr/local/bin/tgd ]; then
			/usr/local/bin/tgd
		else
			echo -e "${red}未找到 tgd 管理命令，请先重新安装应用${white}"
		fi
	}

	tg_download_bot_uninstall() {
		if command -v tgd >/dev/null 2>&1; then
			tgd
		elif [ -x /usr/local/bin/tgd ]; then
			/usr/local/bin/tgd
		elif systemctl list-unit-files 2>/dev/null | grep -q "^${service_name}\\.service"; then
			systemctl disable --now ${service_name}.service >/dev/null 2>&1 || true
			rm -f /etc/systemd/system/${service_name}.service
			rm -f /etc/${service_name}.conf
			rm -f /usr/local/bin/tgd
			systemctl daemon-reload >/dev/null 2>&1 || true
			echo -e "${yellow}已移除 systemd 服务和 tgd 命令，如需彻底删除数据目录，请按 /etc/${service_name}.conf 中 INSTALL_DIR 手动清理${white}"
		else
			echo -e "${yellow}未检测到 TG下载归档Bot 安装${white}"
		fi
	}

	while true; do
		clear
		check_tg_download_bot
		echo -e "$app_name $check_panel"
		echo "$app_text"
		echo "$app_url"
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
				tg_download_bot_install
				check_tg_download_bot
				if [ "$check_panel" = "${green}已安装${white}" ]; then
					add_app_id
				fi
				;;
			2)
				check_tg_download_bot
				if [ "$check_panel" = "${green}已安装${white}" ]; then
					tg_download_bot_manage
					add_app_id
				else
					echo -e "${red}应用未安装，请先安装${white}"
					sleep 1
				fi
				;;
			3)
				tg_download_bot_uninstall
				check_tg_download_bot
				if [ "$check_panel" != "${green}已安装${white}" ]; then
					remove_app_id
				fi
				;;
			*)
				break
				;;
		esac
		break_end
	done
}

# [98] 极简朋友圈
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

# [107] RustDesk远程桌面
rustdesk_server_app(){
	local app_id="107"
	local app_name="RustDesk远程桌面"
	local docker_name="rustdesk-server"
	local docker_img="rustdesk/rustdesk-server:latest"
	local app_text="开源的远程桌面软件服务端"
	local app_url="官网介绍: https://github.com/rustdesk/rustdesk"
	local app_size="1"

	docker_run() {
		mkdir -p /home/docker/rustdesk-server
		# 让用户输入 Web 客户端/API 端口 (默认 8163)
		read -e -p "设置Web客户端/API端口 (默认8163): " web_port
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

		# Web面板端口
		add_app_port "Web客户端/API" "$web_port"
		# TCP/UDP 服务端口保持硬编码 (暂不改)
		add_app_port "中继服务 (TCP)" 21115
		add_app_port "中继服务 (TCP+UDP)" 21116
		add_app_port "心跳服务" 21117
		add_app_port "服务端口" 21118
	}

	docker_app
}

