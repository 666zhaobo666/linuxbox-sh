#!/usr/bin/env bash
# LinuxBox AppStore Category: tools

# [6] WebTop远程桌面网页版
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

# [7] Komari监控
komari_app(){
	clear
	local app_id="7"
	local app_name="Komari监控"
	local docker_name="komari"
	local docker_img="ghcr.io/komari-monitor/komari:latest"
	local docker_port=25774
	local app_text="Komari - 轻量自托管的服务器监控与告警平台"
	local app_url="官网介绍: https://github.com/komari-monitor/komari"

	# 探活: 容器是否存在
	check_komari_installed() {
		if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q "^${docker_name}$"; then
			return 0
		else
			return 1
		fi
	}

	# 解析容器对外端口 (宿主机侧)
	get_komari_port() {
		docker port $docker_name 2>/dev/null | awk -F'[:]' '/->/ {print $NF}' | uniq
	}

	while true; do
		local _state _hp _user_port choice
		clear
		# 顶部状态
		if check_komari_installed; then
			_state=$(docker inspect -f '{{.State.Status}}' $docker_name 2>/dev/null || echo "unknown")
			if [ "$_state" = "running" ]; then
				echo -e "Komari监控  状态: ${green}已安装 (运行中)${white}"
			else
				echo -e "Komari监控  状态: ${yellow}已安装 (${_state})${white}"
			fi
			# 显示访问地址
			_hp=$(get_komari_port)
			if [ -n "$_hp" ]; then
				ip_address
				echo -e "${cyan}面板访问${white}: ${green}http://${ipv4_address}:${_hp}${white}"
			fi
		else
			echo -e "Komari监控  状态: ${grey}未安装${white}"
		fi
		echo "${app_text}"
		echo "${app_url}"
		echo ""

		# 菜单
		echo -e "${pink}------------------------${white}"
		echo "1. 安装           2. 卸载           3. 帮助"
		echo -e "${pink}------------------------${white}"
		echo -e "${yellow}0.     ${white}返回上一级菜单"
		echo -e "${pink}------------------------${white}"
		read -e -p "输入你的选择: " choice

		case $choice in
			1)  # 安装
				if check_komari_installed; then
					echo -e "${yellow}已经安装过, 无需重复安装${white}"
					break_end
					continue
				fi
				read -e -p "服务端口 (默认 25774): " _user_port
				_user_port=${_user_port:-25774}
				docker_port=$_user_port

				mkdir -p /home/docker/komari
				docker run -d \
					--name komari \
					--restart=unless-stopped \
					-v /home/docker/komari:/app/data \
					-p ${docker_port}:25774 \
					ghcr.io/komari-monitor/komari:latest
				add_app_id
				clear
				echo "Komari 已安装完成"
				echo "可在状态栏查看访问地址"
				break_end
				;;
			2)  # 卸载
				docker rm -f $docker_name 2>/dev/null
				docker rmi -f $docker_img 2>/dev/null
				rm -rf /home/docker/komari
				remove_app_id
				clear
				echo "Komari 已卸载"
				break_end
				;;
			3)  # 帮助
				clear
				echo -e "${cyan}============ Komari 帮助 ============${white}"
				echo ""
				echo -e "${green}[1] 查看初始登录信息${white}"
				echo "    容器启动后, 用以下命令查看初始账号/密码:"
				echo ""
				echo "      docker logs komari"
				echo ""
				echo -e "${green}[2] 卸载 Agent (在被控端机器上执行)${white}"
				echo "    当你在面板端添加好一台被控服务器, 它会以 systemd 服务方式运行"
				echo "    Agent (komari-agent), 如需在客户端上彻底卸载, 执行以下命令:"
				echo ""
				echo "      sudo systemctl stop komari-agent && \\"
				echo "      sudo systemctl disable komari-agent && \\"
				echo "      sudo rm -f /etc/systemd/system/komari-agent.service && \\"
				echo "      sudo systemctl daemon-reload && \\"
				echo "      sudo rm -rf /opt/komari/agent /var/log/komari"
				echo ""
				echo -e "${pink}------------------------${white}"
				read -n 1 -s -r -p "按任意键返回..."
				;;
			*)
				break
				;;
		esac
	done
}

# [11] Code-Server(网页vscode)
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

# [14] onlyoffice在线办公OFFICE
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

# [15] UptimeKuma监控工具
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

# [16] Memos网页备忘录
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

# [17] drawio免费的在线图表软件
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

# [19] webssh网页版SSH连接工具
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

# [21] MyIP工具箱
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

# [23] AllinSSL证书管理平台
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

# [29] Beszel服务器监控
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

# [33] Microsoft 365 E5 Renew X
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

# [35] Drawnix在线白板
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

# [36] Portainer容器管理
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

# [43] Vaultwarden密码管理
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

# [44] StirlingPDF工具大全
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

# [47] searxng聚合搜索
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

# [50] it-tools工具箱
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

# [51] n8n自动化工作流
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

# [54] gitea私有代码仓库
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

# [61] Umami网站统计
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

# [62] 思源笔记
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

# [68] 2FAuth二步验证器
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

# [70] Nexterm远程连接
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

# [76] paperless文档管理
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

# [77] Wallos财务管理
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

# [80] PandaWiki文档管理
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

# [81] linkwarden书签管理
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

# [83] Karakeep书签管理
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

# [88] 多格式文件转换
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

# [89] LibreSpeed测速
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

# [92] PVE虚拟化管理
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

# [93] DSM群晖虚拟机
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

# [100] 简单图床lskypro
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

# [101] 禅道项目管理
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

# [102] QD-Today定时任务
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

# [105] 在线翻译服务器
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

# [108] Firefox浏览器
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

# [110] 普罗米修斯监控
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

