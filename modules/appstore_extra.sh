#############################################################################
########################### 补充应用 (36-115) #############################

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

	local docker_describe="基于Java的在线网盘/文件列表程序, 支持多种存储后端"
	local docker_url="官网介绍: https://github.com/zfile-dev/zfile"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# Nexterm远程连接工具
nexterm_app(){
	local app_id="70"
	local docker_name="nexterm"
	local docker_img="germannewsmaker/nexterm:latest"
	local docker_port=8126

	docker_run() {
		mkdir -p /home/docker/nexterm/data
		docker run -d \
			--name nexterm \
			--restart=always \
			-p ${docker_port}:6989 \
			-v /home/docker/nexterm/data:/app/data \
			germannewsmaker/nexterm:latest
	}

	local docker_describe="自托管的远程连接工具, 支持SSH/RDP/VNC/HTTP协议"
	local docker_url="官网介绍: https://github.com/germannewsmaker/nexterm"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# JitsiMeet视频会议
jitsimeet_app(){
	local app_id="71"

	local app_name="Jitsi Meet视频会议"
	local app_text="开源的视频会议系统, 无需注册即可使用"
	local app_url="官网介绍: https://jitsi.org/jitsi-meet/"
	local docker_name="jitsi-web"
	local docker_port="8127"
	local app_size="3"

	docker_app_install() {
		mkdir -p /home/docker/jitsi-meet
		cd /home/docker/jitsi-meet

		curl -fsSL "${gh_proxy}raw.githubusercontent.com/jitsi/docker-jitsi-meet/master/docker-compose.yml" -o docker-compose.yml
		curl -fsSL "${gh_proxy}raw.githubusercontent.com/jitsi/docker-jitsi-meet/master/env.example" -o .env

		sed -i "s/- '8443:443'/#- '8443:443'/g" docker-compose.yml
		sed -i "s/- '4443:443'/#- '4443:443'/g" docker-compose.yml
		sed -i "/HTTP_PORT/a\      - '${docker_port}:80'" docker-compose.yml

		docker compose up -d
		clear
		echo "Jitsi Meet 安装完成"
		check_docker_app_ip
	}

	docker_app_update() {
		cd /home/docker/jitsi-meet && docker compose pull && docker compose up -d
	}

	docker_app_uninstall() {
		cd /home/docker/jitsi-meet && docker compose down --rmi all -v
		rm -rf /home/docker/jitsi-meet
		echo "Jitsi Meet 已卸载"
	}

	docker_app_plus
}

# Stream四层代理转发工具
stream_app(){
	local app_id="72"
	local docker_name="stream"
	local docker_img="ghcr.io/yangchuansheng/ipt2socks:latest"
	local docker_port=8128

	docker_run() {
		docker run -d \
			--name stream \
			--restart=always \
			--network host \
			ghcr.io/yangchuansheng/ipt2socks:latest
	}

	local docker_describe="四层代理转发工具, 支持TCP/UDP流量转发"
	local docker_url="官网介绍: https://github.com/yangchuansheng/ipt2socks"
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
		mkdir -p /home/docker/filecodebox/data
		docker run -d \
			--name filecodebox \
			--restart=always \
			-p ${docker_port}:12345 \
			-v /home/docker/filecodebox/data:/app/data \
			lanol/filecodebox:latest
	}

	local docker_describe="文件快递柜, 支持匿名发送文件/文本, 接收方通过取件码获取"
	local docker_url="官网介绍: https://github.com/vastsa/FileCodeBox"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# matrix去中心化聊天协议
matrix_app(){
	local app_id="74"

	local app_name="Matrix(Synapse)聊天"
	local app_text="去中心化的开源聊天协议服务器"
	local app_url="官网介绍: https://matrix.org/"
	local docker_name="matrix-synapse"
	local docker_port="8130"
	local app_size="3"

	docker_app_install() {
		mkdir -p /home/docker/matrix/data
		cd /home/docker/matrix

		cat > docker-compose.yml << 'EOF'
services:
  synapse:
    image: matrixdotorg/synapse:latest
    container_name: matrix-synapse
    restart: always
    ports:
      - '${docker_port}:8008'
      - 8448:8448
    volumes:
      - synapse_data:/data
    environment:
      SYNAPSE_SERVER_NAME: "localhost"
      SYNAPSE_REPORT_STATS: "no"
    networks:
      - matrix-net

networks:
  matrix-net:
    driver: bridge

volumes:
  synapse_data:
EOF
		sed -i "s/\${docker_port}/${docker_port}/g" docker-compose.yml
		docker compose up -d
		clear
		echo "Matrix Synapse 安装完成"
		check_docker_app_ip
	}

	docker_app_update() {
		cd /home/docker/matrix && docker compose down --rmi all
		cd /home/docker/matrix && docker compose up -d
	}

	docker_app_uninstall() {
		cd /home/docker/matrix && docker compose down --rmi all -v
		rm -rf /home/docker/matrix
		echo "Matrix 已卸载"
	}

	docker_app_plus
}

# yt-dlp视频下载工具
ytdlp_app(){
	local app_id="75"
	local docker_name="ytdlp"
	local docker_img="jmbannon/ytdlweb:latest"
	local docker_port=8131

	docker_run() {
		docker run -d \
			--name ytdlp \
			--restart=always \
			-p ${docker_port}:8080 \
			jmbannon/ytdlweb:latest
	}

	local docker_describe="基于yt-dlp的网页视频下载工具, 支持数千个网站"
	local docker_url="官网介绍: https://github.com/jmbannon/ytdlweb"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# paperless文档管理平台
paperless_app(){
	local app_id="76"

	local app_name="Paperless文档管理"
	local app_text="扫描和管理你的文档, OCR自动识别"
	local app_url="官网介绍: https://paperless-ngx.com/"
	local docker_name="paperless-webserver"
	local docker_port="8132"
	local app_size="3"

	docker_app_install() {
		mkdir -p /home/docker/paperless/{consume,data,export,media}
		cd /home/docker/paperless

		cat > docker-compose.yml << 'EOF'
services:
  db:
    image: postgres:15
    container_name: paperless-db
    restart: always
    volumes:
      - pgdata:/var/lib/postgresql/data
    environment:
      POSTGRES_DB: paperless
      POSTGRES_USER: paperless
      POSTGRES_PASSWORD: paperless_pwd
    networks:
      - paperless-net

  redis:
    image: redis:7
    container_name: paperless-redis
    restart: always
    networks:
      - paperless-net

  webserver:
    image: ghcr.io/paperless-ngx/paperless-ngx:latest
    container_name: paperless-webserver
    restart: always
    ports:
      - '${docker_port}:8000'
    environment:
      PAPERLESS_REDIS: redis://redis:6379
      PAPERLESS_DBHOST: db
      PAPERLESS_DBPASS: paperless_pwd
      PAPERLESS_TIME_ZONE: Asia/Shanghai
      PAPERLESS_OCR_LANGUAGE: chi_sim+eng
      PAPERLESS_URL: http://localhost:8000
    volumes:
      - data:/usr/src/paperless/data
      - media:/usr/src/paperless/media
      - export:/usr/src/paperless/export
      - consume:/usr/src/paperless/consume
    depends_on:
      - db
      - redis
    networks:
      - paperless-net

networks:
  paperless-net:
    driver: bridge

volumes:
  pgdata:
  data:
  media:
  export:
  consume:
EOF
		sed -i "s/\${docker_port}/${docker_port}/g" docker-compose.yml
		docker compose up -d
		clear
		echo "Paperless-ngx 安装完成"
		check_docker_app_ip
	}

	docker_app_update() {
		cd /home/docker/paperless && docker compose pull && docker compose up -d
	}

	docker_app_uninstall() {
		cd /home/docker/paperless && docker compose down --rmi all -v
		rm -rf /home/docker/paperless
		echo "Paperless 已卸载"
	}

	docker_app_plus
}

# Wallos个人财务管理工具
wallos_app(){
	local app_id="77"
	local docker_name="wallos"
	local docker_img="bellamy/wallos:latest"
	local docker_port=8133

	docker_run() {
		mkdir -p /home/docker/wallos/db
		docker run -d \
			--name wallos \
			--restart=always \
			-p ${docker_port}:80 \
			-v /home/docker/wallos/db:/var/lib/wallos \
			bellamy/wallos:latest
	}

	local docker_describe="自托管的个人财务管理和订阅追踪工具"
	local docker_url="官网介绍: https://github.com/ellite/Wallos"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# komari服务器监控工具
komari_app(){
	local app_id="78"
	local docker_name="komari"
	local docker_img="haileykomi/komari:latest"
	local docker_port=8134

	docker_run() {
		mkdir -p /home/docker/komari/data
		docker run -d \
			--name komari \
			--restart=always \
			-p ${docker_port}:8080 \
			-v /home/docker/komari/data:/app/data \
			haileykomi/komari:latest
	}

	local docker_describe="简洁的服务器监控面板, 支持多服务器状态展示"
	local docker_url="官网介绍: https://github.com/HaileyKomi/Komari"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# Dufs极简静态文件服务器
dufs_app(){
	local app_id="79"
	local docker_name="dufs"
	local docker_img="sigp/dufs:latest"
	local docker_port=8135

	docker_run() {
		mkdir -p /home/docker/dufs/data
		docker run -d \
			--name dufs \
			--restart=always \
			-p ${docker_port}:5000 \
			-v /home/docker/dufs/data:/data \
			sigp/dufs:latest -a -S
	}

	local docker_describe="功能丰富的文件服务器, 支持上传/下载/WebDAV"
	local docker_url="官网介绍: https://github.com/sigp/dufs"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# PandaWiki智能文档管理系统
pandawiki_app(){
	local app_id="80"
	local docker_name="pandawiki"
	local docker_img="pandawiki/pandawiki:latest"
	local docker_port=8136

	docker_run() {
		mkdir -p /home/docker/pandawiki/data
		docker run -d \
			--name pandawiki \
			--restart=always \
			-p ${docker_port}:8000 \
			-v /home/docker/pandawiki/data:/app/data \
			pandawiki/pandawiki:latest
	}

	local docker_describe="智能文档管理系统, 支持Markdown和可视化编辑"
	local docker_url="官网介绍: https://github.com/PandaWiki/PandaWiki"
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
		mkdir -p /home/docker/linkwarden/data
		docker run -d \
			--name linkwarden \
			--restart=always \
			-p ${docker_port}:3000 \
			-v /home/docker/linkwarden/data:/data \
			ghcr.io/linkwarden/linkwarden:latest
	}

	local docker_describe="自托管的书签管理器, 支持网页存档和链接整理"
	local docker_url="官网介绍: https://github.com/linkwarden/linkwarden"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# VoceChat多人在线聊天系统
vocechat_app(){
	local app_id="82"
	local docker_name="vocechat"
	local docker_img="privoce/vocechat-server:latest"
	local docker_port=8138

	docker_run() {
		mkdir -p /home/docker/vocechat/data
		docker run -d \
			--name vocechat \
			--restart=always \
			-p ${docker_port}:3000 \
			-v /home/docker/vocechat/data:/home/vocechat-server/data \
			privoce/vocechat-server:latest
	}

	local docker_describe="轻量级的自托管聊天系统, 支持私有部署"
	local docker_url="官网介绍: https://github.com/Privoce/vocechat"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# Karakeep书签管理
karakeep_app(){
	local app_id="83"
	local docker_name="karakeep"
	local docker_img="ghcr.io/karakeep/karakeep:latest"
	local docker_port=8139

	docker_run() {
		mkdir -p /home/docker/karakeep/data
		docker run -d \
			--name karakeep \
			--restart=always \
			-p ${docker_port}:3000 \
			-v /home/docker/karakeep/data:/app/data \
			ghcr.io/karakeep/karakeep:latest
	}

	local docker_describe="开源的书签和稍后阅读管理工具, AI辅助整理"
	local docker_url="官网介绍: https://github.com/karakeep/karakeep"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# NewAPI大模型资产管理
newapi_app(){
	local app_id="84"
	local docker_name="new-api"
	local docker_img="calciumion/new-api:latest"
	local docker_port=8140

	docker_run() {
		mkdir -p /home/docker/new-api/data
		docker run -d \
			--name new-api \
			--restart=always \
			-p ${docker_port}:3000 \
			-v /home/docker/new-api/data:/data \
			calciumion/new-api:latest
	}

	local docker_describe="OpenAI/ChatGPT API管理平台, 支持多渠道负载均衡"
	local docker_url="官网介绍: https://github.com/Calcium-Ion/new-api"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# RAGFlow大模型知识库
ragflow_app(){
	local app_id="85"

	local app_name="RAGFlow知识库"
	local app_text="基于深度文档理解的开源RAG引擎"
	local app_url="官网介绍: https://ragflow.io/"
	local docker_name="ragflow-server"
	local docker_port="8141"
	local app_size="4"

	docker_app_install() {
		mkdir -p /home/docker/ragflow
		cd /home/docker/ragflow

		local compose_url="${gh_proxy}raw.githubusercontent.com/infiniflow/ragflow/main/docker/docker-compose.yml"
		curl -fsSL "$compose_url" -o docker-compose.yml

		sed -i "s/- '80:80'/#- '80:80'/g" docker-compose.yml
		sed -i "/EXPOSE/a\      - '${docker_port}:80" docker-compose.yml

		docker compose up -d
		clear
		echo "RAGFlow 安装完成"
		check_docker_app_ip
	}

	docker_app_update() {
		cd /home/docker/ragflow && docker compose pull && docker compose up -d
	}

	docker_app_uninstall() {
		cd /home/docker/ragflow && docker compose down --rmi all -v
		rm -rf /home/docker/ragflow
		echo "RAGFlow 已卸载"
	}

	docker_app_plus
}

# AstrBot聊天机器人框架
astrbot_app(){
	local app_id="86"
	local docker_name="astrbot"
	local docker_img="soulter/astrbot:latest"
	local docker_port=8142

	docker_run() {
		mkdir -p /home/docker/astrbot/data
		docker run -d \
			--name astrbot \
			--restart=always \
			-p ${docker_port}:6185 \
			-v /home/docker/astrbot/data:/AstrBot/data \
			soulter/astrbot:latest
	}

	local docker_describe="AI聊天机器人框架, 支持接入多种AI模型和平台"
	local docker_url="官网介绍: https://github.com/Soulter/AstrBot"
	local docker_use=""
	local docker_passwd=""
	local app_size="2"
	docker_app
}

# LangBot聊天机器人
langbot_app(){
	local app_id="87"
	local docker_name="langbot"
	local docker_img="rockchinr/langbot:latest"
	local docker_port=8143

	docker_run() {
		mkdir -p /home/docker/langbot/data
		docker run -d \
			--name langbot \
			--restart=always \
			-p ${docker_port}:9000 \
			-v /home/docker/langbot/data:/app/data \
			rockchinr/langbot:latest
	}

	local docker_describe="基于大语言模型的聊天机器人, 支持多平台接入"
	local docker_url="官网介绍: https://github.com/rockchin-langbot/LangBot"
	local docker_use=""
	local docker_passwd=""
	local app_size="2"
	docker_app
}

# 多格式文件转换工具
gotenberg_app(){
	local app_id="88"
	local docker_name="gotenberg"
	local docker_img="gotenberg/gotenberg:8"
	local docker_port=8144

	docker_run() {
		docker run -d \
			--name gotenberg \
			--restart=always \
			-p ${docker_port}:3000 \
			gotenberg/gotenberg:8 gotenberg --api-port=3000
	}

	local docker_describe="Docker化的文件转换API, 支持HTML转PDF/Office转PDF等"
	local docker_url="官网介绍: https://gotenberg.dev/"
	local docker_use=""
	local docker_passwd=""
	local app_size="2"
	docker_app
}

# LibreSpeed测速工具
librespeed_app(){
	local app_id="89"
	local docker_name="librespeed"
	local docker_img="librespeed/speedtest:latest"
	local docker_port=8145

	docker_run() {
		docker run -d \
			--name librespeed \
			--restart=always \
			-p ${docker_port}:80 \
			librespeed/speedtest:latest
	}

	local docker_describe="轻量级的网络测速工具, 支持HTML5测速"
	local docker_url="官网介绍: https://github.com/librespeed/speedtest"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# gpt-load高性能AI透明代理
gptload_app(){
	local app_id="90"
	local docker_name="gpt-load"
	local docker_img="dlz9/gpt-load:latest"
	local docker_port=8146

	docker_run() {
		mkdir -p /home/docker/gpt-load
		docker run -d \
			--name gpt-load \
			--restart=always \
			-p ${docker_port}:8080 \
			dlz9/gpt-load:latest
	}

	local docker_describe="高性能AI API透明代理和负载均衡工具"
	local docker_url="官网介绍: https://github.com/dlz9/gpt-load"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# 补货监控工具
stockmonitor_app(){
	local app_id="91"
	local docker_name="stock-monitor"
	local docker_img="techbureau/stock-monitor:latest"
	local docker_port=8147

	docker_run() {
		mkdir -p /home/docker/stock-monitor
		docker run -d \
			--name stock-monitor \
			--restart=always \
			-p ${docker_port}:8080 \
			techbureau/stock-monitor:latest
	}

	local docker_describe="电商补货监控工具, 支持多平台商品库存监控"
	local docker_url="官网介绍: https://github.com/techbureau/stock-monitor"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# PVE开小鸡面板
pve_app(){
	local app_id="92"
	local docker_name="pve"
	local docker_img="pve/pve-manager:latest"
	local docker_port=8006

	docker_run() {
		echo -e "${yellow}PVE需要直接安装在宿主机上, 不支持Docker部署${white}"
		echo -e "${cyan}安装方式: ISO镜像安装 https://www.proxmox.com/en/downloads${white}"
		break_end
		return 1
	}

	local docker_describe="Proxmox VE虚拟化管理平台, 用于创建和管理虚拟机/容器"
	local docker_url="官网介绍: https://www.proxmox.com/"
	local docker_use=""
	local docker_passwd=""
	local app_size="0"
	docker_app
}

# DSM群晖虚拟机
dsm_app(){
	local app_id="93"
	local docker_name="dsm"
	local docker_img="vdsm/virtual-dsm:latest"
	local docker_port=8148

	docker_run() {
		mkdir -p /home/docker/dsm
		docker run -d \
			--name dsm \
			--restart=always \
			-p ${docker_port}:5000 \
			-v /home/docker/dsm:/dsm \
			--device=/dev/kvm \
			--cap-add=NET_ADMIN \
			vdsm/virtual-dsm:latest
	}

	local docker_describe="在Docker中运行群晖DSM虚拟机"
	local docker_url="官网介绍: https://github.com/vdsm/virtual-dsm"
	local docker_use=""
	local docker_passwd=""
	local app_size="5"
	docker_app
}

# 在线DOS老游戏
dosgame_app(){
	local app_id="94"
	local docker_name="dosgame"
	local docker_img="jgoerzen/dosbox-x:latest"
	local docker_port=8149

	docker_run() {
		mkdir -p /home/docker/dosgame/games
		docker run -d \
			--name dosgame \
			--restart=always \
			-p ${docker_port}:8080 \
			-v /home/docker/dosgame/games:/games \
			jgoerzen/dosbox-x:latest
	}

	local docker_describe="在线DOS游戏模拟器, 在浏览器中运行经典DOS游戏"
	local docker_url="官网介绍: https://github.com/dosbox-staging/dosbox-staging"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# 迅雷离线下载工具
xunlei_app(){
	local app_id="95"
	local docker_name="xunlei"
	local docker_img="cnk3x/xunlei:latest"
	local docker_port=8150

	docker_run() {
		mkdir -p /home/docker/xunlei/data
		docker run -d \
			--name xunlei \
			--restart=always \
			-p ${docker_port}:2345 \
			-v /home/docker/xunlei/data:/xunlei/data \
			cnk3x/xunlei:latest
	}

	local docker_describe="迅雷离线下载Docker版, 支持迅雷会员高速下载"
	local docker_url="官网介绍: https://github.com/cnk3x/xunlei"
	local docker_use=""
	local docker_passwd=""
	local app_size="2"
	docker_app
}

# 小雅alist全家桶
xiaoya_app(){
	local app_id="96"

	local app_name="小雅Alist全家桶"
	local app_text="整合多个媒体资源的Alist网盘聚合方案"
	local app_url="官网介绍: https://github.com/monlor/xiaoya-alist"
	local docker_name="xiaoya"
	local docker_port="8151"
	local app_size="3"

	docker_app_install() {
		mkdir -p /home/docker/xiaoya
		cd /home/docker/xiaoya

		cat > docker-compose.yml << 'EOF'
services:
  alist:
    image: xiaoyaliu/alist:latest
    container_name: xiaoya
    restart: always
    ports:
      - '${docker_port}:5244'
    environment:
      - PUID=0
      - PGID=0
      - UMASK=022
    volumes:
      - config:/config
      - media:/media
    networks:
      - xiaoya-net

networks:
  xiaoya-net:
    driver: bridge

volumes:
  config:
  media:
EOF
		sed -i "s/\${docker_port}/${docker_port}/g" docker-compose.yml
		docker compose up -d
		clear
		echo "小雅Alist全家桶 安装完成"
		check_docker_app_ip
	}

	docker_app_update() {
		cd /home/docker/xiaoya && docker compose pull && docker compose up -d
	}

	docker_app_uninstall() {
		cd /home/docker/xiaoya && docker compose down --rmi all -v
		rm -rf /home/docker/xiaoya
		echo "小雅Alist 已卸载"
	}

	docker_app_plus
}

# Bililive直播录制工具
bililive_app(){
	local app_id="97"
	local docker_name="bililive"
	local docker_img="docker.io/bililive/bililive-recorder:latest"
	local docker_port=8152

	docker_run() {
		mkdir -p /home/docker/bililive/rec
		docker run -d \
			--name bililive \
			--restart=always \
			-p ${docker_port}:8080 \
			-v /home/docker/bililive/rec:/rec \
			bililive/bililive-recorder:latest
	}

	local docker_describe="B站直播录制工具, 自动录制和保存直播内容"
	local docker_url="官网介绍: https://github.com/bililive/bililive-recorder"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# 极简朋友圈
moments_app(){
	local app_id="98"
	local docker_name="moments"
	local docker_img="lucumt/moments:latest"
	local docker_port=8153

	docker_run() {
		mkdir -p /home/docker/moments/data
		docker run -d \
			--name moments \
			--restart=always \
			-p ${docker_port}:8000 \
			-v /home/docker/moments/data:/app/db \
			lucumt/moments:latest
	}

	local docker_describe="极简朋友圈, 自托管的社交动态分享平台"
	local docker_url="官网介绍: https://github.com/lucumt/moments"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# PanSou网盘搜索
pansou_app(){
	local app_id="99"
	local docker_name="pansou"
	local docker_img="pansou/pansou:latest"
	local docker_port=8154

	docker_run() {
		mkdir -p /home/docker/pansou
		docker run -d \
			--name pansou \
			--restart=always \
			-p ${docker_port}:8080 \
			pansou/pansou:latest
	}

	local docker_describe="网盘资源搜索引擎, 聚合多个网盘搜索结果"
	local docker_url="官网介绍: https://github.com/pansou/pansou"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# 简单图床图片管理程序
lskypro_app(){
	local app_id="100"
	local docker_name="lskypro"
	local docker_img="halcyonazure/lsky-pro-docker:latest"
	local docker_port=8155

	docker_run() {
		mkdir -p /home/docker/lskypro
		docker run -d \
			--name lskypro \
			--restart=always \
			-p ${docker_port}:8089 \
			-v /home/docker/lskypro:/var/www/html \
			halcyonazure/lsky-pro-docker:latest
	}

	local docker_describe="Lsky Pro图床程序, 支持多种存储后端"
	local docker_url="官网介绍: https://github.com/lsky-org/lsky-pro"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# 禅道项目管理软件
zentao_app(){
	local app_id="101"

	local app_name="禅道项目管理"
	local app_text="开源的项目管理软件, 支持敏捷开发"
	local app_url="官网介绍: https://www.zentao.net/"
	local docker_name="zentao-app"
	local docker_port="8156"
	local app_size="2"

	docker_app_install() {
		mkdir -p /home/docker/zentao/data
		cd /home/docker/zentao

		cat > docker-compose.yml << 'EOF'
services:
  zentao:
    image: easysoft/zentao:latest
    container_name: zentao-app
    restart: always
    ports:
      - '${docker_port}:80'
    environment:
      - MYSQL_ROOT_PASSWORD=zentao_root_pwd
    volumes:
      - zentao_data:/data
    networks:
      - zentao-net

networks:
  zentao-net:
    driver: bridge

volumes:
  zentao_data:
EOF
		sed -i "s/\${docker_port}/${docker_port}/g" docker-compose.yml
		docker compose up -d
		clear
		echo "禅道安装完成"
		check_docker_app_ip
	}

	docker_app_update() {
		cd /home/docker/zentao && docker compose down --rmi all
		cd /home/docker/zentao && docker compose up -d
	}

	docker_app_uninstall() {
		cd /home/docker/zentao && docker compose down --rmi all -v
		rm -rf /home/docker/zentao
		echo "禅道已卸载"
	}

	docker_app_plus
}

# QD-Today定时任务管理框架
qdtoday_app(){
	local app_id="102"
	local docker_name="qdtoday"
	local docker_img="qdtoday/qd:latest"
	local docker_port=8157

	docker_run() {
		mkdir -p /home/docker/qdtoday/config
		docker run -d \
			--name qdtoday \
			--restart=always \
			-p ${docker_port}:80 \
			-v /home/docker/qdtoday/config:/config \
			qdtoday/qd:latest
	}

	local docker_describe="QD-Today定时任务管理框架, 支持多种签到和自动化任务"
	local docker_url="官网介绍: https://github.com/qdtoday/QD"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# 耗子管理面板
haizi_app(){
	local app_id="103"
	local docker_name="haizi"
	local docker_img="haizi-panel/haizi:latest"
	local docker_port=8158

	docker_run() {
		mkdir -p /home/docker/haizi
		docker run -d \
			--name haizi \
			--restart=always \
			-p ${docker_port}:8080 \
			-v /home/docker/haizi:/app/data \
			haizi-panel/haizi:latest
	}

	local docker_describe="轻量级的服务器管理面板"
	local docker_url="官网介绍: https://github.com/haizi-panel/haizi"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# AMH主机建站管理面板
amh_app(){
	local app_id="104"
	local docker_name="amh"
	local docker_img="amh-panel/amh:latest"
	local docker_port=8159

	docker_run() {
		mkdir -p /home/docker/amh
		docker run -d \
			--name amh \
			--restart=always \
			-p ${docker_port}:8888 \
			-v /home/docker/amh:/data \
			amh-panel/amh:latest
	}

	local docker_describe="AMH主机建站管理面板"
	local docker_url="官网介绍: https://amh.sh/"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# 在线翻译服务器
libretranslate_app(){
	local app_id="105"
	local docker_name="libretranslate"
	local docker_img="libretranslate/libretranslate:latest"
	local docker_port=8160

	docker_run() {
		mkdir -p /home/docker/libretranslate/data
		docker run -d \
			--name libretranslate \
			--restart=always \
			-p ${docker_port}:5000 \
			-v /home/docker/libretranslate/data:/home/libretranslate/data \
			-e LT_DISABLE_WEB_UI=false \
			libretranslate/libretranslate:latest
	}

	local docker_describe="开源的自托管翻译API服务, 支持多语言互译"
	local docker_url="官网介绍: https://libretranslate.com/"
	local docker_use=""
	local docker_passwd=""
	local app_size="2"
	docker_app
}

# AI视频生成工具
videogen_app(){
	local app_id="106"
	local docker_name="videogen"
	local docker_img="video-generation/video-gen:latest"
	local docker_port=8161

	docker_run() {
		mkdir -p /home/docker/videogen
		docker run -d \
			--name videogen \
			--restart=always \
			-p ${docker_port}:7860 \
			--gpus all \
			video-generation/video-gen:latest
	}

	local docker_describe="AI视频生成工具, 基于开源大模型"
	local docker_url="官网介绍: https://github.com/video-generation/video-gen"
	local docker_use=""
	local docker_passwd=""
	local app_size="5"
	docker_app
}

# RustDesk远程桌面(服务端)
rustdesk_server_app(){
	local app_id="107"

	local app_name="RustDesk远程桌面服务端"
	local app_text="开源的远程桌面服务端和中继端"
	local app_url="官网介绍: https://rustdesk.com/"
	local docker_name="rustdesk-server"
	local docker_port="8162"
	local app_size="2"

	docker_app_install() {
		mkdir -p /home/docker/rustdesk
		cd /home/docker/rustdesk

		cat > docker-compose.yml << 'EOF'
services:
  hbbs:
    image: rustdesk/rustdesk-server:latest
    container_name: rustdesk-hbbs
    restart: always
    ports:
      - '21115:21115'
      - '21116:21116'
      - '21116:21116/udp'
      - '21118:21118'
    volumes:
      - data:/root
    networks:
      - rustdesk-net
    command: hbbs

  hbbr:
    image: rustdesk/rustdesk-server:latest
    container_name: rustdesk-hbbr
    restart: always
    ports:
      - '21117:21117'
      - '21119:21119'
    volumes:
      - data:/root
    networks:
      - rustdesk-net
    command: hbbr

networks:
  rustdesk-net:
    driver: bridge

volumes:
  data:
EOF
		sed -i "s/\${docker_port}/${docker_port}/g" docker-compose.yml
		docker compose up -d
		clear
		echo "RustDesk服务端安装完成"
		check_docker_app_ip
	}

	docker_app_update() {
		cd /home/docker/rustdesk && docker compose pull && docker compose up -d
	}

	docker_app_uninstall() {
		cd /home/docker/rustdesk && docker compose down --rmi all -v
		rm -rf /home/docker/rustdesk
		echo "RustDesk已卸载"
	}

	docker_app_plus
}

# Firefox浏览器
firefox_app(){
	local app_id="108"
	local docker_name="firefox"
	local docker_img="linuxserver/firefox:latest"
	local docker_port=8163

	docker_run() {
		mkdir -p /home/docker/firefox/config
		docker run -d \
			--name firefox \
			--restart=always \
			-p ${docker_port}:3000 \
			-v /home/docker/firefox/config:/config \
			-e DISPLAY_WIDTH=1920 \
			-e DISPLAY_HEIGHT=1080 \
			--shm-size="2gb" \
			linuxserver/firefox:latest
	}

	local docker_describe="网页版Firefox浏览器, 在浏览器中运行Firefox"
	local docker_url="官网介绍: https://github.com/linuxserver/docker-firefox"
	local docker_use=""
	local docker_passwd=""
	local app_size="2"
	docker_app
}

# DPanel容器管理面板
dpanel_app(){
	local app_id="109"
	local docker_name="dpanel"
	local docker_img="dpanel/dpanel:latest"
	local docker_port=8164

	docker_run() {
		mkdir -p /home/docker/dpanel/data
		docker run -d \
			--name dpanel \
			--restart=always \
			-p ${docker_port}:8080 \
			-v /var/run/docker.sock:/var/run/docker.sock \
			-v /home/docker/dpanel/data:/data \
			dpanel/dpanel:latest
	}

	local docker_describe="轻量级Docker容器管理面板"
	local docker_url="官网介绍: https://github.com/dpanel/dpanel"
	local docker_use=""
	local docker_passwd=""
	local app_size="1"
	docker_app
}

# 普罗米修斯监控
prometheus_app(){
	local app_id="110"

	local app_name="Prometheus+Grafana监控"
	local app_text="开源的服务监控和可视化平台"
	local app_url="官网介绍: https://prometheus.io/"
	local docker_name="prometheus"
	local docker_port="8165"
	local app_size="2"

	docker_app_install() {
		mkdir -p /home/docker/prometheus/{data,grafana}
		cd /home/docker/prometheus

		cat > docker-compose.yml << 'EOF'
services:
  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    restart: always
    ports:
      - '9090:9090'
    volumes:
      - prom_data:/prometheus
    networks:
      - monitor-net

  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    restart: always
    ports:
      - '${docker_port}:3000'
    volumes:
      - grafana_data:/var/lib/grafana
    depends_on:
      - prometheus
    networks:
      - monitor-net

networks:
  monitor-net:
    driver: bridge

volumes:
  prom_data:
  grafana_data:
EOF
		sed -i "s/\${docker_port}/${docker_port}/g" docker-compose.yml
		docker compose up -d
		clear
		echo "Prometheus+Grafana 安装完成"
		check_docker_app_ip
	}

	docker_app_update() {
		cd /home/docker/prometheus && docker compose pull && docker compose up -d
	}

	docker_app_uninstall() {
		cd /home/docker/prometheus && docker compose down --rmi all -v
		rm -rf /home/docker/prometheus
		echo "Prometheus+Grafana 已卸载"
	}

	docker_app_plus
}
