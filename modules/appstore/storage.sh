#!/usr/bin/env bash
# LinuxBox AppStore Category: storage

# [8] qbittorrent离线下载
qb_app(){
	local app_id="8"
	local app_name="qbittorrent离线下载"
	local docker_name="qbittorrent"
	local docker_img="lscr.io/linuxserver/qbittorrent:latest"
	docker_run() {
		# 让用户输入 Web管理界面 端口 (默认 8081)
		read -e -p "设置Web管理界面端口 (默认8081): " web_port
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

		# Web面板端口
		add_app_port "Web管理界面" "$web_port"
		# BT 端口保持硬编码 (暂不改)
		add_app_port "BT下载端口 (TCP+UDP)" 56881
	}

	local app_text="qbittorrent离线BT磁力下载服务"
	local app_url="官网介绍: https://hub.docker.com/r/linuxserver/qbittorrent"
	local app_size="1"
	docker_app
}

# [37] Cloudreve网盘
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

# [38] Nextcloud私有网盘
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

	docker_app
}

# [48] Pingvin-Share文件分享
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

# [55] FileBrowser文件管理
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

# [60] Syncthing文件同步
syncthing_app(){
	local app_id="60"
	local app_name="Syncthing文件同步"
	local docker_name="syncthing"
	local docker_img="syncthing/syncthing:latest"
	docker_run() {
		mkdir -p /home/docker/syncthing/config
		# 让用户输入 Web管理界面 端口 (默认 8116)
		read -e -p "设置Web管理界面端口 (默认8116): " web_port
		web_port=${web_port:-8116}

		docker run -d \
			--name syncthing \
			--restart=always \
			-p ${web_port}:8384 \
			-p 22000:22000/tcp \
			-p 22000:22000/udp \
			-v /home/docker/syncthing/config:/var/syncthing/config \
			syncthing/syncthing:latest

		# Web面板端口
		add_app_port "Web管理界面" "$web_port"
		# TCP/UDP 同步端口保持硬编码 (暂不改)
		add_app_port "设备同步端口 (TCP+UDP)" 22000
	}

	local app_text="开源的连续文件同步工具, 支持P2P多设备间文件同步"
	local app_url="官网介绍: https://syncthing.net/"
	local app_size="1"
	docker_app
}

# [63] SFTPGo文件传输
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

# [67] Gopeed高速下载
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

# [69] ZFile在线网盘
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

# [73] FileCodeBox文件快递
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

# [78] PairDrop文件传输
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

# [79] Dufs静态文件服务器
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

# [95] 迅雷离线下载
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

# [96] 小雅Alist全家桶
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

# [99] PanSou网盘搜索
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

