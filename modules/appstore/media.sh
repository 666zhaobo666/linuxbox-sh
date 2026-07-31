#!/usr/bin/env bash
# LinuxBox AppStore Category: media

# [26] LibreTV私有影视
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

# [27] MoonTV私有影视
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
		run_watchtower_update "$docker_name"
	}


	docker_app_uninstall() {
		cd /home/docker/moontv/ && docker compose down --rmi all
		rm -rf /home/docker/moontv
		echo "应用已卸载"
	}

	docker_app
}

# [28] Melody音乐精灵
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

# [30] SyncTV一起看片神器
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

# [34] DecoTV私有影视
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
		run_watchtower_update "$docker_name"
	}


	docker_app_uninstall() {
		cd /home/docker/decotv/ && docker compose down --rmi all
		rm -rf /home/docker/decotv
		echo "应用已卸载"
	}

	docker_app
}

# [39] emby媒体管理
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

# [40] jellyfin媒体管理
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

# [42] Navidrome音乐服务器
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

# [46] PhotoPrism私有相册
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
		run_watchtower_update "$docker_name"
	}

	docker_app_uninstall() {
		cd /home/docker/photoprism && docker compose down --rmi all -v
		rm -rf /home/docker/photoprism
		echo "PhotoPrism 已卸载"
	}

	docker_app
}

# [59] immich图片视频管理
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
		run_watchtower_update "$docker_name"
	}

	docker_app_uninstall() {
		cd /home/docker/immich && docker compose down --rmi all -v
		rm -rf /home/docker/immich
		echo "Immich 已卸载"
	}

	docker_app
}

# [64] Owncast自托管直播
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

# [75] yt-dlp视频下载
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

# [94] 在线DOS老游戏
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

# [97] Bililive直播录制
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

