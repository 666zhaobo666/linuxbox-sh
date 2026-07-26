#!/usr/bin/env bash
# LinuxBox AppStore Category: ai

# [20] LobeChatAI聊天聚合网站
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

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="LobeChat聚合市面上主流的AI大模型, ChatGPT/Claude/Gemini/Groq/Ollama"
	local app_url="官网介绍: ${url_proxy}github.com/lobehub/lobe-chat"
	local app_size="2"
	docker_app
}

# [52] OpenWebUI自托管AI
openwebui_app(){
	local app_id="52"
	local app_name="OpenWebUI自托管AI"
	local docker_name="open-webui"
	local docker_img="ghcr.io/open-webui/open-webui:main"
	local docker_port=8108

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8108): " _user_port
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

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="自托管的AI对话界面, 支持Ollama/OpenAI等多种后端"
	local app_url="官网介绍: https://github.com/open-webui/open-webui"
	local app_size="2"
	docker_app
}

# [53] Dify大模型知识库
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

	docker_app
}

# [65] Deepseek AI大模型
deepseek_app(){
	local app_id="65"
	local app_name="Deepseek AI大模型"
	local docker_name="deepseek"
	local docker_img="deepseek-ai/deepseek-coder:6.7b-instruct-q4_0"
	local docker_port=8121

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8121): " _user_port
		_user_port=${_user_port:-8121}
		docker_port=$_user_port

		docker run -d \
			--name deepseek \
			--restart=always \
			-p ${docker_port}:8000 \
			-v /home/docker/deepseek:/root/.ollama \
			deepseek-ai/deepseek-coder:6.7b-instruct-q4_0

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="DeepSeek AI大模型本地部署, 支持代码生成和对话"
	local app_url="官网介绍: https://github.com/deepseek-ai/DeepSeek-Coder"
	local app_size="4"
	docker_app
}

# [84] NewAPI大模型资产管理
newapi_app(){
	local app_id="84"
	local app_name="NewAPI大模型资产管理"
	local docker_name="newapi"
	local docker_img="calciumion/new-api:latest"
	local docker_port=8140

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8140): " _user_port
		_user_port=${_user_port:-8140}
		docker_port=$_user_port

		mkdir -p /home/docker/newapi
		docker run -d \
			--name newapi \
			--restart=always \
			-p ${docker_port}:3000 \
			-v /home/docker/newapi:/data \
			calciumion/new-api:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="大模型API管理和分发系统"
	local app_url="官网介绍: https://github.com/Calcium-Ion/new-api"
	local app_size="1"
	docker_app
}

# [85] RAGFlow知识库
ragflow_app(){
	local app_id="85"
	local app_name="RAGFlow知识库"
	local docker_name="ragflow"
	local docker_img="infiniflow/ragflow:latest"
	local docker_port=8141

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8141): " _user_port
		_user_port=${_user_port:-8141}
		docker_port=$_user_port

		mkdir -p /home/docker/ragflow
		docker run -d \
			--name ragflow \
			--restart=always \
			-p ${docker_port}:80 \
			-v /home/docker/ragflow:/ragflow \
			infiniflow/ragflow:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="开源的RAG引擎, 构建企业知识库"
	local app_url="官网介绍: https://github.com/infiniflow/ragflow"
	local app_size="3"
	docker_app
}

# [86] AstrBot聊天机器人
astrbot_app(){
	local app_id="86"
	local app_name="AstrBot聊天机器人"
	local docker_name="astrbot"
	local docker_img="soulter/astrbot:latest"
	local docker_port=8142

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8142): " _user_port
		_user_port=${_user_port:-8142}
		docker_port=$_user_port

		mkdir -p /home/docker/astrbot
		docker run -d \
			--name astrbot \
			--restart=always \
			-p ${docker_port}:6185 \
			-v /home/docker/astrbot:/AstrBot/data \
			soulter/astrbot:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="多平台聊天机器人框架, 支持QQ/微信/飞书"
	local app_url="官网介绍: https://github.com/Soulter/AstrBot"
	local app_size="1"
	docker_app
}

# [87] LangBot聊天机器人
langbot_app(){
	local app_id="87"
	local app_name="LangBot聊天机器人"
	local docker_name="langbot"
	local docker_img="rockchin/langbot:latest"
	local docker_port=8143

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8143): " _user_port
		_user_port=${_user_port:-8143}
		docker_port=$_user_port

		mkdir -p /home/docker/langbot
		docker run -d \
			--name langbot \
			--restart=always \
			-p ${docker_port}:2280 \
			-v /home/docker/langbot:/app \
			rockchin/langbot:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="大模型原生即时通信机器人平台"
	local app_url="官网介绍: https://github.com/RockChinQ/LangBot"
	local app_size="1"
	docker_app
}

# [90] gpt-load AI透明代理
gptload_app(){
	local app_id="90"
	local app_name="gpt-load AI透明代理"
	local docker_name="gpt-load"
	local docker_img="ghcr.io/gpt-load/gpt-load:latest"
	local docker_port=8146

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8146): " _user_port
		_user_port=${_user_port:-8146}
		docker_port=$_user_port

		mkdir -p /home/docker/gptload
		docker run -d \
			--name gpt-load \
			--restart=always \
			-p ${docker_port}:8080 \
			-v /home/docker/gptload:/data \
			ghcr.io/gpt-load/gpt-load:latest

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="AI服务透明代理工具"
	local app_url="官网介绍: https://github.com/gpt-load"
	local app_size="1"
	docker_app
}

# [106] AI视频生成工具
videogen_app(){
	local app_id="106"
	local app_name="AI视频生成工具"
	local docker_name="videogen"
	local docker_img="videogen-ai:latest"
	local docker_port=8162

	docker_run() {
		# app 自管端口: 让用户输入实际对外服务端口
		read -e -p "服务端口 (默认 8162): " _user_port
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

		# 注册到展示表 (app 自定 label)
		add_app_port "Web 端口" "$docker_port"
	}

	local app_text="AI视频生成工具, 文本生成视频"
	local app_url="官网介绍: https://github.com/videogen-ai"
	local app_size="3"
	docker_app
}

