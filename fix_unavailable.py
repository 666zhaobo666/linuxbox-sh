import re

with open("modules/appstore.sh", "r", encoding="utf-8") as f:
    content = f.read()

# 1. 修复 98 极简朋友圈
old_98 = r'\[98\]="极简朋友圈\|app_unavailable \\"极简朋友圈\\" \\"镜像 moments-app:latest 缺少可验证的公开仓库命名空间。\\"\|disabled"'
new_98 = r'[98]="极简朋友圈|moments_app|normal"'
content = re.sub(old_98, new_98, content)

# 2. 修复 99 PanSou网盘搜索
old_99 = r'\[99\]="PanSou网盘搜索\|app_unavailable \\"PanSou网盘搜索\\" \\"镜像 pansou-search:latest 缺少可验证的公开仓库命名空间。\\"\|disabled"'
new_99 = r'[99]="PanSou网盘搜索|pansou_app|normal"'
content = re.sub(old_99, new_99, content)

# 3. 删除 91, 92, 103, 104, 106
content = re.sub(r'^\s*\[91\]="补货监控工具.*?\n', '', content, flags=re.MULTILINE)
content = re.sub(r'^\s*\[92\]="PVE虚拟化管理.*?\n', '', content, flags=re.MULTILINE)
content = re.sub(r'^\s*\[103\]="耗子管理面板.*?\n', '', content, flags=re.MULTILINE)
content = re.sub(r'^\s*\[104\]="AMH建站面板.*?\n', '', content, flags=re.MULTILINE)
content = re.sub(r'^\s*\[106\]="AI视频生成工具.*?\n', '', content, flags=re.MULTILINE)

# 在文件末尾补上 moments_app 和 pansou_app 的定义函数
app_funcs = """
moments_app() {
	local app_name="极简朋友圈"
	local app_text="极简朋友圈 Moments 是一款极简的朋友圈展示程序。"
	local app_url="开源项目: https://github.com/kingwrcy/moments"
	local docker_name="moments"
	local docker_port=80
	
	docker_app_install() {
		read -e -p "请输入要暴露的端口 (默认 3000): " port
		port=${port:-3000}
		docker run -d --name $docker_name --restart=always -p $port:80 kingwrcy/moments:latest
		add_app_port "Web 端口" $port
	}

	docker_app
}

pansou_app() {
	local app_name="PanSou网盘搜索"
	local app_text="PanSou 是一款基于 Docker 的聚合网盘搜索引擎。"
	local app_url="说明: 聚合搜索网盘资源。"
	local docker_name="pansou"
	local docker_port=8080
	
	docker_app_install() {
		read -e -p "请输入要暴露的端口 (默认 8080): " port
		port=${port:-8080}
		docker run -d --name $docker_name --restart=always -p $port:80 systemsome/pansou:latest
		add_app_port "Web 端口" $port
	}

	docker_app
}
"""

# 把函数追加到文件的末尾
content += app_funcs

with open("modules/appstore.sh", "w", encoding="utf-8") as f:
    f.write(content)
