################################################################
########################### 全局函数 ###########################
## 脚本依赖检测
dependency_check(){
	echo -e "${cyan}正在进行依赖检测, 请稍后......"
	if ! command -v curl &>/dev/null; then
		install curl
	fi
	if ! command -v sudo &>/dev/null; then
		install sudo
	fi
	if ! command -v wget &>/dev/null; then
		install wget
	fi
	if ! command -v bash &>/dev/null; then
		install bash
	fi
	if ! command -v unzip &>/dev/null; then
		install unzip
	fi
	if ! command -v tar &>/dev/null; then
		install tar
	fi
	if ! command -v jq &>/dev/null; then
		install jq
	fi
	if ! command -v grep &>/dev/null; then
		install grep
	fi
}

# 定义一个函数来执行命令
run_command() {
	if [ "$zhushi" -eq 0 ]; then
		"$@"
	fi
}

# 结束脚本
break_end() {
	echo -e "${cyan}按任意键继续...${white}"
	read -n 1 -s -r -p ""
	echo ""
	clear
}

##  返回主菜单
return_to_menu() {
	main_menu
}

##  获取IP地址
ip_address() {
get_public_ip() {
	curl -s https://ipinfo.io/ip && echo
}
get_local_ip() {
	ip route get 8.8.8.8 2>/dev/null | grep -oP 'src \K[^ ]+' || \
	hostname -I 2>/dev/null | awk '{print $1}' || \
	ifconfig 2>/dev/null | grep -E 'inet [0-9]' | grep -v '127.0.0.1' | awk '{print $2}' | head -n1
}

public_ip=$(get_public_ip)
isp_info=$(curl -s --max-time 3 http://ipinfo.io/org)

if echo "$isp_info" | grep -Eiq 'china|mobile|unicom|telecom'; then
    ipv4_address=$(get_local_ip)
else
    ipv4_address="$public_ip"
fi

# ipv4_address=$(curl -s https://ipinfo.io/ip && echo)
ipv6_address=$(curl -s --max-time 1 https://v6.ipinfo.io/ip && echo)

##  通用下载函数 (无 shebang 验证, lib/ 下的库文件首行不一定是 shebang)
# 用法: download_file <remote_url> <local_path>
# 成功返回 0, 失败返回 1
download_file() {
	local url="$1"
	local path="$2"
	if curl -sSL --max-time 60 --fail "$url" -o "$path" 2>/dev/null; then
		[ -s "$path" ] && return 0
	fi
	return 1
}

##  进度条渲染 (覆盖式, 用 \r 回到行首)
# 用法: show_progress <current> <total> [bar_width]
show_progress() {
	local current=$1
	local total=$2
	local width=${3:-30}
	local pct=$(( current * 100 / total ))
	local filled=$(( current * width / total ))
	local empty=$(( width - filled ))

	local bar=""
	local i
	for ((i=0; i<filled; i++)); do bar+="█"; done
	for ((i=0; i<empty; i++)); do bar+="░"; done

	printf "\r${cyan}下载中: [${green}%s${cyan}] %3d%% (%d/%d)${white}" "$bar" "$pct" "$current" "$total"
}
}
