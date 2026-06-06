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

##  终端字符串对齐工具
##  CJK 字符 / 全角字符 在等宽字体里占 2 列, ASCII 占 1 列.
##  UTF-8 编码下: 多字节字符首字节 >= 0xC0 (即字节值 >= 192) 的字符算 2 列.
##  注意: ANSI 颜色码会被算成 1 列 (因为是 ASCII), 所以这几个函数**只接受纯文本**,
##        颜色码请在 printf 里用 "${cyan}...${white}" 这种方式在外面包, 不要混进文本里.

# 计算字符串的可见列数
str_width() {
	# 先剥掉 ANSI 颜色码 (\033[...m), 这些是不可见字符不能算进列数
	local s
	s=$(printf '%s' "$1" | sed $'s/\033\\[[0-9;]*m//g')
	local w=0 i=0 len=${#s} byte
	while [ "$i" -lt "$len" ]; do
		printf -v byte "%d" "'${s:$i:1}"
		if [ "$byte" -ge 192 ] 2>/dev/null; then
			# 检查是否是中文字符（GB2312范围的汉字，首字节 0xE4-0xE9）
			# 中文字符占2列，圆点 ● (U+25CF) 等符号只占1列
			if [ "$byte" -ge 228 ] && [ "$byte" -le 233 ]; then
				w=$((w + 2))
			else
				w=$((w + 1))
			fi
			# 跳过剩余的多字节（UTF-8后续字节在 0x80-0xBF 范围内）
			i=$((i + 1))
			while [ "$i" -lt "$len" ]; do
				printf -v byte "%d" "'${s:$i:1}"
				if [ "$byte" -lt 128 ] || [ "$byte" -ge 192 ]; then
					break
				fi
				i=$((i + 1))
			done
		else
			w=$((w + 1))
			i=$((i + 1))
		fi
	done
	echo "$w"
}

# 右侧补空格到指定可见列数
# 用法: pad_right "1Panel面板" 15
pad_right() {
	local s=$1 target=$2 cur pad
	cur=$(str_width "$s")
	pad=$((target - cur))
	if [ "$pad" -gt 0 ]; then
		printf "%s%${pad}s" "$s" ""
	else
		printf "%s" "$s"
	fi
}

# 左侧补空格到指定可见列数
pad_left() {
	local s=$1 target=$2 cur pad
	cur=$(str_width "$s")
	pad=$((target - cur))
	if [ "$pad" -gt 0 ]; then
		printf "%${pad}s%s" "" "$s"
	else
		printf "%s" "$s"
	fi
}

# 输出一段对齐的"编号 + 名称"菜单项
# 用法: menu_line 1 "1Panel面板" 15
#       配合 printf:  printf "%s  %s  %s\n" "$(menu_line 1 "1Panel面板")" "$(menu_line 2 "宝塔面板")" "$(menu_line 3 "aaPanel面板")"
menu_line() {
	local num=$1 name=$2 target=${3:-20}
	local prefix="${num}."
	# 编号列: 数字+点 共 target 列, 右对齐名称
	local cur pad
	cur=$(str_width "$prefix")
	pad=$((4 - cur))    # 编号段占 4 列 ("1.  " 这种)
	if [ "$pad" -lt 0 ]; then pad=0; fi
	printf "%s%${pad}s" "$prefix" ""
	pad_right "$name" "$target"
}

# 渲染一行 N 个单元格 (虚拟表格, 不显示边框)
# 内部委托给 lib/_render_grid.py (Python) 实现, 准确处理 CJK / ANSI 颜色码 / 超长切行
# 用法: render_grid_row col_width c1 c2 c3 ...
render_grid_row() {
	local col_width=$1
	shift
	# 用 0x1F (Unit Separator) 分隔 cell, 不会出现在 app 名称里
	local SEP=$'\x1f'
	local _input=""
	local _c
	for _c in "$@"; do
		_input+="${_c}${SEP}"
	done
	local _script_dir
	_script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
	printf '%s' "$_input" | python3 "$_script_dir/_render_grid.py" "$col_width"
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

# 注意: download_file / show_progress 不在本文件, 而是内联在
#   lib/update.sh (j update 用)  和  install.sh (一键安装用)
# 之所以不放在这里统一: utils.sh 在 update.sh 之后被 source, 让 update 调本文件
# 的 download_file 会找不到; 各自内联更稳, 也避免模块间加载顺序的隐式依赖.
}
