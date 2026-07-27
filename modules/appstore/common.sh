#!/usr/bin/env bash
# LinuxBox AppStore Common Framework & Helpers

# 检查Docker应用是否安装
check_docker_app() {
	if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q "^${docker_name}$" ; then
		check_docker="${green}已安装${white}"
		return 0
	else
		check_docker="${grey}未安装${white}"
		return 1
	fi
}

# 检查Docker应用的访问地址
check_docker_app_ip() {
	echo -e "${pink}------------------------${white}"
	echo "访问地址:"
	ip_address

	if [ -n "$ipv4_address" ]; then
		echo "http://$ipv4_address:${docker_port}"
	fi

	if [ -n "$ipv6_address" ]; then
		echo "http://[$ipv6_address]:${docker_port}"
	fi

	local search_pattern1="$ipv4_address:${docker_port}"
	local search_pattern2="127.0.0.1:${docker_port}"

	for file in /home/web/conf.d/*; do
		if [ -f "$file" ]; then
			if grep -q "$search_pattern1" "$file" 2>/dev/null || grep -q "$search_pattern2" "$file" 2>/dev/null; then
				echo "https://$(basename "$file" | sed 's/\.conf$//')"
			fi
		fi
	done
}

# 检查Docker镜像更新
check_docker_image_update() {
	local container_name=$1
	local country=$(curl -s --max-time 2 ipinfo.io/country || echo "")
	if [[ "$country" == "CN" ]]; then
		update_status=""
		return
	fi

	# 获取容器的创建时间和镜像名称
	local container_info=$(docker inspect --format='{{.Created}},{{.Config.Image}}' "$container_name" 2>/dev/null)
	local container_created=$(echo "$container_info" | cut -d',' -f1)
	local image_name=$(echo "$container_info" | cut -d',' -f2)

	# 提取镜像仓库和标签
	local image_repo=${image_name%%:*}
	local image_tag=${image_name##*:}

	# 默认标签为 latest
	[[ "$image_repo" == "$image_tag" ]] && image_tag="latest"

	# 添加对官方镜像的支持
	[[ "$image_repo" != */* ]] && image_repo="library/$image_repo"

	# 从 Docker Hub API 获取镜像发布时间
	local hub_info=$(curl -s --max-time 3 "https://hub.docker.com/v2/repositories/$image_repo/tags/$image_tag")
	local last_updated=$(echo "$hub_info" | jq -r '.last_updated' 2>/dev/null)

	# 验证获取的时间
	if [[ -n "$last_updated" && "$last_updated" != "null" ]]; then
		local container_created_ts=$(date -d "$container_created" +%s 2>/dev/null)
		local last_updated_ts=$(date -d "$last_updated" +%s 2>/dev/null)

		# 比较时间戳
		if [[ $container_created_ts -lt $last_updated_ts ]]; then
			update_status="${gl_huang}发现新版本!${white}"
		else
			update_status=""
		fi
	else
		update_status=""
	fi
}

# 检查panel是否安装
check_panel_app() {
	if $panel_path > /dev/null 2>&1; then
		check_panel="${green}已安装${white}"
	else
		check_panel="${grey}未安装${white}"
	fi
}

# 面板管理
panel_manage() {
	while true; do
		clear
		check_panel_app
		echo -e "$panelname $check_panel"
		echo "${panelname}是一款时下流行且强大的运维管理面板."
		echo "官网介绍: $panelurl "

		# 面板应用: 不走端口表, 只展示官网作为参考入口
		echo ""
		echo -e "${cyan}参考入口${white}:  ${green}$panelurl${white}"

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
				install wget
				iptables_open
				panel_app_install

				check_panel_app
				if [ "$check_panel" = "${green}已安装${white}" ]; then
					add_app_id
				fi
				;;
			2)
				# 修复检测 bug: 未装就管理会误标为已装
				check_panel_app
				if [ "$check_panel" = "${green}已安装${white}" ]; then
					panel_app_manage
					add_app_id
				else
					echo -e "${red}面板未安装, 请先安装${white}"
					sleep 1
				fi
				;;
			3)
				panel_app_uninstall

				remove_app_id
				;;
			*)
				break
				;;
		esac
		break_end
	done
}

# 分类显示名称
declare -g -A CAT_NAMES 2>/dev/null || declare -A CAT_NAMES
CAT_NAMES=(
	["panel"]="运维面板"
	["media"]="媒体娱乐"
	["ai"]="AI与大模型"
	["tools"]="实用工具"
	["storage"]="存储网盘"
	["network"]="网络安全"
)

# 按分类渲染应用列表子菜单
render_category_apps_menu() {
	local cat_key="$1"
	local cat_title="${CAT_NAMES[$cat_key]:-$cat_key}"

	while true; do
		dynamic_scan_installed_apps
		clear
		echo -e "${green}===== 应用分类: ${cat_title} =====${white}"
		echo -e "[图例] ${green}●${white} 已安装  ${red}●${white} 未安装"
		echo ""
		docker_tato 2>/dev/null || true
		echo -e "${pink}------------------------------------------------------------------------------------${white}"

		local app_ids=()
		local id
		for id in {1..110}; do
			if [ "${APP_META_CAT[$id]:-}" = "$cat_key" ]; then
				app_ids+=("$id")
			fi
		done

		if [ ${#app_ids[@]} -eq 0 ]; then
			echo -e "${yellow}该分类下暂无应用${white}"
			break_end
			return
		fi

		local col=0
		for id in "${app_ids[@]}"; do
			local name="${APP_META_NAME[$id]:-未知应用}"
			local status="${APP_META_STATUS[$id]:-normal}"
			local dot_str="${red}●${white}"
			if [ "${INSTALLED_MAP[$id]:-0}" = "1" ]; then
				dot_str="${green}●${white}"
			fi
			if [ "$status" = "offline" ]; then
				name="${name}(已下线)"
			fi

			local name_len=${#name}
			local real_len=0
			for ((j=0; j<name_len; j++)); do
				local c="${name:$j:1}"
				if [ $(printf "%d" "'$c" 2>/dev/null || echo 127) -le 127 ]; then
					((real_len+=1))
				else
					((real_len+=2))
				fi
			done
			local pad_len=$((36 - real_len))
			[ $pad_len -lt 0 ] && pad_len=1
			local padding=$(printf "%*s" $pad_len "")

			printf "%b ${cyan}%-4s${white}%s%s" "${dot_str}" "${id}." "${name}" "${padding}"
			((col+=1))
			if [ $((col % 3)) -eq 0 ]; then
				echo ""
			fi
		done
		[ $((col % 3)) -ne 0 ] && echo ""

		echo -e "${pink}------------------------------------------------------------------------------------${white}"
		echo -e "${yellow}0.   ${white}返回应用分类菜单                               ${cyan}666. ${white}查看已安装应用"
		echo -e "${pink}------------------------------------------------------------------------------------${white}"

		read -e -p "输入应用编号进入对应功能 (0 返回): " choice
		case "$choice" in
			0|"") return ;;
			666) render_666_installed_view ;;
			*)
				if [[ "$choice" =~ ^[0-9]+$ ]] && [ -n "${APP_META_NAME[$choice]:-}" ]; then
					dispatch_app_execution "$choice"
				else
					echo -e "${red}无效输入 $choice${white}"
					sleep 1
				fi
				;;
		esac
	done
}

# 模糊搜索应用
render_app_search_menu() {
	clear
	echo -e "${green}===== 应用搜索 =====${white}"
	read -e -p "请输入应用名称关键字: " kw
	if [ -z "$kw" ]; then
		return
	fi

	dynamic_scan_installed_apps
	local matched_ids=()
	local id name
	for id in {1..110}; do
		name="${APP_META_NAME[$id]:-}"
		if echo "$name" | grep -qi "$kw"; then
			matched_ids+=("$id")
		fi
	done

	if [ ${#matched_ids[@]} -eq 0 ]; then
		echo -e "${yellow}未搜索到匹配 '${kw}' 的应用。${white}"
		sleep 1.5
		return
	fi

	echo -e "${green}搜索到 ${#matched_ids[@]} 个匹配项：${white}"
	echo -e "${pink}------------------------------------------------------------------------------------${white}"
	for id in "${matched_ids[@]}"; do
		local name="${APP_META_NAME[$id]:-}"
		local dot_str="${red}●${white}"
		[ "${INSTALLED_MAP[$id]:-0}" = "1" ] && dot_str="${green}●${white}"
		echo -e "  ${dot_str} ${cyan}${id}.${white} ${name}  (分类: ${CAT_NAMES[${APP_META_CAT[$id]}]})"
	done
	echo -e "${pink}------------------------------------------------------------------------------------${white}"
	read -e -p "输入要操作的应用编号 (0 返回): " choice
	if [ "$choice" != "0" ] && [ -n "${APP_META_NAME[$choice]:-}" ]; then
		dispatch_app_execution "$choice"
	fi
}

# 传统全量展现视图 (1..110 传统三列打印)
render_full_grid_menu() {
	while true; do
		dynamic_scan_installed_apps
		clear
		echo -e "${green}===== 全量应用列表 =====${white}"
		echo -e "[图例] ${green}●${white} 已安装  ${red}●${white} 未安装"
		echo ""
		docker_tato 2>/dev/null || true
		echo -e "${pink}------------------------------------------------------------------------------------${white}"

		for i in {1..110}; do
			local name="${APP_META_NAME[$i]:-}"
			[ -z "$name" ] && continue
			local dot_str="${red}●${white}"
			[ "${INSTALLED_MAP[$i]:-0}" = "1" ] && dot_str="${green}●${white}"

			local status="${APP_META_STATUS[$i]:-normal}"
			if [ "$status" = "offline" ]; then
				name="${name}(已下线)"
			fi

			local name_len=${#name}
			local real_len=0
			for ((j=0; j<name_len; j++)); do
				local c="${name:$j:1}"
				if [ $(printf "%d" "'$c" 2>/dev/null || echo 127) -le 127 ]; then
					((real_len+=1))
				else
					((real_len+=2))
				fi
			done
			local pad_len=$((36 - real_len))
			[ $pad_len -lt 0 ] && pad_len=1
			local padding=$(printf "%*s" $pad_len "")
			printf "%b ${cyan}%-4s${white}%s%s" "${dot_str}" "${i}." "${name}" "${padding}"
			if [ $((i % 3)) -eq 0 ]; then
				echo ""
			fi
		done
		echo ""

		echo -e "${pink}------------------------------------------------------------------------------------${white}"
		echo -e "${yellow}0.   ${white}返回上一级菜单                                   ${cyan}666. ${white}查看已安装应用"
		echo -e "${pink}------------------------------------------------------------------------------------${white}"

		read -e -p "输入应用编号进行操作 (0 返回): " choice
		case "$choice" in
			0|"") return ;;
			666) render_666_installed_view ;;
			*)
				if [[ "$choice" =~ ^[0-9]+$ ]] && [ -n "${APP_META_NAME[$choice]:-}" ]; then
					dispatch_app_execution "$choice"
				else
					echo -e "${red}无效选择 $choice${white}"
					sleep 1
				fi
				;;
		esac
	done
}

# ----------------------------------------------------------------------------
# 应用市场主入口
# ----------------------------------------------------------------------------
linux_app() {
	while true; do
		dynamic_scan_installed_apps
		clear
		echo -e "${green}====================================================================================${white}"
		echo -e "${cyan}                              LinuxBox 应用商店 (AppStore)${white}"
		echo -e "${green}====================================================================================${white}"
		echo -e "已动态检测到 ${green}${#INSTALLED_IDS[@]}${white} 个已安装应用  |  输入 ${cyan}666${white} 可直接进入【已安装管理中心】"
		echo -e "${pink}------------------------------------------------------------------------------------${white}"
		echo -e "${cyan}【分类导航】${white}"
		echo -e "  1. 运维面板"
		echo -e "  2. 媒体娱乐"
		echo -e "  3. AI大模型"
		echo -e "  4. 实用工具"
		echo -e "  5. 存储网盘"
		echo -e "  6. 网络安全"
		echo -e "${pink}------------------------------------------------------------------------------------${white}"
		echo -e "${cyan}【快捷视图与检索】${white}"
		echo -e "  7. 搜索应用 (支持名称模糊搜索)"
		echo -e "  8. 全量浏览模式"
		echo -e "  666. 查看已安装应用列表"
		echo -e "${pink}------------------------------------------------------------------------------------${white}"
		echo -e "${yellow}0. 返回主菜单${white}"
		echo -e "${pink}------------------------------------------------------------------------------------${white}"

		read -e -p "请输入选择 [0-8 或 666]: " main_choice
		case "$main_choice" in
			0|"") return ;;
			1) render_category_apps_menu "panel" ;;
			2) render_category_apps_menu "media" ;;
			3) render_category_apps_menu "ai" ;;
			4) render_category_apps_menu "tools" ;;
			5) render_category_apps_menu "storage" ;;
			6) render_category_apps_menu "network" ;;
			7) render_app_search_menu ;;
			8) render_full_grid_menu ;;
			666) render_666_installed_view ;;
			*)
				if [[ "$main_choice" =~ ^[0-9]+$ ]] && [ -n "${APP_META_NAME[$main_choice]:-}" ]; then
					dispatch_app_execution "$main_choice"
				else
					echo -e "${red}无效选择, 请重新输入 !${white}"
					sleep 1
				fi
				;;
		esac
	done
}

# ----------------------------------------------------------------------------
# 增强型 端口冲突检测与自动更换逻辑
# ----------------------------------------------------------------------------
check_port_in_use() {
	local port="$1"
	[ -z "$port" ] && return 1
	if command -v netstat >/dev/null 2>&1; then
		netstat -tuln | grep -E ":${port}\\b" >/dev/null 2>&1 && return 0
	elif command -v ss >/dev/null 2>&1; then
		ss -tuln | grep -E ":${port}\\b" >/dev/null 2>&1 && return 0
	elif command -v lsof >/dev/null 2>&1; then
		lsof -i:"${port}" >/dev/null 2>&1 && return 0
	fi
	(exec 3<"/dev/tcp/127.0.0.1/${port}") >/dev/null 2>&1 && return 0
	return 1
}

assign_available_port() {
	local default_p="$1"
	local prompt_label="${2:-设置通信端口}"
	local target_p="$default_p"

	if [ -n "$default_p" ] && check_port_in_use "$default_p"; then
		echo -e "${yellow}[!] 默认端口 ${default_p} 已被占用，正在自动寻找可用端口...${white}"
		local candidate=$((default_p + 1))
		while check_port_in_use "$candidate"; do
			candidate=$((candidate + 1))
		done
		echo -e "${green}[✓] 已为您自动推荐可用端口: ${candidate}${white}"
		target_p="$candidate"
	fi

	read -e -p "${prompt_label} (默认 ${target_p}): " user_input
	user_input="${user_input:-$target_p}"

	while check_port_in_use "$user_input" && [ "$user_input" != "$default_p" ]; do
		echo -e "${red}[!] 端口 ${user_input} 仍处于占用状态，请重新输入可用端口!${white}"
		read -e -p "${prompt_label}: " user_input
	done
	echo "$user_input"
}

# ----------------------------------------------------------------------------
# 动态 Docker 扫描 + 面板路径检测 组合判定
# ----------------------------------------------------------------------------
declare -g -A INSTALLED_MAP 2>/dev/null || declare -A INSTALLED_MAP
INSTALLED_IDS=()

dynamic_scan_installed_apps() {
	INSTALLED_MAP=()
	INSTALLED_IDS=()
	local docker_ps_names=$'\n'
	if command -v docker >/dev/null 2>&1; then
		# Put all names inside newlines for exact matching without grep
		docker_ps_names=$'\n'$(docker ps -a --format '{{.Names}}' 2>/dev/null)$'\n'
	fi

	local id d_name p_path is_inst
	local nl=$'\n'
	for id in {1..110}; do
		d_name="${APP_META_DOCKER[$id]:-}"
		p_path="${APP_META_PANEL_PATH[$id]:-}"
		is_inst=0

		if [ -n "$d_name" ]; then
			if [[ "$docker_ps_names" == *"${nl}${d_name}${nl}"* ]]; then
				is_inst=1
			fi
		fi

		if [ $is_inst -eq 0 ] && [ -n "$p_path" ]; then
			if eval "$p_path >/dev/null 2>&1" || [ -e "$p_path" ]; then
				is_inst=1
			fi
		fi

		if [ $is_inst -eq 1 ]; then
			INSTALLED_MAP["$id"]=1
			INSTALLED_IDS+=("$id")
		fi
	done

	if [ -d /home/docker ]; then
		if [ ${#INSTALLED_IDS[@]} -gt 0 ]; then
			printf "%s\n" "${INSTALLED_IDS[@]}" > /home/docker/appno.txt 2>/dev/null || true
		else
			> /home/docker/appno.txt 2>/dev/null || true
		fi
	fi
}

# ----------------------------------------------------------------------------
_pad_string() {
	local str="$1"
	local target="$2"
	local w=0
	for ((i=0; i<${#str}; i++)); do
		[[ "${str:i:1}" =~ [a-zA-Z0-9_\.\-\ ] ]] && ((w+=1)) || ((w+=2))
	done
	local p=$((target - w))
	local s="$str"
	for ((i=0; i<p; i++)); do s="$s "; done
	echo -n "$s"
}

render_666_installed_view() {
	while true; do
		dynamic_scan_installed_apps
		clear
		echo -e "${green}====================================================================================${white}"
		echo -e "${cyan}                        LinuxBox 已安装应用中心 (视图 666)${white}"
		echo -e "${green}====================================================================================${white}"
		echo ""

		if [ ${#INSTALLED_IDS[@]} -eq 0 ]; then
			echo -e "${yellow}目前未检测到任何已安装的应用或容器。${white}"
			echo -e "${cyan}提示: 本系统会自动联动 Docker 容器扫描与面板路径检测，安装后将实时显示在这里。${white}"
			echo ""
			echo -e "${pink}------------------------------------------------------------------------------------${white}"
			echo -e "${yellow}0.   ${white}返回应用市场"
			echo -e "${pink}------------------------------------------------------------------------------------${white}"
			read -e -p "输入 0 返回应用市场: " _null_choice
			return
		fi
		echo -e "${white}共检测到 ${green}${#INSTALLED_IDS[@]}${white} 个已安装应用："
		echo -e "${pink}------------------------------------------------------------------------------------${white}"
		echo -e "${cyan}ID    | 应用名称                   | 分类             | 运行状态         | 默认端口${white}"
		echo -e "${pink}------------------------------------------------------------------------------------${white}"

		local sorted
		sorted=$(printf "%s\n" "${INSTALLED_IDS[@]}" | sort -n)
		while read -r id; do
			[ -n "$id" ] || continue
			local name="${APP_META_NAME[$id]:-未知应用}"
			local cat="${APP_META_CAT[$id]:-other}"
			local d_name="${APP_META_DOCKER[$id]:-}"
			local port="${APP_META_PORT[$id]:-}"
			local status_str="${red}● 停止${white}"
			local status_len=6

			if [ -n "$d_name" ] && command -v docker >/dev/null 2>&1; then
				local d_state
				d_state=$(docker inspect --format={{.State.Status}} "$d_name" 2>/dev/null)
				if [ "$d_state" = "running" ]; then
					status_str="${green}● 运行中${white}"
					status_len=8
				elif [ -n "$d_state" ]; then
					status_str="${yellow}● ${d_state}${white}"
					status_len=$((2 + ${#d_state}))
				fi
			else
				status_str="${green}● 已就绪${white}"
				status_len=8
			fi

			local cat_cn="实用工具"
			case "$cat" in
				panel) cat_cn="运维面板" ;;
				media) cat_cn="媒体娱乐" ;;
				ai) cat_cn="AI大模型" ;;
				tools) cat_cn="实用工具" ;;
				storage) cat_cn="存储网盘" ;;
				network) cat_cn="网络安全" ;;
			esac

			local id_pad=$(_pad_string "$id" 5)
			local name_pad=$(_pad_string "$name" 26)
			local cat_pad=$(_pad_string "$cat_cn" 16)
			
			local stat_pad_len=$((16 - status_len))
			local stat_pad=""
			for ((i=0; i<stat_pad_len; i++)); do stat_pad="$stat_pad "; done

			echo -e "${cyan}${id_pad}${white} | ${name_pad} | ${cat_pad} | ${status_str}${stat_pad} | ${port:--}"
		done <<< "$sorted"

		echo -e "${pink}------------------------------------------------------------------------------------${white}"
		echo -e "${yellow}0.   ${white}返回上一级"
		echo -e "${pink}------------------------------------------------------------------------------------${white}"
		read -e -p "输入应用编号进入对应详情管理 (0 返回): " jump_choice
		if [ "$jump_choice" = "0" ] || [ -z "$jump_choice" ]; then
			return
		fi
		if [ -n "${APP_META_NAME[$jump_choice]:-}" ]; then
			dispatch_app_execution "$jump_choice"
		else
			echo -e "${red}无效编号 $jump_choice${white}"
			sleep 1
		fi
	done
}

_render_installed_list() {
	render_666_installed_view
}

# ----------------------------------------------------------------------------
# 规范化生命周期管理: 修改端口、修改配置、重启、日志、干净卸载
# ----------------------------------------------------------------------------
app_lifecycle_set_port() {
	local d_name="$1"
	local cur_port="$2"
	if [ -z "$d_name" ]; then
		echo -e "${red}该应用不支持动态调整 Docker 端口${white}"
		sleep 1
		return
	fi
	echo -e "${cyan}--- 修改应用 [${d_name}] 访问端口 ---${white}"
	local new_port
	new_port=$(assign_available_port "${cur_port:-8080}" "请输入新的宿主机端口")

	echo "$new_port" > "/home/docker/${d_name}_port.conf"
	echo "$new_port" > "/home/docker/${d_name}_ports.txt"
	echo -e "${green}端口修改为 ${new_port}，即将重载/重启应用容器...${white}"
	docker restart "$d_name" 2>/dev/null || true
	echo -e "${green}端口修改完成!${white}"
	sleep 1.5
}

app_lifecycle_edit_config() {
	local d_name="$1"
	local app_dir="/home/docker/${d_name}"
	if [ ! -d "$app_dir" ]; then
		echo -e "${yellow}数据目录 ${app_dir} 不存在或无需要编辑的文本配置。${white}"
		sleep 1.5
		return
	fi
	local cfg_file
	cfg_file=$(find "$app_dir" -maxdepth 2 -type f \( -name "*.env" -o -name "*.conf" -o -name "*.json" -o -name "*.yml" -o -name "*.yaml" \) 2>/dev/null | head -n 1)
	if [ -z "$cfg_file" ]; then
		echo -e "${yellow}在 ${app_dir} 中未找到标准配置文件 (.env/.yaml/.conf/.json)${white}"
		read -e -p "请输入欲编辑的文件路径: " cfg_file
		[ -z "$cfg_file" ] && return
	fi

	local editor="nano"
	command -v nano >/dev/null 2>&1 || editor="vi"
	$editor "$cfg_file"

	read -e -p "修改完成，是否立即重启容器应用生效? [Y/n]: " choice
	if [[ "${choice:-Y}" =~ ^[Yy]$ ]]; then
		docker restart "$d_name" 2>/dev/null || true
		echo -e "${green}容器已成功重启。${white}"
		sleep 1
	fi
}

app_lifecycle_restart() {
	local d_name="$1"
	if [ -n "$d_name" ] && command -v docker >/dev/null 2>&1; then
		echo -e "${cyan}正在重启容器 ${d_name}...${white}"
		if docker restart "$d_name"; then
			echo -e "${green}重启成功!${white}"
		else
			echo -e "${red}重启失败，请检查容器状态!${white}"
		fi
	else
		echo -e "${yellow}未指定 Docker 容器名称或环境不存在 Docker${white}"
	fi
	sleep 1.5
}

app_lifecycle_logs() {
	local d_name="$1"
	if [ -n "$d_name" ] && command -v docker >/dev/null 2>&1; then
		clear
		echo -e "${cyan}===== 实时日志: ${d_name} (按 Ctrl+C 退出日志查看) =====${white}"
		echo ""
		docker logs --tail 100 -f "$d_name"
	else
		echo -e "${yellow}未检测到 Docker 容器${white}"
		sleep 1.5
	fi
}

app_lifecycle_uninstall() {
	local d_name="$1"
	local d_img="$2"
	local default_uninstall_cmd="$3"

	echo -e "${red}--- 卸载确认: ${d_name} ---${white}"
	read -e -p "确定要卸载该应用吗? [y/N]: " confirm
	if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
		echo "已取消卸载。"
		sleep 1
		return 1
	fi

	if [ -n "$default_uninstall_cmd" ] && declare -F "$default_uninstall_cmd" >/dev/null 2>&1; then
		eval "$default_uninstall_cmd"
	elif [ -n "$d_name" ] && command -v docker >/dev/null 2>&1; then
		echo -e "${yellow}正在停止并移除容器 ${d_name}...${white}"
		docker rm -f "$d_name" 2>/dev/null || true
		if [ -n "$d_img" ]; then
			docker rmi -f "$d_img" 2>/dev/null || true
		fi
	fi

	rm -f "/home/docker/${d_name}_port.conf" "/home/docker/${d_name}_ports.txt" 2>/dev/null

	if [ -n "$d_name" ] && [ -d "/home/docker/${d_name}" ]; then
		echo ""
		echo -e "${yellow}[!] 检测到持久化数据目录: /home/docker/${d_name}${white}"
		read -e -p "是否彻底清理该数据目录? (保留数据请输入 N) [y/N]: " clean_data
		if [[ "$clean_data" =~ ^[Yy]$ ]]; then
			rm -rf "/home/docker/${d_name}"
			echo -e "${green}数据目录已被彻底清理。${white}"
		else
			echo -e "${cyan}已保留数据目录: /home/docker/${d_name}${white}"
		fi
	fi

	dynamic_scan_installed_apps
	echo -e "${green}卸载已完成。${white}"
	sleep 1.5
	return 0
}

# ----------------------------------------------------------------------------
# 统一调度器
# ----------------------------------------------------------------------------
dispatch_app_execution() {
	local app_id="$1"
	[ -z "$app_id" ] && return
	local func_name="${APP_META_FUNC[$app_id]:-}"
	local status="${APP_META_STATUS[$app_id]:-normal}"

	if [ "$status" = "offline" ]; then
		# Check if installed
		local is_installed=0
		for id in "${INSTALLED_IDS[@]}"; do
			if [ "$id" = "$app_id" ]; then
				is_installed=1
				break
			fi
		done

		if [ $is_installed -eq 0 ]; then
			clear
			echo -e "${yellow}================================================================${white}"
			echo -e "${red}[已下线] ${APP_META_NAME[$app_id]:-未知应用}${white}"
			echo -e "${yellow}================================================================${white}"
			echo -e "说明: ${APP_META_DESC[$app_id]:-该应用目前缺少公开维护的镜像或脚本。}"
			echo "为保障系统稳定与安全，该应用已隐藏自动安装脚本。"
			echo ""
			break_end
			return
		else
			APP_OFFLINE=1
		fi
	else
		APP_OFFLINE=0
	fi

	if [ -n "$func_name" ] && declare -F "$func_name" >/dev/null 2>&1; then
		eval "$func_name"
	else
		echo -e "${red}错误: 无法找到应用入口函数 $func_name${white}"
		sleep 1.5
	fi
}

_linux_app_dispatch() {
	dispatch_app_execution "$1"
}


# ----------------------------------------------------------------------------
# 多端口注册与恢复机制 (兼容多端口 App 表格渲染)
# ----------------------------------------------------------------------------
APP_PORTS_LABELS=()
APP_PORTS_NUMBERS=()

add_app_port() {
	APP_PORTS_LABELS+=("$1")
	APP_PORTS_NUMBERS+=("$2")
}

clear_app_ports() {
	APP_PORTS_LABELS=()
	APP_PORTS_NUMBERS=()
}

save_app_ports() {
	[ -z "${docker_name:-}" ] && return
	mkdir -p /home/docker 2>/dev/null || true
	> "/home/docker/${docker_name}_ports.txt" 2>/dev/null || true
	for i in "${!APP_PORTS_LABELS[@]}"; do
		echo "${APP_PORTS_LABELS[$i]}|${APP_PORTS_NUMBERS[$i]}" >> "/home/docker/${docker_name}_ports.txt" 2>/dev/null || true
	done
}

load_app_ports() {
	[ -z "${docker_name:-}" ] && return
	local port_file="/home/docker/${docker_name}_ports.txt"
	[ ! -f "$port_file" ] && return

	APP_PORTS_LABELS=()
	APP_PORTS_NUMBERS=()
	while IFS="|" read -r label port; do
		[ -n "$label" ] && [ -n "$port" ] && {
			APP_PORTS_LABELS+=("$label")
			APP_PORTS_NUMBERS+=("$port")
		}
	done < "$port_file"
}

get_primary_port() {
	if [ ${#APP_PORTS_NUMBERS[@]} -gt 0 ]; then
		echo "${APP_PORTS_NUMBERS[0]}"
	elif [ -n "${docker_port:-}" ]; then
		echo "$docker_port"
	fi
}

_auto_register_fallback_port() {
	if [ ${#APP_PORTS_NUMBERS[@]} -eq 0 ] && [ -n "${docker_port:-}" ]; then
		add_app_port "${access_label:-Web 端口}" "$docker_port"
	fi
}


# 输出: "not_installed" | "running <started_iso>" | "<state>" (exited/paused/...)
get_docker_app_status() {
	if ! docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q "^${docker_name}$"; then
		echo "not_installed"
		return
	fi
	local state started
	state=$(docker inspect --format='{{.State.Status}}' "$docker_name" 2>/dev/null)
	started=$(docker inspect --format='{{.State.StartedAt}}' "$docker_name" 2>/dev/null)
	if [ "$state" = "running" ] && [ -n "$started" ]; then
		echo "running $started"
	else
		echo "$state"
	fi
}

# 把秒数格式化成 "X天Y小时Z分" / "X小时Y分" / "X分Y秒"
format_uptime() {
	local secs=$1
	if [ -z "$secs" ] || ! [[ "$secs" =~ ^[0-9]+$ ]]; then
		echo ""
		return
	fi
	local d=$((secs/86400))
	local h=$(((secs%86400)/3600))
	local m=$(((secs%3600)/60))
	local s=$((secs%60))
	if [ "$d" -gt 0 ]; then
		# 天+小时+分 (分可选, 不显示秒)
		if [ "$m" -gt 0 ]; then
			echo "${d}天${h}小时${m}分"
		elif [ "$h" -gt 0 ]; then
			echo "${d}天${h}小时"
		else
			echo "${d}天"
		fi
	elif [ "$h" -gt 0 ]; then
		echo "${h}小时${m}分"
	elif [ "$m" -gt 0 ]; then
		echo "${m}分${s}秒"
	else
		echo "${s}秒"
	fi
}

# 计算两个 ISO 时间戳之间的秒数
_secs_between() {
	local from="$1" to="$2"
	local from_ts to_ts
	from_ts=$(date -d "$from" +%s 2>/dev/null)
	to_ts=$(date -d "$to" +%s 2>/dev/null)
	if [ -z "$from_ts" ] || [ -z "$to_ts" ]; then
		echo "0"
	else
		echo $((to_ts - from_ts))
	fi
}

# 渲染端口表格 (边框 + 多行单元格: 同一端口 v4 / v6 各占一行)
render_app_ports_table() {
	_auto_register_fallback_port
	if [ ${#APP_PORTS_LABELS[@]} -eq 0 ]; then
		load_app_ports
	fi
	if [ ${#APP_PORTS_LABELS[@]} -eq 0 ]; then
		return
	fi

	ip_address
	local ipv4="${ipv4_address:-}"
	local ipv6="${ipv6_address:-}"

	# 列宽
	local LBL_W=22
	local PORT_W=6
	local URL_W=44

	# 绘制表格顶/中/底分隔线
	_hline() {
		printf "${cyan}+%*s+%*s+%*s+${white}\n" \
			$((LBL_W + 2)) '' $((PORT_W + 2)) '' $((URL_W + 2)) '' | tr ' ' '-'
	}

	# 绘制单行
	_row() {
		printf "${cyan}|${white} %-${LBL_W}s ${cyan}|${white} %-${PORT_W}s ${cyan}|${white} %-${URL_W}s ${cyan}|${white}\n" "$1" "$2" "$3"
	}

	_hline
	_row "标签" "端口" "访问地址"
	_hline

	local i label port v4 v6
	for i in "${!APP_PORTS_LABELS[@]}"; do
		label="${APP_PORTS_LABELS[$i]}"
		port="${APP_PORTS_NUMBERS[$i]}"
		v4=""
		v6=""
		[ -n "$ipv4" ] && v4="http://$ipv4:$port"
		[ -n "$ipv6" ] && v6="http://[$ipv6]:$port"
		# 第一行带 label/port
		if [ -n "$v4" ]; then
			_row "$label" "$port" "$v4"
			# v6 单独占一行 (空 label/port)
			[ -n "$v6" ] && _row "" "" "$v6"
		elif [ -n "$v6" ]; then
			_row "$label" "$port" "$v6"
		else
			_row "$label" "$port" "(本机无可用 IP)"
		fi
		_hline
	done
}

# 渲染应用运行状态行 (详情页用)
# 输出: "Docker 状态: running (已运行 3天 4小时)" / "Docker 状态: exited" / ...
render_app_status_line() {
	local status
	status=$(get_docker_app_status)
	case "$status" in
		not_installed)
			echo -e "${red}未安装${white}"
			;;
		running\ *)
			local started="${status#running }"
			local secs
			secs=$(_secs_between "$started" "$(date -Iseconds)")
			local uptime
			uptime=$(format_uptime "$secs")
			echo -e "${green}运行中${white} (已运行 ${uptime})"
			;;
		exited)
			echo -e "${yellow}已停止${white}"
			;;
		paused)
			echo -e "${yellow}已暂停${white}"
			;;
		*)
			echo -e "${yellow}${status}${white}"
			;;
	esac
}

# 检查 /home/web/conf.d/ 下哪些域名 conf 引用了此端口, 输出 https://<domain>
_render_domain_access() {
	local port="$1"
	if [ -z "$port" ]; then return; fi
	ip_address
	local search1="$ipv4_address:$port"
	local search2="127.0.0.1:$port"
	local f
	for f in /home/web/conf.d/*; do
		[ -f "$f" ] || continue
		if grep -q "$search1" "$f" 2>/dev/null || grep -q "$search2" "$f" 2>/dev/null; then
			echo "https://$(basename "$f" | sed 's/\.conf$//')"
		fi
	done
}


# Docker 应用管理 (合并版)
# ----------------------------------------------------------------------------
# 兼容两种应用风格, 通过 compose 标志自动选择路径:
#   1) 单容器风格 (94 个老 app): 调用方定义 docker_run, 框架用默认实现
#      app_id / docker_name / docker_img / docker_port / docker_describe
#      docker_url / docker_use / docker_passwd / app_size
#   2) compose 风格 (8 个老 app): 调用方定义 docker_app_install/update/uninstall
#      app_id / app_name / app_text / app_url / docker_name / docker_port / app_size
# 旧版变量名 (docker_name/docker_describe/docker_url) 与新版 (app_name/app_text/app_url)
# 通过 ${var:-fallback} 兼容, 老的 xxx_app 不用改一行.
# ----------------------------------------------------------------------------

# 单容器风格: 默认安装 (外层已 read app_port → docker_port)
_docker_app_default_install() {
	install jq
	install_docker
	docker_run
	setup_docker_dir
	echo "$docker_port" > "/home/docker/${docker_name}_port.conf"
}

# 单容器风格: 默认更新 (删容器+删镜像+重跑 docker_run)
_docker_app_default_update() {
	docker rm -f "$docker_name"
	docker rmi -f "$docker_img"
	docker_run
}

# 单容器风格: 默认卸载 (删容器+删镜像+清数据目录)
_docker_app_default_uninstall() {
	docker rm -f "$docker_name"
	docker rmi -f "$docker_img"
	rm -rf "/home/docker/$docker_name"
}

# 安装/更新后处理: 优先新式钩子 app_post_install / app_post_install_password,
# 兜底走老式 $docker_use / $docker_passwd (eval 执行)
_docker_app_post_install() {
	if declare -F app_post_install >/dev/null 2>&1; then
		app_post_install
	elif [ -n "${docker_use:-}" ]; then
		eval "$docker_use"
	fi
	if declare -F app_post_install_password >/dev/null 2>&1; then
		app_post_install_password
	elif [ -n "${docker_passwd:-}" ]; then
		eval "$docker_passwd"
	fi
}

# 统一入口
# 调用方需在调用前定义好变量, 可选定义 docker_app_install/update/uninstall (compose)
# 或 docker_run (单容器). 由 declare -F 自动检测.
# 显示标题用变量: 优先 app_* 新名, 兼容老 docker_* 命名.
docker_app() {
	# 选路径: 优先 compose 三函数, 否则用单容器默认实现
	local _install_cmd
	if declare -F docker_app_install >/dev/null 2>&1; then
		_install_cmd="docker_app_install"
	else
		_install_cmd="_docker_app_default_install"
	fi
	local _update_cmd
	if declare -F docker_app_update >/dev/null 2>&1; then
		_update_cmd="docker_app_update"
	else
		_update_cmd="_docker_app_default_update"
	fi
	local _uninstall_cmd
	if declare -F docker_app_uninstall >/dev/null 2>&1; then
		_uninstall_cmd="docker_app_uninstall"
	else
		_uninstall_cmd="_docker_app_default_uninstall"
	fi

	# 显示标题用变量: 兼容老 (docker_*) 与新 (app_*) 两种命名
	local _title="${app_name:-$docker_name}"
	local _text="${app_text:-$docker_describe}"
	local _url="${app_url:-$docker_url}"

	while true; do
		clear
		# 先执行检查函数, 确定容器状态
		check_docker_app
		check_docker_image_update "$docker_name"

		# 标题行 + 状态
		echo -e "$_title  $check_docker  $update_status"
		echo "$_text"
		echo "$_url"

		# 已安装时: 状态行 + 访问入口表
		if check_docker_app; then
			# 容器运行状态 (running/exited/...)
			local _status
			_status=$(get_docker_app_status)
			if [ "$_status" != "not_installed" ]; then
				local _line
				_line=$(render_app_status_line)
				echo ""
				echo -e "${cyan}应用状态${white}:  $_line"
			fi

			# 域名访问 (扫 /home/web/conf.d/)
			local _primary
			_primary=$(get_primary_port)
			local _domain
			_domain=$(_render_domain_access "$_primary")
			if [ -n "$_domain" ]; then
				echo -e "${cyan}域名访问${white}:  ${green}$_domain${white}"
			fi

			# 端口表 (支持多端口)
			render_app_ports_table
		fi

		echo ""
		echo -e "${cyan}------------------------------------------------------${white}"

		# 根据容器是否存在显示不同菜单
		if check_docker_app; then  # 容器存在 (返回0)
			if [ "${APP_OFFLINE:-0}" -eq 1 ]; then
				echo -e "${red}2. 卸载${white} (已下线应用不支持更新)"
			else
				echo -e "${green}1. 更新${white}              ${red}2. 卸载${white}"
			fi
		else  # 容器不存在 (返回非0)
			echo -e "${green}1. 安装${white}"
		fi

		echo -e "${pink}------------------------------------------------------${white}"

		# 仅当容器存在时显示域名和端口相关操作
		if check_docker_app; then
			echo -e "5. 添加域名访问      6. 删除域名访问"
			echo -e "7. 允许IP+端口访问   8. 阻止IP+端口访问"
			echo -e "${pink}------------------------------------------------------${white}"
		fi

		echo -e "${yellow}0. 返回上一级菜单${white}"
		echo -e "${pink}------------------------------------------------------${white}"

		read -e -p "请输入你的选择: " choice

		# 解析主端口 (供 ldnmp_Proxy 等使用)
		local _primary_port
		_primary_port=$(get_primary_port)

		# 根据容器状态限制可执行的选项
		if check_docker_app; then
			# 容器存在时允许的操作
			case $choice in
				1)  # 更新
					if [ "${APP_OFFLINE:-0}" -eq 1 ]; then
						echo -e "${red}该应用已下线，不支持更新!${white}"
						sleep 1.5
					else
						"$_update_cmd"
						if check_docker_app; then
							add_app_id
							save_app_ports
							clear
							echo "$docker_name 已经更新完成"
							render_app_ports_table
							echo ""
							_docker_app_post_install
						else
							echo -e "${red}${docker_name} 更新失败，请检查相关日志${white}"
							sleep 2
						fi
					fi
					;;
				2)  # 卸载
					"$_uninstall_cmd"
					rm -f /home/docker/${docker_name}_port.conf
					rm -f /home/docker/${docker_name}_ports.txt
					remove_app_id
					echo "应用已卸载"
					;;
				5)  # 添加域名访问
					echo "${docker_name}域名访问设置"
					add_yuming
					ldnmp_Proxy "${yuming}" 127.0.0.1 "${_primary_port}"
					block_container_port "$docker_name" "$ipv4_address"
					;;
				6)  # 删除域名访问
					echo "域名格式 example.com 不带https://"
					web_del
					;;
				7)  # 允许IP+端口访问
					clear_container_rules "$docker_name" "$ipv4_address"
					;;
				8)  # 阻止IP+端口访问
					block_container_port "$docker_name" "$ipv4_address"
					;;
				0)  # 返回上一级
					break
					;;
				*)  # 无效选项
					echo -e "${red}无效选择, 请重新输入 !${white}"
					sleep 1
					;;
			esac
		else
			# 容器不存在时仅允许安装和返回操作
			case $choice in
				1)  # 全新安装
					check_disk_space "$app_size"

					"$_install_cmd"
					if check_docker_app; then
						add_app_id
						save_app_ports
						clear
						echo "$docker_name 已经安装完成"
						render_app_ports_table
						echo ""
						_docker_app_post_install
						break_end
					else
						echo -e "${red}${docker_name} 安装失败，请检查报错信息${white}"
						sleep 2
					fi
					;;
				0)  # 返回上一级
					break
					;;
				*)  # 无效选项
					echo -e "${red}无效选择, 当前只能选择安装或返回 !${white}"
					sleep 1
					;;
			esac
		fi
		break_end
	done
}
