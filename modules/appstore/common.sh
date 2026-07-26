#!/usr/bin/env bash

#############################################################################
########################### 八、应用市场 (AppStore) ###########################
#############################################################################

# 定位 appstore 子目录路径
APPSTORE_MODULE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -d "${APPSTORE_MODULE_DIR}/appstore" ]; then
	APPSTORE_CORE_DIR="${APPSTORE_MODULE_DIR}/appstore"
elif [ -d "${LINUXBOX_LIB_DIR:-/usr/local/bin/linuxbox}/modules/appstore" ]; then
	APPSTORE_CORE_DIR="${LINUXBOX_LIB_DIR:-/usr/local/bin/linuxbox}/modules/appstore"
else
	APPSTORE_CORE_DIR="${APPSTORE_MODULE_DIR}"
fi

# 1. 加载元数据
if [ -f "${APPSTORE_CORE_DIR}/apps.sh" ]; then
	. "${APPSTORE_CORE_DIR}/apps.sh"
fi

# 2. 加载核心公共库与生命周期框架
if [ -f "${APPSTORE_CORE_DIR}/common.sh" ]; then
	. "${APPSTORE_CORE_DIR}/common.sh"
fi

# 3. 加载各分类逻辑模块
for _mod in panel media ai tools storage network; do
	if [ -f "${APPSTORE_CORE_DIR}/${_mod}.sh" ]; then
		. "${APPSTORE_CORE_DIR}/${_mod}.sh"
	fi
done

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
		echo -e "  1. 🛠️  运维面板 (1Panel/宝塔/NPM/青龙/雷池/DPanel...)"
		echo -e "  2. 🎬  媒体娱乐 (Emby/Jellyfin/Navidrome/PhotoPrism/Immich...)"
		echo -e "  3. 🤖  AI大模型 (OpenWebUI/Dify/Deepseek/LobeChat/NewAPI...)"
		echo -e "  4. 🧰  实用工具 (WebTop/CodeServer/OnlyOffice/UptimeKuma/StirlingPDF...)"
		echo -e "  5. 💾  存储网盘 (qBittorrent/Cloudreve/Nextcloud/Syncthing/SFTPGo...)"
		echo -e "  6. 🌐  网络安全 (DDNS-GO/Lucky/AdGuardHome/FRP/WireGuard/RustDesk...)"
		echo -e "${pink}------------------------------------------------------------------------------------${white}"
		echo -e "${cyan}【快捷视图与检索】${white}"
		echo -e "  7. 🔍  搜索应用 (支持名称模糊搜索)"
		echo -e "  8. 📋  全量浏览模式 (传统平铺视图 1~110)"
		echo -e "  666. ⭐ 查看已安装应用列表"
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
	local docker_ps_names=""
	if command -v docker >/dev/null 2>&1; then
		docker_ps_names=$(docker ps -a --format {{.Names}} 2>/dev/null || echo "")
	fi

	local id d_name p_path is_inst
	for id in {1..110}; do
		d_name="${APP_META_DOCKER[$id]:-}"
		p_path="${APP_META_PANEL_PATH[$id]:-}"
		is_inst=0

		if [ -n "$d_name" ]; then
			if echo "$docker_ps_names" | grep -q "^${d_name}$"; then
				is_inst=1
			fi
		fi

		if [ $is_inst -eq 0 ] && [ -n "$p_path" ]; then
			if eval "$p_path >/dev/null 2>&1" || [ -e "$p_path" ]; then
				is_inst=1
			fi
		fi

		if [ $is_inst -eq 0 ] && [ -n "$d_name" ] && [ -d "/home/docker/${d_name}" ]; then
			is_inst=1
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
# 666 已安装视图
# ----------------------------------------------------------------------------
render_666_installed_view() {
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
		break_end
		return
	fi

	echo -e "${white}共检测到 ${green}${#INSTALLED_IDS[@]}${white} 个已安装应用："
	echo -e "${pink}------------------------------------------------------------------------------------${white}"
	printf "${cyan}%-6s %-25s %-16s %-18s %-15s${white}\n" "ID" "应用名称" "分类" "运行状态" "默认端口"
	echo -e "${pink}------------------------------------------------------------------------------------${white}"

	local sorted
	sorted=$(printf %s
 "${INSTALLED_IDS[@]}" | sort -n)
	while read -r id; do
		[ -n "$id" ] || continue
		local name="${APP_META_NAME[$id]:-未知应用}"
		local cat="${APP_META_CAT[$id]:-other}"
		local d_name="${APP_META_DOCKER[$id]:-}"
		local port="${APP_META_PORT[$id]:-}"
		local status_str="${red}● 停止${white}"

		if [ -n "$d_name" ] && command -v docker >/dev/null 2>&1; then
			local d_state
			d_state=$(docker inspect --format={{.State.Status}} "$d_name" 2>/dev/null)
			if [ "$d_state" = "running" ]; then
				status_str="${green}● 运行中${white}"
			elif [ -n "$d_state" ]; then
				status_str="${yellow}● ${d_state}${white}"
			fi
		else
			status_str="${green}● 已就绪${white}"
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

		printf "${cyan}%-6s${white} %-25s %-16s %-26b %-15s\n" "$id" "$name" "$cat_cn" "$status_str" "${port:--}"
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
		clear
		echo -e "${yellow}================================================================${white}"
		echo -e "${red}[已下线] ${APP_META_NAME[$app_id]:-未知应用}${white}"
		echo -e "${yellow}================================================================${white}"
		echo -e "说明: ${APP_META_DESC[$app_id]:-该应用目前缺少公开维护的镜像或脚本。}"
		echo "为保障系统稳定与安全，该应用已隐藏自动安装脚本。"
		echo ""
		break_end
		return
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
