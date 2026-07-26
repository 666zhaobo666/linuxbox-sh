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
	init_appstore_registry 2>/dev/null || true
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
