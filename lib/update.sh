#!/bin/bash
###########################################################################
########################### 模块化升级脚本 #################################
# 自包含设计: download_file 和 show_progress 在本文件内联, 不依赖 utils.sh
# 跟 install.sh 一样用一个总进度条, 失败时统一汇总, 不逐文件刷屏

##  下载文件 (无 shebang 验证, lib/ 下的库文件首行不一定是 shebang)
# 用法: download_file <remote_url> <local_path>
# 远端 404 (文件不存在) 时: 删本地副本 + 返回 0, 不阻塞升级
download_file() {
	local url="$1"
	local path="$2"
	local http_code
	http_code=$(curl -sSL --max-time 60 -o "$path" -w "%{http_code}" "$url" 2>/dev/null)
	# 404: 远端已删除, 同步删本地副本
	if [ "${http_code}" = "404" ]; then
		[ -e "${path}" ] && rm -f "${path}"
		return 0
	fi
	# 200 + 非空文件: 成功
	if [ "${http_code}" = "200" ] && [ -s "${path}" ]; then
		return 0
	fi
	return 1
}

##  进度条 (覆盖式, \r 回到行首)
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

## 获取远程版本号 (从入口脚本第一行 version="..." 抓)
get_remote_version() {
	local remote_entry_url="${url_proxy}raw.githubusercontent.com/${SCRIPT_REPO_OWNER}/${SCRIPT_REPO_NAME}/${SCRIPT_BRANCH}/${SCRIPT_FILE}"
	curl -s --max-time 20 "$remote_entry_url" | grep '^version=' | head -n 1 | cut -d '"' -f 2
}

## 主升级函数
update_script() {
	echo "${LX_update_check}"

	# 检查是否在模块化目录中运行
	if [ ! -d "${LINUXBOX_LIB_DIR}/lib" ] || [ ! -d "${LINUXBOX_LIB_DIR}/modules" ]; then
		echo -e "${red}错误: 未检测到模块化目录结构, 请检查安装${white}"
		sleep 2
		return 1
	fi

	# 清理已废弃的目录/文件 (跨版本兼容)
	# 当某个目录/文件被新版移除时, 启动时主动删本地残留
	# (download_file 的 404 处理是下载过程中兜底, 这里是启动时兜底)
	local stale_paths=("lang")
	local stale
	for stale in "${stale_paths[@]}"; do
		if [ -d "${LINUXBOX_LIB_DIR}/${stale}" ]; then
			rm -rf "${LINUXBOX_LIB_DIR}/${stale}"
			echo -e "${yellow}清理已废弃目录: ${stale}/${white}"
		fi
	done

	# 获取远程版本
	local remote_version
	remote_version=$(get_remote_version)
	if [ -z "$remote_version" ]; then
		echo -e "${red}错误: 无法获取远程版本信息, 请检查网络或代理设置${white}"
		sleep 2
		return 1
	fi

	# 比较版本号
	if [ "$remote_version" = "$version" ]; then
		# shellcheck disable=SC2059
		printf "$LX_update_latest\n" "$version"
		break_end
		return 0
	fi

	# 提示更新
	# shellcheck disable=SC2059
	printf "$LX_update_found\n" "$remote_version" "$version"
	read -r -p "是否确认更新？(y/n): " confirm
	if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
		echo "${LX_update_cancel}"
		break_end
		return 1
	fi

	# 整体备份
	local backup_dir="${SCRIPT_HOME}/backup/linuxbox_$(date +%Y%m%d%H%M%S)"
	mkdir -p "$backup_dir"
	cp -r "${LINUXBOX_LIB_DIR}/lib" "$backup_dir/" 2>/dev/null
	cp -r "${LINUXBOX_LIB_DIR}/modules" "$backup_dir/" 2>/dev/null
	cp "${LINUXBOX_LIB_DIR}/${SCRIPT_FILE}" "$backup_dir/" 2>/dev/null
	echo -e "${green}✓ 已创建备份: ${backup_dir}${white}"
	echo ""

	# 准备失败文件列表
	FAILED_FILES=()
	local entry_ok=0

	# 合并所有待下载文件, 用一个总进度条
	# 顺序: 入口 -> lib/ -> modules/
	# 入口必须先下完, 否则 lib/ 里可能引用新接口但代码没换
	local entries=()
	entries+=("${SCRIPT_FILE}|")  # 入口脚本, subdir 为空
	for f in "${LINUXBOX_LIB_FILES[@]}"; do
		entries+=("lib/${f}|lib")
	done
	for f in "${LINUXBOX_MOD_FILES[@]}"; do
		entries+=("modules/${f}|modules")
	done

	local total=${#entries[@]}
	local i=0

	echo -e "${cyan}正在全量更新 (共 ${total} 个文件)...${white}"

	# 单个总进度循环
	local entry path subdir file url target
	for entry in "${entries[@]}"; do
		i=$((i+1))
		show_progress "$i" "$total"
		path="${entry%%|*}"
		subdir="${entry##*|}"

		# 入口脚本特殊处理: 不能原地覆盖 (会破坏正在运行的自己), 走 tmp
		if [ -z "$subdir" ]; then
			local tmp="/tmp/${SCRIPT_FILE}.$$"
			if download_file "${url_proxy}raw.githubusercontent.com/${SCRIPT_REPO_OWNER}/${SCRIPT_REPO_NAME}/${SCRIPT_BRANCH}/${path}" "$tmp"; then
				chmod +x "$tmp"
				cp -f "$tmp" "${LINUXBOX_LIB_DIR}/${path}"
				rm -f "$tmp"
				entry_ok=1
			else
				rm -f "$tmp"
				FAILED_FILES+=("${path}")
			fi
		else
			file="${path##*/}"
			url="${url_proxy}raw.githubusercontent.com/${SCRIPT_REPO_OWNER}/${SCRIPT_REPO_NAME}/${SCRIPT_BRANCH}/${subdir}/${file}"
			target="${LINUXBOX_LIB_DIR}/${path}"
			mkdir -p "$(dirname "$target")"
			if download_file "$url" "$target"; then
				chmod +x "$target" 2>/dev/null || true
			else
				FAILED_FILES+=("${path}")
			fi
		fi
	done

	# 进度条结束换行
	echo ""
	echo ""

	# 汇总报告
	local total_failed=${#FAILED_FILES[@]}
	if [ $entry_ok -eq 1 ] && [ $total_failed -eq 0 ]; then
		echo -e "${green}========================================${white}"
		echo -e "${green}  升级成功!${white}"
		echo -e "${green}  新版本: ${remote_version}${white}"
		echo -e "${green}========================================${white}"
		echo ""
		# shellcheck disable=SC2059
		printf "$LX_shortcut\n" "$key"
		echo -e "${yellow}注意: 请重新运行脚本以使用新版本${white}"
		echo -e "${grey}备份保存在: ${backup_dir}${white}"

		# 清理旧备份 (保留最近 5 个)
		ls -t "${SCRIPT_HOME}/backup/" 2>/dev/null | tail -n +6 | while read -r old_backup; do
			rm -rf "${SCRIPT_HOME}/backup/${old_backup}"
		done

		break_end
		exit 0
	else
		echo -e "${yellow}========================================${white}"
		echo -e "${yellow}  升级未完成${white}"
		if [ $entry_ok -eq 0 ]; then
			echo -e "${red}  - 入口脚本下载失败, 已回滚${white}"
			cp -f "${backup_dir}/${SCRIPT_FILE}" "${LINUXBOX_LIB_DIR}/${SCRIPT_FILE}" 2>/dev/null
		fi
		if [ $total_failed -gt 0 ]; then
			echo -e "${yellow}  - 以下文件下载失败 (${total_failed} 个):${white}"
			local f
			for f in "${FAILED_FILES[@]}"; do
				echo -e "    ${red}✗${white} $f"
			done
		fi
		echo -e "${yellow}  请检查网络后重试, 或: ${white}"
		echo -e "${yellow}    bash <(curl -sL https://raw.githubusercontent.com/${SCRIPT_REPO_OWNER}/${SCRIPT_REPO_NAME}/${SCRIPT_BRANCH}/install.sh)${white}"
		echo -e "${yellow}========================================${white}"
		echo ""
		echo -e "${grey}备份保存在: ${backup_dir}${white}"
		break_end
		return 1
	fi
}

## 回滚到指定版本
rollback_version() {
	echo -e "${cyan}===== 版本回滚 =====${white}"
	if [ ! -d "${SCRIPT_HOME}/backup" ] || [ -z "$(ls -A "${SCRIPT_HOME}/backup" 2>/dev/null)" ]; then
		echo -e "${yellow}没有可用的备份${white}"
		break_end
		return 1
	fi

	echo -e "${cyan}可用备份:${white}"
	local i=1
	ls -t "${SCRIPT_HOME}/backup/" | while read -r backup; do
		local backup_version="unknown"
		if [ -f "${SCRIPT_HOME}/backup/${backup}/${SCRIPT_FILE}" ]; then
			backup_version=$(grep '^version=' "${SCRIPT_HOME}/backup/${backup}/${SCRIPT_FILE}" | head -n 1 | cut -d '"' -f 2)
		fi
		echo "  ${i}. ${backup} (版本: ${backup_version})"
		i=$((i + 1))
	done

	echo ""
	read -r -p "输入要恢复的备份序号 (0取消): " choice
	if [ "$choice" = "0" ] || [ -z "$choice" ]; then
		return 1
	fi

	local selected_backup
	selected_backup=$(ls -t "${SCRIPT_HOME}/backup/" | sed -n "${choice}p")
	if [ -z "$selected_backup" ]; then
		echo -e "${red}无效的选择${white}"
		return 1
	fi

	local backup_path="${SCRIPT_HOME}/backup/${selected_backup}"
	echo -e "${yellow}警告: 这将恢复到 ${selected_backup}${white}"
	read -r -p "确认回滚？(y/n): " confirm
	if [[ "$confirm" =~ ^[Yy]$ ]]; then
		local current_backup="${SCRIPT_HOME}/backup/before_rollback_$(date +%Y%m%d%H%M%S)"
		mkdir -p "$current_backup"
		cp -r "${LINUXBOX_LIB_DIR}/lib" "$current_backup/" 2>/dev/null
		cp -r "${LINUXBOX_LIB_DIR}/modules" "$current_backup/" 2>/dev/null
		cp "${LINUXBOX_LIB_DIR}/${SCRIPT_FILE}" "$current_backup/" 2>/dev/null

		rm -rf "${LINUXBOX_LIB_DIR}/lib" "${LINUXBOX_LIB_DIR}/modules"
		cp -r "${backup_path}/lib" "${LINUXBOX_LIB_DIR}/" 2>/dev/null
		cp -r "${backup_path}/modules" "${LINUXBOX_LIB_DIR}/" 2>/dev/null
		cp "${backup_path}/${SCRIPT_FILE}" "${LINUXBOX_LIB_DIR}/" 2>/dev/null

		echo -e "${green}✓ 回滚完成，请重新运行脚本${white}"
		break_end
		exit 0
	fi
}

## 查看更新日志
view_changelog() {
	echo -e "${cyan}===== 更新日志 =====${white}"
	local changelog_url="${url_proxy}raw.githubusercontent.com/${SCRIPT_REPO_OWNER}/${SCRIPT_REPO_NAME}/${SCRIPT_BRANCH}/CHANGELOG.md"
	if curl -s --max-time 10 "$changelog_url" 2>/dev/null | head -n 50; then
		echo ""
	else
		echo -e "${yellow}无法获取更新日志${white}"
	fi
	break_end
}
