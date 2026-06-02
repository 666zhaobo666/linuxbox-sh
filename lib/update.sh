#!/bin/bash
###########################################################################
########################### 模块化升级脚本 #################################
# 设计原则: 与 install.sh 共用同一套 download_file / show_progress,
# 全量覆盖下载, 用进度条显示, 失败时统一汇总, 不逐文件刷屏

# 获取远程版本号 (从入口脚本第一行 version="..." 抓)
get_remote_version() {
	local remote_entry_url="${url_proxy}raw.githubusercontent.com/${SCRIPT_REPO_OWNER}/${SCRIPT_REPO_NAME}/${SCRIPT_BRANCH}/${SCRIPT_FILE}"
	curl -s --max-time 20 "$remote_entry_url" | grep '^version=' | head -n 1 | cut -d '"' -f 2
}

# 下载入口脚本 (单独处理, 因为下载完成后会替换正在运行的自己, 需特别小心)
download_entry_script() {
	local target="${LINUXBOX_LIB_DIR}/${SCRIPT_FILE}"
	# 不能原地覆盖自己, 写到临时文件再 mv
	local tmp="/tmp/${SCRIPT_FILE}.$$"
	if download_file "${url_proxy}raw.githubusercontent.com/${SCRIPT_REPO_OWNER}/${SCRIPT_REPO_NAME}/${SCRIPT_BRANCH}/${SCRIPT_FILE}" "$tmp"; then
		chmod +x "$tmp"
		cp -f "$tmp" "$target"
		rm -f "$tmp"
		return 0
	fi
	rm -f "$tmp"
	return 1
}

# 通用: 下载一组文件到指定目标目录, 返回失败文件列表 (通过全局变量 RETURNED)
# 用法: download_group <group_name> <file_list_array_name> <target_subdir>
#   例: download_group lib LINUXBOX_LIB_FILES lib
download_group() {
	local group_name="$1"
	local files_array_name="$2"   # 数组变量名
	local target_subdir="$3"       # 目标子目录 (相对 LINUXBOX_LIB_DIR)
	local -n files_ref="$files_array_name"

	local target_dir="${LINUXBOX_LIB_DIR}/${target_subdir}"
	mkdir -p "$target_dir"

	local total=${#files_ref[@]}
	local i=0
	local failed=()
	local file url target

	for file in "${files_ref[@]}"; do
		i=$((i+1))
		show_progress "$i" "$total"
		url="${url_proxy}raw.githubusercontent.com/${SCRIPT_REPO_OWNER}/${SCRIPT_REPO_NAME}/${SCRIPT_BRANCH}/${target_subdir}/${file}"
		target="${target_dir}/${file}"
		if ! download_file "$url" "$target"; then
			failed+=("$file")
		fi
		chmod +x "$target" 2>/dev/null || true
	done

	# 进度条结束, 换行
	echo ""

	# 汇总本组
	if [ ${#failed[@]} -eq 0 ]; then
		echo -e "${green}  ✓ ${group_name}/: ${total}/${total} 成功${white}"
		RETURNED=0
	else
		echo -e "${yellow}  ! ${group_name}/: ${total} 个中 $((total - ${#failed[@]})) 个成功, ${#failed[@]} 个失败${white}"
		# 把失败文件记到全局 (空格分隔), 由调用方统一打印
		FAILED_FILES+=("${group_name}/${failed[@]}")
		RETURNED=1
	fi
}

# 主升级函数
update_script() {
	lx_msg update_check

	# 检查是否在模块化目录中运行
	if [ ! -d "${LINUXBOX_LIB_DIR}/lib" ] || [ ! -d "${LINUXBOX_LIB_DIR}/modules" ]; then
		echo -e "${red}错误: 未检测到模块化目录结构${white}"
		echo -e "${yellow}请确保正确安装 LinuxBox 脚本${white}"
		sleep 2
		return 1
	fi

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
		lx_msg update_latest
		break_end
		return 0
	fi

	# 提示更新
	lx_msg update_found "$remote_version" "$version"
	read -r -p "是否确认更新？(y/n): " confirm
	if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
		lx_msg update_cancel
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

	# 准备全局失败文件列表
	FAILED_FILES=()
	local entry_ok=0

	# 1. 更新入口脚本 (单独处理, 必须先下完, 否则后面源都找不到)
	echo -e "${cyan}正在更新入口脚本...${white}"
	if download_entry_script; then
		echo -e "${green}  ✓ ${SCRIPT_FILE}${white}"
		entry_ok=1
	else
		echo -e "${red}  ✗ ${SCRIPT_FILE} 下载失败${white}"
		FAILED_FILES+=("${SCRIPT_FILE}")
	fi
	echo ""

	# 2. 全量更新 lib/ + modules/ + lang/, 三组合并显示一个总进度
	local all_total=$((${#LINUXBOX_LIB_FILES[@]} + ${#LINUXBOX_MOD_FILES[@]} + ${#LINUXBOX_LANG_FILES[@]}))
	echo -e "${cyan}正在全量更新 lib/ + modules/ + lang/ (共 ${all_total} 个文件)...${white}"

	# 合并下载: 用一个全局进度计数
	local grand_total=$all_total
	local grand_current=0
	local tmp_grand=/tmp/linuxbox_update_grand_$$
	> "$tmp_grand"  # 清空

	# 这里直接对每个目录组依次下载, 复用 download_group 但用全局进度需要稍作改动
	# 简化: 三组串行下载, 每组内部自己显示进度; 不混进度
	download_group "lib"    LINUXBOX_LIB_FILES    "lib"
	download_group "modules" LINUXBOX_MOD_FILES   "modules"
	download_group "lang"   LINUXBOX_LANG_FILES   "lang"
	rm -f "$tmp_grand"
	echo ""

	# 汇总报告
	local total_failed=${#FAILED_FILES[@]}
	if [ $entry_ok -eq 1 ] && [ $total_failed -eq 0 ]; then
		echo -e "${green}========================================${white}"
		echo -e "${green}  升级成功!${white}"
		echo -e "${green}  新版本: ${remote_version}${white}"
		echo -e "${green}========================================${white}"
		echo ""
		lx_msg shortcut
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
			# 回滚入口
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

# 回滚到指定版本
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

# 查看更新日志
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
