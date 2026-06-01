#!/bin/bash
###########################################################################
########################### 模块化升级脚本 #################################
# 支持完整目录结构的升级，包括入口脚本、lib/ 和 modules/

# 获取远程版本号
get_remote_version() {
    local remote_entry_url="${url_proxy}raw.githubusercontent.com/${SCRIPT_REPO_OWNER}/${SCRIPT_REPO_NAME}/${SCRIPT_BRANCH}/LinuxBox.sh"
    curl -s --max-time 20 "$remote_entry_url" | grep '^version=' | head -n 1 | cut -d '"' -f 2
}

# 下载单个文件
download_file() {
    local remote_url="$1"
    local local_path="$2"
    local max_retries=3
    local retry=0

    mkdir -p "$(dirname "$local_path")"

    while [ $retry -lt $max_retries ]; do
        if curl -sSL --max-time 60 --fail "$remote_url" -o "$local_path" 2>/dev/null; then
            # 验证文件
            if [ -s "$local_path" ] && head -n 1 "$local_path" | grep -q '^#!/bin/bash'; then
                chmod +x "$local_path"
                return 0
            fi
        fi
        retry=$((retry + 1))
        sleep 2
    done
    return 1
}

# 下载目录内容
download_directory() {
    local dir_name="$1"
    local files_list="$2"
    local success_count=0
    local fail_count=0

    echo -e "${cyan}正在更新 ${dir_name}/ 目录...${white}"

    # 创建临时目录
    local tmp_dir="/tmp/linuxbox_update_${dir_name}_$$"
    mkdir -p "$tmp_dir"

    # 下载文件列表
    for file in $files_list; do
        local remote_url="${url_proxy}raw.githubusercontent.com/${SCRIPT_REPO_OWNER}/${SCRIPT_REPO_NAME}/${SCRIPT_BRANCH}/${dir_name}/${file}"
        local tmp_file="${tmp_dir}/${file}"

        if download_file "$remote_url" "$tmp_file"; then
            success_count=$((success_count + 1))
        else
            fail_count=$((fail_count + 1))
            echo -e "${red}  ✗ ${file} 下载失败${white}"
        fi
    done

    echo -e "${green}  ✓ ${dir_name}/: ${success_count} 成功, ${fail_count} 失败${white}"

    # 如果全部成功，移动到目标位置
    if [ $fail_count -eq 0 ]; then
        local target_dir="${LINUXBOX_LIB_DIR}/${dir_name}"
        rm -rf "${target_dir}.bak" 2>/dev/null
        mv "$target_dir" "${target_dir}.bak" 2>/dev/null
        mv "$tmp_dir" "$target_dir"
        rm -rf "${target_dir}.bak"
        return 0
    else
        rm -rf "$tmp_dir"
        return 1
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
        echo -e "${red}错误：无法获取远程版本信息${white}"
        echo -e "${yellow}请检查网络连接或代理设置${white}"
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
    lx_msg update_found "$remote_version"
    echo -e "${cyan}当前版本: ${version}${white}"
    echo -e "${cyan}远程版本: ${remote_version}${white}"
    echo ""
    read -r -p "是否确认更新？(y/n): " confirm
    echo

    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        lx_msg update_cancel
        break_end
        return 1
    fi

    echo -e "${cyan}开始模块化升级...${white}"
    echo ""

    # 创建整体备份
    local backup_dir="${SCRIPT_HOME}/backup/linuxbox_$(date +%Y%m%d%H%M%S)"
    mkdir -p "$backup_dir"
    cp -r "${LINUXBOX_LIB_DIR}/lib" "$backup_dir/" 2>/dev/null
    cp -r "${LINUXBOX_LIB_DIR}/modules" "$backup_dir/" 2>/dev/null
    cp "${LINUXBOX_LIB_DIR}/LinuxBox.sh" "$backup_dir/" 2>/dev/null
    echo -e "${green}✓ 已创建备份: ${backup_dir}${white}"
    echo ""

    local update_failed=0

    # 1. 更新入口脚本
    echo -e "${cyan}[1/4] 更新入口脚本...${white}"
    local entry_remote="${url_proxy}raw.githubusercontent.com/${SCRIPT_REPO_OWNER}/${SCRIPT_REPO_NAME}/${SCRIPT_BRANCH}/LinuxBox.sh"
    local entry_tmp="/tmp/linuxbox_entry_$$.sh"

    if download_file "$entry_remote" "$entry_tmp"; then
        cp -f "$entry_tmp" "${LINUXBOX_LIB_DIR}/LinuxBox.sh"
        echo -e "${green}  ✓ LinuxBox.sh 更新成功${white}"
    else
        echo -e "${red}  ✗ LinuxBox.sh 更新失败${white}"
        update_failed=1
    fi
    rm -f "$entry_tmp"
    echo ""

    # 2. 更新 lib/ 目录
    echo -e "${cyan}[2/4] 更新 lib/ 目录...${white}"
    local lib_files="constants.sh config.sh i18n.sh region.sh install.sh update.sh service.sh utils.sh package.sh system.sh dispatch.sh"
    if ! download_directory "lib" "$lib_files"; then
        update_failed=1
    fi
    echo ""

    # 3. 更新 modules/ 目录
    echo -e "${cyan}[3/4] 更新 modules/ 目录...${white}"
    local modules_files="system_info.sh system_tools.sh network_tools.sh docker.sh ldnmp.sh firewall.sh bbr.sh appstore.sh warp.sh cluster.sh game_server.sh dev_env.sh"
    if ! download_directory "modules" "$modules_files"; then
        update_failed=1
    fi
    echo ""

    # 4. 验证更新
    echo -e "${cyan}[4/4] 验证更新...${white}"
    local verify_errors=0

    # 检查关键文件
    for file in lib/constants.sh lib/config.sh modules/system_info.sh modules/docker.sh; do
        if [ ! -f "${LINUXBOX_LIB_DIR}/${file}" ]; then
            echo -e "${red}  ✗ 缺少关键文件: ${file}${white}"
            verify_errors=$((verify_errors + 1))
        fi
    done

    # 检查版本号是否更新
    local new_version
    new_version=$(grep '^version=' "${LINUXBOX_LIB_DIR}/LinuxBox.sh" | head -n 1 | cut -d '"' -f 2)
    if [ "$new_version" = "$remote_version" ]; then
        echo -e "${green}  ✓ 版本号已更新为: ${new_version}${white}"
    else
        echo -e "${yellow}  ! 版本号可能未正确更新 (当前: ${new_version}, 期望: ${remote_version})${white}"
    fi

    if [ $verify_errors -gt 0 ]; then
        echo ""
        echo -e "${red}更新验证失败，正在回滚...${white}"
        # 从备份恢复
        if [ -d "$backup_dir" ]; then
            rm -rf "${LINUXBOX_LIB_DIR}/lib" "${LINUXBOX_LIB_DIR}/modules"
            cp -r "${backup_dir}/lib" "${LINUXBOX_LIB_DIR}/" 2>/dev/null
            cp -r "${backup_dir}/modules" "${LINUXBOX_LIB_DIR}/" 2>/dev/null
            cp "${backup_dir}/LinuxBox.sh" "${LINUXBOX_LIB_DIR}/" 2>/dev/null
            echo -e "${green}✓ 已从备份恢复${white}"
        fi
        break_end
        return 1
    fi

    echo ""
    if [ $update_failed -eq 0 ]; then
        echo -e "${green}========================================${white}"
        echo -e "${green}  升级成功!${white}"
        echo -e "${green}  新版本: ${remote_version}${white}"
        echo -e "${green}========================================${white}"
        echo ""
        lx_msg shortcut
        echo ""
        echo -e "${yellow}注意: 请重新运行脚本以使用新版本${white}"
        echo -e "${grey}备份保存在: ${backup_dir}${white}"

        # 清理旧备份（保留最近5个）
        ls -t "${SCRIPT_HOME}/backup/" 2>/dev/null | tail -n +6 | while read -r old_backup; do
            rm -rf "${SCRIPT_HOME}/backup/${old_backup}"
        done

        break_end
        exit 0
    else
        echo -e "${yellow}========================================${white}"
        echo -e "${yellow}  升级部分完成，但有一些文件更新失败${white}"
        echo -e "${yellow}  请检查网络连接后重试${white}"
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

    # 列出可用备份
    if [ ! -d "${SCRIPT_HOME}/backup" ] || [ -z "$(ls -A "${SCRIPT_HOME}/backup" 2>/dev/null)" ]; then
        echo -e "${yellow}没有可用的备份${white}"
        break_end
        return 1
    fi

    echo -e "${cyan}可用备份:${white}"
    local i=1
    ls -t "${SCRIPT_HOME}/backup/" | while read -r backup; do
        local backup_version="unknown"
        if [ -f "${SCRIPT_HOME}/backup/${backup}/LinuxBox.sh" ]; then
            backup_version=$(grep '^version=' "${SCRIPT_HOME}/backup/${backup}/LinuxBox.sh" | head -n 1 | cut -d '"' -f 2)
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
        # 备份当前版本
        local current_backup="${SCRIPT_HOME}/backup/before_rollback_$(date +%Y%m%d%H%M%S)"
        mkdir -p "$current_backup"
        cp -r "${LINUXBOX_LIB_DIR}/lib" "$current_backup/" 2>/dev/null
        cp -r "${LINUXBOX_LIB_DIR}/modules" "$current_backup/" 2>/dev/null
        cp "${LINUXBOX_LIB_DIR}/LinuxBox.sh" "$current_backup/" 2>/dev/null

        # 执行回滚
        rm -rf "${LINUXBOX_LIB_DIR}/lib" "${LINUXBOX_LIB_DIR}/modules"
        cp -r "${backup_path}/lib" "${LINUXBOX_LIB_DIR}/" 2>/dev/null
        cp -r "${backup_path}/modules" "${LINUXBOX_LIB_DIR}/" 2>/dev/null
        cp "${backup_path}/LinuxBox.sh" "${LINUXBOX_LIB_DIR}/" 2>/dev/null

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
