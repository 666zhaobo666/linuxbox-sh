authorization_check() {
    if grep -q '^user_authorization="true"' "${LINUXBOX_INSTALL_DIR}/LinuxBox.sh" > /dev/null 2>&1; then
        sed -i 's/^user_authorization="false"/user_authorization="true"/' "${LINUXBOX_INSTALL_DIR}/LinuxBox.sh"
    fi
	authorization_false
}
authorization_false() {
    if grep -q '^user_authorization="false"' "${LINUXBOX_INSTALL_DIR}/LinuxBox.sh" > /dev/null 2>&1; then
        UserLicenseAgreement
    fi
}

# 模块化安装：下载单个文件
install_download_file() {
    local remote_url="$1"
    local local_path="$2"
    mkdir -p "$(dirname "$local_path")"
    if curl -sSL --max-time 60 --fail "$remote_url" -o "$local_path" 2>/dev/null; then
        if [ -s "$local_path" ]; then
            chmod +x "$local_path" 2>/dev/null
            return 0
        fi
    fi
    return 1
}

# 模块化安装：下载目录下的一组文件
install_download_dir() {
    local dir_name="$1"
    shift
    local files=("$@")
    local success=0
    local fail=0
    local base_url="${url_proxy}raw.githubusercontent.com/${SCRIPT_REPO_OWNER}/${SCRIPT_REPO_NAME}/${SCRIPT_BRANCH}/${dir_name}"

    for file in "${files[@]}"; do
        if install_download_file "${base_url}/${file}" "${LINUXBOX_INSTALL_DIR}/${dir_name}/${file}"; then
            success=$((success + 1))
        else
            fail=$((fail + 1))
            echo -e "${red}  ✗ ${dir_name}/${file} 下载失败${white}"
        fi
    done

    echo -e "${cyan}  ${dir_name}/: ${success} 成功, ${fail} 失败${white}"
    [ $fail -eq 0 ]
}

CheckFirstRun() {
	if [ ! -f "${LINUXBOX_INSTALL_DIR}/LinuxBox.sh" ]; then
		# 首次安装：下载模块化目录结构
		echo -e "${cyan}正在安装 LinuxBox 脚本工具箱...${white}"
		echo ""

		# 创建安装目录
		mkdir -p "${LINUXBOX_INSTALL_DIR}/lib"
		mkdir -p "${LINUXBOX_INSTALL_DIR}/modules"

		local install_failed=0

		# 1. 下载入口脚本
		echo -e "${cyan}[1/3] 下载入口脚本...${white}"
		local entry_url="${url_proxy}raw.githubusercontent.com/${SCRIPT_REPO_OWNER}/${SCRIPT_REPO_NAME}/${SCRIPT_BRANCH}/LinuxBox.sh"
		if install_download_file "$entry_url" "${LINUXBOX_INSTALL_DIR}/LinuxBox.sh"; then
			echo -e "${green}  ✓ LinuxBox.sh${white}"
		else
			echo -e "${red}  ✗ LinuxBox.sh 下载失败${white}"
			install_failed=1
		fi
		echo ""

		# 2. 下载 lib/ 目录
		echo -e "${cyan}[2/3] 下载 lib/ 目录...${white}"
		local lib_files=(constants.sh config.sh i18n.sh region.sh install.sh update.sh service.sh utils.sh package.sh system.sh dispatch.sh)
		if ! install_download_dir "lib" "${lib_files[@]}"; then
			install_failed=1
		fi
		echo ""

		# 3. 下载 modules/ 目录
		echo -e "${cyan}[3/3] 下载 modules/ 目录...${white}"
		local mod_files=(system_info.sh system_tools.sh network_tools.sh docker.sh ldnmp.sh firewall.sh bbr.sh appstore.sh warp.sh cluster.sh game_server.sh dev_env.sh)
		if ! install_download_dir "modules" "${mod_files[@]}"; then
			install_failed=1
		fi
		echo ""

		if [ $install_failed -eq 0 ]; then
			# 创建符号链接
			ln -sf "${LINUXBOX_INSTALL_DIR}/LinuxBox.sh" "/usr/local/bin/${key}"
			chmod +x "/usr/local/bin/${key}" > /dev/null 2>&1

			save_linuxbox_config
			echo -e "${green}安装完成!${white}"
			echo -e "${yellow}---------${white}"
			echo -e "命令行输入${yellow} ${key} ${cyan}可快速启动脚本${white}"
			break_end
			UserLicenseAgreement
		else
			echo -e "${red}安装过程中部分文件下载失败，请检查网络后重试${white}"
			rm -rf "${LINUXBOX_INSTALL_DIR}"
			exit 1
		fi
	else
		# 文件存在：运行授权检查
		authorization_check
	fi
}

# 提示用户同意条款
UserLicenseAgreement() {
	clear
	echo -e "${cyan}欢迎使用LinuxBox脚本工具箱${white}"
	echo -e "命令行输入${yellow} ${key} ${cyan}可快速启动脚本${white}"
	echo -e ""
	echo -e "${pink}-----------------------------${white}"
	echo -e "${yellow}此脚本基于自用开发${white}"
	echo -e "${yellow}请尽量通过选择脚本选项退出${white}"
	echo -e "${yellow}如有问题, 后果自负!${white}"
	echo -e "${pink}-----------------------------${white}"
	read -r -p "是否同意以上条款？(y/n): " user_input

	if [ "$user_input" = "y" ] || [ "$user_input" = "Y" ]; then
		echo "已同意"
		sed -i 's/^user_authorization="false"/user_authorization="true"/' "${LINUXBOX_INSTALL_DIR}/LinuxBox.sh"
		#安装sudo
        install sudo
	else
		echo "已拒绝"
		clear
		exit 1
	fi
}

## 卸载脚本
uninstall_script() {
	clear
	echo -e "${red}警告: 你即将卸载LinuxBox脚本工具箱!${white}"
	read -r -p "是否确认卸载？(y/n): " confirm
	if [[ "$confirm" =~ ^[Yy]$ ]]; then
		# 删除安装目录
		rm -rf "${LINUXBOX_INSTALL_DIR}"
		# 删除符号链接
		rm -f "/usr/local/bin/${key}"
		
		# 删除快捷键别名
		if [ -f "$HOME/.bashrc" ]; then
			sed -i "/alias ${key}='/d" "$HOME/.bashrc"
			source "$HOME/.bashrc"
		fi
		if [ -f "$HOME/.zshrc" ]; then
			sed -i "/alias ${key}='/d" "$HOME/.zshrc"
			source "$HOME/.zshrc"
		fi
		
		echo -e "${green}LinuxBox脚本工具箱已成功卸载!${white}"
		exit 0
	else
		echo "卸载已取消."
		sleep 1
	fi
}
