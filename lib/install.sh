authorization_check() {
    if grep -q '^user_authorization="true"' /usr/local/bin/${key} > /dev/null 2>&1; then
        sed -i 's/^user_authorization="false"/user_authorization="true"/' /usr/local/bin/${key}
    fi
	authorization_false
}
authorization_false() {
    if grep -q '^user_authorization="false"' /usr/local/bin/${key} > /dev/null 2>&1; then
        UserLicenseAgreement
    fi
}
CheckFirstRun() {
	if [ ! -f "/usr/local/bin/${key}" ]; then
		# 文件不存在：下载安装并赋予权限
		if [ ! -f "./LinuxBox.sh" ]; then
			echo -e "请稍后, 正在下载..."
			# 下载并保存到本地当前目录
			curl -sL "$script_url" -o ./LinuxBox.sh
			echo -e "下载完成!"
			# 赋予执行权限
			chmod +x ./LinuxBox.sh
		fi
		cp -f ./LinuxBox.sh /usr/local/bin/${key} > /dev/null 2>&1
		chmod +x /usr/local/bin/${key} > /dev/null 2>&1
		save_linuxbox_config
		echo -e "${cyan}安装完成!${white}"
		echo -e "${yellow}---------${white}"
		echo -e "命令行输入${yellow} ${key} ${cyan}可快速启动脚本${white}"
		rm -f ./LinuxBox.sh
		break_end
		UserLicenseAgreement
	else
		# 文件存在：运行authorization_false函数
		authorization_check
	fi
}
# 提示用户同意条款
UserLicenseAgreement() {
	clear
	echo -e "${cyan}欢迎使用LinuxBox脚本工具箱${white}"
	echo -e "命令行输入${yellow} j ${cyan}可快速启动脚本${white}"
	echo -e ""
	echo -e "${pink}-----------------------------${white}"
	echo -e "${yellow}此脚本基于自用开发${white}"
	echo -e "${yellow}请尽量通过选择脚本选项退出${white}"
	echo -e "${yellow}如有问题, 后果自负!${white}"
	echo -e "${pink}-----------------------------${white}"
	read -r -p "是否同意以上条款？(y/n): " user_input

	if [ "$user_input" = "y" ] || [ "$user_input" = "Y" ]; then
		echo "已同意"
		sed -i 's/^user_authorization="false"/user_authorization="true"/' /usr/local/bin/${key}
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
		# 删除脚本文件
		## rm -f ~/LinuxBox.sh
		rm -f /usr/local/bin/${key}
		
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
