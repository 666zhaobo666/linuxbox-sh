lx_msg() {
	local msg_key="$1"
	shift
	case "$SCRIPT_LANG:$msg_key" in
		en:welcome) printf "Welcome to LinuxBox script toolbox\n" ;;
		en:shortcut) printf "Type %s to launch LinuxBox quickly\n" "$key" ;;
		en:invalid) printf "Invalid choice, please try again!\n" ;;
		en:help_title) printf "LinuxBox command examples:\n" ;;
		en:update_check) printf "Checking for updates...\n" ;;
		en:update_latest) printf "Already up to date (%s)\n" "$version" ;;
		en:update_found) printf "New version found: %s, current version: %s\n" "$1" "$version" ;;
		en:update_done) printf "Update complete. Please restart LinuxBox.\n" ;;
		en:update_cancel) printf "Update cancelled.\n" ;;
		en:lang_done) printf "LinuxBox language switched to English.\n" ;;
		*:welcome) printf "欢迎使用LinuxBox脚本工具箱\n" ;;
		*:shortcut) printf "命令行输入 %s 可快速启动脚本\n" "$key" ;;
		*:invalid) printf "无效选择, 请重新输入!\n" ;;
		*:help_title) printf "LinuxBox 命令行参考用例：\n" ;;
		*:update_check) printf "正在检查更新...\n" ;;
		*:update_latest) printf "当前已是最新版本 (%s)\n" "$version" ;;
		*:update_found) printf "发现新版本 V%s, 当前版本 V%s\n" "$1" "$version" ;;
		*:update_done) printf "更新完成! 请重新运行脚本\n" ;;
		*:update_cancel) printf "已取消更新\n" ;;
		*:lang_done) printf "LinuxBox脚本语言已切换为中文。\n" ;;
		*) printf "%s\n" "$msg_key" ;;
	esac
}

linuxbox_help() {
	lx_msg help_title
	if [ "$SCRIPT_LANG" = "en" ]; then
		cat <<EOF
  $key                         Open interactive menu
  $key help                    Show command help
  $key lang zh|en              Switch script language
  $key update                  Update LinuxBox
  $key install nano wget       Install packages
  $key service restart docker  Restart a service
  $key docker                  Docker management menu
  $key web                     LDNMP website menu
  $key warp                    WARP management menu
  $key app                     App store menu
  $key cluster                 Cluster management menu
  $key game                    Game server management menu
  $key ssl [domain]            Issue/manage SSL certificates
  $key swap 2048               Set 2048M swap
  $key time Asia/Shanghai      Set timezone
  $key open-port 80 443        Open ports
  $key close-port 8080         Close ports
EOF
	else
		cat <<EOF
  $key                         进入交互菜单
  $key help                    查看命令帮助
  $key lang zh|en              切换脚本语言
  $key update                  更新脚本
  $key install nano wget       安装软件包
  $key service restart docker  重启服务
  $key docker                  Docker 管理菜单
  $key web                     LDNMP 建站菜单
  $key warp                    WARP 管理菜单
  $key app                     应用市场菜单
  $key cluster                 集群管理菜单
  $key game                    游戏服务器管理菜单
  $key ssl [domain]            申请/管理证书
  $key swap 2048               设置 2048M 虚拟内存
  $key time Asia/Shanghai      设置系统时区
  $key open-port 80 443        开放端口
  $key close-port 8080         关闭端口
EOF
	fi
}
