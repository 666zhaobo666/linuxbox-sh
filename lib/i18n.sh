################################################################
########################### i18n 国际化 ##########################
# 通过 lang/<lang>.sh 提供翻译表，调用 lx_msg <key> [args...] 查表
# 增加新翻译：编辑 lang/zh.sh 和 lang/en.sh 添加 LX_<key>='...' 即可

# 加载语言文件
# 用法: load_lang <lang>
load_lang() {
	local lang="${1:-zh}"
	local lang_file="${LINUXBOX_LIB_DIR}/lang/${lang}.sh"
	if [ ! -f "$lang_file" ]; then
		# 找不到请求的语言, 回退英文
		lang_file="${LINUXBOX_LIB_DIR}/lang/en.sh"
		lang="en"
	fi
	# shellcheck source=lang/en.sh
	. "$lang_file"
	LX_LOADED="$lang"
}

# 查表翻译: lx_msg <key> [args...]
# 例: lx_msg welcome                   -> "欢迎..."
#     lx_msg shortcut "$key"           -> "命令行输入 j 可..."
#     lx_msg update_found "$v" "$version"  -> "发现新版本 V3.2, 当前 V3.1"
lx_msg() {
	local key="$1"
	shift
	local var="LX_${key}"
	# 间接变量取值, 找不到时回退到 key 字面值
	local template="${!var}"
	if [ -z "$template" ]; then
		template="$key"
	fi
	# shellcheck disable=SC2059
	printf "$template\n" "$@"
}

# 切换脚本语言 (主菜单 15 / 命令行 j lang xx)
linuxbox_set_lang() {
	case "$1" in
		zh|cn|中文|"")
			SCRIPT_LANG="zh"
			save_linuxbox_config
			load_lang "zh"
			lx_msg lang_done
			;;
		en|english|English)
			SCRIPT_LANG="en"
			save_linuxbox_config
			load_lang "en"
			lx_msg lang_done
			;;
		*)
			echo "用法: $key lang zh|en"
			return 1
			;;
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
