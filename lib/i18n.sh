################################################################
########################### 翻译查询中心 ##########################
# 翻译表在 lang/zh.sh (LX_<key>='模板' 格式)
# 调用 lx_msg <key> [args...] 查表, %s 占位符由后续参数填充
# 增加新翻译: 编辑 lang/zh.sh 添加 LX_<key>='...' 即可

# 加载翻译表 (当前仅中文, 直接 source 一次)
# 用法: load_lang
load_lang() {
	local lang_file="${LINUXBOX_LIB_DIR}/lang/zh.sh"
	if [ ! -f "$lang_file" ]; then
		echo "[错误] 缺少翻译文件: $lang_file" >&2
		return 1
	fi
	# shellcheck source=lang/zh.sh
	. "$lang_file"
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

linuxbox_help() {
	lx_msg help_title
	cat <<EOF
  $key                         进入交互菜单
  $key help                    查看命令帮助
  $key update                  更新脚本
  $key install nano wget       安装软件包
  $key service restart docker  重启服务
  $key docker                  Docker 管理菜单
  $key web                     LDNMP 建站菜单
  $key caddy                   Caddy 反代管理菜单
  $key firewall                防火墙管理菜单
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
}
