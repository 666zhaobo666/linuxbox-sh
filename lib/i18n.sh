################################################################
########################### 中文文案常量 #######################
# 所有界面字符串集中在这里, 直接当变量引用即可:
#   echo "${LX_menu_info}"
#   printf "$LX_update_found\n" "$remote" "$local"
# 没有查表函数, 没有 lx_msg, 不再有 lang/ 目录
# 增加新文案: 在本文件加一行 LX_<key>='...' 即可
################################################################

# 系统级消息
LX_welcome='欢迎使用LinuxBox脚本工具箱'
LX_shortcut='命令行输入 %s 可快速启动脚本'
LX_invalid='无效选择, 请重新输入!'
LX_help_title='LinuxBox 命令行参考用例:'
LX_update_check='正在检查更新...'
LX_update_latest='当前已是最新版本 (%s)'
LX_update_found='发现新版本 V%s, 当前版本 V%s'
LX_update_done='更新完成! 请重新运行脚本'
LX_update_cancel='已取消更新'

# 主菜单项
LX_menu_info='系统信息查询'
LX_menu_tools='系统工具'
LX_menu_clean='系统清理'
LX_menu_basic='基础工具'
LX_menu_test='测试工具'
LX_menu_docker='Docker 容器管理'
LX_menu_ldnmp='LDNMP 建站管理'
LX_menu_firewall='防火墙配置'
LX_menu_caddy='Caddy 反代管理'
LX_menu_bbr='BBR 加速管理'
LX_menu_warp='WARP 管理'
LX_menu_app='应用市场'
LX_menu_cluster='服务器集群管理'
LX_menu_game='游戏服务器管理'
LX_menu_dev='Dev 环境管理'
LX_menu_quit='退出脚本'
LX_menu_update='更新脚本'
LX_menu_uninstall='卸载脚本'
LX_menu_prompt='请选择功能编号: '

## 打印命令行帮助
linuxbox_help() {
	echo "${LX_help_title}"
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
