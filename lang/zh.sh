#!/bin/bash
# LinuxBox 中文语言包
# 加载方式: load_lang "zh"  (在 lib/i18n.sh 中定义)
# 格式: LX_<key>='模板字符串'   %s 占位符用 lx_msg 调用时传入

# 系统级消息
LX_welcome='欢迎使用LinuxBox脚本工具箱'
LX_shortcut='命令行输入 %s 可快速启动脚本'
LX_invalid='无效选择, 请重新输入!'
LX_help_title='LinuxBox 命令行参考用例：'
LX_update_check='正在检查更新...'
LX_update_latest='当前已是最新版本 (%s)'
LX_update_found='发现新版本 V%s, 当前版本 V%s'
LX_update_done='更新完成! 请重新运行脚本'
LX_update_cancel='已取消更新'
LX_lang_done='LinuxBox 脚本语言已切换为中文。'

# 主菜单项
LX_menu_info='系统信息查询'
LX_menu_tools='系统工具'
LX_menu_clean='系统清理'
LX_menu_basic='基础工具'
LX_menu_test='测试工具'
LX_menu_docker='Docker 容器管理'
LX_menu_ldnmp='LDNMP 建站管理'
LX_menu_firewall='防火墙配置'
LX_menu_bbr='BBR 加速管理'
LX_menu_warp='WARP 管理'
LX_menu_app='应用市场'
LX_menu_cluster='服务器集群管理'
LX_menu_game='游戏服务器管理'
LX_menu_dev='Dev 环境管理'
LX_menu_lang='脚本语言 / Language'
LX_menu_quit='退出脚本'
LX_menu_update='更新脚本'
LX_menu_uninstall='卸载脚本'
LX_menu_prompt='请选择功能编号: '
LX_ask_lang='请输入语言 zh/en: '
