#!/bin/bash
# LinuxBox 多功能管理脚本 (模块化版本)
#版本信息
version="3.2.0-modular"

#############################################################################
############################# LinuxBox 运行时配置 #############################
#############################################################################

# 获取脚本所在目录 (支持软链接)
LINUXBOX_LIB_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"

# 检查是否通过管道执行 (bash <(curl ...))
# 如果是，切换到安装目录
if [ ! -d "${LINUXBOX_LIB_DIR}/lib" ] || [ ! -d "${LINUXBOX_LIB_DIR}/modules" ]; then
    # 可能是管道执行，尝试使用安装目录
    LINUXBOX_INSTALL_DIR="/usr/local/bin/linuxbox"
    if [ -d "${LINUXBOX_INSTALL_DIR}/lib" ] && [ -d "${LINUXBOX_INSTALL_DIR}/modules" ]; then
        LINUXBOX_LIB_DIR="${LINUXBOX_INSTALL_DIR}"
    fi
fi

# 加载公共库
for lib_file in constants config i18n region install update service utils package system; do
    lib_path="${LINUXBOX_LIB_DIR}/lib/${lib_file}.sh"
    if [ -f "$lib_path" ]; then
        # shellcheck source=lib/${lib_file}.sh
        . "$lib_path"
    else
        echo "[错误] 缺少库文件: $lib_path"
        echo "请使用以下命令安装:"
        echo "  bash <(curl -sL https://raw.githubusercontent.com/666zhaobo666/linuxbox-sh/ai-enhance/install.sh)"
        exit 1
    fi
done

# 加载功能模块
for mod_file in system_info system_tools network_tools docker ldnmp firewall bbr appstore warp cluster game_server dev_env; do
    mod_path="${LINUXBOX_LIB_DIR}/modules/${mod_file}.sh"
    if [ -f "$mod_path" ]; then
        # shellcheck source=modules/${mod_file}.sh
        . "$mod_path"
    else
        echo "[错误] 缺少模块文件: $mod_path"
        exit 1
    fi
done

# 加载命令行分发
dispatch_path="${LINUXBOX_LIB_DIR}/lib/dispatch.sh"
if [ -f "$dispatch_path" ]; then
    # shellcheck source=lib/dispatch.sh
    . "$dispatch_path"
fi

#############################################################################
################################# 主菜单 #####################################
main_menu() {
    clear
    while true; do
		clear
		echo -e "${green}LinuxBox脚本工具箱 V$version${white}"
        echo -e "$(lx_msg shortcut)"
		echo -e ""
		echo -e "${pink}------------------------${white}"
        echo -e "${cyan}1.   ${white}系统信息查询"
		echo -e "${cyan}2.   ${white}系统工具"
		echo -e "${cyan}3.   ${white}测试工具"
		echo -e "${cyan}4.   ${white}Docker容器管理"
		echo -e "${cyan}5.   ${white}LDNMP建站管理"
		echo -e "${cyan}6.   ${white}防火墙配置"
		echo -e "${cyan}7.   ${white}BBR加速管理"
		echo -e "${cyan}8.   ${white}WARP管理"
		echo -e "${cyan}9.   ${white}应用市场"
		echo -e "${cyan}10.  ${white}服务器集群管理"
		echo -e "${cyan}11.  ${white}游戏服务器管理"
		echo -e "${cyan}12.  ${white}Dev环境管理"
		echo -e "${cyan}13.  ${white}脚本语言 / Language"
		echo -e "${pink}------------------------${white}"
		echo -e "${yellow}0.     ${white}退出脚本"
		echo -e "${green}00.    ${white}更新脚本"
		echo -e "${red}555.   ${white}卸载脚本"
        echo -e "${pink}------------------------${white}"

        read -e -p "请选择功能编号: " choice
        case $choice in
            1) system_info ;;
			2) linux_tools ;;
            3) network_tools ;;
            4) linux_docker ;;
            5) linux_ldnmp ;;
            6) linux_firewall ;;
            7) linux_bbr ;;
            8) linux_warp ;;
            9) linux_app ;;
            10) linux_cluster ;;
            11) linux_game_server ;;
            12) dev_env_management ;;
            13) read -e -p "请输入语言 zh/en: " lang_choice; linuxbox_set_lang "$lang_choice"; break_end ;;
            0) 	clear
				exit 0 ;;
			00) update_script ;;
			555) uninstall_script ;;
            *)
				echo -e "${red}$(lx_msg invalid)${white}"
				sleep 1
				;;
        esac
    done
}

os=$(detect_os)
if [ "$os" == "unsupported" ]; then
    error_exit "不支持的系统类型: $os_id"
fi
if [ "$#" -eq 0 ]; then
	CheckFirstRun
	dependency_check
	main_menu
else
	linuxbox_dispatch "$@"
fi
