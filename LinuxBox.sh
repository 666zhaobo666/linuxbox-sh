#!/bin/bash
# LinuxBox 多功能管理脚本 (模块化版本)
#版本信息
version="3.2.0"

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
        echo "  bash <(curl -sL https://raw.githubusercontent.com/666zhaobo666/linuxbox-sh/main/install.sh)"
        exit 1
    fi
done

# 加载功能模块
for mod_file in system_info system_tools system_clean basic_tools network_tools docker ldnmp firewall bbr appstore warp cluster game_server dev_env; do
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

# 加载当前语言包 (constants.sh 默认 zh, region.sh 末尾会从用户配置覆盖)
load_lang "$SCRIPT_LANG"

#############################################################################
################################# 主菜单 #####################################
main_menu() {
    clear
    while true; do
		clear
		echo -e "${green}LinuxBox V$version${white}"
        echo -e "$(lx_msg shortcut)"
		echo -e ""
		echo -e "${pink}------------------------${white}"
        echo -e "${cyan}1.   ${white}$(lx_msg menu_info)"
		echo -e "${cyan}2.   ${white}$(lx_msg menu_tools)"
		echo -e "${cyan}3.   ${white}$(lx_msg menu_clean)"
		echo -e "${cyan}4.   ${white}$(lx_msg menu_basic)"
		echo -e "${cyan}5.   ${white}$(lx_msg menu_test)"
		echo -e "${cyan}6.   ${white}$(lx_msg menu_docker)"
		echo -e "${cyan}7.   ${white}$(lx_msg menu_ldnmp)"
		echo -e "${cyan}8.   ${white}$(lx_msg menu_firewall)"
		echo -e "${cyan}9.   ${white}$(lx_msg menu_bbr)"
		echo -e "${cyan}10.  ${white}$(lx_msg menu_warp)"
		echo -e "${cyan}11.  ${white}$(lx_msg menu_app)"
		echo -e "${cyan}12.  ${white}$(lx_msg menu_cluster)"
		echo -e "${cyan}13.  ${white}$(lx_msg menu_game)"
		echo -e "${cyan}14.  ${white}$(lx_msg menu_dev)"
		echo -e "${cyan}15.  ${white}$(lx_msg menu_lang)"
		echo -e "${pink}------------------------${white}"
		echo -e "${yellow}0.     ${white}$(lx_msg menu_quit)"
		echo -e "${green}00.    ${white}$(lx_msg menu_update)"
		echo -e "${red}555.   ${white}$(lx_msg menu_uninstall)"
        echo -e "${pink}------------------------${white}"

        read -e -p "$(lx_msg menu_prompt) " choice
        case $choice in
            1) system_info ;;
			2) linux_tools ;;
            3) linux_system_clean ;;
            4) linux_basic_tools ;;
            5) network_tools ;;
            6) linux_docker ;;
            7) linux_ldnmp ;;
            8) linux_firewall ;;
            9) linux_bbr ;;
            10) linux_warp ;;
            11) linux_app ;;
            12) linux_cluster ;;
            13) linux_game_server ;;
            14) dev_env_management ;;
            15) read -e -p "$(lx_msg ask_lang)" lang_choice; linuxbox_set_lang "$lang_choice"; break_end ;;
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
