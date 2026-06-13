#!/bin/bash
# LinuxBox 多功能管理脚本 (模块化版本)

# 全脚本唯一版本号 (主菜单显示 + lib/update.sh 远程比对 + 更新后校验 都读这一行)
# 升版本只需改这一处
version="3.3.0"
user_authorization="${user_authorization:-false}"

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
for mod_file in system_info system_tools system_clean basic_tools network_tools docker ldnmp firewall caddy bbr appstore warp cluster game_server dev_env; do
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
		echo -e "${green}LinuxBox V$version${white}"
        printf "${white}${LX_shortcut}${white}\n" "$key"
		echo -e ""
		echo -e "${pink}------------------------${white}"
        echo -e "${cyan}1.   ${white}${LX_menu_info}"
		echo -e "${cyan}2.   ${white}${LX_menu_tools}"
		echo -e "${cyan}3.   ${white}${LX_menu_clean}"
		echo -e "${cyan}4.   ${white}${LX_menu_basic}"
		echo -e "${cyan}5.   ${white}${LX_menu_test}"
		echo -e "${cyan}6.   ${white}${LX_menu_docker}"
		echo -e "${cyan}7.   ${white}${LX_menu_ldnmp}"
		echo -e "${cyan}8.   ${white}${LX_menu_caddy}"
		echo -e "${cyan}9.   ${white}${LX_menu_firewall}"
		echo -e "${cyan}10.  ${white}${LX_menu_bbr}"
		echo -e "${cyan}11.  ${white}${LX_menu_warp}"
		echo -e "${cyan}12.  ${white}${LX_menu_app}"
		echo -e "${cyan}13.  ${white}${LX_menu_cluster}"
		echo -e "${cyan}14.  ${white}${LX_menu_game}"
		echo -e "${cyan}15.  ${white}${LX_menu_dev}"
		echo -e "${pink}------------------------${white}"
		echo -e "${yellow}0.     ${white}${LX_menu_quit}"
		echo -e "${green}00.    ${white}${LX_menu_update}"
		echo -e "${red}555.   ${white}${LX_menu_uninstall}"
        echo -e "${pink}------------------------${white}"

        read -e -p "${LX_menu_prompt}" choice
        case $choice in
            1) system_info ;;
			2) linux_tools ;;
            3) linux_system_clean ;;
            4) linux_basic_tools ;;
            5) network_tools ;;
            6) linux_docker ;;
            7) linux_ldnmp ;;
            8) linux_caddy ;;
            9) linux_firewall ;;
            10) linux_bbr ;;
            11) linux_warp ;;
            12) linux_app ;;
            13) linux_cluster ;;
            14) linux_game_server ;;
            15) dev_env_management ;;
            0) 	clear
				exit 0 ;;
			00) update_script ;;
			555) uninstall_script ;;
            *)
				echo -e "${red}${LX_invalid}${white}"
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
