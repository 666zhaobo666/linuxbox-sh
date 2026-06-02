#!/bin/bash
# LinuxBox 多功能管理脚本
# version 不在本文件定义, 全脚本唯一版本号在 LinuxBox.sh 顶部

#############################################################################
############################ LinuxBox 运行时配置 #############################
#############################################################################
SCRIPT_NAME="LinuxBox"
SCRIPT_REPO_OWNER="${SCRIPT_REPO_OWNER:-666zhaobo666}"
SCRIPT_REPO_NAME="${SCRIPT_REPO_NAME:-linuxbox-sh}"
SCRIPT_BRANCH="${SCRIPT_BRANCH:-main}"
SCRIPT_FILE="${SCRIPT_FILE:-LinuxBox.sh}"
SCRIPT_INSTALL_DIR="${SCRIPT_INSTALL_DIR:-/usr/local/bin}"
SCRIPT_HOME="${SCRIPT_HOME:-$HOME/.linuxbox}"
SCRIPT_CONFIG_FILE="${SCRIPT_CONFIG_FILE:-$SCRIPT_HOME/config}"
LINUXBOX_INSTALL_DIR="${LINUXBOX_INSTALL_DIR:-/usr/local/bin/linuxbox}"
## 全局颜色变量
white='\033[0m'			# 白色
green='\033[0;32m'		# 绿色
blue='\033[0;34m'		# 蓝色
red='\033[31m'			# 红色
yellow='\033[33m'		# 黄色
grey='\e[37m'			# 灰色
pink='\033[38;5;218m'	# 粉色
cyan='\033[36m'			# 青色
purple='\033[35m'		# 紫色

## 支持系统
SUPPORTED_OS=("ubuntu" "debian" "arch" "fedora" "centos" "rocky" "almalinux" "alpine")

## 地区默认值
region="CN"

## 默认快捷键
key="${LINUXBOX_KEY:-j}"

## 升级/安装需要下载的文件列表 (install.sh 与 lib/update.sh 共用)
## 单一来源, 加新模块/库时改这里即可
LINUXBOX_LIB_FILES=(constants.sh config.sh i18n.sh region.sh install.sh update.sh service.sh utils.sh package.sh system.sh dispatch.sh)
LINUXBOX_MOD_FILES=(system_info.sh system_tools.sh system_clean.sh basic_tools.sh network_tools.sh docker.sh ldnmp.sh firewall.sh caddy.sh bbr.sh appstore.sh warp.sh cluster.sh game_server.sh dev_env.sh)
LINUXBOX_LANG_FILES=(zh.sh)

