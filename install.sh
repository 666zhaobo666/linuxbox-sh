#!/bin/bash
# LinuxBox 模块化安装脚本
# 通过 bash <(curl ...) 触发, 独立运行, 不依赖 lib/
# 设计: 与 lib/update.sh 共用 download_file + show_progress 写法, 全量下载, 进度条 + 简洁报告

set -e

# 颜色
red='\033[31m'
green='\033[0;32m'
yellow='\033[33m'
cyan='\033[36m'
white='\033[0m'

# 配置
SCRIPT_REPO_OWNER="${SCRIPT_REPO_OWNER:-666zhaobo666}"
SCRIPT_REPO_NAME="${SCRIPT_REPO_NAME:-linuxbox-sh}"
SCRIPT_BRANCH="${SCRIPT_BRANCH:-main}"
SCRIPT_FILE="LinuxBox.sh"
INSTALL_DIR="/usr/local/bin/linuxbox"
KEY="${1:-j}"

# 检测地区决定代理
detect_region() {
	local country
	country=$(curl -s --connect-timeout 3 "https://ipapi.co/country/" 2>/dev/null | tr '[:lower:]' '[:upper:]')
	if [ -z "$country" ]; then
		country=$(curl -s --connect-timeout 3 "https://ipinfo.io/country" 2>/dev/null | tr '[:lower:]' '[:upper:]')
	fi
	if [ "$country" = "CN" ]; then
		echo "https://proxy.cccg.top/"
	else
		echo "https://"
	fi
}
URL_PROXY=$(detect_region)

# 下载文件 (与 lib/utils.sh 的 download_file 行为一致)
download_file() {
	local url="$1"
	local path="$2"
	if curl -sSL --max-time 60 --fail "$url" -o "$path" 2>/dev/null; then
		[ -s "$path" ] && return 0
	fi
	return 1
}

# 进度条 (与 lib/utils.sh 的 show_progress 行为一致)
show_progress() {
	local current=$1
	local total=$2
	local width=${3:-30}
	local pct=$(( current * 100 / total ))
	local filled=$(( current * width / total ))
	local empty=$(( width - filled ))
	local bar=""
	local i
	for ((i=0; i<filled; i++)); do bar+="█"; done
	for ((i=0; i<empty; i++)); do bar+="░"; done
	printf "\r${cyan}下载中: [${green}%s${cyan}] %3d%% (%d/%d)${white}" "$bar" "$pct" "$current" "$total"
}

# 文件列表 (与 lib/constants.sh 保持一致, 单一来源在那边, 这里独立硬编码一份)
LIB_FILES=(constants.sh config.sh i18n.sh region.sh install.sh update.sh service.sh utils.sh package.sh system.sh dispatch.sh)
MOD_FILES=(system_info.sh system_tools.sh system_clean.sh basic_tools.sh network_tools.sh docker.sh ldnmp.sh firewall.sh caddy.sh bbr.sh appstore.sh warp.sh cluster.sh game_server.sh dev_env.sh)

echo -e "${cyan}正在安装 LinuxBox 脚本工具箱...${white}"
echo ""

# 创建安装目录
mkdir -p "${INSTALL_DIR}/lib"
mkdir -p "${INSTALL_DIR}/modules"

# 计算总数: 1 入口 + lib + modules
TOTAL=$(( 1 + ${#LIB_FILES[@]} + ${#MOD_FILES[@]} ))
CURRENT=0
FAILED_FILES=()

# 下载入口脚本
CURRENT=$((CURRENT + 1))
show_progress $CURRENT $TOTAL
if download_file "${URL_PROXY}raw.githubusercontent.com/${SCRIPT_REPO_OWNER}/${SCRIPT_REPO_NAME}/${SCRIPT_BRANCH}/${SCRIPT_FILE}" "${INSTALL_DIR}/${SCRIPT_FILE}"; then
	chmod +x "${INSTALL_DIR}/${SCRIPT_FILE}"
else
	FAILED_FILES+=("${SCRIPT_FILE}")
fi

# 下载 lib 目录
for file in "${LIB_FILES[@]}"; do
	CURRENT=$((CURRENT + 1))
	show_progress $CURRENT $TOTAL
	if download_file "${URL_PROXY}raw.githubusercontent.com/${SCRIPT_REPO_OWNER}/${SCRIPT_REPO_NAME}/${SCRIPT_BRANCH}/lib/${file}" "${INSTALL_DIR}/lib/${file}"; then
		chmod +x "${INSTALL_DIR}/lib/${file}" 2>/dev/null || true
	else
		FAILED_FILES+=("lib/${file}")
	fi
done

# 下载 modules 目录
for file in "${MOD_FILES[@]}"; do
	CURRENT=$((CURRENT + 1))
	show_progress $CURRENT $TOTAL
	if download_file "${URL_PROXY}raw.githubusercontent.com/${SCRIPT_REPO_OWNER}/${SCRIPT_REPO_NAME}/${SCRIPT_BRANCH}/modules/${file}" "${INSTALL_DIR}/modules/${file}"; then
		chmod +x "${INSTALL_DIR}/modules/${file}" 2>/dev/null || true
	else
		FAILED_FILES+=("modules/${file}")
	fi
done

# 进度条结束换行
echo ""
echo ""

# 检查结果
if [ ${#FAILED_FILES[@]} -gt 0 ]; then
	echo -e "${red}✗ 安装未完成, ${#FAILED_FILES[@]}/${TOTAL} 个文件下载失败:${white}"
	local f
	for f in "${FAILED_FILES[@]}"; do
		echo -e "  ${red}✗${white} $f"
	done
	echo ""
	echo -e "${yellow}请检查网络后重试${white}"
	rm -rf "${INSTALL_DIR}"
	exit 1
fi

echo -e "${green}✓ 全部文件下载完成 (${TOTAL}/${TOTAL})${white}"

# 创建符号链接
ln -sf "${INSTALL_DIR}/${SCRIPT_FILE}" "/usr/local/bin/${KEY}"
chmod +x "/usr/local/bin/${KEY}"

# 保存配置
mkdir -p "$HOME/.linuxbox"
cat > "$HOME/.linuxbox/config" << EOF
SCRIPT_BRANCH="${SCRIPT_BRANCH}"
key="${KEY}"
EOF

echo -e "${green}========================================${white}"
echo -e "${green}  安装成功!${white}"
echo -e "${green}========================================${white}"
echo ""
echo -e "命令行输入 ${yellow}${KEY}${white} 可快速启动脚本"
echo ""

# 提示用户同意条款
echo -e "${cyan}欢迎使用 LinuxBox 脚本工具箱${white}"
echo -e "${yellow}此脚本基于自用开发，请尽量通过选择脚本选项退出${white}"
echo -e "${yellow}如有问题，后果自负!${white}"
echo ""
read -r -p "是否同意以上条款？(y/n): " user_input

if [ "$user_input" = "y" ] || [ "$user_input" = "Y" ]; then
	echo "已同意"
	sed -i 's/^user_authorization="false"/user_authorization="true"/' "${INSTALL_DIR}/${SCRIPT_FILE}" 2>/dev/null || true
else
	echo "已拒绝"
	rm -rf "${INSTALL_DIR}"
	rm -f "/usr/local/bin/${KEY}"
	exit 1
fi

echo ""
echo -e "${green}安装完成！输入 ${KEY} 启动脚本${white}"
