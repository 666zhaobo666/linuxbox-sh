#!/bin/bash
# LinuxBox 模块化安装脚本
# 用于首次安装，下载完整的模块化目录结构

set -e

# 颜色定义
red='\033[31m'
green='\033[0;32m'
yellow='\033[33m'
cyan='\033[36m'
white='\033[0m'

# 配置
SCRIPT_REPO_OWNER="${SCRIPT_REPO_OWNER:-666zhaobo666}"
SCRIPT_REPO_NAME="${SCRIPT_REPO_NAME:-linuxbox-sh}"
SCRIPT_BRANCH="${SCRIPT_BRANCH:-main}"
INSTALL_DIR="/usr/local/bin/linuxbox"
KEY="${1:-j}"

# 检测地区
detect_region() {
    local country=$(curl -s --connect-timeout 3 "https://ipapi.co/country/" 2>/dev/null | tr '[:lower:]' '[:upper:]')
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

echo -e "${cyan}正在安装 LinuxBox 脚本工具箱...${white}"
echo ""

# 创建安装目录
mkdir -p "${INSTALL_DIR}/lib"
mkdir -p "${INSTALL_DIR}/modules"
mkdir -p "${INSTALL_DIR}/lang"

# 下载文件函数
download_file() {
    local url="$1"
    local path="$2"
    if curl -sSL --max-time 60 --fail "$url" -o "$path" 2>/dev/null; then
        return 0
    else
        return 1
    fi
}

# 进度条渲染函数 (用 \r 回到行首, 覆盖显示)
# 用法: show_progress <current> <total> <bar_width>
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

# 文件列表
lib_files="constants.sh config.sh i18n.sh region.sh install.sh update.sh service.sh utils.sh package.sh system.sh dispatch.sh"
mod_files="system_info.sh system_tools.sh system_clean.sh basic_tools.sh network_tools.sh docker.sh ldnmp.sh firewall.sh bbr.sh appstore.sh warp.sh cluster.sh game_server.sh dev_env.sh"
lang_files="zh.sh en.sh"

# 计算总文件数: 1 (入口) + lib 数量 + modules 数量 + lang 数量
TOTAL=$(( 1 + $(echo $lib_files | wc -w) + $(echo $mod_files | wc -w) + $(echo $lang_files | wc -w) ))
CURRENT=0
FAILED_FILES=()

# 下载入口脚本
CURRENT=$((CURRENT + 1))
show_progress $CURRENT $TOTAL
if download_file "${URL_PROXY}raw.githubusercontent.com/${SCRIPT_REPO_OWNER}/${SCRIPT_REPO_NAME}/${SCRIPT_BRANCH}/LinuxBox.sh" "${INSTALL_DIR}/LinuxBox.sh"; then
    chmod +x "${INSTALL_DIR}/LinuxBox.sh"
else
    FAILED_FILES+=("LinuxBox.sh")
fi

# 下载 lib 目录
for file in $lib_files; do
    CURRENT=$((CURRENT + 1))
    show_progress $CURRENT $TOTAL
    if download_file "${URL_PROXY}raw.githubusercontent.com/${SCRIPT_REPO_OWNER}/${SCRIPT_REPO_NAME}/${SCRIPT_BRANCH}/lib/${file}" "${INSTALL_DIR}/lib/${file}"; then
        chmod +x "${INSTALL_DIR}/lib/${file}" 2>/dev/null || true
    else
        FAILED_FILES+=("lib/${file}")
    fi
done

# 下载 modules 目录
for file in $mod_files; do
    CURRENT=$((CURRENT + 1))
    show_progress $CURRENT $TOTAL
    if download_file "${URL_PROXY}raw.githubusercontent.com/${SCRIPT_REPO_OWNER}/${SCRIPT_REPO_NAME}/${SCRIPT_BRANCH}/modules/${file}" "${INSTALL_DIR}/modules/${file}"; then
        chmod +x "${INSTALL_DIR}/modules/${file}" 2>/dev/null || true
    else
        FAILED_FILES+=("modules/${file}")
    fi
done

# 下载 lang 目录
for file in $lang_files; do
    CURRENT=$((CURRENT + 1))
    show_progress $CURRENT $TOTAL
    if download_file "${URL_PROXY}raw.githubusercontent.com/${SCRIPT_REPO_OWNER}/${SCRIPT_REPO_NAME}/${SCRIPT_BRANCH}/lang/${file}" "${INSTALL_DIR}/lang/${file}"; then
        chmod +x "${INSTALL_DIR}/lang/${file}" 2>/dev/null || true
    else
        FAILED_FILES+=("lang/${file}")
    fi
done

# 进度条结束换行
echo ""
echo ""

# 检查结果
if [ ${#FAILED_FILES[@]} -gt 0 ]; then
    echo -e "${red}✗ 部分文件下载失败 (${#FAILED_FILES[@]}/${TOTAL})${white}"
    echo -e "${red}失败文件列表:${white}"
    for f in "${FAILED_FILES[@]}"; do
        echo -e "  ${red}✗ ${f}${white}"
    done
    rm -rf "${INSTALL_DIR}"
    exit 1
fi

echo -e "${green}✓ 全部文件下载完成 (${TOTAL}/${TOTAL})${white}"

# 创建符号链接
ln -sf "${INSTALL_DIR}/LinuxBox.sh" "/usr/local/bin/${KEY}"
chmod +x "/usr/local/bin/${KEY}"

# 保存配置
mkdir -p "$HOME/.linuxbox"
cat > "$HOME/.linuxbox/config" << EOF
SCRIPT_LANG="zh"
SCRIPT_BRANCH="${SCRIPT_BRANCH}"
key="${KEY}"
EOF

echo -e "${green}========================================${white}"
echo -e "${green}  安装成功!${white}"
echo -e "${green}========================================${white}"
echo ""
echo -e "命令行输入 ${yellow}${KEY}${white} 可快速启动脚本"
echo ""
echo -e "${yellow}首次使用提示:${white}"
echo -e "  - 输入 ${cyan}${KEY}${white} 启动脚本"
echo -e "  - 选择 0 退出"
echo -e "  - 选择 00 更新脚本"
echo ""

# 提示用户同意条款
echo -e "${cyan}欢迎使用 LinuxBox 脚本工具箱${white}"
echo -e "${yellow}此脚本基于自用开发，请尽量通过选择脚本选项退出${white}"
echo -e "${yellow}如有问题，后果自负!${white}"
echo ""
read -r -p "是否同意以上条款？(y/n): " user_input

if [ "$user_input" = "y" ] || [ "$user_input" = "Y" ]; then
    echo "已同意"
    sed -i 's/^user_authorization="false"/user_authorization="true"/' "${INSTALL_DIR}/LinuxBox.sh" 2>/dev/null || true
else
    echo "已拒绝"
    rm -rf "${INSTALL_DIR}"
    rm -f "/usr/local/bin/${KEY}"
    exit 1
fi

echo ""
echo -e "${green}安装完成！输入 ${KEY} 启动脚本${white}"
