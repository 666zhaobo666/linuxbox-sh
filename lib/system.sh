detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        os_id=$ID
    else
        os_id=$(uname -s)
    fi
    for os in "${SUPPORTED_OS[@]}"; do
        if [[ "$os_id" == *"$os"* ]]; then
            echo "$os"
            return
        fi
    done
    echo "unsupported"
}

##  检查root权限
root_use() {
	clear
	if [ "$EUID" -ne 0 ]; then
		echo -e "${yellow}提示: ${white}该功能需要root用户才能运行!"
		break_end
		return 1
	fi
	return 0
}

linuxbox_require_root() {
	if [ "$EUID" -ne 0 ]; then
		echo -e "${yellow}提示: ${white}该命令需要root用户才能运行!"
		return 1
	fi
}

## 检查磁盘空间
check_disk_space() {
	required_gb=$1
	required_space_mb=$((required_gb * 1024))
	available_space_mb=$(df -m / | awk 'NR==2 {print $4}')

	if [ $available_space_mb -lt $required_space_mb ]; then
		echo -e "${yellow}提示: ${white}磁盘空间不足!"
		echo "当前可用空间: $((available_space_mb/1024))G"
		echo "最小需求空间: ${required_gb}G"
		echo "无法继续安装, 请清理磁盘空间后重试."
		break_end
		return 1
	fi
}

##  错误处理
error_exit() {
	echo -e "${red}[错误]${white} $1"
    exit 1
}

## 检查写权限与 sudo 自动提升
check_write_permission() {
	local action="${1:-update}"
	local target_dir="${LINUXBOX_LIB_DIR:-.}"
	local target_file="${target_dir}/${SCRIPT_FILE:-LinuxBox.sh}"

	if [ ! -w "$target_dir" ] || { [ -e "$target_file" ] && [ ! -w "$target_file" ]; }; then
		if [ "${EUID:-$(id -u)}" -ne 0 ]; then
			if command -v sudo &>/dev/null; then
				echo -e "${yellow}提示: 当前用户无写权限，尝试使用 sudo 自动提升权限重新执行...${white}"
				if sudo bash "$target_file" "$action"; then
					return 2
				fi
			fi
		fi
		echo -e "${red}错误: 当前用户无权修改 ${target_dir} 目录！请使用 'sudo j update' 或切换 root 用户后重新执行。${white}"
		return 1
	fi
	return 0
}

