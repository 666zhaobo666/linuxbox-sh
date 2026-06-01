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
	[ "$EUID" -ne 0 ] && echo -e "${yellow}提示: ${white}该功能需要root用户才能运行!" && break_end && return_to_menu
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
		return_to_menu
	fi
}

##  错误处理
error_exit() {
	echo -e "${red}[错误]${white} $1"
    exit 1
}
