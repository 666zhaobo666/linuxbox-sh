# 包管理器更新时间戳缓存 (1 小时内不重复 update)
update_package_manager() {
	local cache_file="${SCRIPT_HOME:-/tmp}/.linuxbox_pkg_update_ts"
	local now
	now=$(date +%s 2>/dev/null || echo 0)
	local last_update=0
	if [ -f "$cache_file" ]; then
		last_update=$(cat "$cache_file" 2>/dev/null || echo 0)
	fi

	# 1 小时 = 3600 秒
	if [ "$now" -gt 0 ] && [ "$last_update" -gt 0 ] && [ $((now - last_update)) -lt 3600 ]; then
		return 0
	fi

	if command -v dnf &>/dev/null; then
		dnf -y update
	elif command -v yum &>/dev/null; then
		yum -y update
	elif command -v apt &>/dev/null; then
		apt update -y
	elif command -v apk &>/dev/null; then
		apk update
	elif command -v pacman &>/dev/null; then
		pacman -Syu --noconfirm
	elif command -v zypper &>/dev/null; then
		zypper refresh
	elif command -v opkg &>/dev/null; then
		opkg update
	elif command -v pkg &>/dev/null; then
		pkg update
	fi

	mkdir -p "$(dirname "$cache_file")" 2>/dev/null || true
	echo "$now" > "$cache_file" 2>/dev/null || true
}

install() {
	if [ $# -eq 0 ]; then
		echo "未提供软件包参数!"
		return 1
	fi

	local package
	for package in "$@"; do
		if ! command -v "$package" &>/dev/null; then
			echo -e "${yellow}正在安装 $package...${white}"
			update_package_manager
			if command -v dnf &>/dev/null; then
				dnf install -y epel-release
				dnf install -y "$package"
			elif command -v yum &>/dev/null; then
				yum install -y epel-release
				yum install -y "$package"
			elif command -v apt &>/dev/null; then
				apt install -y "$package"
			elif command -v apk &>/dev/null; then
				apk add "$package"
			elif command -v pacman &>/dev/null; then
				pacman -S --noconfirm "$package"
			elif command -v zypper &>/dev/null; then
				zypper install -y "$package"
			elif command -v opkg &>/dev/null; then
				opkg install "$package"
			elif command -v pkg &>/dev/null; then
				pkg install -y "$package"
			else
				echo "未知的包管理器!"
				return 1
			fi
		fi
	done
}

##  卸载软件包
remove() {
	if [ $# -eq 0 ]; then
		echo "未提供软件包参数!"
		return 1
	fi

	local package
	for package in "$@"; do
		echo -e "${yellow}正在卸载 $package...${white}"
		if command -v dnf &>/dev/null; then
			dnf remove -y "$package"
		elif command -v yum &>/dev/null; then
			yum remove -y "$package"
		elif command -v apt &>/dev/null; then
			apt remove -y "$package"
		elif command -v apk &>/dev/null; then
			apk del "$package"
		elif command -v pacman &>/dev/null; then
			pacman -Rns --noconfirm "$package"
		elif command -v zypper &>/dev/null; then
			zypper remove -y "$package"
		elif command -v opkg &>/dev/null; then
			opkg remove "$package"
		elif command -v pkg &>/dev/null; then
			pkg delete -y "$package"
		else
			echo "未知的包管理器!"
			return 1
		fi
	done
}

