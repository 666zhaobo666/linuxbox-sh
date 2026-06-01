######################################################################
########################## 系统systemctl管理 ##########################
# 通用 systemctl 函数, 适用于各种发行版
systemctl() {
	local COMMAND="$1"
	local SERVICE_NAME="$2"

	if command -v apk &>/dev/null; then
		service "$SERVICE_NAME" "$COMMAND"
	else
		/bin/systemctl "$COMMAND" "$SERVICE_NAME"
	fi
}
# 重启服务
restart() {
	systemctl restart "$1"
	if [ $? -eq 0 ]; then
		echo "$1 服务已重启."
	else
		echo "错误：重启 $1 服务失败."
	fi
}
# 启动服务
start() {
	systemctl start "$1"
	if [ $? -eq 0 ]; then
		echo "$1 服务已启动."
	else
		echo "错误：启动 $1 服务失败."
	fi
}
# 停止服务
stop() {
	systemctl stop "$1"
	if [ $? -eq 0 ]; then
		echo "$1 服务已停止."
	else
		echo "错误：停止 $1 服务失败."
	fi
}
# 查看服务状态
status() {
	systemctl status "$1"
	if [ $? -eq 0 ]; then
		echo "$1 服务状态已显示."
	else
		echo "错误：无法显示 $1 服务状态."
	fi
}
# 启用服务
enable() {
	local SERVICE_NAME="$1"
	if command -v apk &>/dev/null; then
		rc-update add "$SERVICE_NAME" default
	else
    /bin/systemctl enable "$SERVICE_NAME"
	fi

	echo "$SERVICE_NAME 已设置为开机自启."
}
# 关闭服务
disable() {
	local SERVICE_NAME="$1"
	if command -v apk &>/dev/null; then
		rc-update del "$SERVICE_NAME" default
	else
    /bin/systemctl disable "$SERVICE_NAME"
	fi

	echo "$SERVICE_NAME 已设置为禁止开机自启."
}
