linuxbox_dispatch() {
	local command="$1"
	shift || true

	case "$command" in
		help|-h|--help|帮助)
			linuxbox_help
			;;
		update|更新)
			dependency_check
			update_script
			;;
		install|add|安装)
			install "$@"
			;;
		remove|del|uninstall|卸载)
			remove "$@"
			;;
		service|svc|服务)
			local action="$1"
			local service_name="$2"
			if [ -z "$action" ] || [ -z "$service_name" ]; then
				echo "用法: $key service restart|start|stop|status|enable|disable 服务名"
				return 1
			fi
			case "$action" in
				restart|重启) restart "$service_name" ;;
				start|启动) start "$service_name" ;;
				stop|停止) stop "$service_name" ;;
				status|状态) status "$service_name" ;;
				enable|开机启动) enable "$service_name" ;;
				disable|禁用自启) disable "$service_name" ;;
				*) echo "未知服务动作: $action"; return 1 ;;
			esac
			;;
		info|系统信息)
			system_info
			;;
		docker)
			linux_docker
			;;
		web|ldnmp)
			linux_ldnmp
			;;
		ssl)
			add_ssl "$1"
			;;
		swap)
			if [ -z "$1" ]; then
				modify_swap_size
			else
				linuxbox_require_root || return 1
				add_swap "$1"
			fi
			;;
		time|timezone|时区)
			if [ -z "$1" ]; then
				adjust_timezone
			else
				linuxbox_require_root || return 1
				set_timedate "$1"
			fi
			;;
		open-port|open_port|打开端口|dkdk)
			linuxbox_require_root || return 1
			open_port "$@"
			;;
		close-port|close_port|关闭端口|gbdk)
			linuxbox_require_root || return 1
			close_port "$@"
			;;
		firewall|防火墙)
			linux_firewall
			;;
		caddy)
			linux_caddy
			;;
		warp)
			linux_warp
			;;
		app|应用)
			linux_app
			;;
		cluster|集群)
			linux_cluster
			;;
		game|游戏)
			linux_game_server
			;;
		dev|开发环境)
			dev_env_management
			;;
		*)
			echo "未知命令: $command"
			linuxbox_help
			return 1
			;;
	esac
}
