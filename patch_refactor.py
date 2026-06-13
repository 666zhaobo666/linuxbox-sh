import re

with open("modules/appstore.sh", "r", encoding="utf-8") as f:
    content = f.read()

app_block_match = re.search(r'linux_app\(\) \{.*?\n\}(?=\n|$)', content, re.MULTILINE | re.DOTALL)
if not app_block_match:
    print("Cannot find linux_app")
    exit(1)

app_block = app_block_match.group(0)

# Extract dispatch cases
case_match = re.search(r'_linux_app_dispatch\(\) \{.*?case \$sub_choice in\n(.*?)\n\t\tesac', app_block, re.MULTILINE | re.DOTALL)
cases = case_match.group(1).strip().split('\n')
app_funcs = {}
for line in cases:
    line = line.strip()
    if not line: continue
    m = re.match(r'^(\d+)\)\s+(.+?)\s+;;$', line)
    if m:
        app_funcs[m.group(1)] = m.group(2)

# Extract display names
app_names = {}
for line in app_block.split('\n'):
    if 'echo -e "${cyan}' in line and '$(_dot' in line:
        entries = re.findall(r'\$\{cyan\}(\d+)\.\s*(?:\$\{white\})?(.*?)\s+\$\(_dot', line)
        for num, name in entries:
            app_names[num] = name.strip()

# Build the new APP_REGISTRY string in Bash format
registry_lines = []
for i in range(1, 111):
    num_str = str(i)
    name = app_names.get(num_str, f"UnknownApp{i}")
    func = app_funcs.get(num_str, "")
    
    flags = []
    if 'app_unavailable' in func:
        flags.append('disabled')
        unav_m = re.search(r'app_unavailable\s+"([^"]+)"', func)
        if unav_m:
            name = unav_m.group(1)
            # Make the func safe to evaluate or just keep it as is
            func = func.replace('"', '\\"')
    flag_str = ','.join(flags) if flags else 'normal'
    
    registry_lines.append(f'  [{num_str}]="{name}|{func}|{flag_str}"')

# Generate new linux_app function
new_linux_app = """linux_app() {
	# 新的数据驱动注册表: [id]="名字|调用函数|标志"
	declare -A APP_META=(
""" + "\n".join(registry_lines) + """
	)

	_dot() {
		if [ "${INSTALLED_MAP[$1]:-0}" = "1" ]; then
			echo -n "${green}●${white}"
		else
			echo -n "${red}●${white}"
		fi
	}

	_render_installed_list() {
		clear
		echo -e "${green}===== 已安装应用 =====${white}"
		echo ""
		if [ ${#INSTALLED_IDS[@]} -eq 0 ]; then
			echo -e "${yellow}暂无已安装应用${white}"
			break_end
			return 1
		fi
		local sorted
		sorted=$(printf '%s\\n' "${INSTALLED_IDS[@]}" | sort -n)
		while read -r id; do
			[ -n "$id" ] || continue
			local meta="${APP_META[$id]:-}"
			local name="${meta%%|*}"
			[ -z "$name" ] && name="?未注册"
			echo -e "  ${cyan}$id. ${white}$name  ${green}●${white}"
		done <<< "$sorted"
		echo ""
		echo -e "${pink}------------------------------------------------------------------------------------${white}"
		echo -e "${yellow}0.   ${white}返回应用市场"
		echo -e "${pink}------------------------------------------------------------------------------------${white}"
		read -e -p "输入编号进入应用详情 (0 返回): " jump_choice
		if [ "$jump_choice" = "0" ] || [ -z "$jump_choice" ]; then
			return 1
		fi
		if [ -n "${APP_META[$jump_choice]:-}" ]; then
			_linux_app_dispatch "$jump_choice"
		else
			echo -e "${red}无效编号 $jump_choice${white}"
			sleep 1
			return 1
		fi
	}

	_linux_app_dispatch() {
		local sub_choice="$1"
		unset -f docker_app_install docker_app_update docker_app_uninstall app_post_install app_post_install_password 2>/dev/null
		clear_app_ports
		
		local meta="${APP_META[$sub_choice]:-}"
		if [ -z "$meta" ]; then
			return
		fi
		
		local func_call=$(echo "$meta" | awk -F'|' '{print $2}')
		# 直接执行函数
		eval "$func_call"
	}

	while true; do
		declare -A INSTALLED_MAP=()
		INSTALLED_IDS=()
		if [ -f /home/docker/appno.txt ]; then
			while read -r id; do
				[ -n "$id" ] || continue
				INSTALLED_MAP["$id"]=1
				INSTALLED_IDS+=("$id")
			done < /home/docker/appno.txt
		fi

		clear
		echo -e "${green}===== 应用市场 =====${white}"
		echo -e "[图例] ${green}●${white} 已安装  ${red}●${white} 未安装"
		echo ""
		docker_tato
		echo -e "${pink}------------------------------------------------------------------------------------${white}"
		
		# 自动排版打印 110 个应用
		for i in {1..110}; do
			local meta="${APP_META[$i]:-}"
			local name="${meta%%|*}"
			local dot_str=$(_dot $i)
			# 统一格式化为宽字符列
			printf "${cyan}%-3s ${white}%-32s %s\\t" "${i}." "${name}" "${dot_str}"
			if [ $((i % 3)) -eq 0 ]; then
				echo ""
			fi
		done
		echo ""

		echo -e "${pink}------------------------------------------------------------------------------------${white}"
		echo -e "${yellow}0.   ${white}返回主菜单                                       ${cyan}666. ${white}查看已安装应用"
		echo -e "${pink}------------------------------------------------------------------------------------${white}"
		
		read -e -p "输入应用编号进行操作: " sub_choice
		case $sub_choice in
		0|"") return ;;
		666) _render_installed_list ;;
		*)
			if [[ "$sub_choice" =~ ^[0-9]+$ ]] && [ "$sub_choice" -ge 1 ] && [ "$sub_choice" -le 110 ]; then
				_linux_app_dispatch "$sub_choice"
			else
				echo -e "${red}无效的选择!${white}"
				sleep 1
			fi
			;;
		esac
	done
}"""

content = content.replace(app_block, new_linux_app)

# Replace the APP_DISPLAY_NAMES array usage globally because we deleted it or it might still be there.
# Let's also remove the global APP_DISPLAY_NAMES definition if it exists near the top.
content = re.sub(r'# 定义应用名称数组，用于已安装列表展示\s*declare -A APP_DISPLAY_NAMES=.*?\)\n\n', '', content, flags=re.DOTALL)


with open("modules/appstore.sh", "w", encoding="utf-8") as f:
    f.write(content)
