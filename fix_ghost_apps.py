import re

with open("modules/appstore.sh", "r", encoding="utf-8") as f:
    content = f.read()

# The block to be replaced
old_block = r'''	while true; do
		declare -A INSTALLED_MAP=\(\)
		INSTALLED_IDS=\(\)
		if \[ -f /home/docker/appno\.txt \]; then
			while read -r id; do
				\[ -n "\$id" \] \|\| continue
				INSTALLED_MAP\["\$id"\]=1
				INSTALLED_IDS\+=\("\$id"\)
			done < /home/docker/appno\.txt
		fi'''

new_block = r'''	# 辅助反射提取: 从函数定义中获取 docker_name 或 panel_path
	_get_meta_var() {
		local func_name="$1"
		local var_name="$2"
		declare -f "$func_name" 2>/dev/null | grep -E "^\s*(local\s+)?${var_name}=" | head -n 1 | sed -E "s/.*${var_name}=[\"']?([^\"' \t;]+)[\"']?.*/\1/"
	}

	while true; do
		declare -A INSTALLED_MAP=()
		INSTALLED_IDS=()
		if [ -f /home/docker/appno.txt ]; then
			local valid_ids=()
			local changed=0
			local all_containers
			all_containers=$(docker ps -a --format '{{.Names}}' 2>/dev/null || echo "")
			
			while read -r id; do
				[ -n "$id" ] || continue
				
				local meta="${APP_META[$id]:-}"
				local func_call=$(echo "$meta" | awk -F'|' '{print $2}')
				[ -z "$func_call" ] && continue
				
				local is_installed=1
				local d_name=$(_get_meta_var "$func_call" "docker_name")
				if [ -n "$d_name" ]; then
					if ! echo "$all_containers" | grep -q "^${d_name}$"; then
						is_installed=0
					fi
				else
					local p_path=$(_get_meta_var "$func_call" "panel_path")
					if [ -n "$p_path" ]; then
						if ! eval "ls $p_path >/dev/null 2>&1"; then
							is_installed=0
						fi
					fi
				fi
				
				if [ "$is_installed" -eq 1 ]; then
					INSTALLED_MAP["$id"]=1
					INSTALLED_IDS+=("$id")
					valid_ids+=("$id")
				else
					changed=1
				fi
			done < /home/docker/appno.txt
			
			# 如果发现“幽灵应用”（本地被删但配置还在），则自动瘦身配置表
			if [ "$changed" -eq 1 ]; then
				if [ ${#valid_ids[@]} -gt 0 ]; then
					printf "%s\n" "${valid_ids[@]}" > /home/docker/appno.txt
				else
					> /home/docker/appno.txt
				fi
			fi
		fi'''

content = re.sub(old_block, new_block, content)

with open("modules/appstore.sh", "w", encoding="utf-8") as f:
    f.write(content)
