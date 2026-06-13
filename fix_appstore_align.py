import re

with open("modules/appstore.sh", "r", encoding="utf-8") as f:
    content = f.read()

# Replace the formatting block
old_block = r'''			# 统一格式化为宽字符列
			printf "\$\{cyan\}%-3s \$\{white\}%-30s %b  " "\$\{i\}\." "\$\{name\}" "\$\{dot_str\}"
			if \[ \$\(\(i % 3\)\) -eq 0 \]; then
				echo ""
			fi'''

new_block = r'''			# 计算实际显示宽度实现中文对齐
			local name_len=${#name}
			local real_len=0
			for ((j=0; j<name_len; j++)); do
				local c="${name:$j:1}"
				if [ $(printf "%d" "'$c" 2>/dev/null || echo 127) -le 127 ]; then
					((real_len+=1))
				else
					((real_len+=2))
				fi
			done
			local pad_len=$((36 - real_len))
			[ $pad_len -lt 0 ] && pad_len=1
			local padding=$(printf "%*s" $pad_len "")
			printf "${cyan}%-4s${white}%s%s %b  " "${i}." "${name}" "${padding}" "${dot_str}"
			if [ $((i % 3)) -eq 0 ]; then
				echo ""
			fi'''

content = re.sub(old_block, new_block, content, flags=re.MULTILINE)

with open("modules/appstore.sh", "w", encoding="utf-8") as f:
    f.write(content)
