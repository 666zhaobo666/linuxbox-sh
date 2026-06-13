with open("modules/appstore.sh", "r", encoding="utf-8") as f:
    content = f.read()

import re
old_line = r'''		declare -f "\$func_name" 2>/dev/null \| grep -E "\^\\s\*\(local\\s\+\)\?\$\{var_name\}=" \| head -n 1 \| sed -E "s/\.\*\$\{var_name\}=\[\"\'\]\?\(\[\^\"\' \t;\]\+\)\[\"\'\]\?\.\*/\\1/"'''

# Let's just find the exact line and replace it, it's easier.
new_content = []
for line in content.split('\n'):
    if '_get_meta_var() {' in line:
        pass
    if 'declare -f "$func_name" 2>/dev/null | grep -E "^\\s*(local\\s+)?${var_name}="' in line:
        line = '''		declare -f "$func_name" 2>/dev/null | grep -E "^\\s*(local\\s+)?${var_name}=" | head -n 1 | sed -E 's/.*'"${var_name}"'=["'"'"']?([^"'"'"' 	;]+)["'"'"']?.*/\\1/' '''
    new_content.append(line)

with open("modules/appstore.sh", "w", encoding="utf-8") as f:
    f.write('\n'.join(new_content))

