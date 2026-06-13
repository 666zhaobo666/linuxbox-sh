import re

with open("modules/appstore.sh", "r", encoding="utf-8") as f:
    content = f.read()

# Change the position of the dot_str to be before the cyan number
old_printf = r'printf "\$\{cyan\}%-4s\$\{white\}%s%s %b  " "\$\{i\}\." "\$\{name\}" "\$\{padding\}" "\$\{dot_str\}"'
new_printf = r'printf "%b ${cyan}%-4s${white}%s%s" "${dot_str}" "${i}." "${name}" "${padding}"'

content = re.sub(old_printf, new_printf, content)

with open("modules/appstore.sh", "w", encoding="utf-8") as f:
    f.write(content)

with open("LinuxBox.sh", "r", encoding="utf-8") as f:
    linuxbox = f.read()

linuxbox = re.sub(r'^version="3\.3\.2"', 'version="3.3.3"', linuxbox, flags=re.MULTILINE)

with open("LinuxBox.sh", "w", encoding="utf-8") as f:
    f.write(linuxbox)

