import re

with open("modules/appstore.sh", "r", encoding="utf-8") as f:
    content = f.read()

content = re.sub(
    r'echo -n "\$\{green\}●\$\{white\}"',
    r'echo -ne "${green}●${white}"',
    content
)

content = re.sub(
    r'echo -n "\$\{red\}●\$\{white\}"',
    r'echo -ne "${red}●${white}"',
    content
)

# Also fix the printf to better handle Chinese character widths
# We can use a trick or just leave printf as is, but echo -ne is the main issue.
content = re.sub(
    r'printf "\$\{cyan\}%-3s \$\{white\}%-32s %s\\t"',
    r'printf "${cyan}%-3s ${white}%-30s %b  "',
    content
)

with open("modules/appstore.sh", "w", encoding="utf-8") as f:
    f.write(content)
