import re

with open("modules/firewall.sh", "r", encoding="utf-8") as f:
    content = f.read()

# Fix the returns in firewalld_panel and iptables_panel to return 1 when user explicitly wants to exit
content = re.sub(
    r"0\)\s*# 返回上一级\s*return\s*;;",
    r"0)  # 返回上一级\n\t\t\t\treturn 1\n\t\t\t\t;;",
    content
)

# Fix the outer loop call to break when sub-panel returns 1
content = re.sub(
    r"firewalld_panel\n",
    r"firewalld_panel || break\n",
    content
)
content = re.sub(
    r"iptables_panel\n",
    r"iptables_panel || break\n",
    content
)

with open("modules/firewall.sh", "w", encoding="utf-8") as f:
    f.write(content)
