import re

with open("modules/firewall.sh", "r", encoding="utf-8") as f:
    content = f.read()

# Make SSH port dynamic instead of hardcoded 22
content = re.sub(
    r'sudo firewall-cmd --permanent --add-port=22/tcp',
    r'local ssh_port=$(grep -E "^Port " /etc/ssh/sshd_config | awk \'{print $2}\'); ssh_port=${ssh_port:-22}; sudo firewall-cmd --permanent --add-port=${ssh_port}/tcp',
    content
)

content = re.sub(
    r'sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT\s+# 淇濈暀SSH绔彛',
    r'local ssh_port=$(grep -E "^Port " /etc/ssh/sshd_config | awk \'{print $2}\'); ssh_port=${ssh_port:-22}; sudo iptables -A INPUT -p tcp --dport ${ssh_port} -j ACCEPT  # 保留SSH端口',
    content
)

with open("modules/firewall.sh", "w", encoding="utf-8") as f:
    f.write(content)
