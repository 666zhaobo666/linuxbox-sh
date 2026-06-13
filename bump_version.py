import re

with open("LinuxBox.sh", "r", encoding="utf-8") as f:
    content = f.read()

content = re.sub(r'^version="3\.3\.1"', 'version="3.3.2"', content, flags=re.MULTILINE)

with open("LinuxBox.sh", "w", encoding="utf-8") as f:
    f.write(content)
