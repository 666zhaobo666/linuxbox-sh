import re

with open("LinuxBox.sh", "r", encoding="utf-8") as f:
    linuxbox = f.read()

linuxbox = re.sub(r'^version="3\.3\.3"', 'version="3.3.4"', linuxbox, flags=re.MULTILINE)

with open("LinuxBox.sh", "w", encoding="utf-8") as f:
    f.write(linuxbox)

