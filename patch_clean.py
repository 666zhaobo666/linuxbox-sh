import re

with open("modules/system_clean.sh", "r", encoding="utf-8") as f:
    content = f.read()

# Fix pkill -9 apt|dpkg
content = re.sub(
    r"pkill -9 -f 'apt\|dpkg'",
    r"# Safer: wait or carefully remove lock\n\t# pkill -9 -f 'apt|dpkg' (removed for safety)",
    content
)

# Fix rm -rf /var/log/* to find /var/log -type f -name "*.log" -delete
content = re.sub(
    r"rm -rf /var/log/\*",
    r"find /var/log -type f -name \"*.log\" -delete || true",
    content
)

with open("modules/system_clean.sh", "w", encoding="utf-8") as f:
    f.write(content)
