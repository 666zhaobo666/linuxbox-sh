import re

with open("modules/docker.sh", "r", encoding="utf-8") as f:
    content = f.read()

# Replace the cat > /etc/docker/daemon.json with a jq merge
old_block = r'''cat > /etc/docker/daemon.json << EOF
{
    "registry-mirrors": \[
        "https://docker.mirrors.ustc.edu.cn",
        "https://hub-mirror.c.163.com",
        "https://mirror.baidubce.com"
    \]
}
EOF'''

new_block = r'''# Safe merge to daemon.json
        mkdir -p /etc/docker
        if [ ! -f /etc/docker/daemon.json ]; then
            echo '{}' > /etc/docker/daemon.json
        fi
        local tmp_json=$(mktemp)
        # Use jq to merge the mirrors list safely without wiping out other settings
        jq '. + {"registry-mirrors": ["https://docker.mirrors.ustc.edu.cn", "https://hub-mirror.c.163.com", "https://mirror.baidubce.com"]}' /etc/docker/daemon.json > "$tmp_json"
        mv "$tmp_json" /etc/docker/daemon.json'''

content = re.sub(old_block, new_block, content, flags=re.MULTILINE)

with open("modules/docker.sh", "w", encoding="utf-8") as f:
    f.write(content)
