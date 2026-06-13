import re

with open("modules/network_tools.sh", "r", encoding="utf-8") as f:
    content = f.read()

# Replace the pipe-to-bash calls
replacements = [
    (r"curl \$\{url_proxy\}raw\.githubusercontent\.com/zhucaidan/mtr_trace/main/mtr_trace\.sh \| bash", 
     r"curl -sL ${url_proxy}raw.githubusercontent.com/zhucaidan/mtr_trace/main/mtr_trace.sh -o /tmp/mtr_trace.sh && bash /tmp/mtr_trace.sh || echo '下载失败'"),
    
    (r"curl nxtrace\.org/nt \|bash", 
     r"curl -sL https://nxtrace.org/nt -o /tmp/nt.sh && bash /tmp/nt.sh || echo '下载失败'"),
    
    (r"curl -sL yabs\.sh \| bash -s -- -i -5", 
     r"curl -sL https://yabs.sh -o /tmp/yabs.sh && bash /tmp/yabs.sh -i -5 || echo '下载失败'"),
     
    (r"curl -Lso- bench\.sh \| bash", 
     r"curl -sL https://bench.sh -o /tmp/bench.sh && bash /tmp/bench.sh || echo '下载失败'")
]

for old, new in replacements:
    content = re.sub(old, new, content)

with open("modules/network_tools.sh", "w", encoding="utf-8") as f:
    f.write(content)
