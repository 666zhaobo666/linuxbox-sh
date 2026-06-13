import re

with open("modules/appstore.sh", "r", encoding="utf-8") as f:
    content = f.read()

# 提取所有的 func 对应的 docker_name 或 panel_path
func_to_docker = {}
func_to_panel = {}

funcs = re.findall(r'^([a-zA-Z0-9_-]+)\(\) \{.*?^\}', content, re.MULTILINE | re.DOTALL)
for f_def in funcs:
    pass # this regex might be tricky.

