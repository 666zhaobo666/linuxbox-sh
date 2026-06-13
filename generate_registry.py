import re
import os

with open('modules/appstore.sh', 'r', encoding='utf-8') as f:
    content = f.read()

app_block_match = re.search(r'linux_app\(\) \{.*', content, re.MULTILINE | re.DOTALL)
if not app_block_match:
    print("Cannot find linux_app")
    exit(1)

app_block = app_block_match.group(0)

# get case dict
case_match = re.search(r'_linux_app_dispatch\(\) \{.*?case \$sub_choice in\n(.*?)\n\t\tesac', app_block, re.MULTILINE | re.DOTALL)
cases = case_match.group(1).strip().split('\n')
app_funcs = {}
for line in cases:
    line = line.strip()
    if not line: continue
    m = re.match(r'^(\d+)\)\s+(.+?)\s+;;$', line)
    if m:
        app_funcs[m.group(1)] = m.group(2)

# get app names
app_names = {}
for line in app_block.split('\n'):
    if 'echo -e "${cyan}' in line and '$(_dot' in line:
        entries = re.findall(r'\$\{cyan\}(\d+)\.\s*(?:\$\{white\})?(.*?)\s+\$\(_dot', line)
        for num, name in entries:
            app_names[num] = name.strip()

registry_lines = []
for i in range(1, 111):
    num_str = str(i)
    name = app_names.get(num_str, f"UnknownApp{i}")
    func = app_funcs.get(num_str, "")
    
    flags = []
    # Identify unavailable apps
    if 'app_unavailable' in func:
        flags.append('disabled')
        unav_m = re.search(r'app_unavailable\s+"([^"]+)"', func)
        if unav_m:
            name = unav_m.group(1)
            # Reformat to simple name
            func = func.replace('"', "'")
    
    # Optional category mapping, e.g. panel vs app. (1-6 are panels, etc.)
    # We will just mark basic categories if we can guess
    cat = "app"
    if "panel" in name.lower() or "面板" in name:
        cat = "panel"
        
    flag_str = ','.join(flags) if flags else 'normal'
    
    # Store: id|name|func|flags|category
    registry_lines.append(f'  "{num_str}|{name}|{func}|{flag_str}|{cat}"')

registry_block = "APP_REGISTRY=(\n" + "\n".join(registry_lines) + "\n)\n"

# Now write this to a safe patch file or print
with open('registry_data.txt', 'w', encoding='utf-8') as f:
    f.write(registry_block)

print("Registry parsing done")
