# coding: utf-8
import re

with open('modules/appstore.sh', 'r', encoding='utf-8') as f:
    content = f.read()

# find linux_app function block first
app_block_match = re.search(r'linux_app\(\) \{.*', content, re.MULTILINE | re.DOTALL)
if app_block_match:
    app_block = app_block_match.group(0)
    
    # get the dispatch dict
    case_match = re.search(r'_linux_app_dispatch\(\) \{.*?case \$sub_choice in\n(.*?)\n\t\tesac', app_block, re.MULTILINE | re.DOTALL)
    cases = case_match.group(1).strip().split('\n')
    app_funcs = {}
    for line in cases:
        line = line.strip()
        if not line: continue
        m = re.match(r'^(\d+)\)\s+(.+?)\s+;;$', line)
        if m:
            app_funcs[m.group(1)] = m.group(2)
            
    # get the display names
    echo_lines = re.findall(r'echo -e "\$\{cyan\}\d+\..*?\$\(_dot', app_block)
    
    app_names = {}
    # the entire text might contain multiple entries per line
    for line in app_block.split('\n'):
        if 'echo -e "${cyan}' in line and '$(_dot' in line:
            entries = re.findall(r'\$\{cyan\}(\d+)\.\s*\$\{white\}(.*?)\s+\$\(_dot', line)
            for num, name in entries:
                app_names[num] = name.strip()

    with open('app_registry.txt', 'w', encoding='utf-8') as f:
        f.write('APP_REGISTRY=(\n')
        for i in range(1, 111):
            num_str = str(i)
            name = app_names.get(num_str, '?')
            func = app_funcs.get(num_str, '?')
            flags = []
            if 'app_unavailable' in func:
                flags.append('disabled')
                unav_m = re.search(r'app_unavailable\s+"([^"]+)"', func)
                if unav_m:
                    name = unav_m.group(1)
            flag_str = ','.join(flags) if flags else 'normal'
            func = func.replace('"', "'")
            f.write(f'    "{num_str}|{name}|{func}|{flag_str}"\n')
        f.write(')\n')
