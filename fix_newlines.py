import os

def fix_crlf(filename):
    with open(filename, 'rb') as f:
        content = f.read()
    
    # Replace CRLF with LF
    content = content.replace(b'\r\n', b'\n')
    
    with open(filename, 'wb') as f:
        f.write(content)

for root, _, files in os.walk('modules'):
    for file in files:
        if file.endswith('.sh'):
            fix_crlf(os.path.join(root, file))

fix_crlf('LinuxBox.sh')
