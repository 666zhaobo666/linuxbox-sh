#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "$ROOT_DIR"

find . -name '*.sh' -print0 | xargs -0 -n1 bash -n

grep -q '^version=' LinuxBox.sh
grep -q '^SCRIPT_BRANCH=' lib/constants.sh
grep -q '^load_linuxbox_config()' lib/config.sh
grep -q '^save_linuxbox_config()' lib/config.sh
grep -q '^linuxbox_dispatch()' lib/dispatch.sh
grep -q '^ensure_proxy()' lib/region.sh
grep -q 'raw.githubusercontent.com/${SCRIPT_REPO_OWNER}/${SCRIPT_REPO_NAME}/${SCRIPT_BRANCH}/${SCRIPT_FILE}' lib/update.sh
grep -q 'system_clean.sh' lib/constants.sh
grep -q 'basic_tools.sh' lib/constants.sh

echo "LinuxBox framework smoke test passed."
