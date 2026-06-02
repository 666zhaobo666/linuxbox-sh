#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT_DIR/LinuxBox.sh"

bash -n "$SCRIPT"

grep -q '^SCRIPT_BRANCH=' "$SCRIPT"
grep -q '^load_linuxbox_config()' "$SCRIPT"
grep -q '^save_linuxbox_config()' "$SCRIPT"
grep -q '^linuxbox_dispatch()' "$SCRIPT"
grep -q 'gh_proxy="$url_proxy"' "$SCRIPT"
grep -q 'raw.githubusercontent.com/${SCRIPT_REPO_OWNER}/${SCRIPT_REPO_NAME}/${SCRIPT_BRANCH}/${SCRIPT_FILE}' "$SCRIPT"

echo "LinuxBox framework smoke test passed."
