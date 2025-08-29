#!/usr/bin/env bash
set -euo pipefail

echo "[*] extras-install.sh start (modular)"

# shellcheck disable=SC1091
source "$(dirname "$0")/lib/common.sh"
source "$(dirname "$0")/modules/go_tools.sh"
source "$(dirname "$0")/modules/python_tools.sh"
source "$(dirname "$0")/modules/nuclei_templates.sh"
source "$(dirname "$0")/modules/wordlists.sh"
source "$(dirname "$0")/modules/path.sh"

install_go_tools
install_python_tools
ensure_nuclei_templates
prepare_wordlists
setup_path_and_info

echo "[+] extras-install.sh done"
