#!/usr/bin/env bash
# Common helpers and environment defaults

set -euo pipefail

# ---- mirrors & env defaults ----
export CGO_ENABLED="${CGO_ENABLED:-1}"
export CC="${CC:-gcc}"
export GOPROXY="${GOPROXY:-https://goproxy.cn,direct}"
export GO111MODULE=on
export GOINSECURE="${GOINSECURE:-}"
export PIP_BREAK_SYSTEM_PACKAGES=1
export PIP_INDEX_URL="${PIP_INDEX_URL:-https://pypi.tuna.tsinghua.edu.cn/simple}"
export GIT_BASE="${GIT_BASE:-https://github.com}"
export NUCLEI_TEMPLATES="${NUCLEI_TEMPLATES:-/root/nuclei-templates}"

# ---- logging ----
log()  { echo "[*] $*"; }
warn() { echo "[!] $*" >&2; }
die()  { echo "[x] $*" >&2; exit 1; }

# ---- retry ----
retry() {
  # retry <times> <cmd...>
  local -i tries="${1:-3}"; shift || true
  local -i i=1
  local rc=0
  while (( i <= tries )); do
    if "$@"; then return 0; fi
    rc=$?
    warn "cmd failed (attempt $i/$tries, rc=$rc): $*"
    sleep $(( i * 2 ))
    ((i++))
  done
  return "$rc"
}

# ---- helpers ----
ENSURE_BIN_LINK() {
  local bin="$1"
  if [[ -x "/root/go/bin/${bin}" && ! -e "/usr/local/bin/${bin}" ]]; then
    ln -sf "/root/go/bin/${bin}" "/usr/local/bin/${bin}"
  fi
}

have_yaml_in() {
  local dir="$1"
  [[ -d "$dir" ]] && find "$dir" -type f \( -name '*.yaml' -o -name '*.yml' \) -print -quit | grep -q .
}
