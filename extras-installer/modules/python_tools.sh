#!/usr/bin/env bash
# Install Python-based tools and create convenience wrappers

install_python_tools() {
  log "Installing Python-based tools…"
  python3 -m pip install -U pip -i "$PIP_INDEX_URL"
  pip3 install -U setuptools wheel -i "$PIP_INDEX_URL"
  pip3 install 'cement<2.7' -i "$PIP_INDEX_URL"   # for droopescan
  pip3 install droopescan xsstrike -i "$PIP_INDEX_URL"

  # CMSeeK wrapper
  if ! command -v cmseek >/dev/null 2>&1; then
    cd /opt
    [[ -d /opt/cmseek ]] || retry 3 git clone --depth=1 "$GIT_BASE/Tuhinshubhra/CMSeeK.git" cmseek
    pip3 install -r /opt/cmseek/requirements.txt -i "$PIP_INDEX_URL"
    cat >/usr/local/bin/cmseek <<'EOF'
#!/usr/bin/env bash
exec python3 /opt/cmseek/cmseek.py "$@"
EOF
    chmod +x /usr/local/bin/cmseek
  fi

  # Corsy wrapper
  if ! command -v corsy >/dev/null 2>&1; then
    cd /opt
    [[ -d /opt/corsy ]] || retry 3 git clone --depth=1 "$GIT_BASE/s0md3v/Corsy.git" corsy
    pip3 install -r /opt/corsy/requirements.txt -i "$PIP_INDEX_URL"
    cat >/usr/local/bin/corsy <<'EOF'
#!/usr/bin/env bash
exec python3 /opt/corsy/corsy.py "$@"
EOF
    chmod +x /usr/local/bin/corsy
  fi

  # OpenRedireX wrapper
  if ! command -v openredirex >/dev/null 2>&1; then
    cd /opt
    [[ -d /opt/OpenRedireX ]] || retry 3 git clone --depth=1 "$GIT_BASE/devanshbatham/OpenRedireX.git"
    if [[ -f /opt/OpenRedireX/requirements.txt ]]; then
      pip3 install -r /opt/OpenRedireX/requirements.txt -i "$PIP_INDEX_URL"
    fi
    cat >/usr/local/bin/openredirex <<'EOF'
#!/usr/bin/env bash
exec python3 /opt/OpenRedireX/openredirex.py "$@"
EOF
    chmod +x /usr/local/bin/openredirex
  fi

  # testssl shim
  if command -v testssl.sh >/dev/null 2>&1 && [[ ! -e /usr/local/bin/testssl ]]; then
    ln -sf "$(command -v testssl.sh)" /usr/local/bin/testssl
  fi
}
