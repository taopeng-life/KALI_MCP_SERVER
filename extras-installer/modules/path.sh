#!/usr/bin/env bash
# PATH setup and final info

setup_path_and_info() {
  if ! echo "$PATH" | grep -q "/root/go/bin"; then
    echo 'export PATH="$PATH:/root/go/bin"' >> /etc/profile
  fi

  if command -v nuclei >/dev/null 2>&1; then
    log "nuclei version: $(nuclei -version 2>/dev/null || true)"
    if have_yaml_in "$NUCLEI_TEMPLATES"; then
      log "nuclei-templates ready under: $NUCLEI_TEMPLATES"
    else
      warn "nuclei-templates still missing YAMLs. Check network or provide /opt/nuclei-templates.tgz."
    fi
  fi
}
