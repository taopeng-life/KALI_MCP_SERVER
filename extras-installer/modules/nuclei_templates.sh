#!/usr/bin/env bash
# Ensure nuclei templates exist and are up-to-date

ensure_nuclei_templates() {
  log "Preparing nuclei templates at: $NUCLEI_TEMPLATES"
  mkdir -p "$NUCLEI_TEMPLATES"

  # 1) updater first
  if ! have_yaml_in "$NUCLEI_TEMPLATES"; then
    if command -v nuclei >/dev/null 2>&1; then
      retry 3 nuclei -ut -ud "$NUCLEI_TEMPLATES" || retry 3 nuclei -update-templates -update-directory "$NUCLEI_TEMPLATES" || true
    fi
  fi

  # 2) shallow clone fallback
  if ! have_yaml_in "$NUCLEI_TEMPLATES"; then
    command -v git >/dev/null 2>&1 || die "git not installed"
    log "Cloning nuclei-templates (shallow)…"
    if [[ -z "$(ls -A "$NUCLEI_TEMPLATES" 2>/dev/null || true)" ]]; then
      retry 3 git clone --depth=1 "$GIT_BASE/projectdiscovery/nuclei-templates.git" "$NUCLEI_TEMPLATES" || true
      [[ -d "$NUCLEI_TEMPLATES/.git" ]] && rm -rf "$NUCLEI_TEMPLATES/.git" || true
    fi
  fi

  # 3) offline tarball fallback
  if ! have_yaml_in "$NUCLEI_TEMPLATES" && [[ -f /opt/nuclei-templates.tgz ]]; then
    log "Unpacking offline nuclei-templates.tgz…"
    tar xzf /opt/nuclei-templates.tgz -C "$(dirname "$NUCLEI_TEMPLATES")"
    if [[ -d "$(dirname "$NUCLEI_TEMPLATES")/nuclei-templates" && "$(dirname "$NUCLEI_TEMPLATES")/nuclei-templates" != "$NUCLEI_TEMPLATES" ]]; then
      rm -rf "$NUCLEI_TEMPLATES"
      mv "$(dirname "$NUCLEI_TEMPLATES")/nuclei-templates" "$NUCLEI_TEMPLATES"
    fi
  fi

  # 4) validate & refresh index
  if command -v nuclei >/dev/null 2>&1; then
    nuclei -validate -t "$NUCLEI_TEMPLATES" >/dev/null 2>&1 || true
    retry 2 nuclei -ut -ud "$NUCLEI_TEMPLATES" || retry 2 nuclei -update-templates -update-directory "$NUCLEI_TEMPLATES" || true
  fi

  have_yaml_in "$NUCLEI_TEMPLATES" || warn "No templates detected under $NUCLEI_TEMPLATES (network blocked?). Provide /opt/nuclei-templates.tgz for offline import."
}
