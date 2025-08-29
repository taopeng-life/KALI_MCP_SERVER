#!/usr/bin/env bash
# Prepare wordlists convenience links

prepare_wordlists() {
  log "Preparing wordlists softlinks…"
  mkdir -p /usr/share/wordlists/dirb || true
  if [[ -f /usr/share/dirb/wordlists/common.txt && ! -f /usr/share/wordlists/dirb/common.txt ]]; then
    ln -sf /usr/share/dirb/wordlists/common.txt /usr/share/wordlists/dirb/common.txt
  fi
  mkdir -p /usr/share/wordlists/dns || true
}
