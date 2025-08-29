#!/usr/bin/env bash
# Install ProjectDiscovery and other Go-based tools

install_go_tools() {
  log "Installing ProjectDiscovery tools (go install)…"
  local PD_TOOLS=(
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/katana/cmd/katana@latest"
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  )

  local OTHER_GO_TOOLS=(
    "github.com/lc/gau/v2/cmd/gau@latest"
    "github.com/tomnomnom/waybackurls@latest"
    "github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"
    "github.com/hahwul/dalfox/v2@latest"
  )

  for mod in "${PD_TOOLS[@]}" "${OTHER_GO_TOOLS[@]}"; do
    retry 3 go install -buildvcs=false "$mod" || warn "go install failed for $mod"
  done

  for b in httpx katana nuclei naabu subfinder gau waybackurls crlfuzz dalfox; do
    ENSURE_BIN_LINK "$b"
  done
}
