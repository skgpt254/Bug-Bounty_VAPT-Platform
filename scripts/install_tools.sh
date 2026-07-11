#!/usr/bin/env bash
# =============================================================================
# Installs the external CLI tools the platform shells out to.
# Every tool here is optional — app/core/tool_runner.py checks has_tool()
# before every call and phases degrade to native Python fallbacks (see
# app/core/phases/*.py) if a given tool is missing. Run what you can; the
# platform runs fine with a partial toolset, just with less depth per phase.
#
# Usage: ./scripts/install_tools.sh
# Requires: Go 1.21+, git, python3-pip. Tested on Debian/Ubuntu.
# =============================================================================
set -euo pipefail

if ! command -v go &>/dev/null; then
  echo "Go is not installed. Install Go 1.21+ first: https://go.dev/doc/install"
  exit 1
fi

export GOPATH="${GOPATH:-$HOME/go}"
export PATH="$PATH:$GOPATH/bin"

echo "==> Installing ProjectDiscovery core toolchain (subfinder, dnsx, httpx, katana, nuclei)"
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/notify/cmd/notify@latest

echo "==> Installing supplementary recon tools"
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/gwen001/github-subdomains@latest
go install -v github.com/ffuf/ffuf/v2@latest
go install -v github.com/Sh1Yo/x8@latest

echo "==> Installing trufflehog (verified secret scanning)"
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
  | sh -s -- -b "$GOPATH/bin"

echo "==> Updating nuclei templates"
nuclei -update-templates -silent || true

echo "==> Warming up httpx (it downloads a ~90MB classification model on its"
echo "    very first run — doing that now, at setup time, means a live scan"
echo "    never eats that delay/first-run-network-hiccup risk invisibly)"
echo "example.com" | httpx -silent -json > /dev/null 2>&1 || \
  echo "httpx warm-up run failed/skipped — it'll just download on first real scan instead, no harm done"

echo "==> Cloning SecLists (optional, large — used for fuzzing wordlists if present)"
if [ ! -d "/usr/share/wordlists/seclists" ]; then
  sudo mkdir -p /usr/share/wordlists
  sudo git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/wordlists/seclists || \
    echo "SecLists clone failed/skipped — built-in fallback wordlists in app/wordlists/ will be used instead."
fi

echo ""
echo "Done. Verify what's on PATH with: subfinder -version; httpx -version; nuclei -version; katana -version"
echo "Anything not installed will be silently skipped by the platform at scan time — nothing crashes."
