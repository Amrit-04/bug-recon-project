#!/usr/bin/env bash
# scripts/install_tools.sh
# Manual installation script for scoutr supported external discovery tools.
# All tools are standard Go binaries installed via `go install`.

set -e

echo "Installing scoutr external recon arsenal via go install..."

TOOLS=(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/owasp-amass/amass/v4/...@master"
    "github.com/tomnomnom/assetfinder@latest"
    "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/tomnomnom/waybackurls@latest"
    "github.com/lc/gau/v2/cmd/gau@latest"
    "github.com/projectdiscovery/katana/cmd/katana@latest"
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
)

for pkg in "${TOOLS[@]}"; do
    echo "Installing ${pkg}..."
    go install -v "${pkg}" || echo "Warning: failed to install ${pkg}"
done

echo ""
echo "Installation complete. Ensure '$(go env GOPATH)/bin' is included in your PATH."
echo "Run 'scoutr arsenal' to verify installation status."
