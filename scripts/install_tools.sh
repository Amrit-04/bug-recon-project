#!/usr/bin/env bash
# scripts/install_tools.sh
# Manual installation script for scoutr supported external discovery tools.
#
# Go binaries are installed via `go install`. nmap is NOT a Go program and is
# therefore only installed through the OS package manager when explicitly
# requested with --with-nmap; otherwise a manual hint is printed.
#
# Usage:
#   ./scripts/install_tools.sh              # Tier 0/1 Go binaries only
#   ./scripts/install_tools.sh --with-nmap  # also install nmap via apt/dnf/brew

set -e

INSTALL_NMAP=0
for arg in "$@"; do
  case "$arg" in
    --with-nmap) INSTALL_NMAP=1 ;;
    *) echo "Unknown argument: $arg"; exit 2 ;;
  esac
done

echo "Installing scoutr external recon arsenal via go install..."

GO_TOOLS=(
    # Tier 0 - passive OSINT
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/owasp-amass/amass/v4/...@master"
    "github.com/tomnomnom/assetfinder@latest"
    "github.com/tomnomnom/waybackurls@latest"
    "github.com/lc/gau/v2/cmd/gau@latest"
    # Tier 1 - read-only probes
    "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/katana/cmd/katana@latest"
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    # Tier 1 - active scanning (rate limited, conservative defaults)
    "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    "github.com/ffuf/ffuf/v2@latest"
    "github.com/hahwul/dalfox/v2@latest"
)

for pkg in "${GO_TOOLS[@]}"; do
    echo "Installing ${pkg}..."
    go install -v "${pkg}" || echo "Warning: failed to install ${pkg}"
done

echo ""
if [ "$INSTALL_NMAP" -eq 1 ]; then
    echo "Installing nmap via the OS package manager..."
    if command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update && sudo apt-get install -y nmap
    elif command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y nmap
    elif command -v pacman >/dev/null 2>&1; then
        sudo pacman -S --noconfirm nmap
    elif command -v brew >/dev/null 2>&1; then
        brew install nmap
    else
        echo "No supported package manager found. Install nmap manually:"
        echo "  https://nmap.org/download.html"
    fi
else
    echo "nmap is not a Go binary and was NOT installed automatically."
    echo "To install it:"
    echo "  Debian/Ubuntu:  sudo apt-get install -y nmap"
    echo "  Fedora/RHEL:    sudo dnf install -y nmap"
    echo "  macOS:          brew install nmap"
    echo "  Windows:        winget install -e --id Insecure.Nmap"
    echo "Or re-run this script with --with-nmap."
fi

echo ""
echo "Installation complete. Ensure '$(go env GOPATH)/bin' is included in your PATH."
echo "Run 'scoutr arsenal' to verify installation status."
