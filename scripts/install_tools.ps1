# scripts/install_tools.ps1
# Manual installation script for scoutr supported external discovery tools.
#
# Go binaries are installed via `go install`. nmap is NOT a Go program and is
# therefore only installed through winget when explicitly requested with
# -WithNmap; otherwise a manual hint is printed.
#
# Usage:
#   .\scripts\install_tools.ps1              # Tier 0/1 Go binaries only
#   .\scripts\install_tools.ps1 -WithNmap    # also install nmap via winget

param(
    [switch]$WithNmap
)

Write-Host "Installing scoutr external recon arsenal via go install..." -ForegroundColor Cyan

$tools = @(
    # Tier 0 - passive OSINT
    @{ Name = "subfinder";   Pkg = "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" },
    @{ Name = "amass";       Pkg = "github.com/owasp-amass/amass/v4/...@master" },
    @{ Name = "assetfinder"; Pkg = "github.com/tomnomnom/assetfinder@latest" },
    @{ Name = "waybackurls"; Pkg = "github.com/tomnomnom/waybackurls@latest" },
    @{ Name = "gau";         Pkg = "github.com/lc/gau/v2/cmd/gau@latest" },
    # Tier 1 - read-only probes
    @{ Name = "dnsx";        Pkg = "github.com/projectdiscovery/dnsx/cmd/dnsx@latest" },
    @{ Name = "httpx";       Pkg = "github.com/projectdiscovery/httpx/cmd/httpx@latest" },
    @{ Name = "katana";      Pkg = "github.com/projectdiscovery/katana/cmd/katana@latest" },
    @{ Name = "nuclei";      Pkg = "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" },
    # Tier 1 - active scanning (rate limited, conservative defaults)
    @{ Name = "naabu";       Pkg = "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest" },
    @{ Name = "ffuf";        Pkg = "github.com/ffuf/ffuf/v2@latest" },
    @{ Name = "dalfox";      Pkg = "github.com/hahwul/dalfox/v2@latest" }
)

foreach ($tool in $tools) {
    Write-Host "Installing $($tool.Name) ($($tool.Pkg))..." -ForegroundColor Yellow
    go install -v $tool.Pkg
    if ($LASTEXITCODE -eq 0) {
        Write-Host "$($tool.Name) installed successfully." -ForegroundColor Green
    } else {
        Write-Warning "Failed to install $($tool.Name). Please check errors above."
    }
}

if ($WithNmap) {
    Write-Host "Installing nmap via winget..." -ForegroundColor Yellow
    winget install -e --id Insecure.Nmap --accept-package-agreements --accept-source-agreements
    if ($LASTEXITCODE -eq 0) {
        Write-Host "nmap installed successfully." -ForegroundColor Green
    } else {
        Write-Warning "winget install of nmap failed. Download from https://nmap.org/download.html"
    }
} else {
    Write-Host "`nnmap is not a Go binary and was NOT installed automatically." -ForegroundColor Cyan
    Write-Host "  winget install -e --id Insecure.Nmap" -ForegroundColor Gray
    Write-Host "  or re-run with: .\scripts\install_tools.ps1 -WithNmap" -ForegroundColor Gray
}

Write-Host "`nAll tools processed. Ensure `"$env:GOPATH\bin`" or `"$env:USERPROFILE\go\bin`" is in your PATH." -ForegroundColor Cyan
Write-Host "Run 'scoutr arsenal' to verify installation status." -ForegroundColor Cyan
