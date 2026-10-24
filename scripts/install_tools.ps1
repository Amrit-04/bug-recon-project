# scripts/install_tools.ps1
# Manual installation script for scoutr supported external discovery tools.
# All tools are standard Go binaries installed via `go install`.

Write-Host "Installing scoutr external recon arsenal via go install..." -ForegroundColor Cyan

$tools = @(
    @{ Name = "subfinder";   Pkg = "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" },
    @{ Name = "amass";       Pkg = "github.com/owasp-amass/amass/v4/...@master" },
    @{ Name = "assetfinder"; Pkg = "github.com/tomnomnom/assetfinder@latest" },
    @{ Name = "dnsx";        Pkg = "github.com/projectdiscovery/dnsx/cmd/dnsx@latest" },
    @{ Name = "httpx";       Pkg = "github.com/projectdiscovery/httpx/cmd/httpx@latest" },
    @{ Name = "waybackurls"; Pkg = "github.com/tomnomnom/waybackurls@latest" },
    @{ Name = "gau";         Pkg = "github.com/lc/gau/v2/cmd/gau@latest" },
    @{ Name = "katana";      Pkg = "github.com/projectdiscovery/katana/cmd/katana@latest" },
    @{ Name = "nuclei";      Pkg = "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" }
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

Write-Host "`nAll tools processed. Ensure `"$env:GOPATH\bin`" or `"$env:USERPROFILE\go\bin`" is in your PATH." -ForegroundColor Cyan
Write-Host "Run 'scoutr arsenal' to verify installation status." -ForegroundColor Cyan
