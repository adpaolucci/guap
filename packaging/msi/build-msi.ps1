param(
    [string]$OutMsi = "",
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$BinDir = Join-Path $RepoRoot "target\release"
if ($OutMsi -eq "") {
    $OutMsi = Join-Path $RepoRoot "target\release\guap-0.1.0-x86_64.msi"
}

if (-not $SkipBuild) {
    Push-Location $RepoRoot
    try {
        cargo build --workspace --release --offline
        if ($LASTEXITCODE -ne 0) { throw "cargo build --release --offline failed" }
    } finally {
        Pop-Location
    }
}

$WixCmd = Get-Command wix -ErrorAction SilentlyContinue
if (-not $WixCmd) {
    throw "WiX v4+ CLI ('wix.exe') not found on PATH. Install via: dotnet tool install --global wix"
}

$Wxs = Join-Path $PSScriptRoot "guap.wxs"
& $WixCmd.Source build $Wxs -d "BinDir=$BinDir" -arch x64 -o $OutMsi
if ($LASTEXITCODE -ne 0) { throw "wix build failed" }
Write-Host "Built MSI: $OutMsi"
