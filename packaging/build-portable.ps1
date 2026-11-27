param(
    [string]$OutDir = "",
    [string]$LlamaServerPath = "",
    [string]$GgufPath = "",
    [switch]$Release
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
if ($OutDir -eq "") {
    $OutDir = Join-Path (Split-Path -Parent $RepoRoot) "_portable_dist\guap-portable"
}
Set-Location $RepoRoot

$ProfileFlag = if ($Release) { "--release" } else { "" }
$BinSubdir = if ($Release) { "release" } else { "debug" }

if ($Release) {
    cargo build --workspace --release --offline
} else {
    cargo build --workspace --offline
}
if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }

$GuapExe = Join-Path $RepoRoot "target\$BinSubdir\guap.exe"
$ArgsList = @("bundle", "create", "--out", $OutDir, "--bin-dir", (Join-Path $RepoRoot "target\$BinSubdir"))
if ($LlamaServerPath -ne "") { $ArgsList += @("--llama-server", $LlamaServerPath) }
if ($GgufPath -ne "") { $ArgsList += @("--gguf", $GgufPath) }

& $GuapExe @ArgsList
if ($LASTEXITCODE -ne 0) { throw "guap bundle create failed" }

& $GuapExe bundle verify --dir $OutDir
if ($LASTEXITCODE -ne 0) { throw "guap bundle verify failed" }
