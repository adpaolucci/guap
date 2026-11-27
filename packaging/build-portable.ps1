param(
    [string]$OutDir = "",
    [string]$LlamaServerPath = "",
    [string]$GgufPath = "",
    [switch]$Release,
    [switch]$BuildSuites,
    [switch]$IncludeCuda
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$WsRoot = Split-Path -Parent $RepoRoot
if ($OutDir -eq "") {
    $OutDir = Join-Path $WsRoot "_portable_dist\guap-portable"
}

if ($BuildSuites) {
    $SuiteSpecs = @(
        @{ dir = "sys2rust"; bin = "sys2rust-mcp" },
        @{ dir = "net2rust"; bin = "net2rust-mcp" },
        @{ dir = "forensics2rust"; bin = "forensics2rust" },
        @{ dir = "winctl2rust"; bin = "winctl2rust-mcp" },
        @{ dir = "fs2rust"; bin = "fs2rust-mcp" },
        @{ dir = "chrome2rust"; bin = "chrome2rust-mcp" },
        @{ dir = "mail2rust"; bin = "mail2rust-mcp" },
        @{ dir = "android2rust"; bin = "android2rust-mcp" },
        @{ dir = "robocopy2rust"; bin = "robocopy2rust-mcp" }
    )
    foreach ($s in $SuiteSpecs) {
        $SuitePath = Join-Path $WsRoot $s.dir
        if (Test-Path $SuitePath) {
            Write-Host "Building $($s.dir) ($($s.bin))..."
            Push-Location $SuitePath
            try {
                if ($Release) {
                    cargo build --offline --release --bin $s.bin
                } else {
                    cargo build --offline --bin $s.bin
                }
                if ($LASTEXITCODE -ne 0) { throw "cargo build failed in $($s.dir)" }
            } finally {
                Pop-Location
            }
        }
    }
}

Set-Location $RepoRoot
$BinSubdir = if ($Release) { "release" } else { "debug" }

if ($Release) {
    cargo build --workspace --release --offline
} else {
    cargo build --workspace --offline
}
if ($LASTEXITCODE -ne 0) { throw "cargo build failed in guap" }

$GuapExe = Join-Path $RepoRoot "target\$BinSubdir\guap.exe"
$ArgsList = @("bundle", "create", "--out", $OutDir, "--bin-dir", (Join-Path $RepoRoot "target\$BinSubdir"))
if ($LlamaServerPath -ne "") { $ArgsList += @("--llama-server", $LlamaServerPath) }
if ($GgufPath -ne "") { $ArgsList += @("--gguf", $GgufPath) }
if ($IncludeCuda) { $ArgsList += "--include-cuda" }

& $GuapExe @ArgsList
if ($LASTEXITCODE -ne 0) { throw "guap bundle create failed" }

& $GuapExe bundle verify --dir $OutDir
if ($LASTEXITCODE -ne 0) { throw "guap bundle verify failed" }
