# Packaging Manifests (`Portable USB`, `MSI`, `WinGet`, `Scoop`, `Homebrew`, `Debian`)

This directory stores ready-to-build and ready-to-submit distribution manifests for **`guap` v0.1.0**.

## 1. Self-Contained `guap-portable` USB / Folder Bundle

Assembles `guap.exe`, `guap-mcp.exe`, `guap-win32.exe`, `guap-iced.exe`, all discovered suite MCP binaries + `metadata.json`, optional offline `llama-server` + companion DLLs + `.gguf`, and a dual SHA-256/SHA-512 Merkle `portable-manifest.custody.json`:

```powershell
.\packaging\build-portable.ps1 -Release -BuildSuites `
  -LlamaServerPath path\to\llama-server.exe `
  -GgufPath path\to\gemma-4-E4B-it-UD-Q4_K_XL.gguf
```

## 2. Windows Installer (`MSI` via WiX v4+)

Single-machine per-host MSI (`Zero background services or daemons`, Charter `G3`):

```powershell
.\packaging\msi\build-msi.ps1
```

## 3. Windows Package Manager (`winget`) & `Scoop`

```powershell
winget validate --manifest .\packaging\winget\manifests\a\adpaolucci\guap\0.1.0
scoop install .\packaging\scoop\guap.json
```

## 4. Homebrew (`macOS` & `Linux`) & Debian (`.deb`)

```bash
brew install --formula ./packaging/homebrew/guap.rb
./packaging/deb/build-deb.sh 0.1.0 amd64
```
