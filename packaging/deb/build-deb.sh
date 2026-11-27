#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:-0.1.0}"
ARCH="${2:-amd64}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TARGET_DIR="${REPO_ROOT}/target/release"
STAGE_DIR="${REPO_ROOT}/target/deb-stage/guap_${VERSION}_${ARCH}"

rm -rf "${STAGE_DIR}"
mkdir -p "${STAGE_DIR}/DEBIAN" "${STAGE_DIR}/usr/bin" "${STAGE_DIR}/usr/share/doc/guap"

for bin in guap guap-mcp guap-iced; do
  if [[ ! -f "${TARGET_DIR}/${bin}" ]]; then
    echo "Missing release binary: ${TARGET_DIR}/${bin}. Run: cargo build --workspace --release --offline" >&2
    exit 1
  fi
  install -m 0755 "${TARGET_DIR}/${bin}" "${STAGE_DIR}/usr/bin/${bin}"
done

install -m 0644 "${REPO_ROOT}/README.md" "${STAGE_DIR}/usr/share/doc/guap/README.md"
install -m 0644 "${REPO_ROOT}/LICENSE" "${STAGE_DIR}/usr/share/doc/guap/copyright"

cat > "${STAGE_DIR}/DEBIAN/control" <<EOF
Package: guap
Version: ${VERSION}
Section: admin
Priority: optional
Architecture: ${ARCH}
Maintainer: Andrew D. Paolucci <andrew@paolucci.ca>
Homepage: https://guap.ca/guap/
Description: Pure-Rust single-machine offline AI & IT administration appliance
 Unifies 10 GUAP domain suites (326 MCP tools) behind 6 deterministic runbooks,
 a 6-meta-tool lazy MCP router, Approval Cards, Merkle custody receipts,
 loopback-only llama-server inference, and cross-platform Iced console.
EOF

OUT_DEB="${REPO_ROOT}/target/release/guap_${VERSION}_${ARCH}.deb"
dpkg-deb --root-owner-group --build "${STAGE_DIR}" "${OUT_DEB}"
echo "Built Debian package: ${OUT_DEB}"
