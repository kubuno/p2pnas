#!/usr/bin/env bash
# build_macos.sh — paquet macOS (.pkg) d'un MODULE Kubuno. À exécuter sur un Mac.
#
# Auto-détectant (id/version depuis Cargo.toml). Dépose le module dans
# l'installation du core (/usr/local/kubuno/modules/<id>/) et redémarre le daemon
# launchd. Migrations EMBARQUÉES (sqlx::migrate!) ; le module tourne sans
# config.toml (DB/secret/URL injectés par le core via l'environnement).
#
# Usage (sur un Mac) :
#   bash build_macos.sh                 # → dist/kubuno-<id>-<ver>-arm64.pkg
#   UNIVERSAL=1 bash build_macos.sh     # binaire fat arm64+x86_64
#   MACOS_SIGN_IDENTITY="Developer ID Installer: …" bash build_macos.sh
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
export SQLX_OFFLINE=true

[[ "$(uname -s)" == "Darwin" ]] || { echo "Erreur : à exécuter sur macOS (pkgbuild)." >&2; exit 1; }

PKG_NAME=$(grep -m1 '^name' Cargo.toml | sed -E 's/.*"([^"]+)".*/\1/')
MODULE="${PKG_NAME#kubuno-}"
VERSION=$(grep -m1 '^version' Cargo.toml | sed -E 's/.*"([^"]+)".*/\1/')
TARGET="${TARGET:-aarch64-apple-darwin}"
UNIVERSAL="${UNIVERSAL:-0}"
DIST_DIR="${DIST_DIR:-dist}"; mkdir -p "$DIST_DIR"
IDENTIFIER="com.kubuno.module.${MODULE}"
PKGROOT="$(mktemp -d)"; SCRIPTS="$(mktemp -d)"; trap 'rm -rf "$PKGROOT" "$SCRIPTS"' EXIT

echo "==> Paquet macOS kubuno-${MODULE} ${VERSION}"

# ── Frontend ────────────────────────────────────────────────────────────────
HAS_FRONTEND=0
if [[ -d frontend ]]; then
  [[ -f frontend/dist/entry.js ]] || (cd frontend && npm run build)
  [[ -f frontend/dist/entry.js ]] && HAS_FRONTEND=1
fi

# ── Compilation Rust ────────────────────────────────────────────────────────
build_one() { rustup target add "$1" >/dev/null 2>&1 || true; cargo build --release --target "$1" --bin "kubuno-${MODULE}"; }
if [[ "$UNIVERSAL" == "1" ]]; then
  build_one aarch64-apple-darwin; build_one x86_64-apple-darwin
  mkdir -p target/universal/release
  lipo -create -output "target/universal/release/kubuno-${MODULE}" \
    "target/aarch64-apple-darwin/release/kubuno-${MODULE}" \
    "target/x86_64-apple-darwin/release/kubuno-${MODULE}"
  BIN_DIR="target/universal/release"; ARCH_LABEL="universal"
else
  build_one "$TARGET"; BIN_DIR="target/${TARGET}/release"
  case "$TARGET" in aarch64-apple-darwin) ARCH_LABEL="arm64";; x86_64-apple-darwin) ARCH_LABEL="x86_64";; *) ARCH_LABEL="$TARGET";; esac
fi
[[ -f "$BIN_DIR/kubuno-${MODULE}" ]] || { echo "Erreur : binaire non produit." >&2; exit 1; }

# ── pkgroot ─────────────────────────────────────────────────────────────────
MODDIR="$PKGROOT/usr/local/kubuno/modules/${MODULE}"
mkdir -p "$MODDIR"
install -m 755 "$BIN_DIR/kubuno-${MODULE}" "$MODDIR/kubuno-${MODULE}"
[[ -f module.toml ]] && install -m 644 module.toml "$MODDIR/module.toml"
[[ "$HAS_FRONTEND" == "1" ]] && { mkdir -p "$MODDIR/frontend"; cp -R frontend/dist/. "$MODDIR/frontend/"; }
if [[ -f config.toml.example ]]; then
  mkdir -p "$PKGROOT/etc/kubuno/modules/${MODULE}"
  install -m 644 config.toml.example "$PKGROOT/etc/kubuno/modules/${MODULE}/config.toml.example"
fi

# ── postinstall : data dir + restart daemon ─────────────────────────────────
cat > "$SCRIPTS/postinstall" << POST
#!/bin/bash
set -e
mkdir -p /usr/local/var/kubuno/modules/${MODULE}
if dscl . -read /Users/_kubuno >/dev/null 2>&1; then
    chown -R _kubuno:_kubuno /usr/local/var/kubuno/modules/${MODULE} 2>/dev/null || true
fi
# Redémarre le core pour qu'il découvre/relance le module
launchctl kickstart -k system/com.kubuno.core 2>/dev/null || true
echo "Module ${MODULE} installé. Activez-le si besoin depuis la console admin Kubuno."
exit 0
POST
chmod 755 "$SCRIPTS/postinstall"

# ── .pkg ────────────────────────────────────────────────────────────────────
COMPONENT="$(mktemp -d)/kubuno-${MODULE}-component.pkg"
pkgbuild --root "$PKGROOT" --identifier "$IDENTIFIER" --version "$VERSION" \
  --scripts "$SCRIPTS" --install-location "/" "$COMPONENT"

OUT="$DIST_DIR/kubuno-${MODULE}-${VERSION}-${ARCH_LABEL}.pkg"
productbuild --package "$COMPONENT" \
  ${MACOS_SIGN_IDENTITY:+--sign "$MACOS_SIGN_IDENTITY"} \
  "$OUT"
echo "  ✓ $OUT"
