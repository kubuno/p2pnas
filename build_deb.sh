#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# build_deb.sh — construit le paquet Debian du module Kubuno p2pnas.
#
# Layout d'installation (identique aux autres modules) :
#   /usr/lib/kubuno/modules/p2pnas/{kubuno-p2pnas, module.toml, frontend/}
#   /usr/share/kubuno/modules/p2pnas/migrations/*.sql
#   /etc/kubuno/modules/p2pnas/config.toml.example
#
# Usage :
#   bash build_deb.sh            # build le .deb dans dist/
#   bash build_deb.sh --install  # build puis `apt install` le .deb
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
cd "$(dirname "$0")"
export SQLX_OFFLINE=true   # le module n'utilise pas les query-macros (runtime queries)

MODULE="p2pnas"
PACKAGE="kubuno-${MODULE}"
ARCH="$(dpkg --print-architecture)"
VERSION="$(grep -m1 '^version' crates/server/Cargo.toml | sed -E 's/.*"([^"]+)".*/\1/')"
# Strip any pre-release suffix for the dependency constraint: a Debian revision
# like "1069" sorts BEFORE "alpha", so `>= 0.1.0-alpha` would reject the installed
# `kubuno-core 0.1.0-1069`. Compare against the plain upstream version instead.
CORE_DEP="${VERSION%%-*}"

BUILD_NUM=$(( $(cat .build_number 2>/dev/null || echo 0) + 1 ))
echo "$BUILD_NUM" > .build_number
FULL_VERSION="${VERSION}-${BUILD_NUM}"

echo "==> Build ${PACKAGE} ${FULL_VERSION} (${ARCH})"

# 1. Binaire Rust (native CPU pour les chemins AES-NI/VAES; CI épingle une baseline)
echo "==> cargo build --release"
RUSTFLAGS="${RUSTFLAGS:--C target-cpu=native}" cargo build --release --bin "kubuno-${MODULE}"

# 2. Frontend (l'UI « My Cloud » arrive en phase 2 ; tolérant pour l'instant)
if [[ -f frontend/dist/entry.js ]]; then
  :
elif [[ -f frontend/package.json ]]; then
  echo "==> build frontend"
  (cd frontend && npm run build)
else
  echo "⚠  frontend absent (UI prévue en phase 2) — paquet sans interface"
  mkdir -p frontend/dist
fi

# 3. Assemblage du paquet
PKG_DIR="$(mktemp -d)"
trap 'rm -rf "$PKG_DIR"' EXIT
mkdir -p \
  "${PKG_DIR}/DEBIAN" \
  "${PKG_DIR}/usr/lib/kubuno/modules/${MODULE}/frontend" \
  "${PKG_DIR}/usr/share/kubuno/modules/${MODULE}/migrations" \
  "${PKG_DIR}/etc/kubuno/modules/${MODULE}" \
  "${PKG_DIR}/usr/bin"

install -m 755 "target/release/kubuno-${MODULE}" \
  "${PKG_DIR}/usr/lib/kubuno/modules/${MODULE}/kubuno-${MODULE}"
ln -sf "/usr/lib/kubuno/modules/${MODULE}/kubuno-${MODULE}" \
  "${PKG_DIR}/usr/bin/kubuno-${MODULE}"

[[ -f module.toml ]] && install -m 644 module.toml \
  "${PKG_DIR}/usr/lib/kubuno/modules/${MODULE}/module.toml"

cp -r frontend/dist/. "${PKG_DIR}/usr/lib/kubuno/modules/${MODULE}/frontend/" 2>/dev/null || true

cp migrations/*.sql \
  "${PKG_DIR}/usr/share/kubuno/modules/${MODULE}/migrations/" 2>/dev/null || true

[[ -f config.toml.example ]] && install -m 640 config.toml.example \
  "${PKG_DIR}/etc/kubuno/modules/${MODULE}/config.toml.example"

cat > "${PKG_DIR}/DEBIAN/control" << EOF
Package: ${PACKAGE}
Version: ${FULL_VERSION}
Architecture: ${ARCH}
Maintainer: Kubuno Contributors <kubuno@toiledev.com>
Depends: ca-certificates, kubuno-core (>= ${CORE_DEP})
Section: web
Priority: optional
Homepage: https://github.com/kubuno/${MODULE}
Description: Kubuno p2pnas — stockage pair-à-pair chiffré auto-réparant (build ${BUILD_NUM})
EOF

cat > "${PKG_DIR}/DEBIAN/postinst" << POSTINST
#!/bin/bash
set -e
if ! id -u kubuno &>/dev/null; then
  useradd --system --no-create-home --shell /usr/sbin/nologin kubuno
fi
mkdir -p /var/lib/kubuno/modules/${MODULE}
chown -R kubuno:kubuno /var/lib/kubuno/modules
chmod 750 /var/lib/kubuno/modules
if [ ! -f /etc/kubuno/modules/${MODULE}/config.toml ]; then
  cp /etc/kubuno/modules/${MODULE}/config.toml.example \
     /etc/kubuno/modules/${MODULE}/config.toml
  echo "→ /etc/kubuno/modules/${MODULE}/config.toml créé."
fi
chmod 640 /etc/kubuno/modules/${MODULE}/config.toml
chown root:kubuno /etc/kubuno/modules/${MODULE}/config.toml
systemctl try-restart kubuno.service 2>/dev/null || true
POSTINST
chmod 755 "${PKG_DIR}/DEBIAN/postinst"

# 4. Construction du .deb
mkdir -p dist
DEB="dist/${PACKAGE}_${FULL_VERSION}_${ARCH}.deb"
dpkg-deb --build --root-owner-group "$PKG_DIR" "$DEB"
echo "✓ ${DEB}"

if [[ "${1:-}" == "--install" ]]; then
  echo "==> Installation"
  sudo apt install -y --allow-downgrades "./${DEB}"
fi
