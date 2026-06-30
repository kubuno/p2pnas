#!/usr/bin/env bash
# build_rpm.sh — paquet RPM générique d'un MODULE Kubuno (Fedora/RHEL/openSUSE).
#
# Script auto-détectant : déposé tel quel dans n'importe quel dépôt module, il
# lit l'id/version/description depuis Cargo.toml. Produit le MÊME layout que le
# .deb du module, afin que le core découvre le module à l'identique :
#   /usr/lib/kubuno/modules/<id>/{kubuno-<id>, module.toml, frontend/}
#   /usr/share/kubuno/modules/<id>/migrations/*.sql
#   /etc/kubuno/modules/<id>/config.toml.example
#
# Usage :
#   bash build_rpm.sh            # → dist/kubuno-<id>-<ver>-1.<arch>.rpm
#   bash build_rpm.sh --install  # build + dnf/zypper/rpm install
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
export SQLX_OFFLINE=true

# ── Auto-détection du module ────────────────────────────────────────────────
PKG_NAME=$(grep -m1 '^name' Cargo.toml | sed -E 's/.*"([^"]+)".*/\1/')   # kubuno-<id>
MODULE="${PKG_NAME#kubuno-}"
VERSION=$(grep -m1 '^version' Cargo.toml | sed -E 's/.*"([^"]+)".*/\1/')
DESC=$(grep -m1 '^description' Cargo.toml | sed -E 's/.*"([^"]+)".*/\1/')
[[ -n "$DESC" ]] || DESC="Kubuno ${MODULE} — module"
RELEASE="${RPM_RELEASE:-1}"
case "$(uname -m)" in
  x86_64) ARCH="x86_64" ;; aarch64|arm64) ARCH="aarch64" ;; *) ARCH="$(uname -m)" ;;
esac
DIST_DIR="${DIST_DIR:-dist}"; mkdir -p "$DIST_DIR"

command -v rpmbuild >/dev/null || { echo "Erreur : rpmbuild introuvable (paquet 'rpm-build' / 'rpm')." >&2; exit 1; }

echo "==> RPM kubuno-${MODULE} ${VERSION}-${RELEASE} (${ARCH})"

# ── Pré-requis : binaire + frontend ─────────────────────────────────────────
if [[ ! -x "target/release/kubuno-${MODULE}" ]]; then
  echo "==> cargo build --release --bin kubuno-${MODULE}"
  cargo build --release --bin "kubuno-${MODULE}"
fi
HAS_FRONTEND=0
if [[ -d frontend ]]; then
  if [[ ! -f frontend/dist/entry.js ]]; then
    echo "==> build frontend"; (cd frontend && npm run build)
  fi
  [[ -f frontend/dist/entry.js ]] && HAS_FRONTEND=1
fi

# ── Dépendances système spécifiques ─────────────────────────────────────────
EXTRA_REQUIRES=""; EXTRA_RECOMMENDS=""
case "$MODULE" in
  media) EXTRA_REQUIRES="Requires:       ffmpeg" ;;
  jarvis) EXTRA_RECOMMENDS="Recommends:     ollama" ;;
esac

# ── Arbre de build ──────────────────────────────────────────────────────────
TOP="$(mktemp -d)"; trap 'rm -rf "$TOP"' EXIT
mkdir -p "$TOP"/{BUILD,RPMS,SOURCES,SPECS,SRPMS,BUILDROOT}
SRCDIR="$PWD"

# Lignes %install conditionnelles (frontend / migrations / config / module.toml)
FRONTEND_INSTALL=""
[[ "$HAS_FRONTEND" == "1" ]] && FRONTEND_INSTALL='mkdir -p %{buildroot}/usr/lib/kubuno/modules/'"$MODULE"'/frontend
cp -r %{_srcdir}/frontend/dist/. %{buildroot}/usr/lib/kubuno/modules/'"$MODULE"'/frontend/'
FRONTEND_FILES=""
[[ "$HAS_FRONTEND" == "1" ]] && FRONTEND_FILES="/usr/lib/kubuno/modules/${MODULE}/frontend"

MIG_INSTALL=""; MIG_FILES=""
if [[ -d migrations ]] && compgen -G "migrations/*.sql" >/dev/null; then
  MIG_INSTALL='mkdir -p %{buildroot}/usr/share/kubuno/modules/'"$MODULE"'/migrations
cp %{_srcdir}/migrations/*.sql %{buildroot}/usr/share/kubuno/modules/'"$MODULE"'/migrations/'
  MIG_FILES="/usr/share/kubuno/modules/${MODULE}/migrations"
fi

MODTOML_INSTALL=""; MODTOML_FILES=""
if [[ -f module.toml ]]; then
  MODTOML_INSTALL='install -m 644 %{_srcdir}/module.toml %{buildroot}/usr/lib/kubuno/modules/'"$MODULE"'/module.toml'
  MODTOML_FILES="/usr/lib/kubuno/modules/${MODULE}/module.toml"
fi

CFG_INSTALL=""; CFG_FILES=""; CFG_POST=""
if [[ -f config.toml.example ]]; then
  CFG_INSTALL='mkdir -p %{buildroot}/etc/kubuno/modules/'"$MODULE"'
install -m 644 %{_srcdir}/config.toml.example %{buildroot}/etc/kubuno/modules/'"$MODULE"'/config.toml.example'
  CFG_FILES='%config(noreplace) /etc/kubuno/modules/'"$MODULE"'/config.toml.example
%ghost %config(noreplace) /etc/kubuno/modules/'"$MODULE"'/config.toml'
  CFG_POST='if [ ! -f /etc/kubuno/modules/'"$MODULE"'/config.toml ]; then
    cp /etc/kubuno/modules/'"$MODULE"'/config.toml.example /etc/kubuno/modules/'"$MODULE"'/config.toml
fi
chmod 640 /etc/kubuno/modules/'"$MODULE"'/config.toml
chown root:kubuno /etc/kubuno/modules/'"$MODULE"'/config.toml'
fi

SPEC="$TOP/SPECS/kubuno-${MODULE}.spec"
cat > "$SPEC" << SPEC
Name:           kubuno-${MODULE}
Version:        ${VERSION}
Release:        ${RELEASE}%{?dist}
Summary:        ${DESC}
License:        AGPL-3.0-or-later
URL:            https://github.com/kubuno/${MODULE}
BuildArch:      ${ARCH}
Requires:       openssl-libs
Requires:       ca-certificates
Requires:       kubuno-core >= ${VERSION}
${EXTRA_REQUIRES}
${EXTRA_RECOMMENDS}
Requires(post): systemd

%global _srcdir ${SRCDIR}
%global debug_package %{nil}
%global __os_install_post %{nil}
%global _build_id_links none

%description
${DESC}
Module indépendant de la plateforme Kubuno (un core + des modules).

%prep

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/lib/kubuno/modules/${MODULE} %{buildroot}/usr/bin
install -m 755 %{_srcdir}/target/release/kubuno-${MODULE} %{buildroot}/usr/lib/kubuno/modules/${MODULE}/kubuno-${MODULE}
ln -sf /usr/lib/kubuno/modules/${MODULE}/kubuno-${MODULE} %{buildroot}/usr/bin/kubuno-${MODULE}
${MODTOML_INSTALL}
${FRONTEND_INSTALL}
${MIG_INSTALL}
${CFG_INSTALL}

%files
/usr/lib/kubuno/modules/${MODULE}/kubuno-${MODULE}
/usr/bin/kubuno-${MODULE}
${MODTOML_FILES}
${FRONTEND_FILES}
${MIG_FILES}
${CFG_FILES}

%post
getent group kubuno >/dev/null || groupadd --system kubuno
getent passwd kubuno >/dev/null || useradd --system --gid kubuno --no-create-home --home-dir /var/lib/kubuno --shell /sbin/nologin kubuno
mkdir -p /var/lib/kubuno/modules/${MODULE}
chown -R kubuno:kubuno /var/lib/kubuno/modules
chmod 750 /var/lib/kubuno/modules
${CFG_POST}
systemctl try-restart kubuno.service >/dev/null 2>&1 || :

%postun
if [ \$1 -ge 1 ] ; then
    systemctl try-restart kubuno.service >/dev/null 2>&1 || :
fi

%changelog
* Tue Jun 30 2026 Kubuno Contributors <contact@kubuno.io> - ${VERSION}-${RELEASE}
- Paquet RPM du module (parité layout avec le .deb).
SPEC

echo "==> rpmbuild…"
rpmbuild --define "_topdir $TOP" -bb "$SPEC"
PRODUCED=$(find "$TOP/RPMS" -name "kubuno-${MODULE}-*.rpm" | head -1)
[[ -f "$PRODUCED" ]] || { echo "Erreur : RPM non produit." >&2; exit 1; }
FINAL="$DIST_DIR/$(basename "$PRODUCED")"; cp "$PRODUCED" "$FINAL"
echo "  ✓ $FINAL"

if [[ "${1:-}" == "--install" ]]; then
  if command -v dnf &>/dev/null; then sudo dnf install -y "$FINAL"
  elif command -v zypper &>/dev/null; then sudo zypper --non-interactive install --allow-unsigned-rpm "$FINAL"
  else sudo rpm -Uvh --replacepkgs "$FINAL"; fi
fi
