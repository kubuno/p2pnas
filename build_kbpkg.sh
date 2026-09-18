#!/usr/bin/env bash
# build_kbpkg.sh — le paquet Kubuno générique d'un MODULE, identique sur tous les systèmes.
#
# Script auto-détectant : déposé tel quel dans n'importe quel dépôt module, il
# lit l'id et la version depuis Cargo.toml.
#
# POURQUOI CE FORMAT
# Un module n'est pas un logiciel système. Il n'enregistre aucun service (le core
# le supervise), ne possède rien sous /etc, et porte ses migrations dans son
# binaire. Ce qu'un gestionnaire de paquets faisait vraiment respecter pour lui
# tenait en une ligne de dépendance — une vérification que le core fait mieux,
# connaissant sa propre version. Et la marketplace n'a jamais appelé dpkg : elle
# ouvrait le .deb elle-même pour en extraire la charge utile. Le .deb n'était
# donc déjà qu'un conteneur, de forme debian, ce qui explique que l'installation
# en un clic n'ait jamais fonctionné sur Windows ni macOS.
#
# Détail décisif : le core ouvre un .deb en appelant `dpkg-deb` et un .tar.gz en
# appelant `tar`. Le ZIP est le SEUL format qu'il déballe sans outil externe.
#
# LE FORMAT
# Une archive ZIP dont la RACINE est le répertoire du module tel que le core
# s'attend à le trouver sur disque — rien n'est traduit à l'installation :
#   module.toml            le manifeste que le core lit déjà
#   kubuno-<id>[.exe]      l'exécutable nommé par [process].entrypoint
#   frontend/              entry.js, entry.css, ressources
#   migrations/            référence — les vraies vivent dans le binaire
#   config.toml.example    si le module en livre un
#   LICENSE, CHANGELOG.md
#   SHA256SUMS             chaque fichier ci-dessus, pour vérifier une copie
#                          hors ligne sans catalogue
#
# La cible est portée par le NOM DU FICHIER — <id>-<version>-<os>-<arch>.kbpkg —
# que le catalogue lit pour proposer le bon fichier à chaque serveur.
#
# Usage :
#   bash build_kbpkg.sh                                   # cette machine
#   bash build_kbpkg.sh --install                         # + installe le .kbpkg dans le core local (dev)
#   bash build_kbpkg.sh --skip-build                      # réempaqueter sans recompiler
#   OS=windows ARCH=x86_64 TARGET=x86_64-pc-windows-msvc bash build_kbpkg.sh   # build croisé
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
export SQLX_OFFLINE=true

# Id et version viennent du MANIFESTE du module (module.toml) — la source
# autoritaire, présente aussi quand Cargo.toml est un workspace sans [package]
# (ex. p2pnas). Repli sur Cargo.toml pour un module mono-crate sans les champs.
MODULE=$(grep -m1 '^id'      module.toml | sed -E 's/.*"([^"]+)".*/\1/')
VERSION=$(grep -m1 '^version' module.toml | sed -E 's/.*"([^"]+)".*/\1/')
if [[ -z "$MODULE" ]]; then
  PKG_NAME=$(grep -m1 '^name' Cargo.toml | sed -E 's/.*"([^"]+)".*/\1/')   # kubuno-<id>
  MODULE="${PKG_NAME#kubuno-}"
fi
[[ -n "$VERSION" ]] || VERSION=$(grep -m1 '^version' Cargo.toml | sed -E 's/.*"([^"]+)".*/\1/')
[[ -n "$MODULE" ]]  || { echo "id du module introuvable (module.toml / Cargo.toml)" >&2; exit 1; }
DIST="dist"
SKIP_BUILD=0
INSTALL=0
for a in "$@"; do
  case "$a" in
    --skip-build) SKIP_BUILD=1 ;;
    --install)    INSTALL=1 ;;
    *) echo "Option inconnue : $a" >&2; exit 1 ;;
  esac
done

# Noms de cible identiques à ceux du catalogue et du core (ceux de Rust).
OS="${OS:-$(uname -s | tr '[:upper:]' '[:lower:]')}"
case "$OS" in
  linux|windows)  ;;
  darwin|macos)   OS="macos" ;;
  *) echo "Système non pris en charge : $OS" >&2; exit 1 ;;
esac
ARCH="${ARCH:-$(uname -m)}"
case "$ARCH" in
  x86_64|amd64)   ARCH="x86_64" ;;
  aarch64|arm64)  ARCH="aarch64" ;;
  *) echo "Architecture non prise en charge : $ARCH" >&2; exit 1 ;;
esac

EXE="kubuno-${MODULE}"
[[ "$OS" == "windows" ]] && EXE="kubuno-${MODULE}.exe"

echo "==> ${MODULE} ${VERSION} — ${OS}/${ARCH}"

if [[ "$SKIP_BUILD" -eq 0 ]]; then
  echo "==> Compilation"
  # `TARGET` (facultatif) compile pour un autre triplet — build croisé Windows/macOS.
  cargo build --release ${TARGET:+--target "$TARGET"} --bin "kubuno-${MODULE}"
  [[ -f frontend/package.json ]] && ( cd frontend && npm ci --silent && npm run build --silent )
fi

# Un binaire croisé vit sous target/<triplet>/release ; sinon target/release.
BIN="target/release/${EXE}"
[[ -n "${TARGET:-}" && -f "target/${TARGET}/release/${EXE}" ]] && BIN="target/${TARGET}/release/${EXE}"
[[ -f "$BIN" ]] || { echo "Exécutable introuvable : $BIN" >&2; exit 1; }
[[ -f module.toml ]] || { echo "module.toml introuvable" >&2; exit 1; }
# Le frontend est FACULTATIF : un module d'infrastructure (ex. stt) n'a pas d'UI.
# S'il en a un (frontend/package.json), son build doit avoir produit frontend/dist.
HAS_FRONTEND=0
if [[ -f frontend/package.json ]]; then
  HAS_FRONTEND=1
  [[ -d frontend/dist ]] || { echo "frontend/dist introuvable — construisez le frontend" >&2; exit 1; }
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
ROOT="${WORK}/${MODULE}"
mkdir -p "$ROOT"

install -m 755 "$BIN"       "${ROOT}/${EXE}"
install -m 644 module.toml  "${ROOT}/module.toml"
[[ "$HAS_FRONTEND" -eq 1 ]] && { mkdir -p "${ROOT}/frontend"; cp -r frontend/dist/. "${ROOT}/frontend/"; }
[[ -d migrations ]] && { mkdir -p "${ROOT}/migrations"; cp migrations/*.sql "${ROOT}/migrations/" 2>/dev/null || true; }
[[ -f config.toml.example ]] && install -m 644 config.toml.example "${ROOT}/config.toml.example"
[[ -f LICENSE ]]      && install -m 644 LICENSE      "${ROOT}/LICENSE"
[[ -f CHANGELOG.md ]] && install -m 644 CHANGELOG.md "${ROOT}/CHANGELOG.md"

# Empreintes par fichier : le catalogue signe l'archive entière, mais une copie
# emportée sur une clé USB dans un réseau fermé n'a pas de catalogue à consulter.
( cd "$ROOT" && find . -type f ! -name SHA256SUMS -print0 | sort -z \
    | xargs -0 sha256sum > SHA256SUMS )

mkdir -p "$DIST"
OUT="${DIST}/${MODULE}-${VERSION}-${OS}-${ARCH}.kbpkg"
rm -f "$OUT"
# L'archivage doit marcher partout, y compris là où `zip` n'existe pas : sur
# l'exécuteur Windows de l'intégration continue, il est absent, et le paquet
# Windows a été perdu la première fois pour cette seule raison. 7-Zip y est
# présent, et PowerShell reste le dernier recours.
archive() {
  local root="$1" out="$2"
  if command -v zip >/dev/null 2>&1; then
    ( cd "$root" && zip -qr9 "$out" . -x '.*' )
  elif command -v 7z >/dev/null 2>&1; then
    ( cd "$root" && 7z a -tzip -mx=9 -bso0 -bsp0 "$out" . >/dev/null )
  elif command -v powershell.exe >/dev/null 2>&1; then
    powershell.exe -NoProfile -NonInteractive -Command \
      "Compress-Archive -Path '$root/*' -DestinationPath '$out' -CompressionLevel Optimal -Force"
  else
    echo "Aucun outil d'archivage disponible (zip, 7z ou PowerShell)" >&2
    return 1
  fi
}
archive "$ROOT" "$PWD/$OUT"

SIZE=$(stat -c%s "$OUT" 2>/dev/null || stat -f%z "$OUT")
echo "==> $OUT"
printf '    %s Mo · %d fichiers\n' "$(( (SIZE + 524288) / 1048576 ))" "$(unzip -Z1 "$OUT" | wc -l)"

# Boucle de dev locale : installe le paquet dans le core de cette machine par le
# MÊME chemin que la production (kubuno modules:install → store), puis redémarre.
# Un module s'installe uniquement au format .kbpkg — il n'y a plus de .deb.
if [[ "$INSTALL" -eq 1 ]]; then
  echo "==> Installation locale (kubuno modules:install)"
  sudo kubuno modules:install "$OUT"
  sudo systemctl restart kubuno
  echo "==> ${MODULE} installé + kubuno redémarré"
fi
