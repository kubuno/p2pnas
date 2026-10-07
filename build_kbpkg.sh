#!/usr/bin/env bash
# build_kbpkg.sh — the generic Kubuno package of a MODULE, identical on every system.
#
# Self-detecting: dropped as is into any module repository, it reads the id and the
# version from module.toml (Cargo.toml as a fallback).
#
# WHY THIS FORMAT
# A module is not system software. It registers no service (the core supervises it),
# owns nothing under /etc, and carries its migrations in its binary. What a package
# manager really enforced for it was a single dependency line, a check the core does
# better since it knows its own version. The marketplace never called dpkg either: it
# opened the .deb itself to extract the payload, so the .deb was only a container,
# which is why one-click install never worked on Windows or macOS.
#
# Decisive detail: the core opens a .deb with `dpkg-deb` and a .tar.gz with `tar`.
# ZIP is the ONLY format it unpacks without an external tool.
#
# THE FORMAT
# A ZIP archive whose ROOT is the module directory exactly as the core expects it on
# disk; nothing is translated at install time:
#   module.toml            the manifest the core already reads
#   kubuno-<id>[.exe]      the executable named by [process].entrypoint
#   frontend/              entry.js, entry.css, assets
#   migrations/            reference only; the real ones live in the binary
#   config.toml.example    if the module ships one
#   LICENSE, CHANGELOG.md
#   SHA256SUMS             every file above, to check an offline copy without a catalogue
#
# The target is carried by the FILE NAME, <id>-<version>-<os>-<arch>.kbpkg, which the
# catalogue reads to offer each server the right file.
#
# REPOSITORY LAYOUTS (both supported during the 2026-10 transition)
#   platform layout:  server/ (Cargo.toml, src/, migrations/, config.toml.example) + web/ (frontend)
#   older layout:     Cargo.toml, src/, migrations/ at the root + frontend/
# The archive is the same in both cases (its frontend folder is always `frontend/`).
#
# Usage:
#   bash build_kbpkg.sh                                   # this machine
#   bash build_kbpkg.sh --install                         # + install the .kbpkg into the local core (dev)
#   bash build_kbpkg.sh --skip-build                      # repackage without recompiling
#   OS=windows ARCH=x86_64 TARGET=x86_64-pc-windows-msvc bash build_kbpkg.sh   # cross build
#   CARGO_TARGET_DIR=/elsewhere bash build_kbpkg.sh       # honoured when looking for the binary
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
export SQLX_OFFLINE=true

# Where the server and the web frontend live (platform layout first, older layout as a fallback).
SERVER_DIR="."
[[ -f server/Cargo.toml ]] && SERVER_DIR="server"
WEB_DIR="frontend"
[[ -f web/package.json ]] && WEB_DIR="web"

# Id and version come from the module MANIFEST (module.toml), the authoritative source, present
# even when Cargo.toml is a workspace without [package] (e.g. p2pnas). Cargo.toml is the fallback
# for a single-crate module without those fields.
MODULE=$(grep -m1 '^id'      module.toml | sed -E 's/.*"([^"]+)".*/\1/')
VERSION=$(grep -m1 '^version' module.toml | sed -E 's/.*"([^"]+)".*/\1/')
if [[ -z "$MODULE" ]]; then
  PKG_NAME=$(grep -m1 '^name' "$SERVER_DIR/Cargo.toml" | sed -E 's/.*"([^"]+)".*/\1/')   # kubuno-<id>
  MODULE="${PKG_NAME#kubuno-}"
fi
[[ -n "$VERSION" ]] || VERSION=$(grep -m1 '^version' "$SERVER_DIR/Cargo.toml" | sed -E 's/.*"([^"]+)".*/\1/')
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

# Target names identical to the catalogue's and the core's (Rust's own).
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
  # `TARGET` (optional) builds for another triple: Windows/macOS cross build.
  ( cd "$SERVER_DIR" && cargo build --release ${TARGET:+--target "$TARGET"} --bin "kubuno-${MODULE}" )
  [[ -f "$WEB_DIR/package.json" ]] && ( cd "$WEB_DIR" && npm ci --silent && npm run build --silent )
fi

# A cross-built binary lives under target/<triple>/release, otherwise under target/release.
TARGET_ROOT="${CARGO_TARGET_DIR:-$SERVER_DIR/target}"
BIN="${TARGET_ROOT}/release/${EXE}"
[[ -n "${TARGET:-}" && -f "${TARGET_ROOT}/${TARGET}/release/${EXE}" ]] && BIN="${TARGET_ROOT}/${TARGET}/release/${EXE}"
[[ -f "$BIN" ]] || { echo "Exécutable introuvable : $BIN" >&2; exit 1; }
[[ -f module.toml ]] || { echo "module.toml introuvable" >&2; exit 1; }
# The frontend is OPTIONAL: an infrastructure module (e.g. stt) has no UI. When there is one
# (<web>/package.json), its build must have produced <web>/dist.
HAS_FRONTEND=0
if [[ -f "$WEB_DIR/package.json" ]]; then
  HAS_FRONTEND=1
  [[ -d "$WEB_DIR/dist" ]] || { echo "$WEB_DIR/dist introuvable — construisez le frontend" >&2; exit 1; }
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
ROOT="${WORK}/${MODULE}"
mkdir -p "$ROOT"

install -m 755 "$BIN"       "${ROOT}/${EXE}"
install -m 644 module.toml  "${ROOT}/module.toml"
[[ "$HAS_FRONTEND" -eq 1 ]] && { mkdir -p "${ROOT}/frontend"; cp -r "$WEB_DIR/dist/." "${ROOT}/frontend/"; }
[[ -d "$SERVER_DIR/migrations" ]] && { mkdir -p "${ROOT}/migrations"; cp "$SERVER_DIR"/migrations/*.sql "${ROOT}/migrations/" 2>/dev/null || true; }
CONFIG_EXAMPLE="$SERVER_DIR/config.toml.example"
[[ -f "$CONFIG_EXAMPLE" ]] || CONFIG_EXAMPLE="config.toml.example"
[[ -f "$CONFIG_EXAMPLE" ]] && install -m 644 "$CONFIG_EXAMPLE" "${ROOT}/config.toml.example"
[[ -f LICENSE ]]      && install -m 644 LICENSE      "${ROOT}/LICENSE"
[[ -f CHANGELOG.md ]] && install -m 644 CHANGELOG.md "${ROOT}/CHANGELOG.md"

# Per-file checksums: the catalogue signs the whole archive, but a copy carried on a USB stick
# into a closed network has no catalogue to ask.
( cd "$ROOT" && find . -type f ! -name SHA256SUMS -print0 | sort -z \
    | xargs -0 sha256sum > SHA256SUMS )

mkdir -p "$DIST"
OUT="${DIST}/${MODULE}-${VERSION}-${OS}-${ARCH}.kbpkg"
rm -f "$OUT"
# Archiving must work everywhere, including where `zip` does not exist: the CI's Windows runner
# lacks it, and the Windows package was lost the first time for that reason alone. 7-Zip is
# there, and PowerShell remains the last resort.
archive() {
  local root="$1" out="$2"
  if command -v zip >/dev/null 2>&1; then
    ( cd "$root" && zip -qr9 "$out" . -x '.*' )
  elif command -v 7z >/dev/null 2>&1; then
    ( cd "$root" && 7z a -tzip -mx=9 -bso0 -bsp0 "$out" . >/dev/null )
  elif command -v powershell.exe >/dev/null 2>&1; then
    # PowerShell needs Windows paths (Git Bash hands it /tmp/…, /e/…). Not Compress-Archive: it only writes a
    # `.zip` and, in Windows PowerShell 5.1, stores `frontend\entry.js` with backslashes; the entries are written
    # one by one with `/` separators instead.
    local wroot="$root" wout="$out"
    if command -v cygpath >/dev/null 2>&1; then wroot=$(cygpath -w "$root"); wout=$(cygpath -w "$out"); fi
    powershell.exe -NoProfile -NonInteractive -Command "
      \$ErrorActionPreference = 'Stop'
      Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
      \$zip = [IO.Compression.ZipFile]::Open('$wout', 'Create')
      try {
        Get-ChildItem -LiteralPath '$wroot' -Recurse -File -Name | ForEach-Object {
          [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile(\$zip, (Join-Path '$wroot' \$_), \$_.Replace('\\', '/'), 'Optimal')
        }
      } finally { \$zip.Dispose() }"
  else
    echo "Aucun outil d'archivage disponible (zip, 7z ou PowerShell)" >&2
    return 1
  fi
}
archive "$ROOT" "$PWD/$OUT"

SIZE=$(stat -c%s "$OUT" 2>/dev/null || stat -f%z "$OUT")
echo "==> $OUT"
printf '    %s Mo · %d fichiers\n' "$(( (SIZE + 524288) / 1048576 ))" "$(unzip -Z1 "$OUT" | wc -l)"

# Local dev loop: installs the package into this machine's core through the SAME path as
# production (kubuno modules:install → store), then restarts it. A module installs only as a
# .kbpkg; there is no .deb any more.
if [[ "$INSTALL" -eq 1 ]]; then
  echo "==> Installation locale (kubuno modules:install)"
  sudo kubuno modules:install "$OUT"
  sudo systemctl restart kubuno
  echo "==> ${MODULE} installé + kubuno redémarré"
fi
