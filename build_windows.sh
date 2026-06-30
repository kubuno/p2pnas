#!/usr/bin/env bash
# build_windows.sh — installeur Windows d'un MODULE Kubuno (NSIS).
#
# Auto-détectant (id/version depuis Cargo.toml). L'installeur dépose le module
# dans l'installation existante du core (lue dans le registre HKLM\Software\Kubuno
# InstallLocation, défaut C:\Program Files\Kubuno) puis redémarre le service.
# Les migrations sont EMBARQUÉES dans le binaire (sqlx::migrate!) → non livrées.
# Le module tourne sans config.toml : le core injecte DB/secret/URL par variables
# d'environnement et crée son CWD/données.
#
# Cross-compile depuis Linux (cargo-xwin) ou natif sur Windows (Git Bash).
# Usage : bash build_windows.sh        # → dist/kubuno-<id>-setup-<ver>-x64.exe
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
export SQLX_OFFLINE=true

PKG_NAME=$(grep -m1 '^name' Cargo.toml | sed -E 's/.*"([^"]+)".*/\1/')
MODULE="${PKG_NAME#kubuno-}"
VERSION=$(grep -m1 '^version' Cargo.toml | sed -E 's/.*"([^"]+)".*/\1/')
TARGET="${TARGET:-x86_64-pc-windows-msvc}"
DIST_DIR="${DIST_DIR:-dist}"; mkdir -p "$DIST_DIR"
STAGE="$(mktemp -d)"; trap 'rm -rf "$STAGE"' EXIT

command -v makensis >/dev/null || { echo "Erreur : makensis (NSIS) introuvable." >&2; exit 1; }

echo "==> Installeur Windows kubuno-${MODULE} ${VERSION}"

# ── Frontend ────────────────────────────────────────────────────────────────
HAS_FRONTEND=0
if [[ -d frontend ]]; then
  [[ -f frontend/dist/entry.js ]] || (cd frontend && npm run build)
  [[ -f frontend/dist/entry.js ]] && HAS_FRONTEND=1
fi

# ── Compilation Rust ────────────────────────────────────────────────────────
rustup target add "$TARGET" >/dev/null 2>&1 || true
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*|*NT*) HOST_WIN=1 ;; *) HOST_WIN=0 ;; esac
if [[ "$TARGET" == *"-msvc" && "$HOST_WIN" == "0" ]]; then
  command -v cargo-xwin >/dev/null || cargo xwin --help >/dev/null 2>&1 || {
    echo "Erreur : cargo-xwin requis pour cross-compiler MSVC depuis Linux." >&2; exit 1; }
  cargo xwin build --release --target "$TARGET" --bin "kubuno-${MODULE}"
else
  cargo build --release --target "$TARGET" --bin "kubuno-${MODULE}"
fi
BIN="target/${TARGET}/release/kubuno-${MODULE}.exe"
[[ -f "$BIN" ]] || { echo "Erreur : ${BIN} non produit." >&2; exit 1; }

# ── Staging ─────────────────────────────────────────────────────────────────
install -m 755 "$BIN" "$STAGE/kubuno-${MODULE}.exe"
[[ -f module.toml ]] && cp module.toml "$STAGE/module.toml"
[[ -f config.toml.example ]] && cp config.toml.example "$STAGE/config.toml.example"
[[ "$HAS_FRONTEND" == "1" ]] && cp -r frontend/dist "$STAGE/frontend"

# Lignes NSIS conditionnelles
FRONTEND_NSI=""; [[ "$HAS_FRONTEND" == "1" ]] && FRONTEND_NSI='File /r "frontend"'
MODTOML_NSI=""; [[ -f module.toml ]] && MODTOML_NSI='File "module.toml"'
CFG_NSI=""
[[ -f config.toml.example ]] && CFG_NSI='SetOutPath "$APPDATA\Kubuno\modules-config\'"${MODULE}"'"
  File "config.toml.example"'

# ── Script NSIS ─────────────────────────────────────────────────────────────
cat > "$STAGE/installer.nsi" << NSI
Unicode true
!include "MUI2.nsh"
!include "LogicLib.nsh"
!define MODULE "${MODULE}"
!define VERSION "${VERSION}"
Name "Kubuno ${MODULE} \${VERSION}"
OutFile "kubuno-${MODULE}-setup-${VERSION}-x64.exe"
RequestExecutionLevel admin
ShowInstDetails show

!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "French"
!insertmacro MUI_LANGUAGE "English"

Var CoreDir

Function .onInit
  SetShellVarContext all
  ReadRegStr \$CoreDir HKLM "Software\\Kubuno" "InstallLocation"
  \${If} \$CoreDir == ""
    StrCpy \$CoreDir "\$PROGRAMFILES64\\Kubuno"
  \${EndIf}
  IfFileExists "\$CoreDir\\kubuno-service.exe" +3 0
    MessageBox MB_OK|MB_ICONSTOP "Kubuno Core introuvable (\$CoreDir). Installez d'abord le core."
    Abort
FunctionEnd

Section "Install"
  SetShellVarContext all
  SetOutPath "\$CoreDir\\modules\\\${MODULE}"
  File "kubuno-${MODULE}.exe"
  ${MODTOML_NSI}
  ${FRONTEND_NSI}
  ${CFG_NSI}

  CreateDirectory "\$APPDATA\\Kubuno\\modules-config\\\${MODULE}"
  CreateDirectory "\$APPDATA\\Kubuno\\modules-data\\\${MODULE}"

  ; Redémarre le service core pour qu'il découvre/relance le module
  nsExec::ExecToLog '"\$CoreDir\\kubuno-service.exe" restart'

  WriteUninstaller "\$CoreDir\\modules\\\${MODULE}\\uninstall.exe"
  WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Kubuno-\${MODULE}" "DisplayName" "Kubuno \${MODULE}"
  WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Kubuno-\${MODULE}" "DisplayVersion" "\${VERSION}"
  WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Kubuno-\${MODULE}" "UninstallString" '"\$CoreDir\\modules\\\${MODULE}\\uninstall.exe"'
SectionEnd

Section "Uninstall"
  SetShellVarContext all
  ReadRegStr \$CoreDir HKLM "Software\\Kubuno" "InstallLocation"
  \${If} \$CoreDir == ""
    StrCpy \$CoreDir "\$PROGRAMFILES64\\Kubuno"
  \${EndIf}
  RMDir /r "\$CoreDir\\modules\\\${MODULE}"
  nsExec::ExecToLog '"\$CoreDir\\kubuno-service.exe" restart'
  DeleteRegKey HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Kubuno-\${MODULE}"
SectionEnd
NSI

echo "==> makensis…"
( cd "$STAGE" && makensis -V2 installer.nsi )
OUT="$DIST_DIR/kubuno-${MODULE}-setup-${VERSION}-x64.exe"
cp "$STAGE/kubuno-${MODULE}-setup-${VERSION}-x64.exe" "$OUT"
echo "  ✓ $OUT"
