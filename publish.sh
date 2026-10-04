#!/bin/bash
# =============================================================================
# publish.sh — Inicializa el repo de LonxsGuard con un historial de commits
# real (construyendo el módulo función por función) y lo sube a GitHub.
#
# Requisitos previos:
#   1) Crear el repo VACÍO en GitHub: https://github.com/new  (nombre: LonxsGuard,
#      SIN README/licencia/gitignore — este script los aporta).
#   2) Tener git autenticado (gh auth login, o un token/credencial de GitHub).
#
# Uso:  bash publish.sh
# =============================================================================
set -e
cd "$(dirname "$0")"

REMOTE="https://github.com/Lonxs69/LonxsGuard.git"
# >>> Pon el correo de TU cuenta Lonxs69 (GitHub → Settings → Emails) <<<
NEW_NAME="lonxs69"
NEW_EMAIL="PON_AQUI_TU_EMAIL_DE_LONXS69"
case "$NEW_EMAIL" in PON_AQUI*|"") echo "✋ Edita NEW_EMAIL con el correo de tu cuenta Lonxs69."; exit 1;; esac

TMP="$(mktemp -t lonxsguard_full)"
cp lonxsguard.py "$TMP"

commit() { git add -A; git commit -q -m "$1" >/dev/null 2>&1 || true; }

# --- Repo e identidad -------------------------------------------------------
[ -d .git ] || git init -q
git config user.name  "$NEW_NAME"
git config user.email "$NEW_EMAIL"

# --- Andamiaje --------------------------------------------------------------
: > lonxsguard.py
commit "chore: scaffold project structure"
git add .gitignore && commit "chore: add .gitignore to protect private data"
git add LICENSE    && commit "docs: add MIT license"
git add README.md  && commit "docs: add project README"

# --- Construcción incremental del módulo principal --------------------------
# Un commit por cada definición de nivel superior, en orden (compatible bash 3.2).
for ln in $(grep -nE '^(def |class |MENU = )' "$TMP" | cut -d: -f1); do
  end=$(( ln - 1 ))
  [ "$end" -le 0 ] && continue
  head -n "$end" "$TMP" > lonxsguard.py
  decl=$(sed -n "${ln}p" "$TMP")
  name=$(printf '%s' "$decl" | sed -E 's/^def +([A-Za-z0-9_]+).*/\1/; s/^class +([A-Za-z0-9_]+).*/\1/; s/^MENU.*/interactive menu/')
  commit "feat: implement ${name}"
done

# --- Módulo completo + extras -----------------------------------------------
cp "$TMP" lonxsguard.py
commit "feat: finalize LonxsGuard core module"
git add wordlists/starter.txt  && commit "feat: add starter wordlist"
git add wordlists/espanol.txt  && commit "feat: add Spanish wordlist"
git add docs/USAGE.md          && commit "docs: add usage guide"
commit "chore: final polish"

rm -f "$TMP"
echo "✓ Commits creados: $(git rev-list --count HEAD)"

# --- Publicar ---------------------------------------------------------------
git branch -M main
git remote remove origin 2>/dev/null || true
git remote add origin "$REMOTE"
git push -u origin main

echo "✓ Publicado en $REMOTE"
