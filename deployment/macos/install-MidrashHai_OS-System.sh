#!/bin/zsh
# EXCLUSIVE_CAPABILITY_OWNERSHIP · v1.0 (24 sept 2026)
# Voir 17-Bibliotheque_Tavnit AgentProof/9-Primitives_AgentProof/10-EXCLUSIVE_CAPABILITY_OWNERSHIP/
#
# Crée le compte système dédié "MidrashHai_OS-System" et le répertoire
# protégé qui portera l'état et la clé privée de Yad Emet — état/clé qui,
# aujourd'hui, vivent dans ~/.ctsm_yad_emet_*, accessibles en écriture par
# le compte normal de l'utilisateur (le même compte qui lance le process
# MCP via Claude Desktop/Codex). Ce script ferme cette écriture directe.
#
# CE QUE CE SCRIPT NE FAIT PAS : il ne migre pas le PROCESS lui-même sous ce
# compte. server_local_secure_enclave.py reste, pour l'instant, lancé en
# stdio par Claude Desktop/Codex sous le compte normal de l'utilisateur —
# migrer le lancement du process (LaunchDaemon + socket, comme install-v07.sh
# du dépôt N°14) est une étape distincte, plus invasive, non faite ici.
# Ce script ferme la protection des FICHIERS, pas encore celle du PROCESS.
#
# Usage : sudo deployment/macos/install-MidrashHai_OS-System.sh

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  print -u2 'Lancer avec sudo : sudo deployment/macos/install-MidrashHai_OS-System.sh'
  exit 64
fi

SERVICE_USER="MidrashHai_OS-System"
PROTECTED_ROOT="/var/db/midrash-hai-os-system"

next_id() {
  local kind=$1 candidate=480
  local attribute=UniqueID
  [[ $kind == Groups ]] && attribute=PrimaryGroupID
  local used
  used=$(dscl . -list "/$kind" "$attribute" | awk '{print $2}')
  while print -r -- "$used" | grep -qx "$candidate"; do (( candidate++ )); done
  print -- "$candidate"
}

if ! dscl . -read "/Users/$SERVICE_USER" >/dev/null 2>&1; then
  SERVICE_GID=$(next_id Groups)
  SERVICE_UID=$(next_id Users)
  dscl . -create "/Groups/$SERVICE_USER"
  dscl . -create "/Groups/$SERVICE_USER" PrimaryGroupID "$SERVICE_GID"
  dscl . -create "/Users/$SERVICE_USER"
  dscl . -create "/Users/$SERVICE_USER" UniqueID "$SERVICE_UID"
  dscl . -create "/Users/$SERVICE_USER" PrimaryGroupID "$SERVICE_GID"
  dscl . -create "/Users/$SERVICE_USER" UserShell /usr/bin/false
  dscl . -create "/Users/$SERVICE_USER" NFSHomeDirectory /var/empty
  dscl . -create "/Users/$SERVICE_USER" RealName "Midrash Hai OS System — Yad Emet Effector"
  print "Compte systeme cree : $SERVICE_USER (UID $SERVICE_UID)"
else
  print "Compte systeme deja present : $SERVICE_USER (rien recree, idempotent)"
fi

install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0700 "$PROTECTED_ROOT"
print "Repertoire protege : $PROTECTED_ROOT (0700, proprietaire $SERVICE_USER)"

# Migration de l'etat existant, si present, plutot qu'un depart a vide.
OLD_CLE="$HOME/.ctsm_yad_emet_effect_private.pem"
OLD_ETAT="$HOME/.ctsm_yad_emet_state.json"
if [[ -f "$OLD_CLE" ]]; then
  mv "$OLD_CLE" "$PROTECTED_ROOT/yad-emet-effect-private.pem"
  chown "$SERVICE_USER":"$SERVICE_USER" "$PROTECTED_ROOT/yad-emet-effect-private.pem"
  chmod 0600 "$PROTECTED_ROOT/yad-emet-effect-private.pem"
  print "Cle existante migree et re-chownee vers $SERVICE_USER."
fi
if [[ -f "$OLD_ETAT" ]]; then
  mv "$OLD_ETAT" "$PROTECTED_ROOT/yad-emet-state.json"
  chown "$SERVICE_USER":"$SERVICE_USER" "$PROTECTED_ROOT/yad-emet-state.json"
  chmod 0600 "$PROTECTED_ROOT/yad-emet-state.json"
  print "Etat de rejeu existant migre et re-chowne vers $SERVICE_USER."
fi

print ""
print "Installation terminee. Pour activer ce repertoire protege, ajouter dans"
print "la configuration MCP (Claude Desktop / Codex) qui lance ce serveur :"
print ""
print "  \"env\": { \"MIDRASH_HAI_OS_SYSTEM_HOME\": \"$PROTECTED_ROOT\" }"
print ""
print "Verifier ensuite : python3 scripts/audit_exclusive_capability.py"
