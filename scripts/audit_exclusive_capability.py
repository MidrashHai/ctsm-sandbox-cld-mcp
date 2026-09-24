#!/usr/bin/env python3
"""
Audit EXCLUSIVE_CAPABILITY_OWNERSHIP v1.0 (24 sept 2026).
Voir 17-Bibliotheque_Tavnit AgentProof/9-Primitives_AgentProof/10-EXCLUSIVE_CAPABILITY_OWNERSHIP/

Vérifie l'état RÉEL du système (pas la configuration déclarée) :
- le compte MidrashHai_OS-System existe ;
- le répertoire protégé lui appartient, en 0700 ;
- le compte qui exécute ce script (l'utilisateur normal, celui qui lance
  aussi le serveur MCP via Claude Desktop/Codex) NE PEUT PAS écrire
  directement dedans.

Statut retourné : NOT_CONFIGURED (rien n'est installé), FAIL (installé mais
une propriété ne tient pas), PASS (toutes les propriétés tiennent).

Usage : python3 scripts/audit_exclusive_capability.py
"""
import json
import os
import pwd
import subprocess
import sys

SERVICE_USER = "MidrashHai_OS-System"
PROTECTED_ROOT = "/var/db/midrash-hai-os-system"


def compte_existe(nom: str) -> bool:
    try:
        pwd.getpwnam(nom)
        return True
    except KeyError:
        return False


def main() -> dict:
    checks = []

    if not compte_existe(SERVICE_USER):
        return {
            "schema": "EXCLUSIVE_CAPABILITY_AUDIT_REPORT_V1",
            "status": "NOT_CONFIGURED",
            "reason": "SERVICE_USER_ABSENT",
            "checks": [],
        }

    if not os.path.isdir(PROTECTED_ROOT):
        return {
            "schema": "EXCLUSIVE_CAPABILITY_AUDIT_REPORT_V1",
            "status": "NOT_CONFIGURED",
            "reason": "PROTECTED_ROOT_ABSENT",
            "checks": [],
        }

    st = os.stat(PROTECTED_ROOT)
    proprietaire = pwd.getpwuid(st.st_uid).pw_name
    mode = oct(st.st_mode & 0o777)
    checks.append({"nom": "proprietaire_repertoire_protege", "attendu": SERVICE_USER, "obtenu": proprietaire, "ok": proprietaire == SERVICE_USER})
    checks.append({"nom": "mode_repertoire_protege", "attendu": "0o700", "obtenu": mode, "ok": mode == "0o700"})

    test_path = os.path.join(PROTECTED_ROOT, ".audit-ecriture-directe-test")
    ecriture_refusee = False
    erreur_ecriture = None
    try:
        with open(test_path, "w") as f:
            f.write("ceci ne devrait jamais reussir")
        os.remove(test_path)
    except PermissionError as exc:
        ecriture_refusee = True
        erreur_ecriture = str(exc)
    except Exception as exc:  # noqa: BLE001
        erreur_ecriture = f"ERREUR_INATTENDUE: {exc}"
    checks.append({
        "nom": "ecriture_directe_refusee_depuis_compte_appelant",
        "attendu": True,
        "obtenu": ecriture_refusee,
        "ok": ecriture_refusee,
        "detail": erreur_ecriture,
    })

    whoami = subprocess.run(["whoami"], capture_output=True, text=True).stdout.strip()
    checks.append({"nom": "compte_appelant_distinct_du_compte_service", "attendu": True, "obtenu": whoami != SERVICE_USER, "ok": whoami != SERVICE_USER, "detail": whoami})

    tout_ok = all(c["ok"] for c in checks)
    return {
        "schema": "EXCLUSIVE_CAPABILITY_AUDIT_REPORT_V1",
        "status": "PASS" if tout_ok else "FAIL",
        "checks": checks,
    }


if __name__ == "__main__":
    rapport = main()
    print(json.dumps(rapport, indent=2, ensure_ascii=False))
    sys.exit(0 if rapport["status"] == "PASS" else (1 if rapport["status"] == "FAIL" else 2))
