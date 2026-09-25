#!/usr/bin/env python3
"""
Lanceur unique des tests CTSM — une commande, un verdict.

Chaque fichier de test tourne dans son propre processus : chacun isole HOME
a sa facon, et aucun ne doit heriter de l'etat d'un autre.

Usage : python3 tests/run_all.py
Sortie : code 0 si tous les fichiers passent, 1 sinon.
"""
import os
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

FICHIERS_DE_TEST = [
    "tests/test_gate_souveraine.py",
    "tests/test_yad_emet_effector.py",
    "test_couche6_chaine_stat.py",
]


def main():
    echecs = []
    for rel in FICHIERS_DE_TEST:
        print(f"\n=== {rel} ===", flush=True)
        r = subprocess.run([sys.executable, os.path.join(REPO_ROOT, rel)], cwd=REPO_ROOT)
        if r.returncode != 0:
            echecs.append(rel)

    print("\n" + "=" * 60)
    passes = len(FICHIERS_DE_TEST) - len(echecs)
    print(f"{passes}/{len(FICHIERS_DE_TEST)} fichiers de test passes.")
    for rel in echecs:
        print(f"ECHEC · {rel}")
    sys.exit(1 if echecs else 0)


if __name__ == "__main__":
    main()
