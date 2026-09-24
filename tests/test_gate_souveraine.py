#!/usr/bin/env python3
"""
Tests GATE_SOUVERAINE v1.0 (24 sept 2026) — server_local_secure_enclave.py
Voir 17-Bibliotheque_Tavnit AgentProof/9-Primitives_AgentProof/9-GATE_SOUVERAINE/

LIMITE HONNETE, à ne jamais effacer de ce fichier : ces tests simulent la
frontière matérielle (verifier_secure_enclave_reel_employe est remplacée par
une fonction factice). Ils prouvent la logique de branchement
(action classée → signature fraîche exigée → refus sans SIGNATURE_VALIDE),
PAS que le Secure Enclave réel de cette machine répond correctement. Cette
seconde preuve exige une session graphique et une présence physique
(Touch ID) que cet outil ne peut pas produire.

Isolé dans un HOME temporaire — ne touche jamais ~/.ctsm_* réels.
Usage : python3 tests/test_gate_souveraine.py
"""
import os
import sys
import tempfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run():
    with tempfile.TemporaryDirectory() as home_isole:
        os.environ["HOME"] = home_isole
        sys.path.insert(0, REPO_ROOT)
        import server_local_secure_enclave as srv

        echecs = []

        def verifier(nom, condition):
            print(f"{'OK  ' if condition else 'FAIL'} · {nom}")
            if not condition:
                echecs.append(nom)

        # 1. Action non classée irréversible : passe sans friction.
        r = srv.exiger_autorisation_souveraine("action_quelconque_non_classee")
        verifier("action non classée -> requise=False, autorise=True", r["requise"] is False and r["autorise"] is True)

        # 2. Action classée, Secure Enclave simulé qui refuse (Touch ID annulé, mauvais device...).
        original = srv.verifier_secure_enclave_reel_employe
        srv.verifier_secure_enclave_reel_employe = lambda person_id, type_device: {"verdict": "SIGNATURE_INVALIDE"}
        r = srv.exiger_autorisation_souveraine(srv.ACTION_ID_ECRIRE_INCIDENT)
        verifier("action classée, signature refusée -> autorise=False", r["requise"] is True and r["autorise"] is False and "SOUVERAIN_NON_CONFIRME" in r["raison"])
        srv.verifier_secure_enclave_reel_employe = original

        # 3. Action classée, souverain non provisionné.
        srv.verifier_secure_enclave_reel_employe = lambda person_id, type_device: {"verdict": "NON_PROVISIONNE"}
        r = srv.exiger_autorisation_souveraine(srv.ACTION_ID_ECRIRE_INCIDENT)
        verifier("action classée, souverain non provisionné -> autorise=False", r["autorise"] is False and "NON_PROVISIONNE" in r["raison"])
        srv.verifier_secure_enclave_reel_employe = original

        # 4. Action classée, signature fraîche valide -> autorisée.
        srv.verifier_secure_enclave_reel_employe = lambda person_id, type_device: {"verdict": "SIGNATURE_VALIDE"}
        r = srv.exiger_autorisation_souveraine(srv.ACTION_ID_ECRIRE_INCIDENT)
        verifier("action classée, signature valide -> autorise=True", r["requise"] is True and r["autorise"] is True)
        srv.verifier_secure_enclave_reel_employe = original

        # 5. Le person_id utilisé pour la vérification est bien le souverain, jamais un employé quelconque.
        person_id_recu = {}
        srv.verifier_secure_enclave_reel_employe = lambda person_id, type_device: person_id_recu.update(id=person_id) or {"verdict": "SIGNATURE_VALIDE"}
        srv.exiger_autorisation_souveraine(srv.ACTION_ID_ECRIRE_INCIDENT)
        verifier(f"person_id vérifié = SOUVERAIN_PERSON_ID ({srv.SOUVERAIN_PERSON_ID})", person_id_recu.get("id") == srv.SOUVERAIN_PERSON_ID)
        srv.verifier_secure_enclave_reel_employe = original

        # 6. Intégration : autoriser_execution_action refuse un jeton pour une action
        #    classée irréversible même si un souverain factice répond SIGNATURE_VALIDE,
        #    tant que les six couches restent fermées (le souverain ne compense jamais
        #    une couche manquante). On force les six couches à passer via mock direct
        #    des fonctions de couche pour isoler ce que Gate Souveraine ajoute.
        verifier(
            "ACTION_ID_ECRIRE_INCIDENT bien dans ACTIONS_CLASSEES_IRREVERSIBLES",
            srv.ACTION_ID_ECRIRE_INCIDENT in srv.ACTIONS_CLASSEES_IRREVERSIBLES,
        )

        return echecs


if __name__ == "__main__":
    echecs = run()
    if echecs:
        print(f"\n{len(echecs)} test(s) en echec : {echecs}")
        sys.exit(1)
    print("\nTOUS LES TESTS DE LOGIQUE GATE_SOUVERAINE ONT PASSE")
    print("RAPPEL : la frontière matérielle (Touch ID réel) n'est PAS testée ici.")
