#!/usr/bin/env python3
"""
Tests YAD_EMET_EFFECTOR v1.1 (24 sept 2026) — server_local_secure_enclave.py
Voir 17-Bibliotheque_Tavnit AgentProof/9-Primitives_AgentProof/6-YAD_EMET_EFFECTOR/

Rejoue, en permanent, les tests hostiles qui ont validé l'intégration :
jeton absent, jeton unique consommé une fois, rejeu refusé, signature
falsifiée refusée, binding d'action erroné refusé, jeton expiré refusé.

Isolé dans un HOME temporaire — ne touche jamais ~/.ctsm_* réels.
Usage : python3 tests/test_yad_emet_effector.py
"""
import base64
import copy
import os
import sys
import tempfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run():
    with tempfile.TemporaryDirectory() as home_isole:
        os.environ["HOME"] = home_isole
        sys.path.insert(0, REPO_ROOT)
        import server_local_secure_enclave as srv

        person_id = "person-test-001"
        action_id = srv.ACTION_ID_ECRIRE_INCIDENT
        echecs = []

        def verifier(nom, condition):
            print(f"{'OK  ' if condition else 'FAIL'} · {nom}")
            if not condition:
                echecs.append(nom)

        r = srv.ecrire_incident_urgence_pc_personnel(person_id, "incident test", True)
        verifier("sans jeton -> REFUSE/JETON_ABSENT", r["statut"] == "REFUSE" and "JETON_ABSENT" in r["raison"])

        jeton = srv.emettre_jeton_effet(action_id, person_id, "PC_PERSONNEL", "PUBLIC_GOVERNED_ACTION")
        r = srv.ecrire_incident_urgence_pc_personnel(person_id, "incident test", True, jeton)
        verifier("jeton valide -> INCIDENT_ENREGISTRE", r["statut"] == "INCIDENT_ENREGISTRE")

        r = srv.ecrire_incident_urgence_pc_personnel(person_id, "incident test 2", True, jeton)
        verifier("rejeu du meme jeton -> REFUSE/JETON_REJOUE", r["statut"] == "REFUSE" and "JETON_REJOUE" in r["raison"])

        jeton2 = srv.emettre_jeton_effet(action_id, person_id, "PC_PERSONNEL", "PUBLIC_GOVERNED_ACTION")
        jeton_falsifie = copy.deepcopy(jeton2)
        jeton_falsifie["tokenPayload"]["personId"] = "person-attaquant-999"
        r = srv.ecrire_incident_urgence_pc_personnel("person-attaquant-999", "incident test", True, jeton_falsifie)
        verifier("payload modifie post-signature -> REFUSE/SIGNATURE_INVALIDE", r["statut"] == "REFUSE" and "SIGNATURE_INVALIDE" in r["raison"])

        jeton_autre_action = srv.emettre_jeton_effet("une_autre_action", person_id, "PC_PERSONNEL", "PUBLIC_GOVERNED_ACTION")
        r = srv.ecrire_incident_urgence_pc_personnel(person_id, "incident test", True, jeton_autre_action)
        verifier("jeton d'une autre action -> REFUSE/BINDING_NON_CORRESPONDANT", r["statut"] == "REFUSE" and "BINDING_NON_CORRESPONDANT" in r["raison"])

        jeton3 = srv.emettre_jeton_effet(action_id, person_id, "PC_PERSONNEL", "PUBLIC_GOVERNED_ACTION")
        payload_expire = dict(jeton3["tokenPayload"])
        payload_expire["validUntilIso"] = "2020-01-01T00:00:00+00:00"
        cle = srv._yad_emet_cle_privee()
        sig = cle.sign(srv._yad_emet_canonicaliser(payload_expire).encode("utf-8"))
        jeton_expire = {"tokenPayload": payload_expire, "signatureBase64": base64.b64encode(sig).decode("ascii")}
        r = srv.ecrire_incident_urgence_pc_personnel(person_id, "incident test", True, jeton_expire)
        verifier("jeton re-signe mais expire -> REFUSE/JETON_EXPIRE", r["statut"] == "REFUSE" and "JETON_EXPIRE" in r["raison"])

        clef_path = srv.YAD_EMET_CLE_PATH
        mode = oct(os.stat(clef_path).st_mode & 0o777)
        verifier(f"cle privee en 0600 (obtenu {mode})", mode == "0o600")

        return echecs


if __name__ == "__main__":
    echecs = run()
    if echecs:
        print(f"\n{len(echecs)} test(s) en echec : {echecs}")
        sys.exit(1)
    print("\nTOUS LES TESTS YAD_EMET_EFFECTOR ONT PASSE")
