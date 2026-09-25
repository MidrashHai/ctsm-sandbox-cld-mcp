# ==============================================================================
# TEST · COUCHE 6 · CONTINUITE DE CHAINE STAT (haOr baDerekh)
# ==============================================================================
# Ecrit AVANT le code, selon la discipline "tests avant coding" (Coding baRouah).
# Ces tests definissent le contrat exact de la fonction pas encore codee
# verifier_continuite_chaine_stat(person_id, previous_stat_hash) et de son
# helper _calculer_stat_hash(resultat_porte). Ils doivent d'abord ECHOUER
# (rouge) parce que rien de tout cela n'existe encore dans le serveur, puis
# passer (vert) une fois le code ecrit pour satisfaire exactement ce contrat,
# pas l'inverse.
#
# Granularite proposee et testee ici : UNE CHAINE PAR person_id (pas par
# device). Si ce choix doit changer, ces tests doivent etre corriges EN
# PREMIER, avant le code -- jamais le code ajuste en silence pendant que les
# tests restent inchanges.
# ==============================================================================
import importlib.util
import os
import sys
import tempfile

REPO_ROOT = os.path.dirname(os.path.abspath(__file__))

# Isolation de HOME AVANT tout chargement du serveur : ses chemins ~/.ctsm_*
# sont resolus a l'import. Ce test ne lit ni n'ecrit jamais les vrais
# registres de l'artisan (employes, incidents, PCR, cle YAD_EMET...).
os.environ["HOME"] = tempfile.mkdtemp(prefix="ctsm_test_home_")


def charger_serveur(chaine_path):
    # Chemin relatif au depot : le test charge toujours le serveur voisin,
    # quel que soit le nom du dossier, la machine ou le point de montage.
    spec = importlib.util.spec_from_file_location("srv", os.path.join(
        REPO_ROOT, "server_local_secure_enclave.py"))
    srv = importlib.util.module_from_spec(spec)
    sys.modules["srv"] = srv
    spec.loader.exec_module(srv)
    # Isolation totale : jamais toucher au vrai fichier de chaine de l'artisan.
    srv.CHAINE_STAT_PATH = chaine_path
    return srv


def get_fn(srv, nom):
    obj = getattr(srv, nom)
    return obj.fn if hasattr(obj, "fn") else obj


def test_genese_premier_appel_accepte():
    """Un person_id sans chaine existante doit accepter previous_stat_hash='GENESIS'."""
    with tempfile.TemporaryDirectory() as d:
        srv = charger_serveur(os.path.join(d, "chaine.json"))
        fn = get_fn(srv, "verifier_continuite_chaine_stat")
        r = fn(person_id="test_genese", previous_stat_hash="GENESIS")
        assert r["verdict"] == "CHAINE_GENESE_ACCEPTEE", r
        print("OK  test_genese_premier_appel_accepte")


def test_genese_refusee_si_chaine_deja_commencee():
    """GENESIS ne doit plus etre accepte une fois qu'une chaine existe pour ce person_id."""
    with tempfile.TemporaryDirectory() as d:
        srv = charger_serveur(os.path.join(d, "chaine.json"))
        fn = get_fn(srv, "verifier_continuite_chaine_stat")
        maj = get_fn(srv, "_enregistrer_hash_chaine")
        maj("test_genese2", "hashA")
        r = fn(person_id="test_genese2", previous_stat_hash="GENESIS")
        assert r["verdict"] == "RUPTURE_CHAINE", r
        print("OK  test_genese_refusee_si_chaine_deja_commencee")


def test_continuite_conforme():
    """Le hash precedent exact doit etre accepte et faire avancer la sequence."""
    with tempfile.TemporaryDirectory() as d:
        srv = charger_serveur(os.path.join(d, "chaine.json"))
        fn = get_fn(srv, "verifier_continuite_chaine_stat")
        maj = get_fn(srv, "_enregistrer_hash_chaine")
        maj("test_continuite", "hashA")
        r = fn(person_id="test_continuite", previous_stat_hash="hashA")
        assert r["verdict"] == "CHAINE_CONFORME", r
        print("OK  test_continuite_conforme")


def test_rupture_sur_hash_errone():
    """Un hash different du dernier hash reel doit refuser, meme s'il ressemble a un vrai hash."""
    with tempfile.TemporaryDirectory() as d:
        srv = charger_serveur(os.path.join(d, "chaine.json"))
        fn = get_fn(srv, "verifier_continuite_chaine_stat")
        maj = get_fn(srv, "_enregistrer_hash_chaine")
        maj("test_rupture", "hashA")
        r = fn(person_id="test_rupture", previous_stat_hash="hashB_invente")
        assert r["verdict"] == "RUPTURE_CHAINE", r
        print("OK  test_rupture_sur_hash_errone")


def test_deux_person_id_ne_se_bloquent_pas():
    """Granularite par person_id : la chaine de 5786 n'affecte jamais celle de bc43..."""
    with tempfile.TemporaryDirectory() as d:
        srv = charger_serveur(os.path.join(d, "chaine.json"))
        fn = get_fn(srv, "verifier_continuite_chaine_stat")
        maj = get_fn(srv, "_enregistrer_hash_chaine")
        maj("5786", "hashAgent5786")
        r_autre = fn(person_id="bc43cdc8ef9e4cabb610b93b93d84651", previous_stat_hash="GENESIS")
        assert r_autre["verdict"] == "CHAINE_GENESE_ACCEPTEE", r_autre
        print("OK  test_deux_person_id_ne_se_bloquent_pas")


def test_chaine_avance_seulement_sur_succes_reel():
    """Ecrire un nouveau hash dans la chaine n'est permis que si la Porte a reellement ouvert."""
    with tempfile.TemporaryDirectory() as d:
        srv = charger_serveur(os.path.join(d, "chaine.json"))
        avancer = get_fn(srv, "_avancer_chaine_si_succes")
        # Simule un resultat REFUSE : la chaine ne doit pas bouger.
        resultat_refuse = {"verdict": "REFUSE [PORTE_FERMEE]"}
        avancer("test_avance", resultat_refuse)
        lire = get_fn(srv, "_lire_dernier_hash_chaine")
        assert lire("test_avance") is None, "la chaine n'aurait pas du avancer sur un REFUS"
        # Simule un resultat AUTORISE : la chaine doit avancer et retenir un hash.
        resultat_ok = {"verdict": "AUTORISE [PORTE_OUVERTE]", "timestamp_utc": "2026-09-15T00:00:00Z"}
        avancer("test_avance", resultat_ok)
        h = lire("test_avance")
        assert h is not None and len(h) == 64, f"hash sha256 attendu, obtenu {h!r}"
        print("OK  test_chaine_avance_seulement_sur_succes_reel")




def test_integration_porte_bloque_meme_si_couches_1_a_5_vertes():
    """Integration : la Porte doit refuser sur RUPTURE_CHAINE seule, meme en
    simulant les Couches 1 a 5 toutes vertes -- preuve de non-compensation."""
    with tempfile.TemporaryDirectory() as d:
        srv = charger_serveur(os.path.join(d, "chaine.json"))

        # Simule les Couches 1 a 5 comme toujours vertes, sans dependre de
        # GPS/PCR16/registre reels -- on isole ici la seule question de la
        # Couche 6.
        srv.pcnt_zera_1cm = lambda **k: {"governance": {"status": "LIEU_CONFIRME_PAR_TEMOIN"}, "contexteTerritorial": None}
        srv.STATUTS_POSITION_SUFFISANTS = {"LIEU_CONFIRME_PAR_TEMOIN"}
        srv.verifier_mandat_agent_correia = lambda dl, dg: {"statut_domanial": "DESTINATION_CONFORME_AU_MANDAT", "zoneMatchee": "ABIDJAN"}
        srv.verifier_secure_enclave_et_position = lambda **k: {"verdict": "ACCORDÉ [SAF_OPEN]", "triangulation": None, "signature_opposable": "sig"}
        srv.verifier_secure_enclave_reel_employe = lambda pid, td: {"verdict": "SIGNATURE_VALIDE"}
        srv.verifier_subordination_mandat_employe = lambda person_id, zone_matchee: {"verdict": "SUBORDINATION_CONFORME", "mandatZoneEmploye": zone_matchee}
        srv._PETIHAH_APPELEE = True  # verrou d'ouverture leve pour ce test isole, sans rapport avec la Couche 6

        fn_porte = get_fn(srv, "autoriser_execution_action")
        r = fn_porte(
            latitude=5.0, longitude=-3.0, pcr16_attendu="x", payload_file="/dev/null",
            person_id="test_integration", type_device="PC_BUREAU",
            previous_stat_hash="hash_invente_qui_ne_peut_pas_matcher",
        )
        assert r["verdict"] == "REFUSE [PORTE_FERMEE]", r
        assert any("RUPTURE_CHAINE" in c or "CHAINE" in c for c in r.get("causeRefus", [])), r.get("causeRefus")
        print("OK  test_integration_porte_bloque_meme_si_couches_1_a_5_vertes")


def test_integration_genese_ouvre_et_avance_la_chaine():
    """Integration : un premier appel GENESIS avec les 5 autres couches
    vertes doit ouvrir la Porte ET faire avancer la chaine pour ce person_id."""
    with tempfile.TemporaryDirectory() as d:
        srv = charger_serveur(os.path.join(d, "chaine.json"))
        srv.pcnt_zera_1cm = lambda **k: {"governance": {"status": "LIEU_CONFIRME_PAR_TEMOIN"}, "contexteTerritorial": None}
        srv.STATUTS_POSITION_SUFFISANTS = {"LIEU_CONFIRME_PAR_TEMOIN"}
        srv.verifier_mandat_agent_correia = lambda dl, dg: {"statut_domanial": "DESTINATION_CONFORME_AU_MANDAT", "zoneMatchee": "ABIDJAN"}
        srv.verifier_secure_enclave_et_position = lambda **k: {"verdict": "ACCORDÉ [SAF_OPEN]", "triangulation": None, "signature_opposable": "sig"}
        srv.verifier_secure_enclave_reel_employe = lambda pid, td: {"verdict": "SIGNATURE_VALIDE"}
        srv.verifier_subordination_mandat_employe = lambda person_id, zone_matchee: {"verdict": "SUBORDINATION_CONFORME", "mandatZoneEmploye": zone_matchee}
        srv._PETIHAH_APPELEE = True  # verrou d'ouverture leve pour ce test isole, sans rapport avec la Couche 6

        fn_porte = get_fn(srv, "autoriser_execution_action")
        r1 = fn_porte(
            latitude=5.0, longitude=-3.0, pcr16_attendu="x", payload_file="/dev/null",
            person_id="test_integration2", type_device="PC_BUREAU",
            previous_stat_hash="GENESIS",
        )
        assert r1["verdict"] == "AUTORISE [PORTE_OUVERTE]", r1
        lire = get_fn(srv, "_lire_dernier_hash_chaine")
        h = lire("test_integration2")
        assert h is not None, "la chaine aurait du avancer apres un AUTORISE"

        # Rejouer le MEME GENESIS une deuxieme fois doit maintenant echouer :
        # la chaine a deja commence.
        r2 = fn_porte(
            latitude=5.0, longitude=-3.0, pcr16_attendu="x", payload_file="/dev/null",
            person_id="test_integration2", type_device="PC_BUREAU",
            previous_stat_hash="GENESIS",
        )
        assert r2["verdict"] == "REFUSE [PORTE_FERMEE]", r2
        print("OK  test_integration_genese_ouvre_et_avance_la_chaine")


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    echecs = []
    for t in tests:
        try:
            t()
        except Exception as e:
            echecs.append((t.__name__, repr(e)))
            print(f"ECHEC {t.__name__} : {e!r}")
    print(f"\n{len(tests) - len(echecs)}/{len(tests)} tests passes.")
    if echecs:
        sys.exit(1)
