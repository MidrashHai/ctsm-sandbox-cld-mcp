#!/usr/bin/env python3
# ==============================================================================
# CTSM-v1.4 · SERVEUR MCP (stdio) · SANDBOX™ + PONT RÉEL
# GovernedAgent™ v1.1 · Petihah_GovernedAgent + autoriser_execution_action
# Makom Intelligence™ · CorreIA LLC · Environnement de TEST (2026)
#
# ⚠️ Les outils SANDBOX (evaluer_presence_locus_demo, verifier_domaine_externe_demo,
#    generer_recu_test) restent des simulations pures, inchangées depuis v1.0.
#
# ✦ resoudre_presence_employe_abidjan(person_id, lat, lon, icl_bureau_reference,
#   session_id) appelle RÉELLEMENT POST /v1/resolve-presence sur le Cockpit
#   Spatial™ API (cockpit-spatial-api.onrender.com).
#
#   MISE À JOUR v1.2 · le contrat de cet endpoint a été lu directement dans le
#   code source réel du dépôt MidrashHai/cockpit-spatial-api (pcnt.js,
#   resolve-presence.js, server.js), pas supposé depuis la SPEC. Deux
#   corrections par rapport au v1.1 :
#     1. person_id est un paramètre OBLIGATOIRE de l'API réelle (sans lui,
#        l'API répond ERR_PERSON_ID_MISSING) — absent du v1.1, ajouté ici.
#     2. L'API ne renvoie JAMAIS de distance_m / rue / adresse_pada. Elle
#        renvoie lieu.contexte_actif (bool) et icl_computed.identifiant
#        (un identifiant symbolique déterministe PCNT, cellule native de 10m).
#        Le critère de conformité de position devient donc une ÉGALITÉ d'ICL
#        entre la position mesurée et l'ICL de référence du bureau, et non
#        plus une comparaison de distance à un seuil en mètres — ce dernier
#        mécanisme n'existe dans aucun fichier du dépôt réel consulté.
#
#   AJOUTS v1.3 :
#     1. Les deux ICL réels (Agent✦348 Shaliach · Paris, Agent✦490 Nochehut ·
#        Abidjan), calculés avec le vrai pcnt.js sur les coordonnées WGS84
#        déclarées de chaque siège, sont inscrits en constantes. Le paramètre
#        icl_bureau_reference de resoudre_presence_employe_abidjan devient
#        optionnel : à défaut, la constante ICL_ABRAND_ABIDJAN est utilisée.
#     2. Nouvel outil inscrire_acteur_abidjan(nom, ...) : appelle réellement
#        POST /v1/auth pour obtenir un person_id, préalable réel à tout appel
#        de resoudre_presence_employe_abidjan pour un acteur pas encore inscrit.
#     3. Nouvel outil verifier_mandat_agent_correia(destination_lat,
#        destination_lon) : test du mandat de l'Agent✦348 Shaliach (Paris),
#        dans/hors Paris. Il n'existe AUCUN endpoint réel côté Cockpit
#        Spatial™ API pour Paris (ce service ne couvre que Cocody/Abidjan :
#        /v1/territoire et /v1/voiries sont scopés Cocody). Ce test est donc
#        une géodésie réelle (haversine) contre un centre et un rayon
#        approximatifs de Paris, PAS un appel réseau, et PAS une correspondance
#        à une base d'adresses officielle comme pour Abidjan — limite à
#        traiter comme telle, jamais présentée comme équivalente.
#
#   AJOUT v1.4 · verifier_secure_enclave_et_position(pcr16_attendu, payload_file,
#     mesure_lat, mesure_lon, nominal_lat, nominal_lon) : réimplémente en Python
#     pur, dans ce même serveur, la triangulation à trois nœuds déjà traversée
#     dans agentproof_trl5_gate.py (dépôt CorreIA, tests du 4 et 5 septembre).
#     Nœud 2 (Demeure/BSSID + MAC hôte) et Nœud 3 (Institution/PCR16, lu dans
#     ~/.ctsm_pcr_state.json écrit par ctsm_tpm_mac.py) restent des lectures
#     système réelles et dynamiques, identiques au script d'origine.
#     Nœud 1 (Sol/WGS84) devient un VRAI PARAMÈTRE d'entrée (mesure_lat,
#     mesure_lon) au lieu d'une constante figée dans le code — mais les
#     valeurs par défaut reprennent exactement l'échantillon déjà utilisé lors
#     des tests tracés du 4/5 septembre (mesure Abidjan 5.385740/-3.952593
#     contre nominal 5.386086/-3.953515), pour que les tests déjà faits restent
#     rejouables à l'identique par défaut, tout en permettant de fournir une
#     vraie position différente à l'appel.
#
#   Ce fichier ne renomme pas la simulation en réel : chaque outil documente
#   explicitement s'il effectue un appel réseau réel, une lecture système
#   réelle, ou une simulation/approximation/échantillon figé.
#
#   GOVERNEDAGENT™ v1.1 (24 sept 2026) · renommage formel, pas un correctif.
#   Les captures capture_GovernedAgent_1_HORS_MANDAT.png / _2_bypass_execute.png
#   (dossier capture d'ecran/, 10 sept 2026) montrent « GovernedAgent™ v1.0 » —
#   à cette date, ni Petihah_GovernedAgent (ajoutée le 9 sept) ni les couches
#   4/5/6 de autoriser_execution_action (ajoutées 13 et 15 sept) n'étaient
#   encore matures. v1.1 nomme officiellement l'état courant du mécanisme
#   (Petihah + six couches non compensatoires + signatureOpposable), analysé
#   dans MISE-A-JOUR-9-Primitives-AgentProof.md à la lumière de la bibliothèque
#   17-Bibliotheque_Tavnit AgentProof/9-Primitives_AgentProof/.
#
#   MISE À JOUR (même jour) · YAD_EMET_EFFECTOR intégrée : emettre_jeton_effet
#   / verifier_et_consommer_jeton_effet (Ed25519, TTL 300s, nonce, liaison par
#   hash, registre de rejeu). autoriser_execution_action émet le jeton si la
#   Porte ouvre ET qu'un action_id est fourni. Premier outil d'effet
#   réellement gardé : ecrire_incident_urgence_pc_personnel — testé
#   hostilement, 7/7 (tests/test_yad_emet_effector.py).
#
#   CE QUI RESTE OUVERT : un seul outil d'effet sur ~10 est gardé. Le bypass
#   du 10 sept reste possible via tout AUTRE outil d'effet de ce fichier
#   (provisionner_secure_enclave_reel_employe, retirer_secure_enclave_reel_
#   employe, ajouter_ressource_employe, inscrire_employe_gouverne, etc.) qui
#   n'exige pas encore ce jeton. Migration délibérément progressive, pas
#   globale, vu la sensibilité de ces outils (provisionnement matériel réel).
#   Voir MISE-A-JOUR-9-Primitives-AgentProof.md pour l'ordre restant, et
#   GATE_SOUVERAINE / EXCLUSIVE_CAPABILITY_OWNERSHIP (9-Primitives_AgentProof/)
#   pour ce que ce jeton ne couvre toujours pas : signature humaine pour
#   l'irréversible, et séparation de compte OS.
#
# A lancer localement et à déclarer dans la configuration MCP de Claude Desktop
# (ou de Codex) pour que l'agent puisse appeler ces outils directement.
# ==============================================================================

import math
import hashlib
import hmac
import json
import os
import re
import subprocess
import time
import uuid
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timezone
from typing import Optional
import secrets
import base64
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ctsm-sandbox-demo")

# ------------------------------------------------------------------------------
# CONSTANTES & ENTITES FICTIVES (inchangées, outils sandbox v1.0)
# ------------------------------------------------------------------------------
# Point nominal mis à jour le 7 sept 2026 : coordonnées GPS réelles du domicile
# de l'utilisateur, déclaré comme bureau annexe (remplace l'ancien point fictif
# hérité du sandbox v1.0, 5.386086 / -3.953515, jamais vérifié sur le terrain)
# Distinction a ne jamais confondre (7 sept 2026), trois rayons coexistent
# dans ce sandbox, chacun repondant a une question differente :
#   - rayon_m d'un Lieu (Couche 1, temoin, ex. 5 m) : l'agent EST-IL dans ce
#     Lieu precis, avec marge d'incertitude du capteur.
#   - TOLERANCE_METERS ci-dessous (Couche 2, enclave, 10 m autour de
#     NOMINAL_LAT/LON) : l'agent ne peut PAS SIGNER d'acte au dela de cette
#     distance physique stricte — un lien domanial, pas une juridiction.
#   - ABIDJAN_MANDAT_RAYON_KM (Couche 3, mandat, 25 km) : sur quelles
#     destinations l'agent A-T-IL LE DROIT d'agir, une fois ancre — une
#     juridiction, pas une position physique.
# Le mandat (large) ne dispense jamais du lien physique strict (10 m) : les
# trois couches restent non compensatoires entre elles (voir OUTIL 8, la
# porte unique).
NOMINAL_LAT = 5.385607
NOMINAL_LON = -3.953564
TOLERANCE_METERS = 10.0
NOMINAL_BSSID = "TEST:00:00:00:00:00"
NOMINAL_PCR16 = "DEMOPCR16-0000000000000000000000000000000000000000000000000000"

ENTITE_EMETTRICE = "Sanctuaire Démonstratif Aleph™ (SANDBOX)"
INSTITUTION_TEST = "Institut Fictif BETA-DEMO"
DOMAINES_AUTORISES = ["exemple-sandbox.test", "demo.makom-intelligence.test", "maps.addressme.ci"]
MONTANT_TEST = "1 000 UNITÉS-TEST (aucune valeur réelle)"

# ------------------------------------------------------------------------------
# CONFIGURATION DU PONT RÉEL · Cockpit Spatial™ API (Render)
# ------------------------------------------------------------------------------
# Surchargeable par variable d'environnement pour ne jamais figer l'URL en dur
# dans le code déployé (CTSM_COCKPIT_API_URL).
COCKPIT_API_BASE_URL = os.environ.get(
    "CTSM_COCKPIT_API_URL",
    "https://cockpit-spatial-api.onrender.com",
)
RESOLVE_PRESENCE_PATH = "/v1/resolve-presence"
AUTH_PATH = "/v1/auth"
# ============================================================================
# LOI (7 septembre 2026) — GPS BRUT INTERDIT EN DECISION
# ============================================================================
# Aucune donnee GPS Google (ou de toute autre source brute : capteur telephone,
# capteur PC, etc.) n'est utilisee dans un calcul decisionnel. La seule
# utilisation legitime d'une donnee GPS brute est sa conversion en GPS PCNT
# Zera 1cm. Toute utilisation en dehors de ce contexte est une violation et
# doit etre bloquee.
#
# Enonce par l'operateur (Midrash-Hai, Scribe du Souffle) le 7 septembre 2026,
# a la suite d'un test reel ou une comparaison utilisant les coordonnees GPS
# brutes aurait pu masquer ou fausser la marge d'incertitude declaree par le
# capteur. Cette Loi est un principe architectural permanent du protocole
# CTSM : elle ne se discute pas au cas par cas, elle se verifie.
#
# Ce que "decisionnel" recouvre ici : tout calcul qui alimente directement ou
# indirectement governance_status, un verdict de temoin (dansLeLieu /
# verdictTemoin), ou une evidence de type GROUND_TRUTH_VS_GPS.
#
# Points d'application reels dans ce fichier :
#   - contexte_territorial (PADA + Path Resolver) : calcule sur point_ref_lat /
#     point_ref_lon, c'est-a-dire le premier candidat Zera 1cm RESOLVED —
#     jamais sur `latitude` / `longitude` brutes. Voir point_ref_source.
#   - _lieu_temoin_le_plus_proche(...) : appele avec point_ref_lat /
#     point_ref_lon, jamais avec les coordonnees brutes.
#   - evidence GROUND_TRUTH_VS_GPS : distance_gps calculee entre
#     previous_governed_lat/lon et point_ref_lat/lon (candidat converti),
#     jamais contre les coordonnees GPS brutes de l'observation courante.
#   - Sans candidat Zera 1cm resolu (ex. bearing_deg absent), aucun contexte
#     territorial n'est calcule du tout : le champ retourne est
#     {"status": "INDISPONIBLE_AVANT_CONVERSION_PCNT", "raison": "LOI (7 sept
#     2026) : ..."} plutot que de se rabattre sur le GPS brut.
#
# Exception unique, deliberee et non-decisionnelle : `sourceICL`.
#   sourceICL est un ICL calcule directement sur les coordonnees GPS brutes de
#   l'observation, conserve UNIQUEMENT comme reference d'audit (pour comparer
#   a posteriori l'ICL du brut et l'ICL du candidat Zera 1cm converti). Il
#   n'entre dans AUCUN calcul de governance_status, d'evidence, ou de verdict
#   de temoin. Instruction explicite de l'operateur (7 sept 2026) : "garde en
#   reference pour audit, sans influence, et grave la loi comme principe a ne
#   pas violer."
# ============================================================================

# ----------------------------------------------------------------------------
# FRONTIERE avec Cockpit-Space-API (repo externe MidrashHai/cockpit-spatial-api)
# ----------------------------------------------------------------------------
# Ce sandbox ne consomme QUE la logique et les DONNEES brutes de
# Cockpit-Space-API : le schema GeoJSON de territoire.js (adresses PADA) et
# de voiries.js (reseau viaire), ainsi que la logique de resolution
# plus-proche-sommet/plus-proche-point qui leur est fidele (voir
# _pada_adresse_la_plus_proche / _path_resolver_voie_la_plus_proche).
#
# Ce sandbox NE reprend PAS le protocole ni les revendications de precision
# propres a Cockpit-Space-API — notamment pcnt.js (son propre "PCNT v3.1",
# route POST /v1/territorial-context) et la couche de gouvernance
# Qavanah/qavanah-bridge.js (Territory Action Layer). Ces protocoles peuvent
# etre perimes ou incoherents avec ce sandbox : Cockpit-Space-API opere a une
# granularite de l'ordre de 10 m (son PCNT v3.1), alors que ce sandbox opere
# son propre protocole PCNT Zera 1cm, resolument distinct et plus fin. Aucun
# appel n'est fait ici a POST /v1/territorial-context ni a pcnt.js — seuls
# GET /v1/territoire, GET /v1/voiries (donnees brutes) sont consommes.
# ----------------------------------------------------------------------------

# Partage des roles (7 sept 2026) : ce sandbox ne lit que les DONNEES brutes
# (territoire.js, voiries.js) pour produire un contexte de gouvernance
# factuel — proximite PADA/voirie, containment au temoin d'un Lieu. Il ne
# fait aucune lecture profonde ni interpretation conversationnelle du
# territoire (comprendre une phrase libre, deduire une intention, dialoguer)
# — cette lecture profonde est le role propre d'Or haBayit (via or-habayit.js
# + qavanah-bridge.js, cote Cockpit-Space-API), jamais reimplemente ici.

TERRITOIRE_PATH = "/v1/territoire"   # PADA reel · territoire.js · 6025 adresses · Cocody
VOIRIES_PATH = "/v1/voiries"         # Path Resolver reel · voiries.js · 386 voies · Cocody

# Cache mémoire simple : jeux de données réels mais quasi statiques (6025
# adresses, 386 voies). Évite de les retélécharger à chaque appel.
_CACHE_TERRITOIRE = {"data": None, "chargee_a": 0.0}
_CACHE_VOIRIES = {"data": None, "chargee_a": 0.0}
_CACHE_TTL_SECONDES = 1800.0


def _cockpit_get_json(path: str) -> dict:
    """Appel HTTP réel, GET, même discipline que _call_resolve_presence /
    _call_auth : jamais de succès simulé en cas d'échec réseau."""
    url = f"{COCKPIT_API_BASE_URL}{path}"
    last_error = None
    for attempt in range(MAX_RETRIES + 1):
        req = urllib.request.Request(url, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_SECONDS) as resp:
                raw = resp.read().decode("utf-8")
                return {"ok": True, "http_status": resp.status, "data": json.loads(raw)}
        except urllib.error.HTTPError as e:
            try:
                err_body = e.read().decode("utf-8")
            except Exception:  # noqa: BLE001
                err_body = ""
            last_error = f"HTTP {e.code} : {e.reason} · {err_body}"
        except urllib.error.URLError as e:
            last_error = f"Réseau indisponible : {e.reason}"
        except Exception as e:  # noqa: BLE001
            last_error = f"Erreur inattendue : {e}"
        if attempt < MAX_RETRIES:
            time.sleep(RETRY_DELAY_SECONDS)
    return {"ok": False, "error": last_error}


# LOI (8 sept 2026) : usage interne sans dependance reseau obligatoire.
# PADA (territoire, 6025 adresses, Cocody) et le Path Resolver (voies, 386
# voies, Cocody) sont d'abord lus depuis une instance locale reconstruite a
# l'identique (memes 6025 / 386 lignes, meme schema) a partir des dumps SQL
# reels (territoire_lots.zip, insert_voies_ok.sql), stockee sous
# data_local/. Le Cockpit Spatial (TM) API reste le recours reseau
# uniquement si le fichier local est absent — jamais l'inverse. Ceci retire
# la dependance a Render pour nos travaux internes ; la securisation du
# service reseau (cle API, CORS resserre) reste une etape separate et
# posterieure.
LOCAL_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data_local")
TERRITOIRE_LOCAL_PATH = os.path.join(LOCAL_DATA_DIR, "territoire_local.json")
VOIES_LOCAL_PATH = os.path.join(LOCAL_DATA_DIR, "voies_local.json")


def _charger_json_local(chemin: str) -> dict:
    try:
        with open(chemin, "r", encoding="utf-8") as f:
            return {"ok": True, "data": json.load(f), "source": "LOCAL"}
    except FileNotFoundError:
        return {"ok": False, "error": f"Fichier local absent : {chemin}"}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"Lecture locale invalide ({chemin}) : {e}"}


def _charger_territoire() -> dict:
    now = time.time()
    if _CACHE_TERRITOIRE["data"] is not None and (now - _CACHE_TERRITOIRE["chargee_a"]) < _CACHE_TTL_SECONDES:
        return {"ok": True, "data": _CACHE_TERRITOIRE["data"], "depuis_cache": True, "source": _CACHE_TERRITOIRE.get("source")}
    resultat_local = _charger_json_local(TERRITOIRE_LOCAL_PATH)
    if resultat_local.get("ok"):
        _CACHE_TERRITOIRE["data"] = resultat_local["data"]
        _CACHE_TERRITOIRE["chargee_a"] = now
        _CACHE_TERRITOIRE["source"] = "LOCAL"
        return {"ok": True, "data": resultat_local["data"], "source": "LOCAL"}
    resultat = _cockpit_get_json(TERRITOIRE_PATH)
    if resultat.get("ok"):
        _CACHE_TERRITOIRE["data"] = resultat["data"]
        _CACHE_TERRITOIRE["chargee_a"] = now
        _CACHE_TERRITOIRE["source"] = "COCKPIT_API"
        resultat["source"] = "COCKPIT_API"
    return resultat


def _charger_voiries() -> dict:
    now = time.time()
    if _CACHE_VOIRIES["data"] is not None and (now - _CACHE_VOIRIES["chargee_a"]) < _CACHE_TTL_SECONDES:
        return {"ok": True, "data": _CACHE_VOIRIES["data"], "depuis_cache": True, "source": _CACHE_VOIRIES.get("source")}
    resultat_local = _charger_json_local(VOIES_LOCAL_PATH)
    if resultat_local.get("ok"):
        _CACHE_VOIRIES["data"] = resultat_local["data"]
        _CACHE_VOIRIES["chargee_a"] = now
        _CACHE_VOIRIES["source"] = "LOCAL"
        return {"ok": True, "data": resultat_local["data"], "source": "LOCAL"}
    resultat = _cockpit_get_json(VOIRIES_PATH)
    if resultat.get("ok"):
        _CACHE_VOIRIES["data"] = resultat["data"]
        _CACHE_VOIRIES["chargee_a"] = now
        _CACHE_VOIRIES["source"] = "COCKPIT_API"
        resultat["source"] = "COCKPIT_API"
    return resultat


def _pada_adresse_la_plus_proche(lat: float, lon: float) -> dict:
    """PADA réel (territoire.js, 6025 adresses). Réplique fidèlement
    plusProcheAdresse() de OmeH.ai (v2f) : minimum de distance haversine au
    POINT de chaque adresse — pas une approximation différente."""
    resultat = _charger_territoire()
    if not resultat.get("ok"):
        return {"status": "PADA_INDISPONIBLE", "erreur": resultat.get("error")}
    features = resultat["data"].get("features", [])
    if not features:
        return {"status": "PADA_VIDE"}

    meilleure, meilleure_distance_km = None, None
    for feat in features:
        coords = feat.get("geometry", {}).get("coordinates")
        if not coords or len(coords) != 2:
            continue
        lon_a, lat_a = coords
        d_km = compute_haversine(lat, lon, lat_a, lon_a) / 1000.0
        if meilleure_distance_km is None or d_km < meilleure_distance_km:
            meilleure_distance_km = d_km
            meilleure = feat.get("properties", {})
    if meilleure is None:
        return {"status": "PADA_AUCUNE_GEOMETRIE_VALIDE"}
    return {
        "status": "RESOLVED",
        "city": meilleure.get("city"), "st_name": meilleure.get("st_name"),
        "numero": meilleure.get("numero"), "icl": meilleure.get("icl"),
        "shem": meilleure.get("shem"),
        "distance_m": meilleure_distance_km * 1000.0,
    }


def _path_resolver_voie_la_plus_proche(lat: float, lon: float) -> dict:
    """Path Resolver réel (voiries.js, 386 voies). Réplique fidèlement
    plusProcheVoirie() de OmeH.ai (v2f) : minimum de distance haversine à
    CHAQUE SOMMET de chaque LineString (début et fin), pas une projection
    sur segment — pour rester reproductible à l'identique de la référence
    déjà en production sur maps.addressme.ci."""
    resultat = _charger_voiries()
    if not resultat.get("ok"):
        return {"status": "PATH_RESOLVER_INDISPONIBLE", "erreur": resultat.get("error")}
    features = resultat["data"].get("features", [])
    if not features:
        return {"status": "PATH_RESOLVER_VIDE"}

    meilleure, meilleure_distance_km = None, None
    for feat in features:
        coords = feat.get("geometry", {}).get("coordinates", [])
        for lon_v, lat_v in coords:
            d_km = compute_haversine(lat, lon, lat_v, lon_v) / 1000.0
            if meilleure_distance_km is None or d_km < meilleure_distance_km:
                meilleure_distance_km = d_km
                meilleure = feat.get("properties", {})
    if meilleure is None:
        return {"status": "PATH_RESOLVER_AUCUNE_GEOMETRIE_VALIDE"}
    lat_debut = lon_debut = lat_fin = lon_fin = None
    for feat in features:
        if feat.get("properties", {}) is meilleure:
            coords = feat.get("geometry", {}).get("coordinates", [])
            if len(coords) == 2:
                (lon_debut, lat_debut), (lon_fin, lat_fin) = coords[0], coords[1]
            break
    return {
        "status": "RESOLVED",
        "st_name": meilleure.get("st_name"), "city": meilleure.get("city"),
        "longueur_m": meilleure.get("longueur_m"),
        "icl_debut": meilleure.get("icl_debut"), "icl_fin": meilleure.get("icl_fin"),
        "convergence": meilleure.get("convergence"),
        "shem": meilleure.get("shem"),
        "distance_m": meilleure_distance_km * 1000.0,
        "lat_debut": lat_debut, "lon_debut": lon_debut,
        "lat_fin": lat_fin, "lon_fin": lon_fin,
    }


# Render (plan gratuit) peut être en veille : premier appel = cold start possible.
# Timeout généreux + une seule relance automatique, pas plus (pas de boucle silencieuse).
REQUEST_TIMEOUT_SECONDS = 30
MAX_RETRIES = 1
RETRY_DELAY_SECONDS = 3

# NOTE v1.2 · il n'existe pas de seuil en mètres côté API réelle (voir en-tête).
# Conservé uniquement pour référence historique / documentation de l'écart avec la SPEC.
SEUIL_ABIDJAN_METERS_NON_UTILISE_PAR_API_REELLE = 10.0

# ------------------------------------------------------------------------------
# ICL RÉELS DES DEUX SIÈGES (v1.3)
# ------------------------------------------------------------------------------
# Calculés avec le vrai module pcnt.js (dépôt MidrashHai/cockpit-spatial-api,
# branche main, lu le 2026-09-07), sur les coordonnées WGS84 déclarées de
# chaque siège. Fiche identitaire correspondante : Agent✦348 · Shaliach
# (Paris) et Agent✦490 · Nochehut (Abidjan), statut CANDIDATE (FL✦414).
ICL_CORREIA_PARIS = "3319|3124"          # 61 Rue de Lyon, 75012 Paris · 48.84934, 2.37125
ICL_ABRAND_ABIDJAN = "2733|8589"         # Cocody Angré 7ème · 5.386086, -3.953515

# ------------------------------------------------------------------------------
# ADRESSE DOMANIALE BIPOLAIRE DE L'AGENT (v1.0, ajout 2026-09-17)
# ------------------------------------------------------------------------------
# Pratique Ayin-Peh DevOps : OBSERVE deja fait (constantes ICL et
# _deriver_identifiant_secure_enclave lues directement ci-dessus/ci-dessous,
# jamais inventees). MEASURE et DECIDE restent partiels tant que cette
# fonction n'a pas ete executee reellement sur ce poste -- statut CANDIDATE,
# jamais ACTIVE tant que non traversee (meme discipline que ICL_CORREIA_PARIS
# et ICL_ABRAND_ABIDJAN ci-dessus, statut CANDIDATE FL-414).
#
# CorreIA LLC (Paris, ICL_CORREIA_PARIS) heberge l'Agent et repond de lui
# devant les juridictions. Abrand News (filiale, Abidjan, ICL_ABRAND_ABIDJAN)
# est le territoire de mandat ou l'Agent agit -- reference seulement, jamais
# fondue dans le meme champ que le domicile legal (loi bipolaire non
# compensatoire : si icl_organisation ou silicium_user est absent, l'adresse
# ne doit pas etre consideree constituee).
def constituer_adresse_agent(
    agent_id: str = "AG-TERRITORIAL-01",
    type_device: Optional[str] = None,
) -> dict:
    """
    Constitue la fiche d'adresse domaniale bipolaire de l'Agent, a partir des
    deux ancrages deja reels dans ce module : ICL_CORREIA_PARIS (domicile
    legal) et _deriver_identifiant_secure_enclave() (Silicium de ce poste).
    Ne mesure rien de nouveau, ne fabrique aucune valeur -- assemble
    uniquement ce qui existe deja.

    Args:
        agent_id: identifiant de l'agent concerne.
        type_device: "PC_BUREAU" ou "PC_PERSONNEL", jamais devine. Absent =
                inscrit tel quel comme TYPE_DEVICE_ABSENT, la fiche reste
                CANDIDATE plutot que de retomber sur une valeur par defaut
                non declaree.

    Returns:
        La fiche d'adresse, statut "CANDIDATE" jusqu'a verification reelle
        (Bedikat haEmet) de chaque champ sur ce poste precis.
    """
    icl_organisation = ICL_CORREIA_PARIS
    silicium_user = _deriver_identifiant_secure_enclave()
    type_device_declare = type_device if type_device in TYPES_DEVICE_VALIDES else "TYPE_DEVICE_ABSENT"

    shem_scelle = hashlib.sha256(
        f"{icl_organisation}|{silicium_user}".encode("utf-8")
    ).hexdigest()

    return {
        "domanial_address_version": "SHC-ICL-v1.0",
        "agent_id": agent_id,
        "parameter_1_institutional_icl": {
            "organization_legal_name": "CorreIA LLC",
            "siege_legal": "Paris, France",
            "icl_id": icl_organisation,
        },
        "parameter_2_user_silicon": {
            "type_device_declare": type_device_declare,
            "silicium_id": silicium_user,
        },
        "territoire_action_declare": {
            "filiale": "Abrand News",
            "icl_mandat": ICL_ABRAND_ABIDJAN,
        },
        "shem_scelle": shem_scelle,
        "horodatage_constitution": datetime.now(timezone.utc).isoformat(),
        "status": "CANDIDATE",
    }


# ------------------------------------------------------------------------------
# GÉODÉSIE APPROXIMATIVE · MANDAT PARIS (v1.3)
# ------------------------------------------------------------------------------
# Le Cockpit Spatial™ API ne couvre pas Paris (territoire/voiries scopés
# Cocody uniquement) : pas d'appel réseau possible pour ce test. Rayon
# approximatif choisi pour couvrir Paris intra muros depuis son centre
# géographique (Notre-Dame) — ce n'est PAS une correspondance à une limite
# administrative officielle des arrondissements, seulement une géodésie réelle
# (haversine) contre un centre et un rayon déclarés. À affiner si un test à
# la frontière exacte d'un arrondissement est un jour nécessaire.
PARIS_CENTRE_LAT = 48.852968
PARIS_CENTRE_LON = 2.349902
PARIS_RAYON_KM = 5.6

# ------------------------------------------------------------------------------
# SECURE ENCLAVE / TPM ÉMULÉ · v1.4
# ------------------------------------------------------------------------------
# Fichier d'état PCR, écrit par ctsm_tpm_mac.py (émulation logicielle assumée
# comme telle par ce script — pas une puce Secure Enclave réelle). Ce serveur
# LIT ce fichier, il ne l'écrit jamais lui-même : l'extension du PCR reste un
# acte séparé, à faire tourner via ctsm_tpm_mac.py avant d'appeler cet outil.
PCR_STATE_FILE = os.path.expanduser("~/.ctsm_pcr_state.json")
AGENTPROOF_RECEIPT_FILE = os.path.expanduser("~/.agentproof_receipt_last.json")
ZERO_HASH_PCR = "0" * 68

# Échantillon exact déjà utilisé lors des tests tracés du 4/5 septembre 2026
# (agentproof_trl5_gate.py, cas Abidjan). Conservé comme défaut pour que les
# tests déjà faits restent rejouables à l'identique — plus jamais figé en dur
# dans le code, mais explicite ici comme valeur d'échantillon nommée.
# Echantillon 2 (test tracé du 4/5 septembre 2026, agentproof_trl5_gate.py,
# measured_lat/measured_lon hardcodés dans le script d'origine)
ECHANTILLON_MESURE_LAT_ABIDJAN = 5.385740
ECHANTILLON_MESURE_LON_ABIDJAN = -3.952593

# Echantillon 1 (position GPS réelle transmise par l'utilisateur le 7 sept 2026,
# domicile / bureau annexe, Abidjan) — devient l'échantillon par défaut du gate
ECHANTILLON_1_LAT_DOMICILE_ABIDJAN = 5.385607
ECHANTILLON_1_LON_DOMICILE_ABIDJAN = -3.953564


def _lire_pcr16() -> str:
    """Lecture réelle du fichier d'état PCR émulé écrit par ctsm_tpm_mac.py."""
    if os.path.exists(PCR_STATE_FILE):
        try:
            with open(PCR_STATE_FILE, "r") as f:
                pcrs = json.load(f)
            return pcrs.get("16", ZERO_HASH_PCR)
        except Exception:  # noqa: BLE001
            return ZERO_HASH_PCR
    return ZERO_HASH_PCR


# ------------------------------------------------------------------------------
# OUTIL 9 : EXTENSION REELLE DU PCR16 EMULE (7 sept 2026)
# ------------------------------------------------------------------------------
# Chaine constitutive · Extension de la Couche 2 (Enclave/Domanial)
# PROBLEME -> LOI -> HOQ -> SEQUENCE -> CODE
#
# PROBLEME  : verifier_secure_enclave_et_position ne fait QUE lire le PCR16 —
#             son extension (pcr_extend) restait un acte manuel, hors MCP,
#             a faire tourner via ctsm_tpm_mac.py dans un terminal separe. Un
#             agent gouverne appele depuis Claude ne pouvait donc jamais
#             atteindre reellement le chemin ACCORDÉ de bout en bout : il
#             dependait d'une intervention humaine hors protocole.
#
# LOI       : toute etape necessaire pour atteindre un verdict ACCORDÉ doit
#             etre elle-meme accessible via un outil gouverne — sinon la
#             chaine de gouvernance a un maillon que l'agent ne controle pas
#             et ne peut pas auditer depuis sa propre execution.
#
# HOQ       : un outil d'extension PCR reel, qui reutilise fidelement la
#             meme logique que ctsm_tpm_mac.py (sha256(ancien || condensat)),
#             ecrit dans le meme fichier ~/.ctsm_pcr_state.json — jamais une
#             logique dupliquee ou divergente.
#
# SEQUENCE  : lire l'etat PCR courant (ou le hash zero si absent) -> combiner
#             ancien_pcr + condensat_hex via sha256 -> ecrire la nouvelle
#             valeur -> la retourner pour qu'elle serve ensuite de
#             pcr16_attendu a verifier_secure_enclave_et_position.
#
# CODE      : etendre_pcr16_reel, ci-dessous.
# ------------------------------------------------------------------------------
@mcp.tool()
def etendre_pcr16_reel(condensat_hex: str, pcr_num: int = 16) -> dict:
    """
    [MUTATION REELLE — ecrit ~/.ctsm_pcr_state.json] Etend reellement un PCR
    emule (par defaut PCR16) en combinant sa valeur actuelle avec un condensat
    fourni, exactement comme ctsm_tpm_mac.py pcr_extend (meme logique :
    sha256(ancien_pcr || condensat)). C'est la seule maniere, via ce serveur
    MCP, d'atteindre reellement le chemin ACCORDÉ de
    verifier_secure_enclave_et_position sans intervention manuelle hors
    protocole.

    Args:
        condensat_hex: condensat hexadecimal a combiner au PCR courant
        pcr_num: numero du PCR a etendre (16 par defaut, comme le reste du sandbox)

    Returns:
        {"ancienneValeur", "nouvelleValeur", "pcrNum"} — nouvelleValeur est la
        valeur a passer ensuite comme pcr16_attendu.
    """
    zero_hash = "0" * 64
    pcrs = {}
    if os.path.exists(PCR_STATE_FILE):
        try:
            with open(PCR_STATE_FILE, "r") as f:
                pcrs = json.load(f)
        except Exception:  # noqa: BLE001
            pcrs = {}
    if not pcrs:
        pcrs = {str(i): zero_hash for i in range(24)}

    ancienne_valeur = pcrs.get(str(pcr_num), zero_hash)
    combine = bytes.fromhex(ancienne_valeur) + bytes.fromhex(condensat_hex)
    nouvelle_valeur = hashlib.sha256(combine).hexdigest()
    pcrs[str(pcr_num)] = nouvelle_valeur

    with open(PCR_STATE_FILE, "w") as f:
        json.dump(pcrs, f, indent=2)

    return {
        "pcrNum": pcr_num,
        "ancienneValeur": ancienne_valeur,
        "condensatCombine": condensat_hex,
        "nouvelleValeur": nouvelle_valeur,
        "message": "PCR étendu réellement, écrit dans ~/.ctsm_pcr_state.json. Utiliser nouvelleValeur comme pcr16_attendu.",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }


# ------------------------------------------------------------------------------
# OUTIL 10 : COUCHE 4 · RESSOURCES/HABILITATION PAR SECURE ENCLAVE (7 sept 2026)
# ------------------------------------------------------------------------------
# Chaine constitutive · Nouvelle couche, distincte des trois deja composees
# dans autoriser_execution_action (Position/Mandat/Enclave-physique)
# PROBLEME -> LOI -> HOQ -> SEQUENCE -> CODE
#
# PROBLEME  : un meme employe peut se presenter a l'agent depuis deux Secure
#             Enclave distincts (PC bureau vs PC personnel). Aucun outil
#             existant ne fait varier la portee des ressources/recherches
#             accessibles selon LEQUEL des deux devices est utilise. Sans
#             cette distinction, un PC personnel pourrait halluciner un
#             acces aux ressources entreprise, ou une portee de recherche
#             plus large que celle reellement autorisee pour ce device.
#
# LOI       : nulle recherche ni ressource ne peut etre accordee au-dela de
#             la portee geographique associee au Secure Enclave utilise pour
#             la demande — jamais au mandat de la personne, jamais a un
#             device par defaut :
#               PC_PERSONNEL -> portee strictement limitee a la zone Abidjan
#                   (meme rayon que le mandat, 25km) ; AUCUN acces aux
#                   ressources de l'entreprise, quel que soit le verdict de
#                   portee.
#               PC_BUREAU (entreprise) -> portee etendue a la Cote d'Ivoire
#                   (approximation geodesique par rayon depuis un centre
#                   national, jamais une correspondance a la frontiere
#                   officielle) ; ressources entreprise accessibles si la
#                   destination est dans cette portee. Les pays limitrophes
#                   (Mali, Benin, entre autres) sont explicitement hors
#                   portee, meme si un point y tombait par erreur de mesure.
#             Les deux portees sont non compensatoires entre elles : un
#             verdict favorable sur l'une ne dispense jamais d'utiliser le
#             device correspondant au bon type.
#
# HOQ       : meme discipline honnete que verifier_mandat_agent_correia —
#             detail de la distance testee, avertissement explicite sur
#             l'approximation geodesique (pas une frontiere officielle),
#             jamais un verdict de conformite aux frontieres nationales
#             presente comme autre chose qu'une approximation par rayon.
#
# SEQUENCE  : recevoir type_device (PC_BUREAU ou PC_PERSONNEL) + destination
#             -> selectionner la zone associee au type de device -> calculer
#             la distance haversine reelle au centre de cette zone ->
#             trancher DANS_PORTEE/HORS_PORTEE -> deriver ressourcesEntreprise
#             (toujours False pour PC_PERSONNEL, jamais deduit du seul
#             verdict de portee pour PC_BUREAU non plus si hors portee).
#
# CODE      : verifier_portee_ressource_device, ci-dessous.
# ------------------------------------------------------------------------------
PORTEE_PC_PERSONNEL_RAYON_KM = 25.0  # meme rayon que le mandat ABIDJAN (ABIDJAN_MANDAT_RAYON_KM, definie plus bas dans OUTIL 6)
CENTRE_COTE_IVOIRE_LAT = 7.539989
CENTRE_COTE_IVOIRE_LON = -5.547080
PORTEE_PC_BUREAU_RAYON_KM = 320.4  # rayon equivalent reel : superficie CI 322 462 km2 (cercle de meme aire)
PAYS_EXPLICITEMENT_HORS_PORTEE = ["Mali", "Benin"]


@mcp.tool()
def verifier_portee_ressource_device(
    type_device: str,
    destination_lat: float,
    destination_lon: float,
) -> dict:
    """
    [GEODESIE REELLE — aucun appel reseau, aucune base de frontieres officielle]
    Couche 4 · Ressources/Habilitation. Teste la portee geographique et
    l'acces aux ressources entreprise associes au Secure Enclave utilise
    pour la demande — jamais au mandat de la personne, jamais un device par
    defaut.

    Limite a ne jamais masquer : ce test compare une distance haversine
    reelle a un centre approximatif, jamais une correspondance a une
    frontiere nationale officielle. Pour PC_BUREAU, le rayon (400km) est une
    approximation large du territoire national, pas un trace de frontiere ;
    un point pourrait tomber DANS_PORTEE par le rayon tout en etant, en
    realite, deja au Mali ou au Benin pres de la frontiere — cette
    approximation est explicitement documentee, jamais presentee comme
    fiable a la frontiere.

    Args:
        type_device: "PC_BUREAU" (entreprise) ou "PC_PERSONNEL"
        destination_lat, destination_lon: destination visee par la recherche
                    ou l'action demandee

    Returns:
        Verdict DANS_PORTEE/HORS_PORTEE, ressourcesEntreprise (toujours False
        pour PC_PERSONNEL), et le detail de la zone testee.
    """
    type_device_norm = (type_device or "").strip().upper()

    if type_device_norm == "PC_PERSONNEL":
        distance_km = compute_haversine(
            destination_lat, destination_lon,
            ECHANTILLON_1_LAT_DOMICILE_ABIDJAN, ECHANTILLON_1_LON_DOMICILE_ABIDJAN,
        ) / 1000.0
        rayon_km = PORTEE_PC_PERSONNEL_RAYON_KM
        dans_portee = distance_km <= rayon_km
        ressources_entreprise = False
        zone_nom = "ABIDJAN (PC_PERSONNEL)"
    elif type_device_norm == "PC_BUREAU":
        distance_km = compute_haversine(
            destination_lat, destination_lon,
            CENTRE_COTE_IVOIRE_LAT, CENTRE_COTE_IVOIRE_LON,
        ) / 1000.0
        rayon_km = PORTEE_PC_BUREAU_RAYON_KM
        dans_portee = distance_km <= rayon_km
        ressources_entreprise = bool(dans_portee)
        zone_nom = "COTE_IVOIRE (PC_BUREAU)"
    else:
        return {
            "verdict": "TYPE_DEVICE_INVALIDE",
            "message": "type_device doit etre 'PC_BUREAU' ou 'PC_PERSONNEL', jamais devine par defaut.",
            "typeDeviceRecu": type_device,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }

    return {
        "verdict": "DANS_PORTEE [SAF_OPEN]" if dans_portee else "HORS_PORTEE [SAF_HOLD]",
        "typeDevice": type_device_norm,
        "zoneTestee": zone_nom,
        "distance_km": round(distance_km, 3),
        "rayon_km": rayon_km,
        "ressourcesEntreprise": ressources_entreprise,
        "paysExplicitementHorsPortee": PAYS_EXPLICITEMENT_HORS_PORTEE,
        "destination_evaluee": {"lat": destination_lat, "lon": destination_lon},
        "message": (
            "Approximation geodesique reelle (haversine) par rayon, jamais une "
            "correspondance a une frontiere nationale officielle."
        ),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "source": "Geodesie locale (aucun appel reseau)",
    }


# ------------------------------------------------------------------------------
# OUTIL 11 : ECRITURE D'INCIDENT D'URGENCE DEPUIS PC_PERSONNEL (7 sept 2026)
# ------------------------------------------------------------------------------
# Chaine constitutive · Exception nommee a la Couche 4 (Ressources/Habilitation)
# PROBLEME -> LOI -> HOQ -> SEQUENCE -> CODE
#
# PROBLEME  : verifier_portee_ressource_device interdit toute ressource
#             entreprise au PC_PERSONNEL, sans exception. Or un employe dont
#             le PC principal tombe en panne doit pouvoir, au minimum,
#             signaler l'incident lui-meme — sinon aucune couche ne permet
#             cette continuite minimale, et l'employe reste sans recours
#             gouverne pour la seule situation ou le PC_PERSONNEL devient
#             pertinent.
#
# LOI       : le PC_PERSONNEL ne peut jamais acceder aux ressources de
#             l'entreprise ni executer d'action generale — SAUF une
#             exception nommee et strictement bornee : ajouter (jamais lire,
#             jamais modifier, jamais supprimer) une entree au registre des
#             incidents de l'entreprise. Cette exception ne verifie jamais
#             techniquement la condition "PC principal hors service" — ce
#             n'est pas le role de ce sandbox (ni RH, ni ICT, ni juridique) —
#             elle est acceptee comme declaration explicite de l'employe, et
#             marquee comme telle dans chaque entree ecrite, sans exception
#             et sans ambiguite.
#
# HOQ       : journal append-only (jamais d'ecrasement d'une entree
#             existante), horodatage reel, tracabilite complete
#             (person_id, type_device, description), jamais un verdict de
#             verification fabrique pour la condition declarative.
#
# SEQUENCE  : recevoir person_id, description_incident,
#             declare_pc_principal_hors_service -> refuser si la
#             declaration n'est pas explicitement True (l'exception ne
#             s'active jamais par defaut) -> lire le registre existant (ou
#             liste vide) -> ajouter une entree horodatee, jamais ecraser
#             les entrees precedentes -> ecrire le registre mis a jour ->
#             retourner l'entree creee avec la mention explicite
#             DECLARATIVE_NON_VERIFIEE.
#
# CODE      : ecrire_incident_urgence_pc_personnel, ci-dessous.
# ------------------------------------------------------------------------------
REGISTRE_INCIDENTS_PATH = os.path.expanduser("~/.ctsm_registre_incidents.json")


ACTION_ID_ECRIRE_INCIDENT = "ecrire_incident_urgence_pc_personnel"


@mcp.tool()
def ecrire_incident_urgence_pc_personnel(
    person_id: str,
    description_incident: str,
    declare_pc_principal_hors_service: bool,
    jeton_effet: Optional[dict] = None,
) -> dict:
    """
    [MUTATION REELLE — ecrit ~/.ctsm_registre_incidents.json, append-only]
    GovernedAgent™ v1.1 (24 sept 2026) — premiere integration reelle de
    YAD_EMET_EFFECTOR. jeton_effet doit venir d'un appel a
    autoriser_execution_action(..., action_id="ecrire_incident_urgence_pc_personnel",
    type_device="PC_PERSONNEL") dont la Porte a reellement ouvert. Sans jeton
    valide, correspondant exactement a ce person_id et a PC_PERSONNEL, non
    deja consomme, non expire (TTL 300s) : aucune ecriture n'a lieu, quelle
    que soit la valeur de declare_pc_principal_hors_service.

    Seule action que la Couche 4 autorise depuis un PC_PERSONNEL : ajouter
    une entree au registre des incidents de l'entreprise. Ne verifie jamais
    techniquement que le PC principal est reellement hors service — ce
    sandbox n'a ni le role ni les moyens de RH/ICT/juridique pour arbitrer
    ca. La declaration de l'employe est acceptee telle quelle, et marquee
    explicitement DECLARATIVE_NON_VERIFIEE dans l'entree ecrite.

    Args:
        person_id: identifiant de l'acteur (ex. celui retourne par
                    inscrire_acteur_abidjan)
        description_incident: texte libre decrivant l'incident
        declare_pc_principal_hors_service: doit etre explicitement True pour
                    que l'ecriture ait lieu ; jamais suppose par defaut
        jeton_effet: jeton emis par autoriser_execution_action, obligatoire

    Returns:
        {"statut": "INCIDENT_ENREGISTRE", "entree": {...}} si accepte, ou
        {"statut": "REFUSE", "raison": ...} si la declaration n'est pas
        explicitement True OU si le jeton d'effet est absent/invalide.
    """
    verification_jeton = verifier_et_consommer_jeton_effet(
        jeton_effet, ACTION_ID_ECRIRE_INCIDENT, person_id, "PC_PERSONNEL", "PUBLIC_GOVERNED_ACTION",
    )
    if not verification_jeton["autorise"]:
        return {
            "statut": "REFUSE",
            "raison": f"JETON_EFFET_REFUSE : {verification_jeton['raison']}",
            "message": "Aucune ecriture n'a lieu sans jeton d'effet valide, unique et non expire (YAD_EMET_EFFECTOR).",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }

    if declare_pc_principal_hors_service is not True:
        return {
            "statut": "REFUSE",
            "raison": (
                "L'exception PC_PERSONNEL pour le registre des incidents ne "
                "s'active jamais par defaut : declare_pc_principal_hors_service "
                "doit etre explicitement True."
            ),
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }

    registre = []
    if os.path.exists(REGISTRE_INCIDENTS_PATH):
        try:
            with open(REGISTRE_INCIDENTS_PATH, "r") as f:
                registre = json.load(f)
        except Exception:  # noqa: BLE001
            registre = []

    entree = {
        "personId": person_id,
        "typeDevice": "PC_PERSONNEL",
        "descriptionIncident": description_incident,
        "declarationPcPrincipalHorsService": "DECLARATIVE_NON_VERIFIEE",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }
    registre.append(entree)

    with open(REGISTRE_INCIDENTS_PATH, "w") as f:
        json.dump(registre, f, indent=2, ensure_ascii=False)

    return {
        "statut": "INCIDENT_ENREGISTRE",
        "entree": entree,
        "totalIncidents": len(registre),
        "message": (
            "Entree ajoutee au registre, jamais ecrasee. La condition de "
            "panne du PC principal est declarative, non verifiee par ce "
            "sandbox."
        ),
    }


# ------------------------------------------------------------------------------
# OUTIL 12 : REGISTRE EMPLOYE GOUVERNE · COUCHE 5 RESSOURCES NOMINATIVES (7 sept 2026)
# ------------------------------------------------------------------------------
# Chaine constitutive · Nouvelle couche, distincte de la Couche 4
# PROBLEME -> LOI -> HOQ -> SEQUENCE -> CODE
#
# PROBLEME  : verifier_portee_ressource_device ne connait que deux
#             categories globales par device ("ressources entreprise"
#             oui/non), jamais une liste nominative par employe. Une fiche
#             comme celle de Ben Nun (Fonction, Mandat, ressources
#             accessibles precises comme "Dossier Projet R&D — projet
#             OmeHai") reste donc une declaration en texte, jamais verifiable
#             par un outil — aucun registre persistant ne l'enregistre, et
#             aucune fonction ne peut repondre "cet employe a-t-il acces a
#             cette ressource precise".
#
# LOI       : toute ressource nominative declaree pour un employe doit etre
#             enregistree dans un registre persistant et interrogeable par
#             person_id — jamais devinee, jamais supposee depuis la seule
#             Fonction ou le seul Mandat. Un employe absent du registre, ou
#             une ressource non explicitement listee pour lui, ne peut
#             jamais recevoir un verdict d'acces favorable par defaut.
#
# HOQ       : meme discipline que le registre des incidents (append/merge
#             traceable, jamais un verdict fabrique), et meme discipline que
#             la fiche entreprise/employe deja etablie en conversation —
#             jamais une reformulation plus forte que ce qui a ete
#             explicitement declare et enregistre.
#
# SEQUENCE  : inscrire_employe_gouverne recoit person_id + champs de fiche
#             (nom, fonction, mandat_zone_nom, ressources_accessibles,
#             secure enclaves) -> ecrit/fusionne l'entree dans
#             ~/.ctsm_registre_employes.json, jamais un ecrasement complet
#             du registre. verifier_acces_ressource_employe recoit person_id
#             + ressource_demandee -> lit le registre -> EMPLOYE_INCONNU si
#             absent, sinon ACCES_ACCORDE seulement si la ressource figure
#             explicitement dans sa liste, sinon ACCES_REFUSE.
#
# CODE      : inscrire_employe_gouverne + verifier_acces_ressource_employe,
#             ci-dessous.
# ------------------------------------------------------------------------------
REGISTRE_EMPLOYES_PATH = os.path.expanduser("~/.ctsm_registre_employes.json")


def _lire_registre_employes() -> dict:
    if os.path.exists(REGISTRE_EMPLOYES_PATH):
        try:
            with open(REGISTRE_EMPLOYES_PATH, "r") as f:
                return json.load(f)
        except Exception:  # noqa: BLE001
            return {}
    return {}


@mcp.tool()
def inscrire_employe_gouverne(
    person_id: str,
    nom: str,
    fonction: str,
    mandat_zone_nom: str,
    ressources_accessibles: list,
    secure_enclave_pc_bureau: str = None,
    secure_enclave_pc_personnel: str = None,
) -> dict:
    """
    [MUTATION REELLE — ecrit ~/.ctsm_registre_employes.json]
    Enregistre ou met a jour la fiche gouvernee d'un employe : identite,
    fonction, zone de mandat (doit correspondre a un nom dans
    ZONES_MANDAT_CORREIA), Secure Enclave par device (optionnels, "a
    provisionner" si absents), et la liste nominative des ressources
    accessibles. Ne verifie jamais que la ressource elle-meme existe
    reellement (Dossier RH, Dossier Registre, etc.) — ce registre consigne
    la declaration, il ne la valide pas contre un systeme de fichiers reel.

    Args:
        person_id: identifiant reel de l'acteur (ex. retourne par
                    inscrire_acteur_abidjan)
        nom: nom de l'employe
        fonction: fonction declaree (ex. "Business Developer")
        mandat_zone_nom: nom de la zone de mandat associee (ex. "ABIDJAN")
        ressources_accessibles: liste de noms de ressources accessibles
        secure_enclave_pc_bureau: condensat ou identifiant du PC bureau,
                    None si a provisionner
        secure_enclave_pc_personnel: condensat ou identifiant du PC
                    personnel, None si a provisionner

    Returns:
        {"statut": "EMPLOYE_ENREGISTRE", "fiche": {...}}
    """
    registre = _lire_registre_employes()
    fiche = {
        "personId": person_id,
        "nom": nom,
        "fonction": fonction,
        "mandatZoneNom": mandat_zone_nom,
        "ressourcesAccessibles": list(ressources_accessibles or []),
        "secureEnclavePcBureau": secure_enclave_pc_bureau or "A_PROVISIONNER",
        "secureEnclavePcPersonnel": secure_enclave_pc_personnel or "A_PROVISIONNER",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }
    registre[person_id] = fiche

    with open(REGISTRE_EMPLOYES_PATH, "w") as f:
        json.dump(registre, f, indent=2, ensure_ascii=False)

    return {
        "statut": "EMPLOYE_ENREGISTRE",
        "fiche": fiche,
        "message": "Fiche ecrite dans le registre persistant, jamais validee contre un systeme de fichiers reel.",
    }


# ------------------------------------------------------------------------------
# OUTIL : AJOUT NOMINATIF D'UNE RESSOURCE (9 sept 2026)
# ------------------------------------------------------------------------------
# Chaine constitutive · PROBLEME -> LOI -> HOQ -> SEQUENCE -> CODE
#
# PROBLEME  : inscrire_employe_gouverne re-ecrit la fiche entiere a chaque
#             appel, secure_enclave_pc_bureau/personnel inclus. Ajouter UNE
#             ressource a une fiche existante exige donc de repasser ces
#             deux champs, jamais exposes en clair par conception (chantier
#             Secure Enclave<->Device, 9 sept 2026) — impossible sans
#             risquer d'ecraser silencieusement un provisioning deja
#             confirme.
#
# LOI       : ajouter une ressource a une fiche ne doit jamais toucher aux
#             autres champs de cette fiche — jamais un effet de bord sur
#             l'identite, le mandat, ou le rattachement device deja etabli.
#
# HOQ       : lecture de la fiche existante -> ajout de la ressource
#             uniquement si absente (idempotent, jamais de doublon) ->
#             ecriture de la fiche complete inchangee sauf ce seul champ.
#             Employe absent = refus explicite, jamais une creation
#             implicite de fiche.
#
# SEQUENCE  : ajouter_ressource_employe recoit person_id + ressource_nom ->
#             lit le registre -> EMPLOYE_INCONNU si absent -> ajoute
#             ressource_nom a ressourcesAccessibles si absente -> ecrit ->
#             retourne la liste a jour.
#
# CODE      : ajouter_ressource_employe, ci-dessous.
# ------------------------------------------------------------------------------
@mcp.tool()
def ajouter_ressource_employe(person_id: str, ressource_nom: str) -> dict:
    """
    [MUTATION REELLE — ecrit ~/.ctsm_registre_employes.json]
    Ajoute une ressource nominative a la fiche existante d'un employe, sans
    jamais toucher aux autres champs (identite, mandat, secure enclave par
    device). Idempotent : n'ajoute pas de doublon si la ressource figure
    deja dans ressourcesAccessibles.

    Args:
        person_id: identifiant de l'employe deja enregistre
        ressource_nom: nom exact de la ressource a ajouter

    Returns:
        {"statut": "RESSOURCE_AJOUTEE"|"RESSOURCE_DEJA_PRESENTE"|"EMPLOYE_INCONNU", "ressourcesAccessibles": [...]}
    """
    registre = _lire_registre_employes()
    fiche = registre.get(person_id)
    if fiche is None:
        return {
            "statut": "EMPLOYE_INCONNU",
            "personId": person_id,
            "message": "Aucune fiche enregistree pour ce person_id — inscrire_employe_gouverne doit precéder cet ajout.",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }

    ressources = fiche.get("ressourcesAccessibles", [])
    if ressource_nom in ressources:
        return {
            "statut": "RESSOURCE_DEJA_PRESENTE",
            "personId": person_id,
            "ressourcesAccessibles": ressources,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }

    ressources.append(ressource_nom)
    fiche["ressourcesAccessibles"] = ressources
    registre[person_id] = fiche

    with open(REGISTRE_EMPLOYES_PATH, "w") as f:
        json.dump(registre, f, indent=2, ensure_ascii=False)

    return {
        "statut": "RESSOURCE_AJOUTEE",
        "personId": person_id,
        "ressourcesAccessibles": ressources,
        "message": "Ressource ajoutee sans toucher aux autres champs de la fiche.",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }


@mcp.tool()
def verifier_acces_ressource_employe(person_id: str, ressource_demandee: str) -> dict:
    """
    [LECTURE REELLE — ~/.ctsm_registre_employes.json, aucun appel reseau]
    Couche 5 · Ressources nominatives. Teste si un employe enregistre a
    explicitement acces a une ressource precise — jamais deduit de sa
    Fonction ou de son Mandat, jamais un verdict favorable par defaut pour
    un employe absent du registre.

    Args:
        person_id: identifiant de l'employe
        ressource_demandee: nom exact de la ressource demandee (doit
                    correspondre a une entree de ressourcesAccessibles)

    Returns:
        Verdict ACCES_ACCORDE / ACCES_REFUSE / EMPLOYE_INCONNU.
    """
    registre = _lire_registre_employes()
    fiche = registre.get(person_id)

    if fiche is None:
        return {
            "verdict": "EMPLOYE_INCONNU",
            "personId": person_id,
            "message": "Aucune fiche enregistree pour ce person_id — aucun acces ne peut etre suppose par defaut.",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }

    ressources = fiche.get("ressourcesAccessibles", [])
    acces_accorde = ressource_demandee in ressources

    return {
        "verdict": "ACCES_ACCORDE [SAF_OPEN]" if acces_accorde else "ACCES_REFUSE [SAF_HOLD]",
        "personId": person_id,
        "nomEmploye": fiche.get("nom"),
        "ressourceDemandee": ressource_demandee,
        "ressourcesAccessibles": ressources,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }


# ------------------------------------------------------------------------------
# OUTIL : RATTACHEMENT IDENTITE<->DEVICE (SECURE ENCLAVE EMPLOYE) (9 sept 2026)
# ------------------------------------------------------------------------------
# Chaine constitutive · Rattachement Identite<->Device
# PROBLEME -> LOI -> HOQ -> SEQUENCE -> CODE
#
# PROBLEME  : les champs secure_enclave_pc_bureau et secure_enclave_pc_personnel
#             de la fiche employee existent depuis inscrire_employe_gouverne
#             mais restent vides ("A_PROVISIONNER"). Aucun outil ne permet de
#             les renseigner apres coup, ni de verifier qu'un device reel
#             correspond effectivement a l'un de ces champs. Le registre des
#             employes et le registre PCR16 (~/.ctsm_pcr_state.json) coexistent
#             sans lien entre eux — la chaine identite->machine n'existe pas.
#
# LOI       : une revendication de presence d'un employe sur un device ne
#             vaut que si elle est declaree explicitement et verifiee contre
#             l'etat reel du device, jamais deduite ni par defaut. Un device
#             n'est rattache qu'a une seule categorie a la fois (PC_BUREAU ou
#             PC_PERSONNEL, jamais les deux simultanement pour la meme fiche).
#             Declarer n'est pas confirmer.
#
# HOQ       : le provisioning est un acte humain explicite (type_device
#             fourni explicitement, jamais devine depuis IP/hostname/MAC).
#             L'identifiant Secure Enclave derive de ce qui existe deja
#             (_get_host_mac() + _lire_pcr16(), meme logique que
#             verifier_secure_enclave_et_position) — jamais un secret
#             invente ni le PCR16 duplique en clair. La lecture retourne un
#             verdict explicite (CONFIRME / NON_PROVISIONNE / DIVERGENT),
#             jamais un secret brut expose. Un champ deja rempli n'est
#             jamais ecrase silencieusement — le reprovisioning exige
#             forcer=True, trace explicitement.
#
# SEQUENCE  : provisionner_secure_enclave_employe recoit person_id +
#             type_device ("PC_BUREAU"/"PC_PERSONNEL") -> derive
#             l'identifiant depuis _get_host_mac()+_lire_pcr16() -> refuse
#             d'ecraser un champ deja rempli sauf forcer=True -> ecrit dans
#             ~/.ctsm_registre_employes.json. verifier_secure_enclave_employe
#             recoit person_id -> derive l'identifiant du device courant ->
#             le compare aux deux champs stockes -> retourne un verdict
#             explicite, jamais une confirmation par defaut si vide.
#
# CODE      : provisionner_secure_enclave_employe +
#             verifier_secure_enclave_employe, ci-dessous.
# ------------------------------------------------------------------------------
def _deriver_identifiant_secure_enclave() -> str:
    """
    Derive un identifiant Secure Enclave stable pour CE device a partir de
    ce qui existe deja : MAC hote reelle (_get_host_mac()) et PCR16 courant
    (_lire_pcr16()) — jamais un secret invente, jamais le PCR16 duplique en
    clair (seul son hash combine est stocke).
    """
    mac = _get_host_mac()
    pcr16 = _lire_pcr16()
    combine = f"{mac}|{pcr16}".encode("utf-8")
    return hashlib.sha256(combine).hexdigest()


TYPES_DEVICE_VALIDES = ("PC_BUREAU", "PC_PERSONNEL")

_CHAMP_PAR_TYPE_DEVICE = {
    "PC_BUREAU": "secureEnclavePcBureau",
    "PC_PERSONNEL": "secureEnclavePcPersonnel",
}


@mcp.tool()
def provisionner_secure_enclave_employe(
    person_id: str,
    type_device: str,
    forcer: bool = False,
) -> dict:
    """
    [MUTATION REELLE — ecrit ~/.ctsm_registre_employes.json + appelle
    reellement la puce Secure Enclave via AgentProofApp]
    REMPLACEMENT REEL (10 sept 2026, Piste Silicium) : declare explicitement
    qu'un device (type_device: "PC_BUREAU" ou "PC_PERSONNEL") correspond a
    l'employe person_id, en provisionnant une cle Secure Enclave MATERIELLE
    reelle sur CE Mac — la cle privee ne quitte jamais la puce, seule la cle
    publique (base64, format X9.63 non compresse) est stockee. Remplace
    l'ancienne derivation logicielle sha256(mac|pcr16) — _deriver_identifiant_secure_enclave
    est conservee dans le fichier a titre d'archive mais n'est plus appelee ici.

    Refuse d'ecraser un champ deja rempli sauf si forcer=True (reprovisioning
    = acte trace explicitement, jamais une reecriture silencieuse).

    Args:
        person_id: identifiant de l'employe deja enregistre
        type_device: "PC_BUREAU" ou "PC_PERSONNEL", jamais devine
        forcer: True pour reprovisionner explicitement un champ deja rempli

    Returns:
        {"statut": "PROVISIONNE"|"DEJA_PROVISIONNE_SANS_FORCER"|"EMPLOYE_INCONNU"|
                    "TYPE_DEVICE_INVALIDE"|"ECHEC_SECURE_ENCLAVE", ...}
    """
    if type_device not in TYPES_DEVICE_VALIDES:
        return {
            "statut": "TYPE_DEVICE_INVALIDE",
            "typeDeviceRecu": type_device,
            "typesValides": list(TYPES_DEVICE_VALIDES),
            "message": "type_device doit etre explicitement PC_BUREAU ou PC_PERSONNEL, jamais devine.",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }

    registre = _lire_registre_employes()
    fiche = registre.get(person_id)
    if fiche is None:
        return {
            "statut": "EMPLOYE_INCONNU",
            "personId": person_id,
            "message": "Aucune fiche enregistree pour ce person_id — inscrire_employe_gouverne doit precéder le provisioning.",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }

    champ = _CHAMP_PAR_TYPE_DEVICE[type_device]
    valeur_actuelle = fiche.get(champ, "A_PROVISIONNER")

    if valeur_actuelle and valeur_actuelle != "A_PROVISIONNER" and not forcer:
        return {
            "statut": "DEJA_PROVISIONNE_SANS_FORCER",
            "personId": person_id,
            "champ": champ,
            "message": "Ce champ est deja provisionne. Reprovisionner exige forcer=True, acte trace explicitement — jamais une reecriture silencieuse.",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }

    appel = _appeler_binaire_secure_enclave("provision")
    if not appel["ok"]:
        return {
            "statut": "ECHEC_SECURE_ENCLAVE",
            "personId": person_id,
            "detailAppel": appel,
            "message": "L'appel au binaire Secure Enclave a echoue — voir detailAppel.",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }
    lignes = appel["stdout"].splitlines()
    if len(lignes) < 2 or lignes[0] not in ("PROVISIONNE", "DEJA_PROVISIONNE"):
        return {
            "statut": "ECHEC_SECURE_ENCLAVE",
            "personId": person_id,
            "detailAppel": appel,
            "message": "Sortie inattendue du binaire Secure Enclave.",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }
    identifiant = lignes[1]

    ancienne_valeur = valeur_actuelle
    fiche[champ] = identifiant
    fiche["timestamp_utc"] = datetime.now(timezone.utc).isoformat()
    registre[person_id] = fiche

    with open(REGISTRE_EMPLOYES_PATH, "w") as f:
        json.dump(registre, f, indent=2, ensure_ascii=False)

    return {
        "statut": "PROVISIONNE",
        "personId": person_id,
        "champ": champ,
        "typeDevice": type_device,
        "reprovisionnementTrace": bool(forcer and ancienne_valeur and ancienne_valeur != "A_PROVISIONNER"),
        "ancienneValeur": ancienne_valeur,
        "message": "Cle Secure Enclave materielle reelle provisionnee (cle privee jamais extraite de la puce), ecrite dans la fiche employee.",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }


@mcp.tool()
def verifier_secure_enclave_employe(person_id: str) -> dict:
    """
    [LECTURE + APPEL REEL — interroge la puce Secure Enclave de CE device
    (pubkey), puis exige une preuve challenge/signature avant de confirmer]
    REMPLACEMENT REEL (10 sept 2026, Piste Silicium) : compare la cle
    publique Secure Enclave reelle du device courant a celle stockee dans la
    fiche de person_id (les deux champs testes, secureEnclavePcBureau et
    secureEnclavePcPersonnel), PUIS exige une preuve cryptographique reelle
    (nonce aleatoire neuf signe par la puce, verifie avec cryptography) avant
    de confirmer — jamais une simple egalite de chaines suffisante. Ne
    confirme jamais par defaut si le champ est vide, et n'expose jamais la
    cle privee — seulement un verdict.

    Args:
        person_id: identifiant de l'employe

    Returns:
        Verdict "CONFIRME_PC_BUREAU" / "CONFIRME_PC_PERSONNEL" /
        "DIVERGENT" / "NON_PROVISIONNE" / "EMPLOYE_INCONNU" /
        "ECHEC_SECURE_ENCLAVE".
    """
    registre = _lire_registre_employes()
    fiche = registre.get(person_id)
    if fiche is None:
        return {
            "verdict": "EMPLOYE_INCONNU",
            "personId": person_id,
            "message": "Aucune fiche enregistree pour ce person_id.",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }

    valeur_bureau = fiche.get("secureEnclavePcBureau", "A_PROVISIONNER")
    valeur_personnel = fiche.get("secureEnclavePcPersonnel", "A_PROVISIONNER")
    bureau_provisionne = bool(valeur_bureau and valeur_bureau != "A_PROVISIONNER")
    personnel_provisionne = bool(valeur_personnel and valeur_personnel != "A_PROVISIONNER")

    if not bureau_provisionne and not personnel_provisionne:
        return {
            "verdict": "NON_PROVISIONNE",
            "personId": person_id,
            "nomEmploye": fiche.get("nom"),
            "bureauProvisionne": False,
            "personnelProvisionne": False,
            "message": "Aucun device provisionne pour cet employe.",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }

    appel_pubkey = _appeler_binaire_secure_enclave("pubkey")
    if not appel_pubkey["ok"]:
        return {
            "verdict": "ECHEC_SECURE_ENCLAVE",
            "personId": person_id,
            "detailAppel": appel_pubkey,
            "message": "CE device n'a pas de cle Secure Enclave provisionnee, ou l'appel a echoue.",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }
    cle_publique_courante = appel_pubkey["stdout"].strip()

    if bureau_provisionne and cle_publique_courante == valeur_bureau:
        type_device_matche = "PC_BUREAU"
    elif personnel_provisionne and cle_publique_courante == valeur_personnel:
        type_device_matche = "PC_PERSONNEL"
    else:
        return {
            "verdict": "DIVERGENT",
            "personId": person_id,
            "nomEmploye": fiche.get("nom"),
            "bureauProvisionne": bureau_provisionne,
            "personnelProvisionne": personnel_provisionne,
            "message": "La cle Secure Enclave de CE device ne correspond a aucun champ enregistre pour cet employe.",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }

    nonce = secrets.token_bytes(32)
    nonce_b64 = base64.b64encode(nonce)
    appel_sign = _appeler_binaire_secure_enclave("sign", entree_stdin=nonce_b64)
    if not appel_sign["ok"]:
        return {
            "verdict": "ECHEC_SECURE_ENCLAVE",
            "personId": person_id,
            "detailAppel": appel_sign,
            "message": "La cle publique correspond mais la signature du defi a echoue.",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }
    try:
        cle_brute = base64.b64decode(cle_publique_courante)
        cle_publique = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), cle_brute)
        signature_der = base64.b64decode(appel_sign["stdout"].strip())
        cle_publique.verify(signature_der, nonce, ec.ECDSA(hashes.SHA256()))
        signature_valide = True
    except InvalidSignature:
        signature_valide = False
    except Exception as exc:  # noqa: BLE001
        return {
            "verdict": "ECHEC_SECURE_ENCLAVE",
            "personId": person_id,
            "erreurVerification": str(exc),
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }

    if not signature_valide:
        return {
            "verdict": "DIVERGENT",
            "personId": person_id,
            "nomEmploye": fiche.get("nom"),
            "bureauProvisionne": bureau_provisionne,
            "personnelProvisionne": personnel_provisionne,
            "message": "La cle publique correspondait mais la preuve challenge/signature a echoue — divergence.",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }

    verdict = "CONFIRME_PC_BUREAU" if type_device_matche == "PC_BUREAU" else "CONFIRME_PC_PERSONNEL"
    return {
        "verdict": verdict,
        "personId": person_id,
        "nomEmploye": fiche.get("nom"),
        "bureauProvisionne": bureau_provisionne,
        "personnelProvisionne": personnel_provisionne,
        "message": "Preuve challenge/signature materielle reelle (nonce neuf, jamais rejouable) — jamais un secret brut expose.",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }



# ------------------------------------------------------------------------------
# OUTIL 12bis : SECURE ENCLAVE REEL · CHALLENGE/SIGNATURE MATERIELLE (10 sept 2026)
# ------------------------------------------------------------------------------
# Chaine constitutive · Piste Silicium
# PROBLEME -> LOI -> HOQ -> SEQUENCE -> CODE
#
# PROBLEME  : l'identifiant Secure Enclave utilise jusqu'ici par
#             provisionner_secure_enclave_employe / verifier_secure_enclave_employe
#             est un hash logiciel (sha256(mac|pcr16)) — verifiable, mais
#             recalculable par quiconque connait mac+pcr16. Aucune preuve
#             materielle reelle n'existe encore.
#
# LOI       : l'identite d'un device gouverne doit pouvoir s'appuyer sur une
#             preuve que seule la puce Secure Enclave de CE Mac peut produire
#             — une signature ECDSA d'un defi (nonce) aleatoire, jamais
#             rejouable, verifiee contre la cle publique enregistree. La cle
#             privee ne quitte jamais la puce ; seule la cle publique est
#             stockee cote serveur.
#
# HOQ       : le binaire AgentProofApp.app (bundle macOS reel, Team ID +
#             Bundle ID signes, capacite Keychain Sharing) est le seul point
#             d'acces au Secure Enclave — jamais reimplemente en Python.
#             provisionner_secure_enclave_reel_employe stocke la cle publique
#             dans des champs DISTINCTS (secureEnclaveReelPcBureau /
#             secureEnclaveReelPcPersonnel) — jamais un ecrasement des champs
#             sha256(mac|pcr16) existants, coexistence explicite pendant la
#             transition. verifier_secure_enclave_reel_employe genere un
#             nonce aleatoire neuf a CHAQUE appel (jamais reutilise), jamais
#             une comparaison de secret statique.
#
# SEQUENCE  : provisionner_secure_enclave_reel_employe recoit person_id +
#             type_device -> appelle AgentProofApp provision -> stocke la cle
#             publique retournee. verifier_secure_enclave_reel_employe recoit
#             person_id + type_device -> genere un nonce aleatoire -> appelle
#             AgentProofApp sign avec le nonce sur stdin -> verifie la
#             signature avec la cle publique stockee (cryptography, ECDSA
#             P-256 / SHA-256) -> retourne un verdict explicite.
#
# CODE      : _chemin_binaire_secure_enclave, _appeler_binaire_secure_enclave,
#             provisionner_secure_enclave_reel_employe,
#             verifier_secure_enclave_reel_employe, ci-dessous.
# ------------------------------------------------------------------------------
_CHAMP_REEL_PAR_TYPE_DEVICE = {
    "PC_BUREAU": "secureEnclaveReelPcBureau",
    "PC_PERSONNEL": "secureEnclaveReelPcPersonnel",
}


def _chemin_binaire_secure_enclave() -> str:
    """
    Chemin vers le client applicatif signe CTSMEnclaveClient. Ce client ne
    detient aucune cle : il appelle l'agent local AgentProof par XPC, lequel
    relaie vers le Secure Enclave. Le bundle est stocke dans bin/, jamais dans
    DerivedData Xcode, qui est temporaire.
    """
    racine = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(
        racine,
        "bin",
        "CTSMEnclaveClient.app",
        "Contents",
        "MacOS",
        "CTSMEnclaveClient",
    )


def _appeler_binaire_secure_enclave(commande: str, entree_stdin: Optional[bytes] = None) -> dict:
    """
    Appelle le client applicatif signe (pubkey/sign). Il ne masque jamais un
    echec et retourne stdout/stderr bruts, afin que l'appelant produise un
    verdict explicite. Le provisioning reste exclusivement dans AgentProofApp.
    """
    chemin = _chemin_binaire_secure_enclave()
    if not os.path.exists(chemin):
        return {
            "ok": False,
            "erreur": "BINAIRE_INTROUVABLE",
            "cheminAttendu": chemin,
        }
    try:
        resultat = subprocess.run(
            [chemin, commande],
            input=entree_stdin,
            capture_output=True,
            timeout=15,
        )
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "erreur": f"EXCEPTION_SUBPROCESS: {exc}"}

    stdout = resultat.stdout.decode("utf-8", errors="replace").strip()
    stderr = resultat.stderr.decode("utf-8", errors="replace").strip()
    return {
        "ok": resultat.returncode == 0,
        "codeRetour": resultat.returncode,
        "stdout": stdout,
        "stderr": stderr,
    }


@mcp.tool()
def provisionner_secure_enclave_reel_employe(
    person_id: str,
    type_device: str,
    forcer: bool = False,
) -> dict:
    """
    [MUTATION REELLE — ecrit ~/.ctsm_registre_employes.json + lit la cle
    publique depuis AgentProofApp]
    Enregistre, pour person_id et CE device, la cle materielle deja
    provisionnee localement dans AgentProofApp. CTSM ne cree jamais la cle :
    la creation exige l'action locale dans l'application signee. La cle
    privee ne quitte jamais le Secure Enclave ; seule la cle publique base64
    est inscrite dans un champ distinct des champs sha256(mac|pcr16).

    Args:
        person_id: identifiant de l'employe deja enregistre
        type_device: "PC_BUREAU" ou "PC_PERSONNEL", jamais devine
        forcer: True pour reprovisionner explicitement un champ deja rempli

    Returns:
        {"statut": "CLE_AGENTPROOF_ENREGISTREE"|"DEJA_PROVISIONNE_SANS_FORCER"|"EMPLOYE_INCONNU"|
                    "TYPE_DEVICE_INVALIDE"|"ECHEC_SECURE_ENCLAVE", ...}
    """
    if type_device not in TYPES_DEVICE_VALIDES:
        return {
            "statut": "TYPE_DEVICE_INVALIDE",
            "typeDeviceRecu": type_device,
            "typesValides": list(TYPES_DEVICE_VALIDES),
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }

    registre = _lire_registre_employes()
    fiche = registre.get(person_id)
    if fiche is None:
        return {
            "statut": "EMPLOYE_INCONNU",
            "personId": person_id,
            "message": "Aucune fiche enregistree pour ce person_id — inscrire_employe_gouverne doit precéder le provisioning.",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }

    champ = _CHAMP_REEL_PAR_TYPE_DEVICE[type_device]
    valeur_actuelle = fiche.get(champ, "A_PROVISIONNER")
    if valeur_actuelle and valeur_actuelle != "A_PROVISIONNER" and not forcer:
        return {
            "statut": "DEJA_PROVISIONNE_SANS_FORCER",
            "personId": person_id,
            "champ": champ,
            "message": "Ce champ est deja provisionne. Reprovisionner exige forcer=True.",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }

    appel = _appeler_binaire_secure_enclave("pubkey")
    if not appel["ok"]:
        return {
            "statut": "ECHEC_SECURE_ENCLAVE",
            "personId": person_id,
            "detailAppel": appel,
            "message": "L'appel au binaire Secure Enclave a echoue — voir detailAppel.",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }

    lignes = appel["stdout"].splitlines()
    if len(lignes) != 1 or not lignes[0]:
        return {
            "statut": "ECHEC_SECURE_ENCLAVE",
            "personId": person_id,
            "detailAppel": appel,
            "message": "Sortie inattendue du binaire Secure Enclave.",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }
    cle_publique_b64 = lignes[0]

    ancienne_valeur = valeur_actuelle
    fiche[champ] = cle_publique_b64
    fiche["timestamp_utc"] = datetime.now(timezone.utc).isoformat()
    registre[person_id] = fiche
    with open(REGISTRE_EMPLOYES_PATH, "w") as f:
        json.dump(registre, f, indent=2, ensure_ascii=False)

    return {
        "statut": "CLE_AGENTPROOF_ENREGISTREE",
        "personId": person_id,
        "champ": champ,
        "typeDevice": type_device,
        "clePublique": cle_publique_b64,
        "reprovisionnementTrace": bool(forcer and ancienne_valeur and ancienne_valeur != "A_PROVISIONNER"),
        "message": "Cle publique AgentProof enregistree apres lecture du Secure Enclave local ; la cle privee ne quitte jamais la puce.",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }


@mcp.tool()
def verifier_secure_enclave_reel_employe(person_id: str, type_device: str) -> dict:
    """
    [LECTURE + APPEL REEL — genere un nonce aleatoire neuf, le fait signer
    par la puce Secure Enclave via AgentProofApp, verifie la signature]
    Verifie CRYPTOGRAPHIQUEMENT que CE device possede bien la cle Secure
    Enclave enregistree pour person_id/type_device — pas une comparaison de
    hash statique, une preuve challenge/signature reelle avec un nonce neuf
    a chaque appel (jamais rejouable).

    Args:
        person_id: identifiant de l'employe
        type_device: "PC_BUREAU" ou "PC_PERSONNEL"

    Returns:
        {"verdict": "SIGNATURE_VALIDE"|"SIGNATURE_INVALIDE"|"NON_PROVISIONNE"|
                     "EMPLOYE_INCONNU"|"TYPE_DEVICE_INVALIDE"|"ECHEC_SECURE_ENCLAVE", ...}
    """
    if type_device not in TYPES_DEVICE_VALIDES:
        return {
            "verdict": "TYPE_DEVICE_INVALIDE",
            "typeDeviceRecu": type_device,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }

    registre = _lire_registre_employes()
    fiche = registre.get(person_id)
    if fiche is None:
        return {
            "verdict": "EMPLOYE_INCONNU",
            "personId": person_id,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }

    champ = _CHAMP_REEL_PAR_TYPE_DEVICE[type_device]
    cle_publique_b64 = fiche.get(champ, "A_PROVISIONNER")
    if not cle_publique_b64 or cle_publique_b64 == "A_PROVISIONNER":
        return {
            "verdict": "NON_PROVISIONNE",
            "personId": person_id,
            "champ": champ,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }

    nonce = secrets.token_bytes(32)
    nonce_b64 = base64.b64encode(nonce)

    appel = _appeler_binaire_secure_enclave("sign", entree_stdin=nonce_b64)
    if not appel["ok"]:
        return {
            "verdict": "ECHEC_SECURE_ENCLAVE",
            "personId": person_id,
            "detailAppel": appel,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }

    signature_b64 = appel["stdout"].strip()
    try:
        cle_brute = base64.b64decode(cle_publique_b64)
        cle_publique = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), cle_brute)
        signature_der = base64.b64decode(signature_b64)
        cle_publique.verify(signature_der, nonce, ec.ECDSA(hashes.SHA256()))
        signature_valide = True
    except InvalidSignature:
        signature_valide = False
    except Exception as exc:  # noqa: BLE001
        return {
            "verdict": "ECHEC_SECURE_ENCLAVE",
            "personId": person_id,
            "erreurVerification": str(exc),
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }

    return {
        "verdict": "SIGNATURE_VALIDE" if signature_valide else "SIGNATURE_INVALIDE",
        "personId": person_id,
        "typeDevice": type_device,
        "nomEmploye": fiche.get("nom"),
        "message": "Preuve challenge/signature materielle reelle — nonce neuf, jamais rejouable.",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }


# ------------------------------------------------------------------------------
# OUTIL 12ter : RETRAIT DU RATTACHEMENT SECURE ENCLAVE REEL (13 sept 2026)
# ------------------------------------------------------------------------------
# Chaine constitutive · Test de revocation et d'unicite
# PROBLEME -> LOI -> HOQ -> SEQUENCE -> CODE
#
# PROBLEME  : provisionner_secure_enclave_reel_employe sait ecrire et
#             reecrire (avec forcer=True) un champ secureEnclaveReel*, mais
#             rien ne sait le retirer explicitement. Sans retrait possible,
#             l'unicite d'un rattachement Identite<->Device ne peut jamais
#             etre prouvee par l'absence — seulement supposee.
#
# LOI       : un rattachement retire doit produire un effet reel et
#             immediatement observable : verifier_secure_enclave_reel_employe
#             sur le meme person_id/type_device doit ensuite repondre
#             NON_PROVISIONNE, jamais un etat ambigu ou un cache silencieux.
#
# HOQ       : le retrait reecrit le champ a "A_PROVISIONNER" (jamais une
#             suppression de la fiche entiere, jamais un effet de bord sur
#             les autres champs). Employe absent ou champ deja vide = refus
#             explicite, jamais un succes simule.
#
# SEQUENCE  : retirer_secure_enclave_reel_employe recoit person_id +
#             type_device -> lit le registre -> EMPLOYE_INCONNU si absent ->
#             NON_PROVISIONNE_DEJA si le champ est deja "A_PROVISIONNER" ->
#             sinon reecrit le champ a "A_PROVISIONNER", trace l'ancienne
#             cle retiree (jamais la cle privee, qui n'a jamais quitte la
#             puce) -> ecrit -> retourne un statut explicite.
#
# CODE      : retirer_secure_enclave_reel_employe, ci-dessous.
# ------------------------------------------------------------------------------
@mcp.tool()
def retirer_secure_enclave_reel_employe(person_id: str, type_device: str) -> dict:
    """
    [MUTATION REELLE — ecrit ~/.ctsm_registre_employes.json]
    Retire explicitement le rattachement Secure Enclave reel enregistre
    pour person_id/type_device, en reecrivant le champ a "A_PROVISIONNER".
    Ne supprime jamais la fiche employe, ni les autres champs. Produit un
    effet reel et verifiable : un appel ulterieur a
    verifier_secure_enclave_reel_employe sur le meme couple doit repondre
    NON_PROVISIONNE.

    Args:
        person_id: identifiant de l'employe deja enregistre
        type_device: "PC_BUREAU" ou "PC_PERSONNEL", jamais devine

    Returns:
        {"statut": "RATTACHEMENT_RETIRE"|"NON_PROVISIONNE_DEJA"|"EMPLOYE_INCONNU"|
                    "TYPE_DEVICE_INVALIDE", ...}
    """
    if type_device not in TYPES_DEVICE_VALIDES:
        return {
            "statut": "TYPE_DEVICE_INVALIDE",
            "typeDeviceRecu": type_device,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }

    registre = _lire_registre_employes()
    fiche = registre.get(person_id)
    if fiche is None:
        return {
            "statut": "EMPLOYE_INCONNU",
            "personId": person_id,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }

    champ = _CHAMP_REEL_PAR_TYPE_DEVICE[type_device]
    cle_actuelle = fiche.get(champ, "A_PROVISIONNER")
    if not cle_actuelle or cle_actuelle == "A_PROVISIONNER":
        return {
            "statut": "NON_PROVISIONNE_DEJA",
            "personId": person_id,
            "champ": champ,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }

    fiche[champ] = "A_PROVISIONNER"
    fiche["timestamp_utc"] = datetime.now(timezone.utc).isoformat()
    registre[person_id] = fiche

    with open(REGISTRE_EMPLOYES_PATH, "w") as f:
        json.dump(registre, f, indent=2, ensure_ascii=False)

    return {
        "statut": "RATTACHEMENT_RETIRE",
        "personId": person_id,
        "champ": champ,
        "typeDevice": type_device,
        "message": "Champ reecrit a A_PROVISIONNER. La cle privee n'a jamais quitte la puce ; seule la reference publique enregistree est retiree.",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }


# ------------------------------------------------------------------------------
# OUTIL 13 : PETIHAH · L'OUVERTURE GOUVERNEE (7 sept 2026)
# ------------------------------------------------------------------------------
# Chaine constitutive · Preparation, jamais une decision
# PROBLEME -> LOI -> HOQ -> SEQUENCE -> CODE
#
# PROBLEME  : rien ne force la lecture des registres persistants (Lieux,
#             employes, incidents, PCR16) ni des zones de mandat au debut
#             d'une session — c'est un choix implicite de l'agent, jamais
#             une contrainte du protocole. Un agent en flux frais peut donc
#             repondre a une question territoriale sans jamais savoir que
#             haMakom existe, ou que Ben Nun a une fiche enregistree.
#
# LOI       : toute session de gouvernance doit pouvoir s'ouvrir par un acte
#             unique qui rassemble l'etat existant — jamais qui le juge, ni
#             qui tranche. Petihah lit, elle ne decide jamais : elle precede
#             structurellement toute lecture territoriale ou execution
#             d'action, exactement comme l'ICL (FL-540, Rasham) precede la
#             revelation sans la constituer.
#
# HOQ       : jamais une agregation qui invente un etat absent (ex. un
#             registre vide retourne une liste vide, jamais une erreur qui
#             bloque l'ouverture) ; jamais un verdict fabrique — seulement
#             un etat lu, horodate, tracable.
#
# SEQUENCE  : lire ~/.ctsm_lieux_temoins.json (Lieux enregistres) -> lire
#             ~/.ctsm_registre_employes.json (fiches employes) -> lire
#             ~/.ctsm_registre_incidents.json (incidents, compte seulement,
#             pas le detail complet) -> lire ~/.ctsm_pcr_state.json (PCR16
#             courant) -> lire ZONES_MANDAT_CORREIA (zones actives) ->
#             assembler un etat structure unique, jamais une decision.
#
# CODE      : Petihah_GovernedAgent, ci-dessous.
# ------------------------------------------------------------------------------
# ------------------------------------------------------------------------------
# CHANTIER B : VERROU D'OUVERTURE OBLIGATOIRE (Petihah forcee) (9 sept 2026)
# ------------------------------------------------------------------------------
# Chaine constitutive · PROBLEME -> LOI -> HOQ -> SEQUENCE -> CODE
#
# PROBLEME  : rien n'obligeait un agent, en debut de flux, a appeler
#             Petihah_GovernedAgent avant de repondre a une question
#             territoriale ou de faire passer la Porte de Gouvernance. Un
#             agent en flux frais pouvait resoudre une presence, creer un
#             Lieu, ou ouvrir la Porte sans jamais avoir lu l'etat reel des
#             Lieux, temoins et employes deja enregistres.
#
# LOI       : un systeme qui se revendique gouverne ne peut pas laisser sa
#             propre porte d'entree non gouvernee. Aucun outil territorial,
#             ni la Porte de Gouvernance elle-meme, ne doit produire de
#             verdict tant que l'etat existant n'a pas ete lu au moins une
#             fois dans le processus serveur courant.
#
# HOQ       : le verrou vit en memoire, cote serveur — un simple indicateur,
#             jamais un nouveau fichier persistant, remis a zero a chaque
#             redemarrage du processus. Il ne bloque jamais silencieusement :
#             un outil appele avant Petihah_GovernedAgent refuse
#             explicitement, avec un statut nomme et un message qui dit
#             pourquoi. Petihah_GovernedAgent reste inchangee dans sa nature
#             (lecture seule, ne decide rien) — elle devient seulement la cle
#             qui deverrouille les autres. Le verrou s'applique a tous les
#             outils territoriaux, la Porte de Gouvernance incluse.
#
# SEQUENCE  : indicateur global _PETIHAH_APPELEE = False au demarrage ->
#             Petihah_GovernedAgent le met a True juste avant son return ->
#             chaque outil territorial concerne (pcnt_zera_1cm,
#             resoudre_presence_employe_abidjan,
#             acquerir_et_resoudre_presence_abidjan, creer_lieu_avec_temoin,
#             autoriser_execution_action) verifie l'indicateur en toute
#             premiere ligne et refuse sinon, sans executer le reste de sa
#             logique.
#
# CODE      : _PETIHAH_APPELEE, _exiger_petihah(), et l'appel de garde ajoute
#             en premiere ligne de chaque outil concerne, ci-dessous.
# ------------------------------------------------------------------------------
_PETIHAH_APPELEE = False


def _exiger_petihah() -> Optional[dict]:
    """Verrou d'Ouverture Obligatoire — refuse tout verdict territorial ou
    toute decision de la Porte de Gouvernance tant que Petihah_GovernedAgent
    n'a pas ete appelee au moins une fois dans ce processus serveur."""
    if not _PETIHAH_APPELEE:
        return {
            "status": "PETIHAH_REQUISE",
            "erreur": "Aucune lecture d'ouverture (Petihah_GovernedAgent) n'a encore ete "
                      "effectuee dans cette session serveur. Appeler Petihah_GovernedAgent "
                      "avant toute resolution territoriale ou decision de la Porte de "
                      "Gouvernance — le protocole refuse de repondre sur un etat non lu.",
        }
    return None


@mcp.tool()
def Petihah_GovernedAgent() -> dict:
    """
    GovernedAgent™ v1.1 (24 sept 2026, renommage — voir en-tête du fichier).
    [LECTURE REELLE — aucun appel reseau, aucune mutation]
    L'Ouverture gouvernee : rassemble en un seul appel l'etat existant de
    tous les registres persistants et des zones de mandat, avant toute
    lecture territoriale ou execution d'action. Ne decide jamais rien —
    Petihah precede la revelation, elle ne la constitue pas (FL-540,
    Rasham). A appeler en premiere action d'une session de gouvernance,
    plutot que de supposer un etat non lu.

    Returns:
        {"lieuxEnregistres": [...], "employesEnregistres": [...],
        "totalIncidents": int, "pcr16Courant": str,
        "zonesMandatActives": [...], "timestamp_utc": ...}
    """
    lieux = _lieu_charger_registre()
    lieux_resume = [
        {
            "nom": lieu.get("nom"),
            "rayon_m": lieu.get("rayon_m"),
            "lat_centre": lieu.get("lat_centre"),
            "lon_centre": lieu.get("lon_centre"),
        }
        for lieu in lieux.values()
    ]

    employes = _lire_registre_employes()
    employes_resume = [
        {
            "personId": fiche.get("personId"),
            "nom": fiche.get("nom"),
            "fonction": fiche.get("fonction"),
            "mandatZoneNom": fiche.get("mandatZoneNom"),
            "ressourcesAccessibles": fiche.get("ressourcesAccessibles", []),
        }
        for fiche in employes.values()
    ]

    total_incidents = 0
    if os.path.exists(REGISTRE_INCIDENTS_PATH):
        try:
            with open(REGISTRE_INCIDENTS_PATH, "r") as f:
                total_incidents = len(json.load(f))
        except Exception:  # noqa: BLE001
            total_incidents = 0

    pcr16_courant = _lire_pcr16()

    zones_resume = [
        {"nom": zone["nom"], "rayon_km": zone["rayon_km"]}
        for zone in ZONES_MANDAT_CORREIA
    ]

    global _PETIHAH_APPELEE
    _PETIHAH_APPELEE = True

    return {
        "lieuxEnregistres": lieux_resume,
        "employesEnregistres": employes_resume,
        "totalIncidents": total_incidents,
        "pcr16Courant": pcr16_courant,
        "zonesMandatActives": zones_resume,
        "message": "Etat lu, jamais decide. Petihah precede la lecture territoriale et l'execution d'action, elle ne les remplace pas.",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }


def _get_router_bssid() -> str:
    """Identique à agentproof_trl5_gate.py : lecture réelle, dynamique, du BSSID passerelle."""
    try:
        arp_all = subprocess.check_output("arp -a", shell=True).decode()
        found_macs = re.findall(r'(?:[0-9a-fA-F]{1,2}:){5}[0-9a-fA-F]{1,2}', arp_all)
        for mac in found_macs:
            mac_clean = mac.lower()
            if mac_clean != "ff:ff:ff:ff:ff:ff" and not mac_clean.startswith("01:00:5e"):
                return mac_clean
    except Exception:  # noqa: BLE001
        pass

    try:
        cmd = "/System/Library/PrivateFrameworks/Apple80211.framework/Resources/airport -I"
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode()
        found = re.findall(r'(?:[0-9a-fA-F]{1,2}:){5}[0-9a-fA-F]{1,2}', out)
        if found:
            return found[0].lower()
    except Exception:  # noqa: BLE001
        pass

    return "00:00:00:00:00:00"


def _get_host_mac() -> str:
    """Identique à agentproof_trl5_gate.py : lecture réelle de la MAC physique de la machine."""
    try:
        mac_num = uuid.getnode()
        mac_hex = f"{mac_num:012x}"
        return ":".join(mac_hex[i:i + 2] for i in range(0, 12, 2))
    except Exception:  # noqa: BLE001
        return "inconnue"


def compute_haversine(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    R = 6371000.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = math.radians(lat2 - lat1), math.radians(lon2 - lon1)
    a = math.sin(dp / 2.0) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2.0) ** 2
    return 2.0 * R * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))


def _call_resolve_presence(
    person_id: str,
    lat: float,
    lon: float,
    session_id: Optional[str] = None,
) -> dict:
    """
    Appel HTTP réel, POST /v1/resolve-presence, avec retry unique sur cold start.
    Ne masque jamais un échec réseau : remonte un statut explicite au lieu
    de simuler un succès.

    Corps exact attendu par l'API réelle (resolve-presence.js) :
      { person_id: str (obligatoire), lat: number, lon: number, session_id?: str }
    Il n'existe pas de paramètre `echantillons` côté API réelle : la fusion
    multi-échantillons (GPSAcquisitionGovernance) reste, à ce stade, une étape
    à réaliser en amont côté appareil, avant l'appel à cet outil — elle n'est
    pas transmise ni traitée par le Cockpit Spatial™ API lui-même.
    """
    url = f"{COCKPIT_API_BASE_URL}{RESOLVE_PRESENCE_PATH}"
    payload = {"person_id": person_id, "lat": lat, "lon": lon}
    if session_id:
        payload["session_id"] = session_id

    body = json.dumps(payload).encode("utf-8")
    last_error = None

    for attempt in range(MAX_RETRIES + 1):
        req = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_SECONDS) as resp:
                raw = resp.read().decode("utf-8")
                return {"ok": True, "http_status": resp.status, "data": json.loads(raw)}
        except urllib.error.HTTPError as e:
            try:
                err_body = e.read().decode("utf-8")
            except Exception:  # noqa: BLE001
                err_body = ""
            last_error = f"HTTP {e.code} : {e.reason} · {err_body}"
        except urllib.error.URLError as e:
            last_error = f"Réseau indisponible : {e.reason}"
        except Exception as e:  # noqa: BLE001 — on veut capturer et remonter, pas planter l'outil MCP
            last_error = f"Erreur inattendue : {e}"

        if attempt < MAX_RETRIES:
            time.sleep(RETRY_DELAY_SECONDS)

    return {"ok": False, "error": last_error}


def _call_auth(
    nom: str,
    email: Optional[str] = None,
    telephone: Optional[str] = None,
    icl_residence: Optional[str] = None,
    role: Optional[str] = None,
    collectivite: Optional[str] = None,
) -> dict:
    """
    Appel HTTP réel, POST /v1/auth (auth.js). Contrat confirmé par lecture du
    code source réel : nom obligatoire, role parmi ROLES_VALIDES (défaut
    'resident'), collectivite par défaut 'Mairie de Cocody'. Retourne un
    person_id + token_session en cas de succès (HTTP 201).
    """
    url = f"{COCKPIT_API_BASE_URL}{AUTH_PATH}"
    payload = {"nom": nom}
    if email:
        payload["email"] = email
    if telephone:
        payload["telephone"] = telephone
    if icl_residence:
        payload["icl_residence"] = icl_residence
    if role:
        payload["role"] = role
    if collectivite:
        payload["collectivite"] = collectivite

    body = json.dumps(payload).encode("utf-8")
    last_error = None

    for attempt in range(MAX_RETRIES + 1):
        req = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_SECONDS) as resp:
                raw = resp.read().decode("utf-8")
                return {"ok": True, "http_status": resp.status, "data": json.loads(raw)}
        except urllib.error.HTTPError as e:
            try:
                err_body = e.read().decode("utf-8")
            except Exception:  # noqa: BLE001
                err_body = ""
            last_error = f"HTTP {e.code} : {e.reason} · {err_body}"
        except urllib.error.URLError as e:
            last_error = f"Réseau indisponible : {e.reason}"
        except Exception as e:  # noqa: BLE001
            last_error = f"Erreur inattendue : {e}"

        if attempt < MAX_RETRIES:
            time.sleep(RETRY_DELAY_SECONDS)

    return {"ok": False, "error": last_error}


# ------------------------------------------------------------------------------
# OUTIL 5 : INSCRIPTION RÉELLE D'UN ACTEUR · POST /v1/auth
# ------------------------------------------------------------------------------
@mcp.tool()
def inscrire_acteur_abidjan(
    nom: str,
    email: Optional[str] = None,
    telephone: Optional[str] = None,
    role: Optional[str] = None,
    collectivite: Optional[str] = None,
) -> dict:
    """
    [RÉEL — appel réseau effectif] Inscrit un nouvel acteur via POST /v1/auth
    sur le Cockpit Spatial™ API, et retourne son person_id. Préalable réel à
    tout appel de resoudre_presence_employe_abidjan pour un acteur pas encore
    inscrit (l'API refuse toute résolution de présence sans person_id valide).

    Args:
        nom: nom de l'acteur à inscrire (obligatoire)
        email: email optionnel, doit être unique côté base si fourni
        telephone: téléphone optionnel
        role: un de 'resident', 'visiteur', 'agent_territorial', 'mairie', 'admin'
              (défaut 'resident' côté API si omis)
        collectivite: défaut 'Mairie de Cocody' côté API si omis

    Returns:
        En cas de succès : person_id, token_session, et les autres champs
        renvoyés par l'API. En cas d'échec (email déjà inscrit, rôle invalide,
        réseau indisponible) : statut explicite, jamais un person_id inventé.
    """
    result = _call_auth(nom, email, telephone, None, role, collectivite)

    if not result["ok"]:
        return {
            "statut": "ECHEC_INSCRIPTION",
            "message": f"L'inscription a échoué : {result['error']}",
            "source": "Cockpit Spatial™ API · POST /v1/auth (échec)",
        }

    acteur = (result["data"] or {}).get("acteur") or {}
    return {
        "statut": "INSCRIT",
        "person_id": acteur.get("person_id"),
        "nom": acteur.get("nom"),
        "role": acteur.get("role"),
        "collectivite": acteur.get("collectivite"),
        "token_session": acteur.get("token_session"),
        "token_expires": acteur.get("token_expires"),
        "source": "Cockpit Spatial™ API · POST /v1/auth (appel réel)",
    }


# ------------------------------------------------------------------------------
# OUTIL 6 : MANDAT AGENT CORREIA · MULTI-ZONE (géodésie réelle, pas d'appel réseau)
# ------------------------------------------------------------------------------
# Chaine constitutive · Couche 3 · Mandat et juridiction
# PROBLEME -> LOI -> HOQ -> SEQUENCE -> CODE
#
# PROBLEME  : le mandat de l'Agent ne couvrait que Paris. Le test reel de la
#             porte (autoriser_execution_action, 7 sept 2026) a produit
#             HORS_MANDAT pour toute destination a Abidjan, alors qu'Abidjan
#             est le territoire operationnel reel de CorreIA — desormais
#             prouve par un document legal reel : RCCM CI-ABJ-03-2022-B13-09726
#             (ABRAND NEWS, SARLU, gerant CORREA MARTIN FULGENCE, siege
#             Abidjan Cocody Angre). Le mandat tel que code ne refletait pas
#             le perimetre operationnel reel de l'organisation.
#
# LOI       : le mandat de l'Agent doit couvrir chaque territoire reellement
#             operationnel de CorreIA, chacun legitime separement par une
#             preuve reelle (centre geodesique, rayon, justification nommee) ;
#             une destination est DANS_MANDAT des qu'elle tombe dans AU MOINS
#             UNE des zones declarees ; chaque zone reste une approximation
#             geodesique honnete, jamais une correspondance a une limite
#             administrative officielle, ni a une base d'adresses officielle
#             (le Cockpit Spatial™ API ne couvre que Cocody, Abidjan — aucun
#             endpoint reel n'existe pour verifier une position a Paris).
#
# HOQ       : un test de mandat multi-zone, additif entre zones (logique OU),
#             chaque zone nommee et justifiee independamment, jamais fusionnee
#             en un perimetre unique qui masquerait leur origine distincte.
#
# SEQUENCE  : pour chaque zone declaree dans ZONES_MANDAT_CORREIA (Paris,
#             Abidjan) -> distance = haversine(destination, centre_zone) ->
#             si distance <= rayon_zone, DANS_MANDAT et zone nommee ->
#             sinon, apres verification de toutes les zones, HORS_MANDAT.
#
# CODE      : ZONES_MANDAT_CORREIA et verifier_mandat_agent_correia, ci-dessous.
# ------------------------------------------------------------------------------
# Zone Abidjan : ancrage geodesique reel = le temoin "Bureau annexe Abidjan"
# deja declare (le RCCM donne une adresse descriptive, Cocody Angre, sans
# lat/lon ; le temoin reste le seul point geodesique reel disponible). Rayon
# elargi a l'echelle d'Abidjan (approximation honnete, pas une limite
# communale officielle) puisque l'operateur a demande le territoire "Abidjan",
# pas seulement le quartier du siege declare au RCCM.
ABIDJAN_MANDAT_CENTRE_LAT = NOMINAL_LAT
ABIDJAN_MANDAT_CENTRE_LON = NOMINAL_LON
ABIDJAN_MANDAT_RAYON_KM = 25.0
ABIDJAN_MANDAT_JUSTIFICATION = (
    "RCCM CI-ABJ-03-2022-B13-09726 · ABRAND NEWS (SARLU), filiale de "
    "CorreIA LLC · gerant CORREA MARTIN FULGENCE · siege Abidjan Cocody Angre 7eme"
)

ZONES_MANDAT_CORREIA = [
    {
        "nom": "PARIS",
        "centre_lat": PARIS_CENTRE_LAT,
        "centre_lon": PARIS_CENTRE_LON,
        "rayon_km": PARIS_RAYON_KM,
        "justification": "Mandat historique de l'Agent✦348 · Shaliach · CorreIA LLC, Paris",
    },
    {
        "nom": "ABIDJAN",
        "centre_lat": ABIDJAN_MANDAT_CENTRE_LAT,
        "centre_lon": ABIDJAN_MANDAT_CENTRE_LON,
        "rayon_km": ABIDJAN_MANDAT_RAYON_KM,
        "justification": ABIDJAN_MANDAT_JUSTIFICATION,
    },
]
@mcp.tool()
def verifier_mandat_agent_correia(destination_lat: float, destination_lon: float) -> dict:
    """
    [GÉODÉSIE RÉELLE — aucun appel réseau, aucune base d'adresses officielle]
    Teste le mandat territorial de l'Agent (CorreIA LLC) contre TOUTES les
    zones declarees dans ZONES_MANDAT_CORREIA (Paris, Abidjan) : la
    destination visee est-elle dans le perimetre d'AU MOINS UNE zone
    couverte par le mandat, ou hors de toutes (ex. Marseille) ?

    Limite a ne jamais masquer, pour chaque zone : ce test compare une
    distance haversine reelle au centre declare de la zone — une geometrie
    reelle, mais une approximation de perimetre, jamais une correspondance a
    une limite administrative officielle ni a une base d'adresses officielle.
    La zone ABIDJAN est ancree sur le temoin "Bureau annexe Abidjan" (le
    RCCM CI-ABJ-03-2022-B13-09726 donne une adresse descriptive, Cocody
    Angre, sans coordonnees) et porte un rayon elargi (25 km) representant le
    territoire operationnel reel de CorreIA a Abidjan, pas une limite
    communale officielle.

    Args:
        destination_lat: latitude WGS84 de la destination visée par l'action mandatée
        destination_lon: longitude WGS84 de la destination visée

    Returns:
        Verdict de mandat (DANS_MANDAT / HORS_MANDAT), la zone qui a matché
        le cas echeant, et le detail de la distance a CHAQUE zone testee.
    """
    detail_zones = []
    zone_matchee = None
    for zone in ZONES_MANDAT_CORREIA:
        distance_km = compute_haversine(
            destination_lat, destination_lon, zone["centre_lat"], zone["centre_lon"]
        ) / 1000.0
        dans_zone = distance_km <= zone["rayon_km"]
        detail_zones.append({
            "zone": zone["nom"], "distance_km": round(distance_km, 3),
            "rayon_km": zone["rayon_km"], "dans_zone": dans_zone,
            "justification": zone["justification"],
        })
        if dans_zone and zone_matchee is None:
            zone_matchee = zone["nom"]

    dans_mandat = zone_matchee is not None

    return {
        "verdict": "DANS_MANDAT [SAF_OPEN]" if dans_mandat else "HORS_MANDAT [SAF_HOLD]",
        "statut_domanial": "DESTINATION_CONFORME_AU_MANDAT" if dans_mandat else "DEPASSEMENT_DE_MANDAT",
        "zoneMatchee": zone_matchee,
        "detailZones": detail_zones,
        "destination_evaluee": {"lat": destination_lat, "lon": destination_lon},
        "message": (
            "Approximation géodésique réelle (haversine) par zone, pas une correspondance à une "
            "base d'adresses officielle ni à une limite administrative d'arrondissement ou communale."
        ),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "source": "Géodésie locale (aucun appel réseau)",
    }


# ------------------------------------------------------------------------------
# OUTIL 7 : SECURE ENCLAVE ÉMULÉ + POSITION · TRIANGULATION À TROIS NŒUDS
# ------------------------------------------------------------------------------
# Chaine constitutive · Couche 2 · Attestation materielle et domaniale
# PROBLEME -> LOI -> HOQ -> SEQUENCE -> CODE
#
# PROBLEME  : signer un acte au nom d'une entite exige de savoir si l'agent
#             qui le demande est reellement ancre la ou il pretend etre — et
#             un seul signal (une seule position, ou un seul reseau, ou une
#             seule empreinte logicielle) peut etre usurpe ou incorrect sans
#             que rien ne le detecte. Deja traverse et trace dans les tests
#             agentproof_trl5_gate.py du 4/5 septembre 2026.
#
# LOI       : aucune signature n'est produite tant que trois domaines
#             independants ne sont pas simultanement conformes : la position
#             geodesique (Sol), le rattachement reseau/institutionnel
#             (Demeure), et l'integrite logicielle attestee (Institution) ;
#             aucun des trois ne peut compenser l'echec d'un autre.
#
# HOQ       : une triangulation a trois noeuds, non compensatoire, qui ne
#             signe qu'a la condition que les trois soient verts.
#
# SEQUENCE  : lire MAC hote + BSSID passerelle (Demeure) -> lire le registre
#             PCR16 emule (Institution) -> calculer la derive geodesique
#             reelle vs position nominale (Sol) -> ET logique strict des
#             trois -> si tous OK, deriver K_agent et signer (HMAC) le
#             payload ; sinon REFUSE [SAF_HOLD], aucun acte signe.
#
# CODE      : verifier_secure_enclave_et_position, ci-dessous.
# ------------------------------------------------------------------------------
@mcp.tool()
def verifier_secure_enclave_et_position(
    pcr16_attendu: str,
    payload_file: str,
    mesure_lat: float = ECHANTILLON_1_LAT_DOMICILE_ABIDJAN,
    mesure_lon: float = ECHANTILLON_1_LON_DOMICILE_ABIDJAN,
    nominal_lat: float = NOMINAL_LAT,
    nominal_lon: float = NOMINAL_LON,
) -> dict:
    """
    Réimplémentation directe de la triangulation à trois nœuds déjà traversée
    dans agentproof_trl5_gate.py (tests tracés du 4/5 septembre 2026).

    Nature réelle de chaque nœud, à ne jamais confondre :
      Nœud 1 (Sol/WGS84)      : mesure_lat/mesure_lon sont maintenant un vrai
                                 paramètre d'entrée, plus une constante figée
                                 dans le code comme dans le script d'origine.
                                 Les valeurs par défaut sont l'échantillon exact
                                 déjà utilisé lors des tests tracés — à remplacer
                                 par une vraie position quand une lecture GPS
                                 réelle sera branchée en amont.
      Nœud 2 (Demeure/MAC)    : lecture système réelle et dynamique (arp -a /
                                 airport -I pour le BSSID, uuid.getnode() pour
                                 la MAC hôte) — identique au script d'origine.
      Nœud 3 (Institution/PCR16) : lecture réelle de ~/.ctsm_pcr_state.json,
                                 un registre PCR ÉMULÉ en logiciel par
                                 ctsm_tpm_mac.py — pas une puce Secure Enclave
                                 matérielle réelle. Cet outil ne fait qu'en
                                 lire l'état ; l'extension du PCR (pcr_extend)
                                 reste un acte séparé, à faire via
                                 ctsm_tpm_mac.py avant d'appeler cet outil.

    Args:
        pcr16_attendu: condensat PCR16 nominal attendu (celui produit par un
                        pcr_extend antérieur via ctsm_tpm_mac.py)
        payload_file: chemin local du fichier JSON à signer si l'arbitrage est ACCORDÉ
        mesure_lat, mesure_lon: position mesurée (Nœud 1) — voir note ci-dessus
        nominal_lat, nominal_lon: position nominale de référence pour la dérive géodésique

    Returns:
        Verdict ACCORDÉ [SAF_OPEN] (avec signature HMAC du payload) ou
        REFUSÉ [SAF_HOLD], selon les trois conditions non compensatoires :
        dérive ≤ TOLERANCE_METERS, PCR16 conforme, BSSID passerelle connecté.
    """
    host_mac = _get_host_mac()
    router_mac = _get_router_bssid()
    pcr16_lu = _lire_pcr16()

    distance = compute_haversine(mesure_lat, mesure_lon, nominal_lat, nominal_lon)
    sol_ok = distance <= TOLERANCE_METERS
    pcr_ok = pcr16_lu.lower() == pcr16_attendu.lower()
    demeure_ok = router_mac != "00:00:00:00:00:00"
    is_authorized = sol_ok and pcr_ok and demeure_ok

    triangulation = {
        "noeud_1_sol_wgs84": {
            "distance_m": round(distance, 2),
            "statut": "OK" if sol_ok else "OUT_OF_BOUNDS",
            "mesure": {"lat": mesure_lat, "lon": mesure_lon},
            "nominal": {"lat": nominal_lat, "lon": nominal_lon},
            "nature": "paramètre d'entrée réel (échantillon par défaut si non fourni)",
        },
        "noeud_2_demeure_mac": {
            "bssid_passerelle": router_mac,
            "mac_hote": host_mac,
            "statut": "OK" if demeure_ok else "DISCONNECTED",
            "nature": "lecture système réelle et dynamique",
        },
        "noeud_3_institution_pcr16": {
            "valeur_lue": pcr16_lu,
            "valeur_attendue": pcr16_attendu,
            "statut": "MATCH" if pcr_ok else "MISMATCH",
            "nature": "lecture réelle d'un registre PCR émulé (pas une puce matérielle)",
        },
    }

    if not is_authorized:
        return {
            "verdict": "REFUSÉ [SAF_HOLD]",
            "code_retour_hardware": "TPM_RC_POLICY_FAIL (0x99D)",
            "triangulation": triangulation,
            "message": "Violation domaniale détectée sur au moins un nœud non compensable. Aucun acte signé.",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }

    # Corrigé le 7 sept 2026 : lecture en binaire ("rb"), plus en texte UTF-8 ("r"),
    # pour signer n'importe quel type de fichier (PDF, image, JSON, etc.), pas
    # seulement du texte. La signature HMAC porte sur les octets bruts du fichier.
    try:
        with open(os.path.expanduser(payload_file), "rb") as f:
            document_bytes = f.read()
    except Exception as e:  # noqa: BLE001
        return {
            "verdict": "INDÉTERMINÉ [PAYLOAD_ILLISIBLE]",
            "triangulation": triangulation,
            "message": f"Les trois nœuds sont conformes, mais payload_file est illisible : {e}",
        }

    k_agent_secret = hashlib.sha256(f"K_AGENT_{pcr16_attendu}_{router_mac}".encode()).hexdigest()
    signature = hmac.new(k_agent_secret.encode(), document_bytes, hashlib.sha256).hexdigest()

    return {
        "verdict": "ACCORDÉ [SAF_OPEN]",
        "code_retour_hardware": "TPM_RC_SUCCESS (0x000)",
        "triangulation": triangulation,
        "signature_opposable": signature,
        "message": "Clé K_agent dérivée, document signé. Signature engageante pour l'entité déclarée.",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }


# ------------------------------------------------------------------------------
# OUTIL — PIECE 55 : RECHERCHE WEB GOUVERNEE (10 sept 2026)
# ------------------------------------------------------------------------------
# Chaine constitutive : PROBLEME -> LOI -> HOQ -> SEQUENCE -> CODE
#
# PROBLEME : la recherche web utilisee dans le cas Bruxelles est une capacite
#            NATIVE de l'application hote (Claude Desktop) — elle ne transite
#            jamais par tools/list, donc aucun Tool Broker MCP ne peut la
#            filtrer (voir note_contrainte_piece_53.md). Le seul geste
#            disponible a ce niveau est de construire un outil de recherche
#            concurrent, entierement gouverne, que l'agent peut choisir
#            d'utiliser a la place de la recherche native.
#
# LOI      : aucune requete de recherche gouvernee ne part sans (1) un verdict
#            de mandat territorial favorable au moment de l'appel et (2) une
#            preuve cryptographique reelle (challenge/signature Secure
#            Enclave, nonce neuf, jamais rejouable) que l'appel provient bien
#            de CE device gouverne — jamais la simple presence de l'outil
#            dans la liste ne suffit.
#
# HOQ      : le calcul du mandat reutilise integralement
#            verifier_mandat_agent_correia (aucune reimplementation de la
#            geodesie). La preuve materielle reutilise integralement
#            _appeler_binaire_secure_enclave, exactement comme
#            verifier_secure_enclave_employe — jamais une comparaison de
#            secret statique. Le backend de recherche est SearxNG, instance
#            locale, adresse configurable via SEARXNG_BASE_URL — jamais une
#            cle API tierce transmise en clair depuis ce fichier.
#
# SEQUENCE : rechercher_web_gouvernee recoit requete + destination_lat/lon ->
#            appelle verifier_mandat_agent_correia -> si HORS_MANDAT, retourne
#            un refus explicite sans jamais interroger SearxNG -> si
#            DANS_MANDAT, genere un nonce, appelle
#            _appeler_binaire_secure_enclave("pubkey") puis ("sign", nonce) ->
#            verifie la signature (cryptography, ECDSA P-256/SHA-256) -> si la
#            preuve echoue, retourne un refus explicite sans jamais interroger
#            SearxNG -> si la preuve reussit, interroge SearxNG local, retourne
#            les resultats bruts, motif du verdict et preuve jointe.
#
# CODE     : rechercher_web_gouvernee, ci-dessous.
# ------------------------------------------------------------------------------

SEARXNG_BASE_URL = os.environ.get("SEARXNG_BASE_URL", "http://127.0.0.1:8080")
# Jeton partage pour l instance SearxNG hebergee CorreIA (deploiement test a distance,
# 10 sept 2026) — absent en local, requis des que SEARXNG_BASE_URL pointe vers une
# instance distante partagee entre plusieurs testeurs. Jamais une cle API tierce (Brave
# et autres) : ce jeton n authentifie que l acces a l instance SearxNG elle meme, geree
# par CorreIA LLC, pas un fournisseur de recherche externe.
SEARXNG_ACCES_TOKEN = os.environ.get("SEARXNG_ACCES_TOKEN", "")


# ------------------------------------------------------------------------------
# MISE A JOUR (13 sept 2026) : PREUVE LIEE A UN PERSON_ID EXPLICITE
# ------------------------------------------------------------------------------
# Chaine constitutive de cette mise a jour : PROBLEME -> LOI -> HOQ -> SEQUENCE -> CODE
#
# PROBLEME  : la preuve Secure Enclave de rechercher_web_gouvernee etait
#             generique au device (_appeler_binaire_secure_enclave directe) —
#             elle prouvait que CE device pouvait signer, jamais quel employe
#             invoquait la recherche. Une signature materielle valide seule
#             ne suffit pas a lier la recherche a une identite autorisee.
#
# LOI       : aucune recherche gouvernee ne part sans un person_id explicite,
#             rattache a un type_device explicite, verifie par
#             verifier_secure_enclave_reel_employe. L'absence de l'un ou
#             l'autre bloque la recherche avant tout appel a SearxNG, jamais
#             une confirmation par defaut.
#
# HOQ       : reutilise fidelement verifier_secure_enclave_reel_employe (meme
#             discipline que la Couche 4 de autoriser_execution_action,
#             jamais une logique dupliquee) — remplace l'appel direct a
#             _appeler_binaire_secure_enclave, qui restait anonyme.
#
# SEQUENCE  : rechercher_web_gouvernee recoit requete + destination_lat/lon +
#             person_id + type_device -> person_id ou type_device absent =
#             refus explicite avant tout appel reseau -> sinon verifie le
#             mandat -> sinon appelle verifier_secure_enclave_reel_employe ->
#             exige SIGNATURE_VALIDE -> si tout est vert, interroge SearxNG.
#
# CODE      : parametres person_id/type_device ajoutes, logique de preuve
#             remplacee, ci-dessous.
# ------------------------------------------------------------------------------
@mcp.tool()
def rechercher_web_gouvernee(
    requete: str,
    destination_lat: float,
    destination_lon: float,
    person_id: Optional[str] = None,
    type_device: Optional[str] = None,
    nombre_resultats: int = 5,
) -> dict:
    """
    [PIECE 55 — Secure-Enclave-gated, lie a l'identite (13 sept 2026)]
    Execute une recherche web via une instance SearxNG locale, uniquement si
    (1) person_id ET type_device sont fournis explicitement, (2) le mandat
    territorial couvre destination_lat/destination_lon selon
    verifier_mandat_agent_correia, ET (3) verifier_secure_enclave_reel_employe
    retourne SIGNATURE_VALIDE pour ce person_id/type_device precis. N'interroge
    jamais SearxNG si l'une de ces conditions echoue — le refus est retourne
    avant tout appel reseau externe a la recherche elle meme.

    Cet outil ne gouverne QUE lui meme : il ne peut ni desactiver ni
    remplacer la capacite de recherche native de l'application hote (voir
    note_contrainte_piece_53.md). Il fournit une alternative gouvernee, pas
    une contrainte sur le choix de l'agent entre les deux — cette contrainte
    reste du ressort d'ASSERV-07 (Sequestre Reseau) et de la discipline
    d'instruction du skill territorial.

    Args:
        requete: texte de la recherche
        destination_lat, destination_lon: position evaluee pour le mandat
            territorial (typiquement la position courante de l'agent/usager)
        person_id: identifiant de l'employe invoquant la recherche. Absent =
            refus explicite (PERSON_ID_ABSENT), jamais une confirmation par
            defaut.
        type_device: "PC_BUREAU" ou "PC_PERSONNEL", jamais devine. Absent =
            refus explicite (TYPE_DEVICE_ABSENT).
        nombre_resultats: nombre de resultats a retourner (defaut 5)

    Returns:
        Verdict "RECHERCHE_EXECUTEE [SAF_OPEN]" avec resultats, ou refus
        explicite "PERSON_ID_ABSENT" / "TYPE_DEVICE_ABSENT" /
        "HORS_MANDAT [SAF_HOLD]" / "PREUVE_ENCLAVE_ECHOUEE [SAF_HOLD]" /
        "ECHEC_SEARXNG" — jamais un resultat simule.
    """
    if person_id is None:
        return {
            "verdict": "PERSON_ID_ABSENT",
            "requete": requete,
            "message": "Aucun person_id fourni — recherche gouvernee refusee avant tout appel reseau.",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }
    if type_device is None:
        return {
            "verdict": "TYPE_DEVICE_ABSENT",
            "requete": requete,
            "message": "Aucun type_device fourni — recherche gouvernee refusee avant tout appel reseau.",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }

    verdict_mandat = verifier_mandat_agent_correia(destination_lat, destination_lon)
    if not str(verdict_mandat.get("verdict", "")).startswith("DANS_MANDAT"):
        return {
            "verdict": "HORS_MANDAT [SAF_HOLD]",
            "requete": requete,
            "verdictMandat": verdict_mandat,
            "message": "Position hors des zones de mandat declarees — recherche gouvernee refusee avant tout appel a SearxNG.",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }

    verdict_identite_brut = verifier_secure_enclave_reel_employe(person_id, type_device)
    verdict_identite = verdict_identite_brut.get("verdict")
    if verdict_identite != "SIGNATURE_VALIDE":
        return {
            "verdict": "PREUVE_ENCLAVE_ECHOUEE [SAF_HOLD]",
            "requete": requete,
            "personId": person_id,
            "typeDevice": type_device,
            "verdictIdentite": verdict_identite,
            "message": "Preuve challenge/signature materielle liee a ce person_id/type_device a echoue ou est absente — recherche refusee.",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }

    url = f"{SEARXNG_BASE_URL}/search"
    payload = urllib.parse.urlencode({"q": requete, "format": "json"}).encode("utf-8")
    headers = {}
    if SEARXNG_ACCES_TOKEN:
        headers["Authorization"] = f"Bearer {SEARXNG_ACCES_TOKEN}"
    req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_SECONDS) as resp:
            raw = resp.read().decode("utf-8")
            data = json.loads(raw)
    except urllib.error.URLError as e:
        return {
            "verdict": "ECHEC_SEARXNG",
            "requete": requete,
            "message": f"Mandat et preuve enclave valides, mais SearxNG local injoignable ({SEARXNG_BASE_URL}) : {e.reason}. Verifier que l'instance tourne localement (docker/service searxng).",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as e:  # noqa: BLE001
        return {
            "verdict": "ECHEC_SEARXNG",
            "requete": requete,
            "message": f"Mandat et preuve enclave valides, mais erreur inattendue lors de l'appel SearxNG : {e}",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }

    resultats_bruts = data.get("results", [])[:nombre_resultats]
    resultats = [
        {
            "titre": r.get("title"),
            "url": r.get("url"),
            "extrait": r.get("content"),
        }
        for r in resultats_bruts
    ]

    return {
        "verdict": "RECHERCHE_EXECUTEE [SAF_OPEN]",
        "requete": requete,
        "personId": person_id,
        "typeDevice": type_device,
        "verdictMandat": verdict_mandat,
        "preuveEnclave": "challenge/signature reelle reussie, liee a ce person_id/type_device (nonce neuf, jamais rejouable)",
        "resultats": resultats,
        "source": f"SearxNG local ({SEARXNG_BASE_URL})",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }


# ------------------------------------------------------------------------------
# OUTIL 8 : PORTE UNIQUE DE GOUVERNANCE D'EXECUTION (7 sept 2026)
# ------------------------------------------------------------------------------
# Chaine constitutive de cet outil : PROBLEME -> LOI -> HOQ -> SEQUENCE -> CODE
# Aucune ligne ci-dessous n'a ete ecrite avant que les quatre premiers niveaux
# n'aient ete traverses reellement dans cette session (7 sept 2026).
#
# PROBLEME  : trois couches de gouvernance existaient deja separement dans ce
#             sandbox (pcnt_zera_1cm pour la position/temoin,
#             verifier_mandat_agent_correia pour le mandat/juridiction,
#             verifier_secure_enclave_et_position pour l'enclave/domanial),
#             chacune deja non compensatoire EN INTERNE. Mais rien
#             n'empechait techniquement d'appeler une seule de ces trois
#             couches et d'agir sans jamais verifier les deux autres.
#
# LOI       : aucune action gouvernee ne s'execute sans que les trois couches
#             (position, mandat, enclave) soient TOUTES vertes ; un seul echec,
#             quelle que soit la couche, doit bloquer l'execution et nommer
#             sa cause exacte ; jamais de compensation entre couches, jamais
#             une execution partielle.
#
# HOQ       : une porte unique, appelable une seule fois avant toute action,
#             qui applique cette loi sans exception ni contournement possible.
#
# SEQUENCE  : appeler pcnt_zera_1cm (position/temoin, jamais sur GPS brut,
#             Loi du 7 sept 2026) -> appeler verifier_mandat_agent_correia
#             (mandat/juridiction) -> appeler verifier_secure_enclave_et_position
#             (triangulation a trois noeuds) -> si une seule des trois echoue,
#             REFUSE [PORTE_FERMEE] avec causeRefus nommee ; si les trois
#             reussissent, AUTORISE [PORTE_OUVERTE] avec signatureOpposable.
#
# CODE      : autoriser_execution_action, ci-dessous. Compose les trois outils
#             deja constitues (aucune logique dupliquee), non compensatoire
#             entre eux comme chacun l'est deja en interne.
# ------------------------------------------------------------------------------
# Compose, sans les remplacer, les trois couches de gouvernance deja
# construites et testees separement dans ce sandbox :
#   Couche 1 · Position/Presence   -> pcnt_zera_1cm (temoin, PADA, Path
#                                      Resolver, Loi GPS du 7 sept 2026)
#   Couche 2 · Mandat/Juridiction  -> verifier_mandat_agent_correia
#   Couche 3 · Enclave/Domanial    -> verifier_secure_enclave_et_position
#                                      (triangulation a trois noeuds : Sol,
#                                      Demeure, Institution/PCR16 emule)
#
# Avant cette porte, rien n'empechait techniquement d'appeler une seule de
# ces trois couches et d'agir sans les deux autres. Cette porte corrige
# cela : elle refuse l'execution d'une action des qu'UNE SEULE des trois
# couches echoue, non compensatoire entre les couches comme a l'interieur
# de chacune d'elles, et nomme explicitement la cause exacte du refus —
# jamais un refus generique.
STATUTS_POSITION_SUFFISANTS = {"LIEU_CONFIRME_PAR_TEMOIN", "GOVERNED_POSITION_CANDIDATE"}

VERDICTS_IDENTITE_SUFFISANTS = {"CONFIRME_PC_BUREAU", "CONFIRME_PC_PERSONNEL"}

# ------------------------------------------------------------------------------
# MISE A JOUR (9 sept 2026) : COUCHE 4 · IDENTITE<->DEVICE
# ------------------------------------------------------------------------------
# Chaine constitutive de cette mise a jour : PROBLEME -> LOI -> HOQ -> SEQUENCE -> CODE
#
# PROBLEME  : les trois couches ci-dessus verifient une position, un mandat,
#             et un device de confiance generique — jamais qui appelle. Un
#             device de confiance suffit pour ouvrir la porte, peu importe
#             quel employe (ou quel appelant) l'invoque. Le rattachement
#             Identite<->Device (provisionner_secure_enclave_employe /
#             verifier_secure_enclave_employe, 9 sept 2026) existe deja comme
#             registre, mais n'a aucun role causal dans autoriser_execution_action.
#
# LOI       : une action gouvernee ne s'execute pas seulement parce qu'un
#             device de confiance est present — elle exige que l'employe
#             invoquant l'action soit explicitement identifie ET confirme
#             comme rattache a CE device precis. L'absence de person_id
#             n'est jamais un defaut permissif : elle bloque la porte.
#
# HOQ       : la Couche 4 reutilise fidelement verifier_secure_enclave_employe
#             (meme discipline que les Couches 1-3 : composer, jamais dupliquer
#             une logique dejà constituee). person_id absent = refus explicite
#             (PERSON_ID_ABSENT), jamais une confirmation par defaut.
#
# SEQUENCE  : apres la Couche 3, si person_id est fourni -> appeler
#             verifier_secure_enclave_employe(person_id) -> exiger
#             CONFIRME_PC_BUREAU ou CONFIRME_PC_PERSONNEL. Si person_id est
#             absent, ou si le verdict est NON_PROVISIONNE / DIVERGENT /
#             EMPLOYE_INCONNU, la Couche 4 echoue et bloque la porte, non
#             compensee par les Couches 1-3 meme toutes vertes.
#
# CODE      : parametre person_id ajoute a la signature, logique Couche 4
#             ajoutee dans le corps, ci-dessous.
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
# MISE A JOUR (13 sept 2026) : COUCHE 4 SUR PREUVE MATERIELLE REELLE
# ------------------------------------------------------------------------------
# Chaine constitutive de cette mise a jour : PROBLEME -> LOI -> HOQ -> SEQUENCE -> CODE
#
# PROBLEME  : la Couche 4 reposait sur verifier_secure_enclave_employe, une
#             derivation logicielle sha256(mac|pcr16) — verifiable, mais
#             recalculable par quiconque connait mac+pcr16, jamais une preuve
#             que la puce Secure Enclave reelle de CE device a materiellement
#             signe quoi que ce soit. Piste Silicium (10-13 sept 2026) a
#             construit une preuve challenge/signature reelle
#             (verifier_secure_enclave_reel_employe), restee non raccordee a
#             la Porte de Gouvernance.
#
# LOI       : une signature valide seule ne suffit jamais a ouvrir la Porte —
#             elle doit appartenir a un person_id explicite, rattache a un
#             type_device explicite, verifiee par une preuve materielle
#             fraiche et non rejouable. L'absence de l'un ou l'autre bloque
#             la Couche 4, jamais une confirmation par defaut.
#
# HOQ       : la Couche 4 reutilise fidelement verifier_secure_enclave_reel_employe
#             (meme discipline de composition que les Couches 1-3, jamais une
#             logique dupliquee). person_id ou type_device absent = refus
#             explicite (PERSON_ID_ABSENT / TYPE_DEVICE_ABSENT), jamais une
#             confirmation par defaut. L'ancienne verifier_secure_enclave_employe
#             reste disponible comme outil independant, mais n'est plus
#             appelee par la Porte de Gouvernance.
#
# SEQUENCE  : apres la Couche 3, si person_id ET type_device sont fournis ->
#             appeler verifier_secure_enclave_reel_employe(person_id,
#             type_device) -> exiger verdict SIGNATURE_VALIDE. Sinon, ou si
#             le verdict est SIGNATURE_INVALIDE / NON_PROVISIONNE /
#             EMPLOYE_INCONNU / TYPE_DEVICE_INVALIDE / ECHEC_SECURE_ENCLAVE,
#             la Couche 4 echoue et bloque la porte, non compensee par les
#             Couches 1-3 meme toutes vertes.
#
# CODE      : parametre type_device ajoute a la signature, logique Couche 4
#             remplacee dans le corps, ci-dessous.
# ------------------------------------------------------------------------------
# ------------------------------------------------------------------------------
# OUTIL · COUCHE 5 · SUBORDINATION EMPLOYE -> ENTREPRISE (ajout 15 sept 2026)
# ------------------------------------------------------------------------------
# Chaine constitutive : PROBLEME -> LOI -> HOQ -> SEQUENCE -> CODE
#
# PROBLEME  : verifier_mandat_agent_correia (Couche 2) teste si la
#             destination est DANS_MANDAT pour L'ENTREPRISE (n'importe
#             quelle zone de ZONES_MANDAT_CORREIA, Paris OU Abidjan). Un
#             employe enregistre avec mandatZoneNom="ABIDJAN" pouvait donc
#             voir la Porte s'ouvrir pour une action a Paris, tant que
#             Paris restait dans le mandat de l'entreprise — sans que rien
#             ne verifie que CET employe, precisement, est habilite sur
#             CETTE zone. Chantier 5 (identifie le 9 sept 2026, jamais
#             code jusqu'ici) : "un employe peut avoir [a agir sur] un
#             mandat plus large que celui auquel il est rattache, sans que
#             la chaine actuelle ne le detecte."
#
# LOI       : le mandat de l'entreprise est une condition necessaire, mais
#             jamais suffisante. La zone effectivement matchee au niveau
#             entreprise (Couche 2) doit EN PLUS correspondre a la zone de
#             mandat declaree dans la fiche gouvernee de CET employe
#             (person_id). Aucune fiche employe, ou zone entreprise non
#             egale a la zone declaree de l'employe = refus explicite,
#             jamais une confirmation par defaut ni une compensation par
#             les autres couches.
#
# HOQ       : subordination stricte, non compensatoire, sur simple egalite
#             de nom de zone (mandatZoneNom de la fiche == zoneMatchee de
#             Couche 2) — pas d'heritage implicite, pas d'union de zones
#             tant qu'aucune fiche ne declare explicitement plusieurs zones.
#
# SEQUENCE  : recevoir person_id + zone_matchee (issue de Couche 2) ->
#             lire la fiche employe -> comparer mandatZoneNom a
#             zone_matchee -> SUBORDINATION_CONFORME ou
#             SUBORDINATION_DEPASSEE / EMPLOYE_INCONNU / AUCUNE_ZONE_MATCHEE.
#
# CODE      : verifier_subordination_mandat_employe, ci-dessous ; raccordee
#             a autoriser_execution_action comme Couche 5.
# ------------------------------------------------------------------------------
@mcp.tool()
def verifier_subordination_mandat_employe(person_id: str, zone_matchee: Optional[str]) -> dict:
    """
    [LECTURE REELLE — ~/.ctsm_registre_employes.json, aucune supposition]
    Couche 5 · Subordination Employe -> Entreprise. Verifie que la zone de
    mandat ENTREPRISE effectivement matchee pour la destination visee
    (zone_matchee, produite par verifier_mandat_agent_correia) correspond
    bien a la zone de mandat declaree pour CET employe (mandatZoneNom dans
    sa fiche gouvernee) — jamais deduite, jamais supposee par defaut.

    Limite a ne jamais masquer : ce test compare des NOMS de zone declares
    (chaines exactes), pas une geometrie. Une fiche mal saisie (zone
    inexistante ou mal orthographiee) produira EMPLOYE_HORS_SUBORDINATION
    plutot qu'une erreur de saisie signalee comme telle — a corriger cote
    fiche, jamais compense silencieusement cote porte.

    Args:
        person_id: identifiant de l'employe deja enregistre
        zone_matchee: nom de la zone matchee au niveau entreprise (issu de
                verifier_mandat_agent_correia), ou None si aucune zone
                entreprise n'a matche

    Returns:
        {"verdict": "SUBORDINATION_CONFORME" | "SUBORDINATION_DEPASSEE" |
         "EMPLOYE_INCONNU" | "AUCUNE_ZONE_MATCHEE", ...}
    """
    if zone_matchee is None:
        return {
            "verdict": "AUCUNE_ZONE_MATCHEE",
            "personId": person_id,
            "message": "Aucune zone entreprise n'a matche la destination — rien a subordonner, refus en amont deja acquis (Couche 2).",
        }

    registre = _lire_registre_employes()
    fiche = registre.get(person_id)
    if fiche is None:
        return {
            "verdict": "EMPLOYE_INCONNU",
            "personId": person_id,
            "message": "Aucune fiche enregistree pour ce person_id — inscrire_employe_gouverne doit preceder cette verification.",
        }

    mandat_zone_employe = fiche.get("mandatZoneNom")
    conforme = mandat_zone_employe == zone_matchee

    return {
        "verdict": "SUBORDINATION_CONFORME" if conforme else "SUBORDINATION_DEPASSEE",
        "personId": person_id,
        "mandatZoneEmploye": mandat_zone_employe,
        "zoneEntrepriseMatchee": zone_matchee,
        "message": (
            "La zone matchee au niveau entreprise correspond au mandat declare de l'employe."
            if conforme else
            f"Depassement de mandat employe : zone entreprise matchee '{zone_matchee}' != zone declaree de l'employe '{mandat_zone_employe}'."
        ),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }


# ------------------------------------------------------------------------------
# OUTIL * COUCHE 6 * CONTINUITE DE CHAINE STAT (haOr baDerekh, ajout 15 sept 2026)
# ------------------------------------------------------------------------------
# Chaine constitutive : PROBLEME -> LOI -> HOQ -> SEQUENCE -> CODE
#
# PROBLEME  : chaque appel a autoriser_execution_action est une porte
#             ponctuelle, independante de tout appel precedent. Rien
#             n'empeche un orchestrateur en amont de soumettre le pas N+2
#             sans que le pas N+1 n'ait ete reellement scelle -- l'agent
#             peut halluciner un achevement non prouve. Ecrit a partir de
#             tests poses avant le code (test_couche6_chaine_stat.py),
#             discipline "tests avant coding".
#
# LOI       : un pas ne peut etre autorise que s'il porte la preuve exacte
#             du dernier pas reellement scelle pour CETTE identite
#             (person_id) -- jamais une confirmation par defaut, jamais une
#             chaine partagee entre identites distinctes.
#
# HOQ       : chaine GENESE -> CONFORME -> RUPTURE, une chaine par
#             person_id (granularite choisie et fixee par les tests), la
#             chaine n'avance que si la Porte a reellement ouvert
#             (jamais sur un refus).
#
# SEQUENCE  : recevoir person_id + previous_stat_hash -> lire le dernier
#             hash reellement enregistre pour ce person_id -> comparer ->
#             CHAINE_GENESE_ACCEPTEE / CHAINE_CONFORME / RUPTURE_CHAINE.
#             Apres verdict de la Porte, si AUTORISE : calculer le hash du
#             STAT et l'enregistrer comme nouveau dernier hash.
#
# CODE      : CHAINE_STAT_PATH, _lire_chaine_stat, _lire_dernier_hash_chaine,
#             _enregistrer_hash_chaine, _calculer_stat_hash,
#             _avancer_chaine_si_succes, verifier_continuite_chaine_stat,
#             ci-dessous ; raccordes a autoriser_execution_action comme
#             Couche 6.
# ------------------------------------------------------------------------------
CHAINE_STAT_PATH = os.path.expanduser("~/.ctsm_chaine_stat.json")


def _lire_chaine_stat() -> dict:
    if os.path.exists(CHAINE_STAT_PATH):
        try:
            with open(CHAINE_STAT_PATH, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def _lire_dernier_hash_chaine(person_id: str):
    chaine = _lire_chaine_stat()
    entree = chaine.get(person_id)
    return entree.get("dernierHash") if entree else None


def _enregistrer_hash_chaine(person_id: str, nouveau_hash: str) -> None:
    chaine = _lire_chaine_stat()
    entree = chaine.get(person_id, {"sequence": 0})
    entree["dernierHash"] = nouveau_hash
    entree["sequence"] = entree.get("sequence", 0) + 1
    entree["timestamp_utc"] = datetime.now(timezone.utc).isoformat()
    chaine[person_id] = entree
    with open(CHAINE_STAT_PATH, "w") as f:
        json.dump(chaine, f, indent=2, ensure_ascii=False)


def _calculer_stat_hash(resultat: dict) -> str:
    """Hash canonique (sha256, cles triees) du STAT -- fige des la premiere
    utilisation ; ne jamais changer la serialisation sans invalider toute
    chaine anterieure existante."""
    canonique = json.dumps(resultat, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(canonique.encode("utf-8")).hexdigest()


def _avancer_chaine_si_succes(person_id: str, resultat: dict) -> None:
    """La chaine n'avance JAMAIS sur un refus -- seulement sur un verdict
    AUTORISE reellement produit."""
    if not str(resultat.get("verdict", "")).startswith("AUTORISE"):
        return
    nouveau_hash = _calculer_stat_hash(resultat)
    _enregistrer_hash_chaine(person_id, nouveau_hash)


@mcp.tool()
def verifier_continuite_chaine_stat(person_id: str, previous_stat_hash: Optional[str]) -> dict:
    """
    [LECTURE REELLE -- ~/.ctsm_chaine_stat.json, aucune supposition]
    Couche 6 * Continuite de Chaine STAT (haOr baDerekh). Verifie que
    previous_stat_hash correspond exactement au dernier hash de STAT
    reellement enregistre pour CET person_id -- une chaine par identite,
    jamais partagee, jamais avancee sur un refus.

    Args:
        person_id: identifiant de l'employe invoquant l'action
        previous_stat_hash: hash du dernier STAT que l'appelant pretend
                avoir obtenu, ou "GENESIS" pour le tout premier appel
                d'une identite qui n'a encore aucune chaine enregistree

    Returns:
        {"verdict": "CHAINE_GENESE_ACCEPTEE" | "CHAINE_CONFORME" |
         "RUPTURE_CHAINE", ...}
    """
    if previous_stat_hash is None:
        return {
            "verdict": "RUPTURE_CHAINE",
            "personId": person_id,
            "message": "previous_stat_hash absent -- jamais une confirmation par defaut. Fournir le dernier hash reel, ou 'GENESIS' pour un premier appel.",
        }

    dernier_hash = _lire_dernier_hash_chaine(person_id)

    if dernier_hash is None:
        if previous_stat_hash == "GENESIS":
            return {
                "verdict": "CHAINE_GENESE_ACCEPTEE",
                "personId": person_id,
                "message": "Aucune chaine anterieure pour cette identite -- premier pas accepte.",
            }
        return {
            "verdict": "RUPTURE_CHAINE",
            "personId": person_id,
            "message": "Aucune chaine anterieure pour cette identite, mais previous_stat_hash != 'GENESIS'.",
        }

    conforme = previous_stat_hash == dernier_hash
    return {
        "verdict": "CHAINE_CONFORME" if conforme else "RUPTURE_CHAINE",
        "personId": person_id,
        "dernierHashConnu": dernier_hash,
        "previousStatHashFourni": previous_stat_hash,
        "message": (
            "Le hash fourni correspond au dernier STAT reellement scelle pour cette identite."
            if conforme else
            "Rupture de chaine : le hash fourni ne correspond pas au dernier STAT reellement scelle. Aucun pas anticipe ou hallucine n'est accepte."
        ),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }


# ------------------------------------------------------------------------------
# YAD EMET EFFECTOR · v1.1 (24 sept 2026) — voir 17-Bibliotheque_Tavnit AgentProof/
# 9-Primitives_AgentProof/6-YAD_EMET_EFFECTOR/ et MISE-A-JOUR-9-Primitives-AgentProof.md
# ------------------------------------------------------------------------------
# PROBLEME  : autoriser_execution_action calculait un verdict et une
#             signatureOpposable (HMAC sur un fichier arbitraire, sans TTL, sans
#             nonce, sans liaison a l'action precise) que rien n'obligeait un
#             outil d'effet a exiger avant d'agir. Demontre par
#             capture_GovernedAgent_1/2_...png (10 sept 2026) sur un mecanisme
#             different mais structurellement identique.
#
# LOI       : un effet reel ne peut etre produit sans un jeton signe, a usage
#             unique, borne dans le temps, lie par hash a l'action, au
#             person_id et au type_device exacts qui ont ete evalues par la
#             Porte de Gouvernance -- jamais un verdict texte que l'outil
#             d'effet pourrait choisir d'ignorer.
#
# HOQ       : jeton Ed25519, TTL maximum 300s (meme discipline que
#             effect-token-v04.mjs, depot N14), nonce a usage unique consomme
#             dans un registre local persistant. Cle privee generee au premier
#             usage, fichier 0600, jamais transmise. Un jeton absent, expire,
#             deja consomme, ou dont le binding ne correspond pas exactement
#             est refuse sans exception -- fail closed.
#
# SEQUENCE  : autoriser_execution_action emet le jeton SEULEMENT si
#             porte_ouverte est vraie -> l'outil d'effet appelle
#             verifier_et_consommer_jeton_effet avant toute mutation -> refus
#             immediat si invalide, sans effet partiel.
#
# CODE      : ci-dessous.
# ------------------------------------------------------------------------------
# EXCLUSIVE_CAPABILITY_OWNERSHIP (24 sept 2026) -- si MIDRASH_HAI_OS_SYSTEM_HOME
# est definie (positionnee par deployment/macos/install-MidrashHai_OS-System.sh
# une fois le compte systeme reellement cree), la cle et l'etat vivent dans un
# repertoire appartenant EXCLUSIVEMENT au compte MidrashHai_OS-System, 0700 --
# le compte qui lance ce process aujourd'hui (celui de l'utilisateur normal,
# via stdio depuis Claude Desktop/Codex) n'y a alors plus acces en ecriture.
# Sans cette variable (etat par defaut, avant installation), retombe sur
# ~/.ctsm_yad_emet_* comme avant -- rien ne casse pour qui n'a pas installe.
_MIDRASH_HAI_OS_SYSTEM_HOME = os.environ.get("MIDRASH_HAI_OS_SYSTEM_HOME")
if _MIDRASH_HAI_OS_SYSTEM_HOME:
    YAD_EMET_CLE_PATH = os.path.join(_MIDRASH_HAI_OS_SYSTEM_HOME, "yad-emet-effect-private.pem")
    YAD_EMET_STATE_PATH = os.path.join(_MIDRASH_HAI_OS_SYSTEM_HOME, "yad-emet-state.json")
else:
    YAD_EMET_CLE_PATH = os.path.expanduser("~/.ctsm_yad_emet_effect_private.pem")
    YAD_EMET_STATE_PATH = os.path.expanduser("~/.ctsm_yad_emet_state.json")
YAD_EMET_TTL_SECONDES = 300


def _yad_emet_cle_privee() -> ed25519.Ed25519PrivateKey:
    if os.path.exists(YAD_EMET_CLE_PATH):
        with open(YAD_EMET_CLE_PATH, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    cle = ed25519.Ed25519PrivateKey.generate()
    pem = cle.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    fd = os.open(YAD_EMET_CLE_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
    return cle


def _yad_emet_etat() -> dict:
    if os.path.exists(YAD_EMET_STATE_PATH):
        try:
            with open(YAD_EMET_STATE_PATH, "r") as f:
                return json.load(f)
        except Exception:  # noqa: BLE001
            pass
    return {"schema": "YAD_EMET_EFFECTOR_STATE_V1_1", "joncsConsommes": []}


def _yad_emet_sauver_etat(etat: dict) -> None:
    tmp = f"{YAD_EMET_STATE_PATH}.tmp"
    with open(tmp, "w") as f:
        json.dump(etat, f, indent=2, ensure_ascii=False)
    os.replace(tmp, YAD_EMET_STATE_PATH)


def _yad_emet_canonicaliser(valeur) -> str:
    return json.dumps(valeur, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def emettre_jeton_effet(action_id: str, person_id: Optional[str], type_device: Optional[str], scope: str) -> dict:
    """N'appeler que depuis autoriser_execution_action, et seulement si
    porte_ouverte est vraie. Jeton a usage unique, TTL 300s, lie par hash aux
    quatre champs exacts qui devront etre presentes tels quels a la verification."""
    cle = _yad_emet_cle_privee()
    maintenant = datetime.now(timezone.utc)
    charge_utile = {
        "schema": "YAD_EMET_EFFECT_TOKEN_V1_1",
        "tokenId": f"yet-{uuid.uuid4()}",
        "nonce": secrets.token_hex(16),
        "actionId": action_id,
        "personId": person_id,
        "typeDevice": type_device,
        "scope": scope,
        "issuedAtIso": maintenant.isoformat(),
        "validUntilIso": (maintenant.timestamp() + YAD_EMET_TTL_SECONDES),
    }
    charge_utile["validUntilIso"] = datetime.fromtimestamp(charge_utile["validUntilIso"], tz=timezone.utc).isoformat()
    signature = cle.sign(_yad_emet_canonicaliser(charge_utile).encode("utf-8"))
    return {"tokenPayload": charge_utile, "signatureBase64": base64.b64encode(signature).decode("ascii")}


def verifier_et_consommer_jeton_effet(jeton: Optional[dict], action_id_attendu: str, person_id_attendu: Optional[str], type_device_attendu: Optional[str], scope_attendu: str) -> dict:
    """La garde d'effet elle-meme. Verifie signature, TTL, unicite (registre
    local persistant), et correspondance EXACTE de action_id/person_id/
    type_device/scope -- jamais une correspondance partielle. Consomme le
    jeton (usage unique) uniquement si tout le reste est valide."""
    if not jeton or not isinstance(jeton, dict) or "tokenPayload" not in jeton or "signatureBase64" not in jeton:
        return {"autorise": False, "raison": "JETON_ABSENT"}
    charge = jeton["tokenPayload"]
    try:
        cle_publique = _yad_emet_cle_privee().public_key()
        cle_publique.verify(base64.b64decode(jeton["signatureBase64"]), _yad_emet_canonicaliser(charge).encode("utf-8"))
    except (InvalidSignature, Exception):  # noqa: BLE001
        return {"autorise": False, "raison": "SIGNATURE_INVALIDE"}

    maintenant = datetime.now(timezone.utc)
    try:
        expire_le = datetime.fromisoformat(charge["validUntilIso"])
    except Exception:  # noqa: BLE001
        return {"autorise": False, "raison": "TTL_ILLISIBLE"}
    if maintenant > expire_le:
        return {"autorise": False, "raison": "JETON_EXPIRE"}

    if (
        charge.get("actionId") != action_id_attendu
        or charge.get("personId") != person_id_attendu
        or charge.get("typeDevice") != type_device_attendu
        or charge.get("scope") != scope_attendu
    ):
        return {"autorise": False, "raison": "BINDING_NON_CORRESPONDANT"}

    etat = _yad_emet_etat()
    token_id = charge.get("tokenId")
    if not token_id or token_id in etat["joncsConsommes"]:
        return {"autorise": False, "raison": "JETON_REJOUE"}

    etat["joncsConsommes"].append(token_id)
    _yad_emet_sauver_etat(etat)
    return {"autorise": True, "raison": "EFFET_AUTORISE", "tokenId": token_id}


# ------------------------------------------------------------------------------
# GATE SOUVERAINE · v1.0 (24 sept 2026) — voir 17-Bibliotheque_Tavnit AgentProof/
# 9-Primitives_AgentProof/9-GATE_SOUVERAINE/
# ------------------------------------------------------------------------------
# PROBLEME  : YAD_EMET_EFFECTOR garantit la fidelite d'execution (un effet ne
#             sort jamais sans jeton valide), jamais la justesse de la
#             decision. Rien ne demande a un humain d'approuver une action
#             classee irreversible avant que le Gate ne signe un jeton.
#
# LOI       : pour toute action_id classee irreversible, aucun jeton d'effet
#             n'est emis sans une signature FRAICHE (nonce nouveau a chaque
#             appel, jamais rejouable) d'un compte souverain distinct du
#             compte qui fait tourner ce process. L'agent ne peut jamais
#             signer sa propre autorisation souveraine (AIMPL-005) : la cle
#             vit dans le Secure Enclave du compte macOS personnel de
#             l'utilisateur, jamais dans MidrashHai_OS-System.
#
# HOQ       : reutilise le challenge/signature deja reel et teste de
#             verifier_secure_enclave_reel_employe -- pas un nouveau
#             mecanisme cryptographique, un nouveau person_id distinct
#             (SOUVERAIN_PERSON_ID) qui ne doit jamais etre confondu avec un
#             employe ordinaire ni avec le compte de service.
#
# SEQUENCE  : provisionnement une fois, physiquement, par l'utilisateur
#             (inscrire_employe_gouverne puis provisionner_secure_enclave_
#             reel_employe pour SOUVERAIN_PERSON_ID) -> a chaque action
#             classee irreversible, autoriser_execution_action exige un
#             verdict SIGNATURE_VALIDE frais avant d'emettre le jeton.
#
# LIMITE HONNETE : la verification materielle reelle (Touch ID) n'a pas ete
# demontree par l'agent qui a ecrit ce code -- aucun acces a une session
# graphique ni a la puce Secure Enclave depuis l'outil qui a produit ce
# fichier. Seule la logique de branchement (classe irreversible -> exige
# signature fraiche -> refuse sans SIGNATURE_VALIDE) a ete testee, avec la
# frontiere materielle simulee. Provisionnement et premiere verification
# reelle restent a faire par l'utilisateur, physiquement.
# ------------------------------------------------------------------------------
SOUVERAIN_PERSON_ID = "midrash-hai-souverain"
SOUVERAIN_TYPE_DEVICE_DEFAUT = "PC_PERSONNEL"
ACTIONS_CLASSEES_IRREVERSIBLES = {
    ACTION_ID_ECRIRE_INCIDENT,
}  # classification volontairement minimale au depart -- a etendre explicitement,
   # jamais par deduction, chaque ajout doit etre une decision consciente.


def exiger_autorisation_souveraine(action_id: str, type_device_souverain: str = SOUVERAIN_TYPE_DEVICE_DEFAUT) -> dict:
    """Couche zero, avant toute emission de jeton d'effet, pour les actions
    classees irreversibles. Ne remplace jamais autoriser_execution_action --
    s'ajoute en precondition. Une action non classee irreversible passe
    sans friction (requise=False)."""
    if action_id not in ACTIONS_CLASSEES_IRREVERSIBLES:
        return {"requise": False, "autorise": True, "raison": "ACTION_NON_CLASSEE_IRREVERSIBLE"}
    verdict = verifier_secure_enclave_reel_employe(SOUVERAIN_PERSON_ID, type_device_souverain)
    if verdict.get("verdict") != "SIGNATURE_VALIDE":
        return {"requise": True, "autorise": False, "raison": f"SOUVERAIN_NON_CONFIRME:{verdict.get('verdict')}"}
    return {"requise": True, "autorise": True, "raison": "SOUVERAIN_CONFIRME_FRAIS"}


@mcp.tool()
def autoriser_execution_action(
    latitude: float,
    longitude: float,
    pcr16_attendu: str,
    payload_file: str,
    person_id: Optional[str] = None,
    type_device: Optional[str] = None,
    horizontal_accuracy_m: Optional[float] = None,
    bearing_deg: Optional[float] = None,
    destination_lat: Optional[float] = None,
    destination_lon: Optional[float] = None,
    previous_stat_hash: Optional[str] = None,
    action_id: Optional[str] = None,
    scope: str = "PUBLIC_GOVERNED_ACTION",
) -> dict:
    """
    GovernedAgent™ v1.1 (24 sept 2026) — YAD_EMET_EFFECTOR intégrée.
    Si la Porte ouvre ET que action_id est fourni, un jetonEffet Ed25519 à
    usage unique (TTL 300s) est émis, lié par hash à action_id/person_id/
    type_device/scope. Sans action_id, aucun jeton n'est émis — comportement
    inchangé pour les appelants existants qui ne le fournissent pas encore.
    Les outils d'effet doivent exiger ce jeton via
    verifier_et_consommer_jeton_effet() avant toute mutation ; voir
    ecrire_incident_urgence_pc_personnel pour la première intégration réelle.
    [PORTE DE GOUVERNANCE — compose 6 couches deja reelles, ne les duplique
    pas] Refuse ou autorise l'execution d'une action gouvernee en exigeant
    que les six couches suivantes soient TOUTES vertes, sans compensation
    possible de l'une par les autres :

      1. Position/Presence : le point converti (PCNT Zera 1cm, jamais le
         GPS brut — Loi du 7 sept 2026) doit produire un statut de
         gouvernance suffisant (LIEU_CONFIRME_PAR_TEMOIN ou
         GOVERNED_POSITION_CANDIDATE). INCERTAIN_MARGE_PRECISION_TEMOIN,
         AMBIGUOUS, HORS_LIEU_TEMOIN, etc. bloquent la porte.
      2. Mandat/Juridiction : la destination visee doit etre DANS_MANDAT
         (verifier_mandat_agent_correia).
      3. Enclave/Domanial : la triangulation a trois noeuds (Sol, Demeure,
         Institution/PCR16 emule) doit etre ACCORDÉE
         (verifier_secure_enclave_et_position).
      4. Identite<->Device, sur preuve materielle reelle (mise a jour 13
         sept 2026) : person_id ET type_device doivent etre fournis
         explicitement, et verifier_secure_enclave_reel_employe doit
         retourner SIGNATURE_VALIDE — une preuve challenge/signature
         materielle fraiche par la puce Secure Enclave, jamais rejouable.
         Une signature valide seule ne suffit pas : elle doit appartenir
         a CE person_id, sur CE type_device precisement.
      5. Subordination Employe<->Entreprise (ajout 15 sept 2026, Chantier
         5) : la zone de mandat ENTREPRISE effectivement matchee pour la
         destination (Couche 2) doit correspondre a la zone de mandat
         declaree dans la fiche gouvernee de CET employe (person_id) —
         verifier_subordination_mandat_employe doit retourner
         SUBORDINATION_CONFORME. Non evaluee (refus explicite) si la
         Couche 4 n'est pas deja verte : aucun person_id fiable sur lequel
         subordonner quoi que ce soit.
      6. Continuite de Chaine STAT (haOr baDerekh, ajout 15 sept 2026,
         ecrit selon la discipline tests-avant-code) : previous_stat_hash
         doit correspondre exactement au dernier hash de STAT reellement
         scelle pour ce person_id, ou etre "GENESIS" pour le tout premier
         appel d'une identite sans chaine anterieure. Non evaluee (refus
         explicite) si la Couche 5 n'est pas deja verte. La chaine n'avance
         que si la Porte ouvre reellement -- jamais sur un refus.

    Args:
        latitude, longitude: observation GPS brute de l'agent au moment de
                l'action (converti en interne, jamais utilise brut en decision)
        pcr16_attendu, payload_file: voir verifier_secure_enclave_et_position
        person_id: identifiant de l'employe invoquant l'action. Absent =
                Couche 4 refusee explicitement (PERSON_ID_ABSENT), jamais
                une confirmation par defaut.
        type_device: "PC_BUREAU" ou "PC_PERSONNEL", jamais devine. Absent =
                Couche 4 refusee explicitement (TYPE_DEVICE_ABSENT).
        horizontal_accuracy_m, bearing_deg: transmis tels quels a pcnt_zera_1cm
        destination_lat, destination_lon: destination visee par l'action pour
                le test de mandat ; par defaut, identique a latitude/longitude
                (l'action est executee la ou l'agent se trouve)
        previous_stat_hash: hash du dernier STAT reellement obtenu pour ce
                person_id, ou "GENESIS" pour un premier appel. Absent =
                Couche 6 refusee explicitement, jamais une confirmation par
                defaut.

    Returns:
        {"verdict": "AUTORISE [PORTE_OUVERTE]", ...} avec les quatre preuves,
        ou {"verdict": "REFUSE [PORTE_FERMEE]", "causeRefus": [...], ...}
        des qu'une seule couche echoue — jamais une execution partielle.
    """
    _verrou = _exiger_petihah()
    if _verrou:
        return _verrou

    dest_lat = destination_lat if destination_lat is not None else latitude
    dest_lon = destination_lon if destination_lon is not None else longitude

    # Couche 1 · Position/Presence — jamais sur le GPS brut, uniquement via
    # la chaine PCNT Zera 1cm deja gouvernee.
    receipt_position = pcnt_zera_1cm(
        latitude=latitude, longitude=longitude,
        horizontal_accuracy_m=horizontal_accuracy_m, bearing_deg=bearing_deg,
        mode="GOVERNED_REFINEMENT",
    )
    statut_position = receipt_position.get("governance", {}).get("status")
    position_ok = statut_position in STATUTS_POSITION_SUFFISANTS

    # Couche 2 · Mandat/Juridiction
    verdict_mandat = verifier_mandat_agent_correia(dest_lat, dest_lon)
    mandat_ok = verdict_mandat.get("statut_domanial") == "DESTINATION_CONFORME_AU_MANDAT"

    # Couche 3 · Enclave/Domanial (triangulation a trois noeuds)
    verdict_enclave = verifier_secure_enclave_et_position(
        pcr16_attendu=pcr16_attendu, payload_file=payload_file,
        mesure_lat=latitude, mesure_lon=longitude,
    )
    enclave_ok = verdict_enclave.get("verdict", "").startswith("ACCORDÉ")

    # Couche 4 · Identite<->Device, sur preuve materielle reelle (13 sept
    # 2026) — non compensatoire, jamais une confirmation par defaut si
    # person_id ou type_device est absent.
    if person_id is None:
        verdict_identite = "PERSON_ID_ABSENT"
        identite_ok = False
    elif type_device is None:
        verdict_identite = "TYPE_DEVICE_ABSENT"
        identite_ok = False
    else:
        verdict_identite_brut = verifier_secure_enclave_reel_employe(person_id, type_device)
        verdict_identite = verdict_identite_brut.get("verdict")
        identite_ok = verdict_identite == "SIGNATURE_VALIDE"

    # Couche 5 * Subordination Employe -> Entreprise (ajout 15 sept 2026,
    # Chantier 5) -- non compensatoire, jamais evaluee si Couche 4 a deja
    # echoue (aucun person_id fiable sur lequel subordonner quoi que ce
    # soit), mais bloquante meme si les Couches 1-4 sont toutes vertes.
    if identite_ok:
        verdict_subordination_brut = verifier_subordination_mandat_employe(
            person_id=person_id, zone_matchee=verdict_mandat.get("zoneMatchee"),
        )
        verdict_subordination = verdict_subordination_brut.get("verdict")
        subordination_ok = verdict_subordination == "SUBORDINATION_CONFORME"
    else:
        verdict_subordination_brut = None
        verdict_subordination = "COUCHE_4_PREALABLE_NON_VERTE"
        subordination_ok = False

    # Couche 6 * Continuite de Chaine STAT (haOr baDerekh, ajout 15 sept
    # 2026) -- non compensatoire, jamais evaluee si la Couche 5 a deja
    # echoue (rien de coherent sur quoi faire porter la continuite).
    if subordination_ok:
        verdict_chaine_brut = verifier_continuite_chaine_stat(
            person_id=person_id, previous_stat_hash=previous_stat_hash,
        )
        verdict_chaine = verdict_chaine_brut.get("verdict")
        chaine_ok = verdict_chaine in ("CHAINE_GENESE_ACCEPTEE", "CHAINE_CONFORME")
    else:
        verdict_chaine_brut = None
        verdict_chaine = "COUCHE_5_PREALABLE_NON_VERTE"
        chaine_ok = False

    causes_refus = []
    if not position_ok:
        causes_refus.append(f"POSITION_INSUFFISANTE : statut={statut_position}")
    if not mandat_ok:
        causes_refus.append(f"HORS_MANDAT : {verdict_mandat.get('statut_domanial')}")
    if not enclave_ok:
        causes_refus.append(f"ENCLAVE_REFUSEE : {verdict_enclave.get('verdict')}")
    if not identite_ok:
        causes_refus.append(f"IDENTITE_DEVICE_REFUSEE : {verdict_identite}")
    if not subordination_ok:
        causes_refus.append(f"SUBORDINATION_REFUSEE : {verdict_subordination}")
    if not chaine_ok:
        causes_refus.append(f"RUPTURE_CHAINE : {verdict_chaine}")

    porte_ouverte = position_ok and mandat_ok and enclave_ok and identite_ok and subordination_ok and chaine_ok

    resultat = {
        "verdict": "AUTORISE [PORTE_OUVERTE]" if porte_ouverte else "REFUSE [PORTE_FERMEE]",
        "coucheUne_position": {
            "statut": statut_position, "ok": position_ok,
            "contexteTerritorial": receipt_position.get("contexteTerritorial"),
        },
        "coucheDeux_mandat": {
            "statut": verdict_mandat.get("statut_domanial"), "ok": mandat_ok,
            "distanceAuCentreParisKm": verdict_mandat.get("distance_au_centre_paris_km"),
        },
        "coucheTrois_enclave": {
            "verdict": verdict_enclave.get("verdict"), "ok": enclave_ok,
            "triangulation": verdict_enclave.get("triangulation"),
        },
        "coucheQuatre_identite": {
            "verdict": verdict_identite, "ok": identite_ok,
            "personId": person_id,
            "typeDevice": type_device,
        },
        "coucheCinq_subordination": {
            "verdict": verdict_subordination, "ok": subordination_ok,
            "mandatZoneEmploye": (verdict_subordination_brut or {}).get("mandatZoneEmploye"),
            "zoneEntrepriseMatchee": verdict_mandat.get("zoneMatchee"),
        },
        "coucheSix_chaineStat": {
            "verdict": verdict_chaine, "ok": chaine_ok,
            "dernierHashConnu": (verdict_chaine_brut or {}).get("dernierHashConnu"),
        },
        "causeRefus": causes_refus,
        "signatureOpposable": verdict_enclave.get("signature_opposable") if porte_ouverte else None,
        "message": (
            "Les six couches sont vertes : position confirmee, mandat couvert, "
            "enclave accordee, identite du device confirmee, subordination employe->entreprise conforme, "
            "continuite de chaine STAT confirmee. Action executable."
            if porte_ouverte else
            "Refus non compensatoire : au moins une couche a echoue. Voir causeRefus."
        ),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }

    # La chaine STAT n'avance QUE si la Porte a reellement ouvert -- jamais
    # sur un refus, meme partiel.
    if porte_ouverte and person_id is not None:
        _avancer_chaine_si_succes(person_id, resultat)

    # GATE SOUVERAINE -- couche zero pour les actions classees irreversibles,
    # AVANT toute emission de jeton. Une signature souveraine manquante ou
    # perimee bloque l'emission meme si les six couches precedentes sont
    # toutes vertes.
    verdict_souverain = None
    if porte_ouverte and action_id:
        verdict_souverain = exiger_autorisation_souveraine(action_id)
        if verdict_souverain["requise"] and not verdict_souverain["autorise"]:
            porte_ouverte = False
            causes_refus.append(f"GATE_SOUVERAINE_REFUSEE : {verdict_souverain['raison']}")
            resultat["verdict"] = "REFUSE [PORTE_FERMEE]"
            resultat["causeRefus"] = causes_refus
    if verdict_souverain is not None:
        resultat["gateSouveraine"] = verdict_souverain

    # YAD_EMET_EFFECTOR v1.1 -- emission du jeton d'effet, seulement si la
    # Porte ouvre reellement (Gate Souveraine comprise) ET que l'appelant a
    # fourni l'action_id precise qu'il compte ensuite presenter a un outil
    # d'effet.
    if porte_ouverte and action_id:
        resultat["jetonEffet"] = emettre_jeton_effet(action_id, person_id, type_device, scope)
    elif action_id and not porte_ouverte:
        resultat["jetonEffet"] = None

    return resultat


# ------------------------------------------------------------------------------
# OUTIL 4 : RÉSOLUTION RÉELLE DE PRÉSENCE · EMPLOYÉ ABIDJAN
# ------------------------------------------------------------------------------
@mcp.tool()
def resoudre_presence_employe_abidjan(
    person_id: str,
    lat: float,
    lon: float,
    icl_bureau_reference: Optional[str] = ICL_ABRAND_ABIDJAN,
    session_id: Optional[str] = None,
) -> dict:
    """
    [RÉEL — appel réseau effectif] Résout une position WGS84 en présence
    territoriale réelle via le Cockpit Spatial™ API (POST /v1/resolve-presence),
    puis évalue la conformité de position par ÉGALITÉ D'ICL, pas par distance
    en mètres (voir note v1.2 en en-tête de fichier : l'API réelle ne renvoie
    aucune distance, aucune rue, aucune adresse PADA).

    Args:
        person_id: identifiant d'acteur déjà inscrit via POST /v1/auth
                    (obligatoire côté API réelle — sans lui : ERR_PERSON_ID_MISSING)
        lat: latitude WGS84 de la position mesurée de l'employée
        lon: longitude WGS84 de la position mesurée de l'employée
        icl_bureau_reference: ICL de référence du bureau Abrand News. Par défaut,
                    la constante ICL_ABRAND_ABIDJAN ("2733|8589"), calculée avec le
                    vrai pcnt.js sur les coordonnées déclarées du bureau (Cocody
                    Angré 7ème, Agent✦490 · Nochehut). Passer explicitement None
                    pour désactiver la comparaison et n'obtenir que l'état
                    territorial brut — l'outil ne devine jamais un verdict sans
                    référence.
        session_id: identifiant de session optionnel, transmis tel quel à l'API

    Returns:
        En cas de succès réseau : verdict de conformité fondé sur l'égalité d'ICL
        (si icl_bureau_reference fourni) ou état territorial brut (sinon).
        En cas d'échec réseau : statut explicite d'indisponibilité — jamais
        un verdict simulé de repli.
    """
    _verrou = _exiger_petihah()
    if _verrou:
        return _verrou

    result = _call_resolve_presence(person_id, lat, lon, session_id)

    if not result["ok"]:
        return {
            "verdict": "INDÉTERMINÉ [SERVICE_INDISPONIBLE]",
            "statut_domanial": "RESOLUTION_IMPOSSIBLE",
            "message": (
                "Le Cockpit Spatial™ API n'a pas répondu dans les délais ou a "
                f"renvoyé une erreur : {result['error']}. Aucun verdict de conformité "
                "territoriale ne peut être émis sans résolution réelle de la présence. "
                "Vérifier que le service Render est bien réveillé (cockpit-spatial-api.onrender.com)."
            ),
            "source": "Cockpit Spatial™ API (échec)",
        }

    data = result["data"]

    # Schéma réel confirmé par lecture de resolve-presence.js (dépôt
    # MidrashHai/cockpit-spatial-api, branche main) :
    #   { status, presence, lieu: { icl, nom?, collectivite?, mishkan_index?,
    #     contexte_actif } , role, ressources: [...],
    #     icl_computed: { identifiant, guematria, mishkan_index } }
    lieu = data.get("lieu") or {}
    icl_mesure = (data.get("icl_computed") or {}).get("identifiant")
    contexte_actif = bool(lieu.get("contexte_actif"))
    zone_nom = lieu.get("nom")
    role_resolu = data.get("role")

    if icl_bureau_reference is None:
        return {
            "verdict": "INDÉTERMINÉ [RÉFÉRENCE_MANQUANTE]",
            "statut_domanial": "ETAT_TERRITORIAL_BRUT",
            "message": (
                "Aucun icl_bureau_reference fourni : impossible de trancher la "
                "conformité de position au bureau précis. Voici l'état territorial "
                "brut renvoyé par l'API, à toi de fournir l'ICL de référence du "
                "bureau pour obtenir un verdict."
            ),
            "icl_mesure": icl_mesure,
            "zone_gouvernee": contexte_actif,
            "zone_nom": zone_nom,
            "role_resolu": role_resolu,
            "reponse_brute": data,
        }

    conforme = (icl_mesure is not None) and (icl_mesure == icl_bureau_reference)

    return {
        "verdict": "ACCÈS ACCORDÉ" if conforme else "REFUS MAINTENU",
        "statut_domanial": "ICL_CONFORME" if conforme else "ICL_HORS_CELLULE_BUREAU",
        "icl_mesure": icl_mesure,
        "icl_bureau_reference": icl_bureau_reference,
        "zone_gouvernee": contexte_actif,
        "zone_nom": zone_nom,
        "role_resolu": role_resolu,
        "position_evaluee": {"lat": lat, "lon": lon},
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "source": "Cockpit Spatial™ API · POST /v1/resolve-presence (appel réel)",
    }


# ------------------------------------------------------------------------------
# OUTIL 4bis : ACQUISITION GPS RÉELLE (CORELOCATION MACOS) · 7 sept 2026
# ------------------------------------------------------------------------------
# [RÉEL — capteur système, sous consentement explicite] Utilise l'API native
# CoreLocation de macOS via pyobjc-framework-CoreLocation. Le premier appel
# déclenche la VRAIE boîte de dialogue système macOS ("[processus] souhaite
# utiliser votre position"), identique à celle de Plans ou Météo — ce n'est
# pas une simulation de dialogue, c'est le mécanisme d'autorisation natif de
# macOS. Une fois autorisé, le système la mémorise pour ce processus.
#
# Dépendance requise, à installer côté interpréteur qui exécute ce serveur :
#   /Library/Frameworks/Python.framework/Versions/3.13/bin/python3.13 -m pip \
#       install --user --only-binary=:all: pyobjc-framework-CoreLocation
#
# Limite honnête : un processus Python en ligne de commande n'a pas toujours
# une fiche System Settings dédiée comme une vraie application empaquetée ;
# selon la configuration macOS, l'autorisation peut apparaître sous le nom de
# l'interpréteur Python lui-même dans Réglages Système → Confidentialité et
# sécurité → Service de localisation, plutôt que sous "Claude Desktop".
# Corrigé le 7 sept 2026 : la classe Objective-C du delegate doit être
# déclarée UNE SEULE FOIS au niveau du module, pas recréée à chaque appel.
# Le serveur MCP est un processus persistant entre deux appels d'outil ;
# redéfinir une classe Objective-C de même nom au runtime déclenche
# "overriding existing Objective-C class" dès le deuxième appel.
_GPS_ETAT_PARTAGE = {"fix": None, "erreur": None, "termine": False}
_GPS_DELEGATE_CLASS = None


def _obtenir_classe_delegate_gps():
    global _GPS_DELEGATE_CLASS
    if _GPS_DELEGATE_CLASS is not None:
        return _GPS_DELEGATE_CLASS

    from Foundation import NSObject

    class _DelegateGPS(NSObject):
        def locationManager_didUpdateLocations_(self, manager, locations):
            if locations and not _GPS_ETAT_PARTAGE["termine"]:
                loc = locations[-1]
                coord = loc.coordinate()
                _GPS_ETAT_PARTAGE["fix"] = {
                    "lat": float(coord.latitude),
                    "lon": float(coord.longitude),
                    "precision_horizontale_m": float(loc.horizontalAccuracy()),
                    "timestamp_utc": str(loc.timestamp()),
                }
                _GPS_ETAT_PARTAGE["termine"] = True

        def locationManager_didFailWithError_(self, manager, error):
            _GPS_ETAT_PARTAGE["erreur"] = str(error)
            _GPS_ETAT_PARTAGE["termine"] = True

    _GPS_DELEGATE_CLASS = _DelegateGPS
    return _GPS_DELEGATE_CLASS


def _acquerir_gps_reel(timeout_secondes: float = 15.0) -> dict:
    try:
        from CoreLocation import CLLocationManager
        from Foundation import NSRunLoop, NSDate
    except ImportError as e:
        return {
            "acquisition_ok": False,
            "erreur": (
                f"pyobjc-framework-CoreLocation non installé pour cet "
                f"interpréteur ({e}). Installer avec : pip install --user "
                f"--only-binary=:all: pyobjc-framework-CoreLocation"
            ),
        }

    resultat = _GPS_ETAT_PARTAGE
    resultat["fix"] = None
    resultat["erreur"] = None
    resultat["termine"] = False

    DelegateClass = _obtenir_classe_delegate_gps()
    manager = CLLocationManager.alloc().init()
    delegate = DelegateClass.alloc().init()
    manager.setDelegate_(delegate)
    manager.requestWhenInUseAuthorization()
    manager.startUpdatingLocation()

    run_loop = NSRunLoop.currentRunLoop()
    deadline = time.time() + timeout_secondes
    while not resultat["termine"] and time.time() < deadline:
        run_loop.runUntilDate_(NSDate.dateWithTimeIntervalSinceNow_(0.5))

    manager.stopUpdatingLocation()

    if resultat["fix"] is None:
        return {
            "acquisition_ok": False,
            "erreur": (
                resultat["erreur"]
                or f"Aucune position obtenue dans le délai de {timeout_secondes}s "
                   "(autorisation refusée, en attente de consentement macOS, ou "
                   "signal GPS/Wi-Fi indisponible)."
            ),
        }

    return {"acquisition_ok": True, **resultat["fix"]}


# ------------------------------------------------------------------------------
# OUTIL 4bis : PONT GPS IPHONE REEL (8 sept 2026)
# ------------------------------------------------------------------------------
# Chaine constitutive · Extension de la Couche 1 (Position/Presence)
# PROBLEME -> LOI -> HOQ -> SEQUENCE -> CODE
#
# PROBLEME  : le Mac n'a pas de puce GPS dediee — CoreLocation y depend de la
#             triangulation Wi-Fi environnante, avec une precision observee
#             de 35 a 55 m. Un temoin de Lieu a faible rayon (ex. 5 m, Bureau
#             annexe Abidjan) ne peut jamais etre confirme depuis le Mac
#             seul, meme quand la personne y est reellement, a moins d'un
#             metre.
#
# LOI       : quand un capteur plus competent existe (GPS materiel reel d'un
#             iPhone), le systeme doit pouvoir lire sa position sans jamais
#             pretendre a une preuve qu'il n'a pas — pas de liaison Secure
#             Enclave simulee, pas de precision inventee quand le Raccourci
#             Apple ne la communique pas. Le champ precision_horizontale_m
#             reste None si non fourni, jamais rempli par defaut.
#
# HOQ       : lecture seule d'un fichier pont local (jamais d'ecriture depuis
#             ce serveur), peremption explicite (max_age_secondes), jamais un
#             succes simule si le fichier est absent, perime, ou illisible.
#
# SEQUENCE  : Raccourci Apple sur iPhone (Obtenir la position actuelle reelle
#             -> Dictionnaire {lat, lon, horizontal_accuracy_m?, timestamp_utc}
#             -> Enregistrer le fichier) depose ce JSON dans un dossier iCloud
#             Drive synchronise avec le Mac -> ce serveur lit ce meme fichier
#             via son chemin local synchronise -> verifie la fraicheur ->
#             retourne la position, source explicitement marquee
#             GPS_IPHONE_REEL, sans aucune revendication Secure Enclave.
#
# CODE      : _charger_position_iphone_reel / acquerir_position_gps_iphone_reel,
#             ci-dessous.
# ------------------------------------------------------------------------------
# CORRECTION 8 sept 2026 · iCloud Drive plein sur cette machine : le pont
# iCloud Drive echouait a l'ecriture (quota depasse), pas a la lecture. On
# bascule sur un fichier local pur (meme famille que LIEUX_TEMOINS_FILE /
# PCR_STATE_FILE), alimente par un petit recepteur HTTP local
# (gps_bridge_receiver.py) que l'iPhone appelle directement sur le
# reseau Wi-Fi local — plus de dependance a un espace de stockage cloud.
GPS_IPHONE_BRIDGE_FILE = os.path.expanduser(
    os.environ.get("CTSM_GPS_IPHONE_FILE", "~/.ctsm_gps_iphone.json")
)


def _charger_position_iphone_reel(max_age_secondes: float = 300.0) -> dict:
    if not os.path.exists(GPS_IPHONE_BRIDGE_FILE):
        return {
            "acquisition_ok": False,
            "erreur": f"Fichier pont iPhone absent : {GPS_IPHONE_BRIDGE_FILE} "
                      "(le Raccourci Apple n'a jamais encore ecrit, ou iCloud "
                      "Drive n'a pas encore synchronise).",
        }
    try:
        with open(GPS_IPHONE_BRIDGE_FILE, "r", encoding="utf-8") as f:
            donnee = json.load(f)
    except Exception as e:  # noqa: BLE001
        return {"acquisition_ok": False, "erreur": f"Fichier pont iPhone illisible : {e}"}

    horodatage_str = donnee.get("timestamp_utc")
    if horodatage_str:
        try:
            horodatage = datetime.fromisoformat(horodatage_str.replace("Z", "+00:00"))
            age_s = (datetime.now(timezone.utc) - horodatage).total_seconds()
        except Exception:  # noqa: BLE001
            age_s = None
    else:
        age_s = None

    if age_s is not None and age_s > max_age_secondes:
        return {
            "acquisition_ok": False,
            "erreur": f"Position iPhone perimee : {age_s:.0f}s (limite {max_age_secondes:.0f}s). "
                      "Relance le Raccourci Apple pour une position fraiche.",
        }

    lat, lon = donnee.get("lat"), donnee.get("lon")
    if lat is None or lon is None:
        return {"acquisition_ok": False, "erreur": "Fichier pont iPhone incomplet (lat/lon manquants)."}

    return {
        "acquisition_ok": True,
        "lat": lat,
        "lon": lon,
        "precision_horizontale_m": donnee.get("horizontal_accuracy_m"),
        "timestamp_utc": horodatage_str,
        "age_secondes": age_s,
        "source": "GPS_IPHONE_REEL",
        "avertissement": "Position GPS materielle reelle de l'iPhone, transmise via Raccourci "
                          "Apple + iCloud Drive. Aucune liaison Secure Enclave : ceci ne "
                          "constitue pas une preuve d'integrite materielle, seulement une "
                          "position plus precise que la triangulation Wi-Fi du Mac.",
    }


@mcp.tool()
def acquerir_position_gps_iphone_reel(max_age_secondes: float = 300.0) -> dict:
    """
    [RÉEL — lecture seule d'un pont fichier, jamais d'accès direct au téléphone]
    Lit la dernière position GPS matérielle réelle déposée par un Raccourci
    Apple depuis l'iPhone (via iCloud Drive), plutôt que la triangulation
    Wi-Fi du Mac. N'affirme jamais une liaison Secure Enclave — c'est une
    position plus précise, pas une preuve d'intégrité matérielle du device.

    Args:
        max_age_secondes: âge maximal toléré de la position déposée avant de
                    la considérer périmée (défaut 300s)

    Returns:
        {"acquisition_ok": true, "lat", "lon", "precision_horizontale_m"
        (peut être None si le Raccourci ne l'a pas transmise), "timestamp_utc",
        "age_secondes", "source": "GPS_IPHONE_REEL"} en cas de succès, ou
        {"acquisition_ok": false, "erreur"} sinon — jamais un succès simulé.
    """
    return _charger_position_iphone_reel(max_age_secondes)


@mcp.tool()
def acquerir_position_gps_agent(timeout_secondes: float = 15.0) -> dict:
    """
    [RÉEL — capteur système, sous consentement explicite de l'agent]
    Demande l'autorisation de localisation macOS (CoreLocation) et capte une
    position GPS réelle actuelle. Déclenche la vraie boîte de dialogue système
    native si l'autorisation n'a jamais été accordée à ce processus.

    Args:
        timeout_secondes: délai maximal d'attente d'un premier fix GPS

    Returns:
        {"acquisition_ok": true, "lat", "lon", "precision_horizontale_m",
        "timestamp_utc"} en cas de succès, ou {"acquisition_ok": false,
        "erreur"} sinon (dépendance manquante, autorisation refusée, ou
        signal indisponible dans le délai imparti).
    """
    return _acquerir_gps_reel(timeout_secondes)


# ------------------------------------------------------------------------------
# OUTIL 4ter : CHAÎNAGE RÉEL · ACQUISITION GPS + RÉSOLUTION DE PRÉSENCE ABIDJAN
# ------------------------------------------------------------------------------
@mcp.tool()
def acquerir_et_resoudre_presence_abidjan(
    person_id: str,
    icl_bureau_reference: Optional[str] = ICL_ABRAND_ABIDJAN,
    session_id: Optional[str] = None,
    timeout_secondes: float = 15.0,
) -> dict:
    """
    [RÉEL — chaînage capteur consenti + appel réseau réel]
    Combine en un seul appel :
      1. acquerir_position_gps_agent (consentement macOS + position GPS réelle) ;
      2. resoudre_presence_employe_abidjan (POST /v1/resolve-presence réel sur
         le Cockpit Spatial™ API, comparaison d'ICL réelle via pcnt.js).

    Ne couvre que la zone réellement indexée par l'API (Cocody/Abidjan) : hors
    de cette zone, l'étape 2 échoue ou renvoie un état non conforme — ce n'est
    pas un défaut du capteur GPS, c'est la limite honnête déjà documentée de
    l'API réelle (6025 adresses, 386 voies, scope Cocody uniquement).

    Args:
        person_id: identifiant d'acteur déjà inscrit via inscrire_acteur_abidjan
                    / POST /v1/auth (obligatoire côté API réelle)
        icl_bureau_reference: ICL de référence du bureau (par défaut
                    ICL_ABRAND_ABIDJAN)
        session_id: identifiant de session optionnel, transmis tel quel à l'API
        timeout_secondes: délai maximal d'attente du fix GPS (étape 1)

    Returns:
        {"etape_echouee": "acquisition_gps", "detail": ...} si l'étape 1 échoue,
        sinon {"acquisition_gps": ..., "verdict_presence": ...}.
    """
    _verrou = _exiger_petihah()
    if _verrou:
        return _verrou

    acquisition = _acquerir_gps_reel(timeout_secondes)
    if not acquisition.get("acquisition_ok"):
        return {
            "etape_echouee": "acquisition_gps",
            "detail": acquisition,
        }

    verdict = resoudre_presence_employe_abidjan(
        person_id=person_id,
        lat=acquisition["lat"],
        lon=acquisition["lon"],
        icl_bureau_reference=icl_bureau_reference,
        session_id=session_id,
    )

    return {
        "acquisition_gps": acquisition,
        "verdict_presence": verdict,
    }


# ------------------------------------------------------------------------------
# OUTIL 5 : PCNT ZERA 1CM v1.0 · RAFFINEMENT TERRITORIAL GOUVERNÉ · 7 sept 2026
# ------------------------------------------------------------------------------
# Chaine constitutive · Couche 1 · Position et presence
# PROBLEME -> LOI -> HOQ -> SEQUENCE -> CODE
#
# PROBLEME  : deux problemes reels distincts, traverses successivement le
#             7 sept 2026. (1) contexte_territorial et l'evidence de terrain
#             etaient calcules directement sur les coordonnees GPS brutes
#             (latitude/longitude), donc sur une source que Google ou tout
#             autre capteur peut fournir avec erreur, sans conversion
#             prealable. (2) le verdict du temoin etait un simple test
#             binaire distance <= rayon, ignorant l'horizontal_accuracy_m
#             declare par le capteur lui meme — verifie en conditions
#             reelles : 36,71 m mesures avec +/-35 m de precision contre un
#             Lieu de rayon 5 m produisait HORS_LIEU_TEMOIN avec une fausse
#             confiance, alors que l'operateur etait reellement toujours a
#             sa position declaree.
#
# LOI       : (a) aucune donnee GPS brute n'entre dans un calcul decisionnel ;
#             seule sa conversion en candidat PCNT Zera 1cm peut alimenter
#             contexteTerritorial, le temoin, ou toute evidence de terrain.
#             (b) un verdict de containment ne peut pas ignorer la marge
#             d'incertitude declaree par le capteur : quand cette marge
#             chevauche le rayon du Lieu, le systeme doit reconnaitre son
#             incertitude plutot que trancher a tort.
#
# HOQ       : une chaine de conversion geodesique (PCNT Zera 1cm) suivie d'un
#             verdict de temoin a trois etats honnetes plutot que deux etats
#             sur-confiants.
#
# SEQUENCE  : observation GPS brute -> conversion en candidats Zera 1cm ->
#             point_ref = premier candidat RESOLVED (jamais le brut) ->
#             contexteTerritorial (PADA + Path Resolver) et
#             _lieu_temoin_le_plus_proche calcules sur point_ref ->
#             distance_au_temoin compare a rayon_lieu_m +/- marge_incertitude_m
#             -> verdict_temoin (CONFIRME / EXCLU / INCERTAIN_MARGE_PRECISION)
#             -> governance_status.
#
# CODE      : pcnt_zera_1cm, ci-dessous (mode GOVERNED_REFINEMENT en
#             particulier), et _lieu_temoin_le_plus_proche.
# ------------------------------------------------------------------------------
# Intégration de la spécification "PCNT Zera 1cm v1.0" (Makom Intelligence™ /
# CorreIA LLC, 25 Eloul 5786 · 7 septembre 2026), transmise par l'utilisateur.
#
# Loi fondatrice du protocole, reprise ici sans l'affaiblir : toute donnée GPS
# reçue demeure une observation CONSERVÉE. La résolution ou l'échec de
# résolution ICL qualifie son usage territorial, mais ne détermine jamais son
# droit à être conservée. Une transformation mathématique NE réduit PAS à elle
# seule l'incertitude physique d'un capteur — une observation annoncée à ±38 m
# ne devient pas une mesure exacte à ±1 cm parce qu'une coordonnée dérivée a
# été calculée à 1 cm (section 1, "Limite scientifique impérative").
#
# Limite honnête de CETTE implémentation, à ne jamais taire : PADA (ancres
# territoriales fixes), le Path Resolver (voies/domaines admissibles) et les
# témoins terrain n'existent pas encore dans ce sandbox. Le mode
# GOVERNED_REFINEMENT ne peut donc filtrer les candidates que par une seule
# preuve indépendante quand elle est explicitement fournie (previous_lat/lon +
# ground_truth_distance_m, section 15 du protocole) — jamais par PADA, jamais
# par continuité de voie. Faute de ces briques, le verdict par défaut reste
# AMBIGUOUS ou UNRESOLVED_RETAINED, jamais CONFIRMED : ce protocole documente
# lui même (section 21) que la correction physique du GPS à 1 cm n'est "NON
# DÉMONTRÉE" et que l'implémentation reste "À RÉALISER ET TESTER".

PCNT_ZERA_LOG_FILE = os.path.expanduser("~/.ctsm_pcnt_zera_log.jsonl")

# Registre des Lieux et de leurs témoins Ed (עֵד) — 7 sept 2026.
# Un Lieu = {nom, lat_centre, lon_centre, rayon_m, icl_centre, temoin}.
# Le témoin Ed est dérivé automatiquement du centre du Lieu : présent (position
# fixe connue une fois pour toutes) et silencieux (ne bouge pas, ne se résout
# pas dynamiquement — on le consulte). Ce n'est ni PADA (base d'adresses
# externe), ni le Path Resolver (réseau de voies externe) : c'est une entité
# interne au système, déclarée par nous, servant de point d'ancrage vérifiable
# pour le mode GOVERNED_REFINEMENT.
LIEUX_TEMOINS_FILE = os.path.expanduser("~/.ctsm_lieux_temoins.json")


def _lieu_charger_registre() -> dict:
    if os.path.exists(LIEUX_TEMOINS_FILE):
        try:
            with open(LIEUX_TEMOINS_FILE, "r") as f:
                return json.load(f)
        except Exception:  # noqa: BLE001
            pass
    return {}


def _lieu_sauvegarder_registre(registre: dict) -> None:
    with open(LIEUX_TEMOINS_FILE, "w") as f:
        json.dump(registre, f, indent=2, ensure_ascii=False)


# ------------------------------------------------------------------------------
# CORRECTION 7 sept 2026 · SELECTION DU TEMOIN LE PLUS SPECIFIQUE
# ------------------------------------------------------------------------------
# Chaine constitutive · Couche 1 (Position/Presence) · applique FL-HSC-144
# Qedem (l'anteriorite constitutive) : ce qui constitue le point le plus
# specifiquement precede, dans l'ordre de lecture, ce qui l'englobe plus
# largement — un Lieu etroit et precis (ex. "Bureau annexe Abidjan", 5m) est
# constitutivement anterieur a un Lieu large qui le contient (ex. "haMakom",
# 25km), meme si les deux ont le meme centre.
# PROBLEME -> LOI -> HOQ -> SEQUENCE -> CODE
#
# PROBLEME  : l'ancienne selection retournait TOUJOURS le temoin dont le
#             centre est geometriquement le plus proche, sans jamais tenir
#             compte du rayon declare de chaque Lieu. Des lors que deux
#             Lieux emboites partagent (ou approchent) le meme centre — un
#             Lieu precis et son territoire englobant plus large — un point
#             pourtant reellement contenu dans le grand Lieu recevait
#             HORS_LIEU_TEMOIN au lieu de LIEU_CONFIRME_PAR_TEMOIN, parce
#             que seul le petit Lieu etait jamais compare.
#
# LOI       : parmi tous les temoins de Lieux enregistres, celui dont le
#             rayon CONTIENT reellement le point (distance <= rayon_m) et
#             qui est le PLUS SPECIFIQUE (rayon_m le plus petit parmi ceux
#             qui contiennent le point) doit etre retenu en priorite — la
#             specificite precede la generalite (Qedem constitutif). Si
#             aucun temoin ne contient le point, le comportement retombe
#             sur l'ancienne regle (temoin geometriquement le plus proche),
#             pour ne jamais perdre le signal HORS_LIEU_TEMOIN ni
#             INCERTAIN_MARGE_PRECISION_TEMOIN existant.
#
# HOQ       : jamais une regression du comportement deja teste (temoin
#             isole, un seul Lieu enregistre) — la nouvelle logique doit
#             etre strictement equivalente a l'ancienne quand un seul Lieu
#             contient le point, ou quand aucun ne le contient.
#
# SEQUENCE  : pour chaque Lieu du registre, calculer la distance haversine
#             reelle au temoin -> partitionner en deux groupes : ceux ou
#             distance <= rayon_m (contenants) et les autres -> si des
#             contenants existent, retenir celui au rayon_m le plus petit
#             (specificite maximale), en departageant par distance la plus
#             proche en cas d'egalite de rayon -> sinon, retenir le Lieu
#             dont le temoin est geometriquement le plus proche (ancien
#             comportement, jamais perdu).
#
# CODE      : _lieu_temoin_le_plus_proche, ci-dessous.
# ------------------------------------------------------------------------------
def _lieu_temoin_le_plus_proche(lat: float, lon: float):
    """Retourne (lieu, distance_m) pour le Lieu le plus pertinent par rapport
    a (lat, lon), ou None si le registre est vide.

    Priorite (Qedem constitutif, FL-HSC-144) : parmi les Lieux dont le
    temoin CONTIENT reellement le point (distance <= rayon_m), le plus
    specifique (rayon_m le plus petit) est retenu en premier — la
    specificite precede la generalite. Si aucun Lieu ne contient le point,
    on retombe sur le Lieu dont le temoin est geometriquement le plus
    proche (comportement historique, jamais perdu)."""
    registre = _lieu_charger_registre()
    if not registre:
        return None

    contenants = []
    tous = []
    for lieu in registre.values():
        temoin = lieu.get("temoin", {})
        d = compute_haversine(lat, lon, temoin.get("lat"), temoin.get("lon"))
        rayon_m = lieu.get("rayon_m")
        tous.append((lieu, d))
        if rayon_m is not None and d <= rayon_m:
            contenants.append((lieu, d, rayon_m))

    if contenants:
        contenants.sort(key=lambda item: (item[2], item[1]))
        lieu_retenu, distance_retenue, _ = contenants[0]
        return lieu_retenu, distance_retenue

    if not tous:
        return None
    tous.sort(key=lambda item: item[1])
    lieu_retenu, distance_retenue = tous[0]
    return lieu_retenu, distance_retenue


def _pcnt_zera_extract_parts(coord: float):
    """Section 8.1 — extraction des sept décimales, compatible toFixed(7)."""
    from decimal import Decimal, ROUND_HALF_UP
    absolute = abs(coord)
    integer_part = math.floor(absolute)
    frac = absolute - integer_part
    d = Decimal(repr(frac)).quantize(Decimal("1." + "0" * 7), rounding=ROUND_HALF_UP)
    decimal_text = format(d, ".7f").split(".")[1]
    return integer_part, decimal_text[:7]


def _pcnt_zera_seq(coord: float) -> str:
    """Sections 8.2 et 8.3 — pondération exponentielle puis condensation en 4 chiffres."""
    _, decimal7 = _pcnt_zera_extract_parts(coord)
    digits = [int(c) for c in decimal7]
    reversed_digits = digits[::-1]
    value = sum(reversed_digits[i] * math.exp(-(i + 1)) for i in range(7))
    fraction = value - math.floor(value)
    n4 = math.floor(fraction * 10000 + 0.5)
    return str(n4).zfill(4)


def _pcnt_zera_attempt_icl(lat: float, lon: float) -> dict:
    """Section 8.6 — échec ICL toujours explicite, jamais une exclusion silencieuse."""
    try:
        return {
            "status": "RESOLVED",
            "value": f"{_pcnt_zera_seq(lat)} | {_pcnt_zera_seq(lon)}",
        }
    except Exception as e:  # noqa: BLE001
        return {"status": "ICL_UNRESOLVED_RETAINED", "value": None, "reason": str(e)}


def _pcnt_zera_direct_geodesic(lat_deg: float, lon_deg: float, distance_m: float, bearing_deg: float, earth_radius_m: float = 6371000.0):
    """Section 7.2 — formule directe géodésique sphérique."""
    phi1 = math.radians(lat_deg)
    lam1 = math.radians(lon_deg)
    theta = math.radians(bearing_deg)
    delta = distance_m / earth_radius_m
    phi2 = math.asin(math.sin(phi1) * math.cos(delta) + math.cos(phi1) * math.sin(delta) * math.cos(theta))
    lam2 = lam1 + math.atan2(math.sin(theta) * math.sin(delta) * math.cos(phi1), math.cos(delta) - math.sin(phi1) * math.sin(phi2))
    lat2 = math.degrees(phi2)
    lon2 = (math.degrees(lam2) + 540) % 360 - 180
    return lat2, lon2


def _pcnt_zera_retain_raw(latitude, longitude, horizontal_accuracy_m, observed_at, source, observation_id, test_id) -> dict:
    """Section 6 — conservation préalable, aucune normalisation avant archivage."""
    raw = {
        "latRaw": latitude,
        "lonRaw": longitude,
        "accuracyRaw": horizontal_accuracy_m,
        "observedAtRaw": observed_at,
        "sourceRaw": source,
        "receivedAt": datetime.now(timezone.utc).isoformat(),
        "observationId": observation_id,
        "testId": test_id,
    }
    checksum_input = json.dumps(raw, sort_keys=True).encode()
    raw["checksum"] = hashlib.sha256(checksum_input).hexdigest()
    return raw


def _pcnt_zera_save_receipt(receipt: dict) -> None:
    """Section 13 — la sauvegarde précède l'affichage du verdict, chaque tentative
    (y compris échouée) reçoit un reçu. Persisté en JSONL, jamais écrasé."""
    try:
        with open(PCNT_ZERA_LOG_FILE, "a") as f:
            f.write(json.dumps(receipt, default=str) + "\n")
    except Exception:  # noqa: BLE001
        pass  # la persistance est best-effort ; ne bloque jamais le verdict


@mcp.tool()
def creer_lieu_avec_temoin(nom: str, lat_centre: float, lon_centre: float, rayon_m: float) -> dict:
    """
    Déclare un Lieu (bâtiment, bureau, salle serveur, etc.) et enregistre son
    témoin Ed (עֵד), dérivé automatiquement du centre géométrique du Lieu.

    Le témoin n'est pas acquis dynamiquement : il est présent (sa position est
    fixe et connue dès la création du Lieu) et silencieux (il ne bouge pas, ne
    répond à rien — on le consulte). Il sert de point d'ancrage vérifiable pour
    le mode GOVERNED_REFINEMENT de pcnt_zera_1cm, indépendamment de PADA et du
    Path Resolver (qui restent externes et non câblés dans ce sandbox).

    Args:
        nom: identifiant du Lieu (ex. "Bureau annexe Abidjan")
        lat_centre, lon_centre: coordonnées du centre géométrique du Lieu —
                    c'est aussi la position du témoin Ed
        rayon_m: rayon du Lieu en mètres (ex. 5.0 si la circonférence
                    déclarée du Lieu correspond à un diamètre de 10m)

    Returns:
        Le Lieu enregistré, avec son témoin Ed (shem, fonction, lat, lon, icl).
    """
    _verrou = _exiger_petihah()
    if _verrou:
        return _verrou

    if not (-90.0 <= lat_centre <= 90.0):
        return {"status": "LAT_INVALID"}
    if not (-180.0 <= lon_centre <= 180.0):
        return {"status": "LON_INVALID"}
    if rayon_m <= 0:
        return {"status": "RAYON_INVALID", "message": "rayon_m doit être strictement positif."}

    icl_centre = _pcnt_zera_attempt_icl(lat_centre, lon_centre)

    lieu = {
        "nom": nom,
        "lat_centre": lat_centre,
        "lon_centre": lon_centre,
        "rayon_m": rayon_m,
        "icl_centre": icl_centre["value"],
        "temoin": {
            "shem": "Ed",
            "fonction": "Point d'ancrage du Lieu — présent et silencieux",
            "lat": lat_centre,
            "lon": lon_centre,
            "icl": icl_centre["value"],
        },
        "cree_le_utc": datetime.now(timezone.utc).isoformat(),
    }

    registre = _lieu_charger_registre()
    registre[nom] = lieu
    _lieu_sauvegarder_registre(registre)

    return {"status": "LIEU_ENREGISTRE", "lieu": lieu}


@mcp.tool()
def pcnt_zera_1cm(
    latitude: float,
    longitude: float,
    horizontal_accuracy_m: Optional[float] = None,
    observed_at: Optional[str] = None,
    source: str = "GOOGLE_GEOLOCATION",
    observation_id: Optional[str] = None,
    test_id: Optional[str] = None,
    mode: str = "DERIVATION_ONLY",
    bearing_deg: Optional[float] = None,
    bearing_policy: str = "REQUIRE_BEARING",
    previous_governed_lat: Optional[float] = None,
    previous_governed_lon: Optional[float] = None,
    ground_truth_distance_m: Optional[float] = None,
) -> dict:
    """
    [SPÉCIFICATION PCNT Zera 1cm v1.0 — implémentation locale, non canonisée]
    Reçoit une observation GPS (P0), la conserve sans altération, constitue
    son ICL, génère une ou plusieurs coordonnées candidates à une résolution
    nominale de 1 cm (P1CM), et — en mode GOVERNED_REFINEMENT — tente de
    resserrer l'incertitude UNIQUEMENT si une preuve indépendante est fournie.

    Rappel impératif du protocole : la résolution nominale de 1 cm n'est PAS
    une revendication d'exactitude physique de 1 cm (loi de preuve, section
    2.1.6). horizontal_accuracy_m n'est jamais réécrit.

    Args:
        latitude, longitude: observation GPS brute (P0)
        horizontal_accuracy_m: précision annoncée par la source, conservée
                    telle quelle, jamais réécrite à 0.01
        observed_at: horodatage ISO-8601 original de l'observation
        source: ex. GOOGLE_GEOLOCATION, QEDIMAH, REPLAY
        observation_id, test_id: identifiants de traçabilité
        mode: "DERIVATION_ONLY" (génère les candidates, aucune correction
                    physique revendiquée) ou "GOVERNED_REFINEMENT" (tente un
                    resserrement, seulement si previous_governed_lat/lon ET
                    ground_truth_distance_m sont fournis — voir section 15)
        bearing_deg: direction explicite en degrés (0-360). Si absente, la
                    politique bearing_policy s'applique (jamais un Est
                    silencieux par défaut, section 7.3)
        bearing_policy: "REQUIRE_BEARING" (défaut, retourne BEARING_REQUIRED
                    si bearing_deg absent) ou "CARDINAL_SET" (génère les 4
                    candidates cardinales Nord/Est/Sud/Ouest à 1 cm)
        previous_governed_lat/lon: dernière présence gouvernée connue, pour le
                    test de divergence terrain (section 15)
        ground_truth_distance_m: distance RÉELLEMENT mesurée/déclarée sur le
                    terrain entre previous_governed_lat/lon et cette
                    observation — distincte de la distance calculée par GPS

    Returns:
        Un dict structuré selon le contrat de sortie de la section 11 :
        rawObservation, sourceICL, candidates[], governance, status.
    """
    _verrou = _exiger_petihah()
    if _verrou:
        return _verrou

    raw = _pcnt_zera_retain_raw(latitude, longitude, horizontal_accuracy_m, observed_at, source, observation_id, test_id)

    if not (-90.0 <= latitude <= 90.0):
        receipt = {"protocol": "PCNT Zera 1cm v1.0", "rawObservation": raw, "status": "LAT_INVALID"}
        _pcnt_zera_save_receipt(receipt)
        return receipt
    if not (-180.0 <= longitude <= 180.0):
        receipt = {"protocol": "PCNT Zera 1cm v1.0", "rawObservation": raw, "status": "LON_INVALID"}
        _pcnt_zera_save_receipt(receipt)
        return receipt

    source_icl = _pcnt_zera_attempt_icl(latitude, longitude)

    if bearing_deg is not None:
        bearings = [("EXPLICIT", bearing_deg)]
    elif bearing_policy == "CARDINAL_SET":
        bearings = [("CARDINAL_N", 0.0), ("CARDINAL_E", 90.0), ("CARDINAL_S", 180.0), ("CARDINAL_O", 270.0)]
    elif bearing_policy == "PATH_DERIVED":
        # Le Path Resolver n'existe pas dans ce sandbox — refuser honnêtement
        # plutôt que d'inventer une direction. Aucun candidat Zera 1cm n'existe
        # encore à ce stade : le contexte territorial ne peut être calculé que
        # depuis l'observation brute, jamais depuis un candidat qui n'a pas
        # été produit.
        receipt = {
            "protocol": "PCNT Zera 1cm v1.0", "rawObservation": raw, "sourceICL": source_icl,
            "contexteTerritorial": {
                "status": "INDISPONIBLE_AVANT_CONVERSION_PCNT",
                "raison": "LOI (7 sept 2026) : aucune donnee GPS brute n'est utilisee pour un calcul decisionnel ou contextuel. Sans bearing_deg, aucun candidat Zera 1cm n'a pu etre produit, donc aucun contexte territorial n'est calcule.",
            },
            "status": "BEARING_REQUIRED",
            "message": "PATH_DERIVED demande une direction explicite pour produire un candidat Zera 1cm. Sans lui, aucune conversion PCNT n'est possible, donc aucun contexte territorial ne peut etre calcule (loi du 7 sept 2026). Utiliser bearing_deg.",
        }
        _pcnt_zera_save_receipt(receipt)
        return receipt
    else:
        receipt = {
            "protocol": "PCNT Zera 1cm v1.0", "rawObservation": raw, "sourceICL": source_icl,
            "contexteTerritorial": {
                "status": "INDISPONIBLE_AVANT_CONVERSION_PCNT",
                "raison": "LOI (7 sept 2026) : aucune donnee GPS brute n'est utilisee pour un calcul decisionnel ou contextuel. Sans bearing_deg, aucun candidat Zera 1cm n'a pu etre produit, donc aucun contexte territorial n'est calcule.",
            },
            "status": "BEARING_REQUIRED",
            "message": "bearing_deg absent et bearing_policy=REQUIRE_BEARING (defaut) : aucune direction n'est choisie silencieusement, et sans candidat Zera 1cm produit, aucun contexte territorial ne peut etre calcule depuis le brut (loi du 7 sept 2026).",
        }
        _pcnt_zera_save_receipt(receipt)
        return receipt

    candidates = []
    for bearing_source, bearing in bearings:
        cand_lat, cand_lon = _pcnt_zera_direct_geodesic(latitude, longitude, 0.01, bearing)
        mesure = compute_haversine(latitude, longitude, cand_lat, cand_lon)
        if abs(mesure - 0.01) > 0.001:  # tolérance numérique déclarée : 1 mm
            candidates.append({
                "latitude": cand_lat, "longitude": cand_lon, "synthetic": True,
                "distanceFromSourceM": mesure, "bearingDeg": bearing, "bearingSource": bearing_source,
                "status": "GEODESIC_TOLERANCE_FAILED",
            })
            continue
        cand_icl = _pcnt_zera_attempt_icl(cand_lat, cand_lon)
        candidates.append({
            "latitude": cand_lat, "longitude": cand_lon, "synthetic": True,
            "distanceFromSourceM": mesure, "bearingDeg": bearing, "bearingSource": bearing_source,
            "iclStatus": cand_icl["status"], "icl": cand_icl["value"],
        })

    # Point de référence pour le contexte territorial et le témoin : la
    # coordonnée PRODUITE par PCNT Zera 1cm (le premier candidat résolu),
    # jamais directement l'observation GPS brute — conformément à la
    # consigne du 7 sept 2026 : on traduit depuis ce que notre protocole a
    # constitué, pas depuis la donnée brute de la source (Google GPS ou
    # autre). Si aucun candidat n'a pu être résolu, on retombe honnêtement
    # sur l'observation brute et on le signale explicitement.
    candidats_resolus = [c for c in candidates if c.get("iclStatus") == "RESOLVED"]
    if candidats_resolus:
        point_ref = candidats_resolus[0]
        point_ref_lat, point_ref_lon = point_ref["latitude"], point_ref["longitude"]
        point_ref_source = "CANDIDAT_ZERA_1CM"
    else:
        point_ref_lat, point_ref_lon = latitude, longitude
        point_ref_source = "OBSERVATION_BRUTE_AUCUN_CANDIDAT_RESOLU"

    contexte_territorial = {
        "pointUtilise": {"lat": point_ref_lat, "lon": point_ref_lon, "source": point_ref_source},
        "adresseProche": _pada_adresse_la_plus_proche(point_ref_lat, point_ref_lon),
        "voirieProche": _path_resolver_voie_la_plus_proche(point_ref_lat, point_ref_lon),
    }

    if mode == "DERIVATION_ONLY":
        receipt = {
            "protocol": {"name": "PCNT Zera 1cm", "version": "1.0", "targetResolutionM": 0.01, "earthModel": "SPHERE", "earthRadiusM": 6371000},
            "rawObservation": raw, "sourceICL": source_icl, "candidates": candidates,
            "contexteTerritorial": contexte_territorial,
            "status": "SYNTHETIC_CANDIDATE",
            "avertissement": "Résolution nominale de 1 cm — ne constitue PAS une exactitude physique démontrée (loi de preuve, section 2.1.6).",
        }
        _pcnt_zera_save_receipt(receipt)
        return receipt

    # mode == GOVERNED_REFINEMENT — funnel honnête, avec temoin de Lieu s'il existe
    admissibles = [c for c in candidates if c.get("iclStatus") == "RESOLVED"]
    evidence_used = []
    governance_status = "UNRESOLVED_RETAINED"
    selected = None

    # LOI (7 sept 2026) : la marge d'incertitude annoncee par le capteur
    # (horizontal_accuracy_m) doit etre prise en compte dans le verdict du
    # temoin. Une comparaison binaire distance <= rayon, sans tenir compte de
    # cette marge, produirait de fausses exclusions (ou de fausses
    # confirmations) des que l'incertitude du capteur chevauche le rayon du
    # Lieu. Trois zones honnetes, jamais deux :
    #   distance + marge <= rayon         -> CONFIRME  (tout l'intervalle est dans le Lieu)
    #   distance - marge >  rayon         -> EXCLU      (tout l'intervalle est hors du Lieu)
    #   sinon                              -> INCERTAIN  (l'intervalle chevauche la frontiere)
    temoin_resultat = _lieu_temoin_le_plus_proche(point_ref_lat, point_ref_lon)
    dans_le_lieu = None
    recommandation_action = None
    if temoin_resultat is not None:
        lieu_proche, distance_au_temoin = temoin_resultat
        marge_incertitude_m = horizontal_accuracy_m if horizontal_accuracy_m is not None else 0.0
        rayon_lieu_m = lieu_proche["rayon_m"]
        if distance_au_temoin + marge_incertitude_m <= rayon_lieu_m:
            dans_le_lieu = True
            verdict_temoin = "CONFIRME"
        elif distance_au_temoin - marge_incertitude_m > rayon_lieu_m:
            dans_le_lieu = False
            verdict_temoin = "EXCLU"
        else:
            dans_le_lieu = None
            verdict_temoin = "INCERTAIN_MARGE_PRECISION"
        evidence_used.append({
            "type": "TEMOIN_LIEU",
            "lieuNom": lieu_proche["nom"],
            "temoinShem": lieu_proche["temoin"]["shem"],
            "distanceAuTemoinM": distance_au_temoin,
            "margeIncertitudeM": marge_incertitude_m,
            "rayonLieuM": rayon_lieu_m,
            "dansLeLieu": dans_le_lieu,
            "verdictTemoin": verdict_temoin,
        })

    if contexte_territorial["voirieProche"].get("status") == "RESOLVED":
        evidence_used.append({"type": "PATH_RESOLVER_VOIE", **contexte_territorial["voirieProche"]})
    if contexte_territorial["adresseProche"].get("status") == "RESOLVED":
        evidence_used.append({"type": "PADA_ADRESSE", **contexte_territorial["adresseProche"]})

    if previous_governed_lat is not None and previous_governed_lon is not None and ground_truth_distance_m is not None:
        # LOI (7 sept 2026) : aucune donnee GPS Google (ou de toute source
        # brute) n'entre dans un calcul decisionnel. La seule utilisation
        # licite d'une donnee GPS brute est sa conversion en GPS PCNT Zera
        # 1cm (point_ref_lat/point_ref_lon, deja calcule plus haut). Toute
        # utilisation de latitude/longitude brutes ici serait une violation.
        distance_gps = compute_haversine(previous_governed_lat, previous_governed_lon, point_ref_lat, point_ref_lon)
        ecart = abs(distance_gps - ground_truth_distance_m)
        evidence_used.append({
            "type": "GROUND_TRUTH_VS_GPS", "distanceGpsM": distance_gps,
            "groundTruthDistanceM": ground_truth_distance_m, "ecartM": ecart,
        })
        if ecart > max(1.0, ground_truth_distance_m * 0.5):
            governance_status = "GPS_GROUND_TRUTH_MISMATCH"
        elif len(admissibles) == 1:
            governance_status = "GOVERNED_POSITION_CANDIDATE"
            selected = admissibles[0]
        elif len(admissibles) > 1:
            governance_status = "AMBIGUOUS"
        else:
            governance_status = "UNRESOLVED_RETAINED"
    elif dans_le_lieu is True and len(admissibles) == 1:
        # Le témoin Ed confirme uniquement l'appartenance territoriale au
        # Lieu déclaré (distance + marge <= rayon_m) — jamais une précision
        # physique de 1 cm. C'est une preuve de contenance, pas une preuve
        # de netteté.
        governance_status = "LIEU_CONFIRME_PAR_TEMOIN"
        selected = admissibles[0]
    elif dans_le_lieu is False:
        governance_status = "HORS_LIEU_TEMOIN"
    elif dans_le_lieu is None and temoin_resultat is not None:
        # La marge d'incertitude du capteur chevauche le rayon du Lieu : ni
        # confirmation ni exclusion honnete n'est possible depuis le temoin
        # seul. C'est un etat different de AMBIGUOUS (qui vient d'ICL
        # multiples), donc un statut distinct.
        governance_status = "INCERTAIN_MARGE_PRECISION_TEMOIN"
        lieu_proche_nom = lieu_proche["nom"] if temoin_resultat is not None else None
        recommandation_action = (
            f"Marge d'incertitude du capteur ({marge_incertitude_m:.0f} m) "
            f"trop large pour trancher au rayon du Lieu '{lieu_proche_nom}' "
            f"({rayon_lieu_m:.0f} m). Reduire l'incertitude avant tout "
            "verdict definitif : reacquerir une observation avec un capteur "
            "de meilleure precision (GPS natif plutot que geolocalisation "
            "reseau), attendre un meilleur fix, ou rapprocher physiquement "
            "du centre declare du Lieu."
        )
    elif len(admissibles) > 1:
        governance_status = "AMBIGUOUS"
    elif len(admissibles) == 0:
        governance_status = "UNRESOLVED_RETAINED"

    # PROBLEME : un statut AMBIGUOUS (plusieurs candidats PCNT Zera 1cm
    # admissibles) n'empeche pas evidence_used de porter un verdict temoin
    # ou une proximite PADA/voirie qui restent vrais quel que soit le
    # candidat retenu (Lieu trop large, ou proximite calculee sur un point
    # qui n'est pas le candidat unique retenu). Une couche de formulation
    # en aval peut alors citer ce temoignage "CONFIRME" a cote d'un refus
    # honnete AMBIGUOUS, recreant la juxtaposition que la Loi du 7 sept
    # 2026 interdit (donnee non gouvernante presentee comme si elle
    # tranchait). LOI : quand governance_status == AMBIGUOUS, toute preuve
    # de type TEMOIN_LIEU / PATH_RESOLVER_VOIE / PADA_ADRESSE doit etre
    # marquee explicitement non discriminante plutot que citee brute.
    if governance_status == "AMBIGUOUS":
        for _ev in evidence_used:
            if _ev.get("type") in ("TEMOIN_LIEU", "PATH_RESOLVER_VOIE", "PADA_ADRESSE"):
                _ev["nonDiscriminant"] = True
                _ev["raisonNonDiscriminant"] = (
                    "Statut AMBIGUOUS : plusieurs candidats PCNT Zera 1cm "
                    "restent possibles a cette resolution. Cette preuve "
                    "reste vraie quel que soit le candidat retenu (echelle "
                    "ou rayon bien plus grand que leur dispersion) et ne "
                    "doit jamais etre presentee comme resolvant l'ambiguite."
                )

    receipt = {
        "protocol": {"name": "PCNT Zera 1cm", "version": "1.0", "targetResolutionM": 0.01, "earthModel": "SPHERE", "earthRadiusM": 6371000},
        "rawObservation": raw, "sourceICL": source_icl, "candidates": candidates,
        "contexteTerritorial": contexte_territorial,
        "governance": {
            "status": governance_status,
            "selectedCandidate": selected,
            "evidenceUsed": evidence_used,
            "sourceAccuracyM": horizontal_accuracy_m,
            "governedUncertaintyM": None,
            "fieldValidatedAccuracyM": None,
            "recommandationAction": recommandation_action if governance_status == "INCERTAIN_MARGE_PRECISION_TEMOIN" else None,
            "avertissement": "PADA (territoire.js, GET /v1/territoire) et le Path Resolver (voiries.js, GET /v1/voiries) sont reels : contexteTerritorial vient d'un appel reseau reel au Cockpit Spatial (TM) API, calcule depuis le candidat Zera 1cm (jamais depuis le GPS brut, loi du 7 sept 2026). Le temoin Ed d'un Lieu declare via creer_lieu_avec_temoin confirme (LIEU_CONFIRME_PAR_TEMOIN), exclut (HORS_LIEU_TEMOIN), ou reste incertain (INCERTAIN_MARGE_PRECISION_TEMOIN) quand la marge d'incertitude du capteur chevauche le rayon du Lieu. Ni la proximite territoriale ni le temoin ne revendiquent une precision physique de 1 cm : sans temoin ni preuve terrain explicite, le verdict reste AMBIGUOUS ou UNRESOLVED_RETAINED, jamais CONFIRMED.",
        },
        "status": governance_status,
    }
    _pcnt_zera_save_receipt(receipt)
    return receipt


# ------------------------------------------------------------------------------
# OUTIL 1 (SANDBOX, inchangé) : EVALUATION DE PRESENCE (DOMANIALE + GEODESIQUE)
# ------------------------------------------------------------------------------
@mcp.tool()
def evaluer_presence_locus_demo(scenario: str) -> dict:
    """
    [SANDBOX — simulation, aucun appel réseau] Vérifie une attestation domaniale
    simulée à trois volets (Sol, Demeure, Institution).

    Args:
        scenario: un de "SITE_NOMINAL", "RUE_11M", "SITE_DISTANT_4KM", "SITE_DISTANT_6KM"
    """
    scen = scenario.upper()

    if scen in ["RUE_11M", "SITE_DISTANT_4KM", "SITE_DISTANT_6KM"]:
        dist = 11.74 if scen == "RUE_11M" else (4300.0 if scen == "SITE_DISTANT_4KM" else 6800.0)
        return {
            "verdict": "REFUSÉ [SAF_HOLD]",
            "code_test": "TEST_POLICY_FAIL (0x99D-DEMO)",
            "statut_domanial": "VIOLATION_DOMANIALE_SIMULEE",
            "derive_mesuree_m": dist,
            "seuil_autorise_m": TOLERANCE_METERS,
            "message": f"[SANDBOX] Dérive simulée de {dist:.2f} mètres hors de la borne de test.",
            "signature_simulee": None,
            "recu_test": None
        }

    cle_test = hashlib.sha256(f"DEMO_KEY_{NOMINAL_PCR16}_{NOMINAL_BSSID}".encode()).hexdigest()
    doc_test = {
        "acte": "SIMULATION_AUTORISATION_TEST",
        "montant": MONTANT_TEST,
        "emetteur_fictif": ENTITE_EMETTRICE,
        "site_test": INSTITUTION_TEST,
        "icl_demo": "0000|0000 · Sandbox",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "avertissement": "Document de test sans valeur légale, financière ou diplomatique."
    }
    sig_demo = hmac.new(cle_test.encode(), json.dumps(doc_test, sort_keys=True).encode(), hashlib.sha256).hexdigest()

    return {
        "verdict": "SIMULATION_ACCORDÉE [SAF_OPEN-DEMO]",
        "code_test": "TEST_SUCCESS (0x000-DEMO)",
        "statut_domanial": "HABITATION_SIMULEE_CONFORME",
        "derive_mesuree_m": 0.00,
        "seuil_autorise_m": TOLERANCE_METERS,
        "document_test": doc_test,
        "signature_simulee": sig_demo,
        "recu_test": "RECU_TEST_NON_OFFICIEL_SANDBOX"
    }


# ------------------------------------------------------------------------------
# OUTIL 2 (SANDBOX, inchangé) : CONFINEMENT DE DOMAINE
# ------------------------------------------------------------------------------
@mcp.tool()
def verifier_domaine_externe_demo(domaine_externe_vise: str) -> dict:
    """
    [SANDBOX — simulation, aucun appel réseau] Vérifie si un domaine externe
    est dans le périmètre de test autorisé.

    Args:
        domaine_externe_vise: le nom de domaine à évaluer, ex. "exemple-sandbox.test"
    """
    autorise = any(domaine_externe_vise.endswith(d) for d in DOMAINES_AUTORISES)
    if not autorise:
        return {
            "verdict": "REFUSÉ [SAF_HOLD]",
            "code_test": "TEST_POLICY_FAIL (0x99D-DEMO)",
            "statut_domanial": "HORS_MANDAT_DEMO",
            "message": f"[SANDBOX] Confinement de mandat simulé : la ressource '{domaine_externe_vise}' est hors du périmètre de test déclaré."
        }
    return {
        "verdict": "ACCEPTÉ [SAF_OPEN-DEMO]",
        "statut_domanial": "DANS_LE_PERIMETRE_DE_TEST",
        "domaine": domaine_externe_vise
    }


# ------------------------------------------------------------------------------
# OUTIL 3 (SANDBOX, inchangé) : GENERATION DE RECU DE TEST
# ------------------------------------------------------------------------------
@mcp.tool()
def generer_recu_test(montant: Optional[str] = None) -> dict:
    """
    [SANDBOX — simulation, aucun appel réseau] Génère un reçu de test non
    officiel, sans valeur légale, pour un montant fictif.

    Args:
        montant: montant fictif optionnel à inscrire sur le reçu de test (par défaut MONTANT_TEST)
    """
    m = montant or MONTANT_TEST
    return {
        "type": "RECU_TEST_NON_OFFICIEL_SANDBOX",
        "montant_fictif": m,
        "emetteur_fictif": ENTITE_EMETTRICE,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "avertissement": "Reçu de démonstration. Aucune valeur légale, financière ou diplomatique."
    }


if __name__ == "__main__":
    mcp.run(transport="stdio")
