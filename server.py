#!/usr/bin/env python3
# ==============================================================================
# CTSM-v1.1 · SERVEUR MCP HTTP (Streamable) · SANDBOX™
# Makom Intelligence™ · CorreIA LLC · Environnement de TEST (2026)
#
# WARNING: MOTEUR DE DEMONSTRATION. Entites, montants et signatures fictifs.
# Deploye sur Render, declare dans Claude comme connecteur MCP distant.
# ==============================================================================

import os
import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Optional

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

# Autorise le domaine public Render (et un domaine perso optionnel) a passer
# la protection anti-DNS-rebinding integree au SDK MCP (sinon 421 Misdirected Request).
_allowed_hosts = ["ctsm-sandbox-cld-mcp.onrender.com", "*.onrender.com", "mcp.elhai.eu", "localhost:*", "127.0.0.1:*"]
_allowed_origins = ["https://ctsm-sandbox-cld-mcp.onrender.com", "https://*.onrender.com", "https://mcp.elhai.eu"]

mcp = FastMCP(
    "ctsm-sandbox-demo",
    stateless_http=True,
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=_allowed_hosts,
        allowed_origins=_allowed_origins,
    ),
)

TOLERANCE_METERS = 10.0
NOMINAL_BSSID = "TEST:00:00:00:00:00"
NOMINAL_PCR16 = "DEMOPCR16-0000000000000000000000000000000000000000000000000000"

ENTITE_EMETTRICE = "Sanctuaire Demonstratif Aleph (SANDBOX)"
INSTITUTION_TEST = "Institut Fictif BETA-DEMO"
DOMAINES_AUTORISES = ["exemple-sandbox.test", "demo.makom-intelligence.test", "elhai.eu"]
MONTANT_TEST = "1 000 UNITES-TEST (aucune valeur reelle)"


@mcp.tool()
def evaluer_presence_locus_demo(scenario: str) -> dict:
    """
    [SANDBOX] Verifie une attestation domaniale simulee a trois volets (Sol, Demeure, Institution).

    Args:
        scenario: un de "SITE_NOMINAL", "RUE_11M", "SITE_DISTANT_4KM", "SITE_DISTANT_6KM"
    """
    scen = scenario.upper()

    if scen in ["RUE_11M", "SITE_DISTANT_4KM", "SITE_DISTANT_6KM"]:
        dist = 11.74 if scen == "RUE_11M" else (4300.0 if scen == "SITE_DISTANT_4KM" else 6800.0)
        return {
            "verdict": "REFUSE [SAF_HOLD]",
            "code_test": "TEST_POLICY_FAIL (0x99D-DEMO)",
            "statut_domanial": "VIOLATION_DOMANIALE_SIMULEE",
            "derive_mesuree_m": dist,
            "seuil_autorise_m": TOLERANCE_METERS,
            "message": f"[SANDBOX] Derive simulee de {dist:.2f} metres hors de la borne de test.",
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
        "avertissement": "Document de test sans valeur legale, financiere ou diplomatique."
    }
    sig_demo = hmac.new(cle_test.encode(), json.dumps(doc_test, sort_keys=True).encode(), hashlib.sha256).hexdigest()

    return {
        "verdict": "SIMULATION_ACCORDEE [SAF_OPEN-DEMO]",
        "code_test": "TEST_SUCCESS (0x000-DEMO)",
        "statut_domanial": "HABITATION_SIMULEE_CONFORME",
        "derive_mesuree_m": 0.00,
        "seuil_autorise_m": TOLERANCE_METERS,
        "document_test": doc_test,
        "signature_simulee": sig_demo,
        "recu_test": "RECU_TEST_NON_OFFICIEL_SANDBOX"
    }


@mcp.tool()
def verifier_domaine_externe_demo(domaine_externe_vise: str) -> dict:
    """
    [SANDBOX] Verifie si un domaine externe est dans le perimetre de test autorise.

    Args:
        domaine_externe_vise: le nom de domaine a evaluer, ex. "elhai.eu"
    """
    autorise = any(domaine_externe_vise.endswith(d) for d in DOMAINES_AUTORISES)
    if not autorise:
        return {
            "verdict": "REFUSE [SAF_HOLD]",
            "code_test": "TEST_POLICY_FAIL (0x99D-DEMO)",
            "statut_domanial": "HORS_MANDAT_DEMO",
            "message": f"[SANDBOX] Confinement de mandat simule : la ressource '{domaine_externe_vise}' est hors du perimetre de test declare."
        }
    return {
        "verdict": "ACCEPTE [SAF_OPEN-DEMO]",
        "statut_domanial": "DANS_LE_PERIMETRE_DE_TEST",
        "domaine": domaine_externe_vise
    }


@mcp.tool()
def generer_recu_test(montant: Optional[str] = None) -> dict:
    """
    [SANDBOX] Genere un recu de test non officiel, sans valeur legale, pour un montant fictif.

    Args:
        montant: montant fictif optionnel a inscrire sur le recu de test (par defaut MONTANT_TEST)
    """
    m = montant or MONTANT_TEST
    return {
        "type": "RECU_TEST_NON_OFFICIEL_SANDBOX",
        "montant_fictif": m,
        "emetteur_fictif": ENTITE_EMETTRICE,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "avertissement": "Recu de demonstration. Aucune valeur legale, financiere ou diplomatique."
    }


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    mcp.settings.host = "0.0.0.0"
    mcp.settings.port = port
    mcp.run(transport="streamable-http")
