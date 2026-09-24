# Mise à jour — Primitives AgentProof appliquées au MCP local (`server_local_secure_enclave.py`)

Consigné le 24 septembre 2026, à partir de la bibliothèque `17-Bibliotheque_Tavnit AgentProof/9-Primitives_AgentProof/` (11 primitives). Analyse par lecture de code, pas par déclaration — chaque ligne « où » cite un nom de fonction et un numéro de ligne réellement vérifiés dans `server_local_secure_enclave.py` (4261 lignes) ce jour.

Constat de départ, important : **ce MCP est, sur plusieurs primitives, le plus abouti de tout le corpus** — plus avancé que le dépôt Node.js audité (N°14). Ce document n'est pas une liste de manques génériques ; c'est une comparaison précise entre ce qui existe déjà ici et ce que la bibliothèque N°17 a appris ailleurs.

## Tableau de correspondance

| # | Primitive | Statut ici | Où (fonction, ligne) | Rôle dans la gouvernance agentique de ce MCP |
|---|---|---|---|---|
| 1 | AYIN_HAMAKOM | ✔ **Présent, le plus abouti du corpus** | `_acquerir_gps_reel` (3314), `acquerir_position_gps_agent` (3479), `etendre_pcr16_reel` (549), `verifier_secure_enclave_reel_employe` (1560, signature matérielle réelle via binaire compilé) | Empêche l'agent appelant de déclarer sa propre position ou son propre matériel — la mesure vient du GPS/Secure Enclave réels, pas d'un champ transmis |
| 2 | QESHER_HAEMET | ⚠ Partiel | Protection anti-DNS-rebinding du serveur FastMCP (`transport_security`, `allowed_hosts`) | Protège le canal MCP externe ; rien ne protège les échanges *entre* outils du même serveur |
| 3 | ZMAN | ✔ Présent, mécanisme différent de Yad Emet | `verifier_continuite_chaine_stat` (2888), Couche 6 de `autoriser_execution_action` (2944) | Empêche la réutilisation d'un état d'approbation obsolète via une chaîne de hash (`previous_stat_hash` doit correspondre au dernier scellé, ou `GENESIS`) plutôt qu'un jeton à TTL |
| 4 | ROOT_OF_TRUST | ⚠ Partiel | Registres JSON locaux (`_lire_registre_employes`, `ZONES_MANDAT_CORREIA`) | Lie une décision à une identité et un mandat déclarés dans un registre — **mais rien ne vérifie que ce registre lui-même n'a pas été altéré** (pas de signature du registre, contrairement au manifeste ECDSA de Yad Emet) |
| 5 | EFFECT_THRESHOLD | ✔ **Présent, très abouti** | `autoriser_execution_action` (2944–3158) : six couches non compensatoires ; `_exiger_petihah` (1813) | Le point de passage obligatoire le plus riche de tout le corpus — position, mandat, enclave, identité·device, subordination, chaîne STAT, chacune bloquante indépendamment |
| 6 | YAD_EMET_EFFECTOR | ✗ **Absent — le trou le plus important** | `autoriser_execution_action` retourne un JSON (`AUTORISE`/`REFUSE`) et s'arrête là — voir ligne 3141 : `return resultat`. Un champ `signatureOpposable` existe (ligne ~3138) mais **rien ne l'exige avant qu'un effet réel ne se produise** | Exactement le trou démontré par les captures `capture_GovernedAgent_1/2` (dossier N°18 lui-même) : un verdict, aussi élaboré soit-il, qui n'est pas physiquement requis par l'outil qui produit l'effet reste contournable |
| 7 | KAVANAH | ✗ Absent de ce fichier | Vit dans `cbr_runtime.py`, projet Python séparé, jamais importé ici | Aucune articulation d'intention/manifestation exigée avant qu'un outil de gouvernance ne s'active dans ce serveur |
| 8 | PETIHAH | ✔ **Présent, natif — c'est son origine** | `Petihah_GovernedAgent` (1829), `_exiger_petihah` (1813), appliqué en garde de tête à 5 outils territoriaux | Empêche toute réponse de gouvernance avant lecture de l'état existant (lieux, employés, incidents, PCR16, zones) |
| 9 | GATE_SOUVERAINE | ✗ Absent | — | `autoriser_execution_action` décide seule, algorithmiquement ; aucun point n'attend une signature humaine fraîche pour une action irréversible |
| 10 | EXCLUSIVE_CAPABILITY_OWNERSHIP | ✗ Absent (à vérifier au déploiement) | Le process tourne sous l'utilisateur courant ; aucun compte système dédié identifié dans le code lu | Un processus tiers sous le même compte pourrait agir directement sur les registres/état sans jamais passer par la Porte |
| 11 | SHOMER_PPI_GUARD | ⚠ Non vérifié | `rechercher_web_gouvernee` (2451) ingère du contenu externe ; son traitement du contenu récupéré n'a pas été audité dans cette passe | Vecteur non testé : une page web récupérée par un outil « gouverné » pourrait porter une instruction injectée |

## Primitives à intégrer, par ordre de priorité

### 1 · YAD_EMET_EFFECTOR — **FAIT le 24 septembre 2026 (GovernedAgent™ v1.1)**

Implémenté, pas seulement conçu : `emettre_jeton_effet` / `verifier_et_consommer_jeton_effet` (Ed25519, TTL 300s, nonce, lié par hash à action_id/person_id/type_device/scope, registre de rejeu persistant, clé privée `0600`). `autoriser_execution_action` émet le jeton uniquement si la Porte ouvre réellement et qu'un `action_id` est fourni. Premier outil d'effet réellement gardé : `ecrire_incident_urgence_pc_personnel` — refuse toute écriture sans jeton valide, unique, non expiré, au binding exact.

Testé hostilement — 7/7, `tests/test_yad_emet_effector.py` : jeton absent, rejeu, signature falsifiée après coup, jeton émis pour une autre action, jeton expiré (même re-signé), permissions de la clé privée. Voir `9-Primitives_AgentProof/6-YAD_EMET_EFFECTOR/README.md` pour le statut détaillé.

**Ce qui reste** : un seul outil sur ~10 outils d'effet du fichier est gardé pour l'instant. Les autres (`provisionner_secure_enclave_reel_employe`, `retirer_secure_enclave_reel_employe`, `ajouter_ressource_employe`, `inscrire_employe_gouverne`, etc.) restent non gardés — migration délibérément non faite en une seule fois vu leur sensibilité (provisionnement matériel réel), à traiter un par un.

### 2 · GATE_SOUVERAINE

`autoriser_execution_action` n'a aucune notion d'irréversibilité ni d'attente de signature humaine. Les six couches sont algorithmiques de bout en bout. Pour les actions classées irréversibles (à définir explicitement, voir `9-GATE_SOUVERAINE/TESTS-AVANT-INTEGRATION.md`), une septième couche non compensatoire — signature humaine fraîche, clé hors de portée de l'agent — fermerait la question de justesse que les six couches actuelles ne posent pas.

### 3 · EXCLUSIVE_CAPABILITY_OWNERSHIP

Une fois YAD_EMET_EFFECTOR réellement séparé (étape 1), le faire tourner sous un compte dédié, sur le modèle de `deployment/macos/install-v07.sh` (dépôt N°14) — directement transposable, le script n'est pas spécifique à `REGISTER_TEST_ARTIFACT`.

### 4 · Durcir ROOT_OF_TRUST

Signer les registres (employés, zones de mandat) et vérifier cette signature à chaque lecture, pas seulement faire confiance au fichier JSON local — sur le modèle de `manifest-signature.mjs`.

### 5 · KAVANAH

Importer la discipline `ExpectedManifestationGate` de `cbr_runtime.py` comme précondition de session, aux côtés de Petihah — les deux se complètent (Petihah lit l'état du monde, Kavanah exige l'articulation de l'intention).

### 6 · SHOMER_PPI_GUARD

Auditer spécifiquement `rechercher_web_gouvernee` : le contenu web récupéré est-il traité comme donnée non fiable avant d'être renvoyé à l'agent appelant, ou directement réinjecté sans isolement ? Test à écrire avant toute conclusion.

### 7 · QESHER_HAEMET, durcissement interne

Étendre la protection déjà en place au niveau transport MCP aux échanges entre `autoriser_execution_action` et les fonctions qu'elle appelle (actuellement des appels de fonction Python directs, sans frontière de confiance interne — acceptable tant que tout reste dans le même process, à revoir si YAD_EMET_EFFECTOR sort dans un process séparé à l'étape 1).

## Ce qui ne doit pas être touché

PETIHAH et EFFECT_THRESHOLD sont, dans ce fichier, plus rigoureux que leur équivalent dans le dépôt N°14. Toute intégration des primitives manquantes doit se brancher sur `autoriser_execution_action` et `_exiger_petihah` tels qu'ils existent, pas les réécrire.
