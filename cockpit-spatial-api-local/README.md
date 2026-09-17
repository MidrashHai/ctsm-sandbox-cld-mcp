# Cockpit Spatial API — copie locale patchée (SSL)

Ce dossier contient une copie de 5 fichiers du service `cockpit-spatial-api`
(source officielle : https://github.com/MidrashHai/cockpit-spatial-api.git),
adaptés pour tourner en local contre une base PostgreSQL locale (`mk_omhai`)
sans TLS.

**⚠️ Ces fichiers NE sont PAS la source de déploiement Render.**
La source GitHub pristine (`cockpit-spatial-api`) n'a jamais été modifiée et
reste utilisée telle quelle pour le déploiement Render.

## Modification apportée

Chaque fichier instancie son propre `pg.Pool` / `pg.Client`. La config SSL
`{ rejectUnauthorized: false }` a été rendue conditionnelle :

```js
const _isLocalDb = /localhost|127\.0\.0\.1/.test(process.env.DATABASE_URL || '');
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: _isLocalDb ? false : { rejectUnauthorized: false },
});
```

Fichiers concernés : `server.js`, `resolve-presence.js`, `territoire.js`,
`voiries.js`, `auth.js`.

## Usage

Ces fichiers tournent depuis le dossier de travail local
`CTSM-MCP-Sandbox/Cockpit Spatial CTSM_AgentProof/` (avec ses propres
`node_modules`, `.env`, `package.json`, etc.). Ce dossier `cockpit-spatial-api-local/`
n'est qu'une copie archivée à des fins de traçabilité git — pour relancer le
serveur local, utiliser le dossier de travail, pas cette copie.
