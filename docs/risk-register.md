# Registre des risques : TECHCORP Orders API

## Mesures déjà en place
- Conteneur non-root (utilisateur `appuser`, UID 10001)
- Système de fichiers en lecture seule (`read_only: true`) avec `tmpfs` sur `/tmp`
- `no-new-privileges:true`
- Ports exposés uniquement sur `127.0.0.1`
- Dépendances Python épinglées, images Prometheus et Grafana versionnées
- Permissions du workflow limitées à `contents: read`

## Risques identifiés

| # | Risque | Preuve | Gravité | Probabilité | Mesure corrective |
|---|--------|--------|---------|-------------|-------------------|
| 1 | Dépendances vulnérables | `app/requirements.txt` fige 3 paquets, mais les dépendances transitives ne sont pas verrouillées | Élevée | Moyenne | Scan Trivy en CI, lockfile avec hashes, Dependabot |
| 2 | Image de base mutable | `FROM python:3.11-slim` est un tag flottant | Moyenne | Élevée | Épingler le digest sha256, scan Trivy de l'image |
| 3 | Actions CI non épinglées | `actions/checkout@v4` et `setup-python@v5` sont des tags déplaçables | Élevée | Faible à moyenne | Épingler sur un SHA de commit complet |
| 4 | Aucun contrôle de secrets | Rien n'empêche de committer un token ; il resterait dans l'historique Git | Critique | Moyenne | Gitleaks en CI, `.env` dans `.gitignore`, GitHub Secrets |
| 5 | Grafana ouvert | `GF_AUTH_ANONYMOUS_ENABLED: "true"` ; admin par défaut si non modifié | Moyenne | Faible (labo local) | Désactiver l'anonyme hors labo, mot de passe via secret |

## Risques secondaires
- Pas de `HEALTHCHECK` ni de limites CPU/mémoire
- Le CI construit l'image mais ne bloque rien (deux `TODO` dans `ci.yml`)
- Pas de protection de branche sur `main`