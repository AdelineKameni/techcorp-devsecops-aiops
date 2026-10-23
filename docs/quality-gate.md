# Quality gate : TECHCORP Orders API

## Règles de blocage automatique

| Contrôle | Condition | Décision |
|---|---|---|
| Gitleaks | Tout secret détecté (historique inclus) | **Bloque** : le secret est considéré comme compromis |
| Pytest | Au moins un test en échec | **Bloque** |
| Trivy | CVE HIGH ou CRITICAL avec correctif disponible | **Bloque** |
| Trivy | CVE sans correctif disponible (`ignore-unfixed`) | Ne bloque pas, suivi dans le registre de risques |

## Catégories de résultats

- **Vulnérabilité exploitable** : composant utilisé à l'exécution, chemin atteignable. Correction obligatoire.
- **Faux positif** : détection erronée. Consigné dans `.trivyignore` ou `.gitleaksignore` avec la preuve.
- **Vulnérabilité réelle mais non atteignable** : on supprime le composant si possible. Sinon exception approuvée.
- **Exception approuvée** : identifiant, justification, approbateur, **date d'expiration**. Sans échéance, elle devient une dette permanente.

## Premier run Trivy (23/10/2026)

Image `techcorp-api:ci` : 0 vulnérabilité OS, 5 HIGH Python, 0 CRITICAL.

| Paquet | CVE | Constat | Décision |
|---|---|---|---|
| starlette 0.46.2 | CVE-2025-62727, CVE-2026-48818, CVE-2026-54283 | Dépendance de FastAPI, correctif disponible | Corrigé par mise à jour de FastAPI |
| jaraco.context 5.3.0 | CVE-2026-23949 | Copie embarquée dans setuptools, non utilisée à l'exécution | Corrigé : setuptools supprimé de l'image |
| wheel 0.45.1 | CVE-2026-24049 | Copie embarquée dans setuptools, outil de build | Corrigé : setuptools supprimé de l'image |

Aucune exception approuvée à ce jour.