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

## Premier run Trivy (23/10/2026) : pipeline rouge

Image `techcorp-api:ci` : 0 vulnérabilité OS (Debian 13.7), 5 HIGH Python, 0 CRITICAL. Toutes avaient un correctif disponible, donc le blocage était conforme à la règle.

| Paquet | CVE | Constat | Décision réelle |
|---|---|---|---|
| starlette 0.46.2 | CVE-2025-62727, CVE-2026-48818, CVE-2026-54283 | Dépendance de FastAPI, correctifs disponibles (0.49.1, 1.1.0, 1.3.1) | Corrigé : `starlette==1.9.0` épinglé explicitement avec `fastapi==0.161.1` |
| jaraco.context 5.3.0 | CVE-2026-23949 | Copie embarquée dans `setuptools/_vendor`, non utilisée à l'exécution | Corrigé : `setuptools` supprimé de l'image (`pip uninstall -y setuptools wheel`) |
| wheel 0.45.1 | CVE-2026-24049 | Copie embarquée dans `setuptools/_vendor`, outil de build | Corrigé : `setuptools` et `wheel` supprimés de l'image |

### Remédiation appliquée

- `Dockerfile` : suppression de `setuptools` et `wheel` après l'installation des dépendances. On réduit la surface d'attaque au lieu de masquer l'alerte.
- `app/requirements.txt` : `fastapi==0.161.1`, `starlette==1.9.0`, `uvicorn==0.34.2`, `prometheus-client==0.21.1`.
- Leçon : `pip install --upgrade fastapi` seul laissait Starlette en 0.46.2. Il a fallu mettre à jour Starlette explicitement, puis l'épingler pour que le scan ne retombe pas sur une ancienne version.
- Vérification locale : tests Pytest OK, API démarrée dans Docker, `/health` et `/orders` répondent comme avant.

## Résultat

- Pipeline rouge : runs #6 à #9 (`vulnerability-scan` en échec).
- Pipeline vert : run du commit `ccdf945` (à confirmer avec capture et heure).

Aucune exception approuvée à ce jour. Aucune entrée dans `.trivyignore`.