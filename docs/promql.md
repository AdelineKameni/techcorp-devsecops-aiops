# Requêtes PromQL : TECHCORP Orders API

Métriques exposées par l'API : `techcorp_http_requests_total{path,status}` (compteur)
et `techcorp_request_duration_seconds` (histogramme par `path`).

| Indicateur | Requête |
|---|---|
| Disponibilité de la cible | `up{job="techcorp-api"}` |
| Débit par statut | `sum by (status) (rate(techcorp_http_requests_total{path="/orders"}[1m]))` |
| Taux d'erreur | `sum(rate(techcorp_http_requests_total{path="/orders",status="500"}[1m])) / sum(rate(techcorp_http_requests_total{path="/orders"}[1m]))` |
| Latence p95 | `histogram_quantile(0.95, sum by (le) (rate(techcorp_request_duration_seconds_bucket{path="/orders"}[1m])))` |

Notes :
- `rate(...[1m])` donne un débit par seconde sur 1 minute. Sans trafic dans la fenêtre, la série est vide.
- Le taux d'erreur est un ratio : il est indéfini quand il n'y a aucune requête.
- La latence est mesurée dans un bloc `finally` : les requêtes en erreur 500 sont aussi comptées.