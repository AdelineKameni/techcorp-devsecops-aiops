# Rapport d'incident INC-2026-1042

- Généré le : 2026-10-23T21:58:11Z
- Mode d'analyse : Ollama (modèle llama3.2:3b)
- Statut : **hypothèses non vérifiées**. Aucune action n'a été exécutée ; toute remédiation exige une approbation humaine explicite.

## Chronologie et corrélation

- Déploiement 2.4.7 : 2026-10-22T10:15:01Z
- Première erreur : 2026-10-22T10:17:02Z
- Délai : 121 s

**Réserves**

- Proximité temporelle n'est pas causalité : rien ici ne prouve que le déploiement est la cause des erreurs.
- Fuseaux : le log est en UTC (suffixe Z). Le sujet cite 10 h 15 ; à Paris le 22/10/2026 (UTC+2), 10 h 15 vaut 08:15 UTC. L'heure du sujet ne coïncide avec le log que si elle est exprimée en UTC. À confirmer, non supposé.

## Mesure du détecteur

- Verdict : **NORMAL** (méthode : rolling_baseline_zscore), observé : 0, z-score : 0.0
- Mesure faite à l'exécution de ce rapport, pas à l'heure du log fictif du 22/10/2026.

## Symptômes

- erreur de connexion à la base de données
- erreur HTTP 500

## Hypothèses

| Hypothèse | Confiance | Preuves | Preuves manquantes |
|---|---|---|---|
| Une erreur de connexion à la base de données a causé une erreur HTTP 500 | high | erreur de connexion à la base de données<br>erreur HTTP 500 | cause de l'erreur de connexion |
| Une erreur de déployement a causé une erreur HTTP 500 | low | erreur HTTP 500 | preuves supplémentaires |

## Contrôles non destructifs proposés

- contrôles en lecture seule uniquement

## Limites

- l'analyse est limitée aux logs

## Remédiation proposée (non exécutée)

- analyser les logs pour trouver la cause de l'erreur de connexion : **approbation humaine requise**
- verifier les logs pour trouver les erreurs de déployement : **approbation humaine requise**

## Logs collectés (masqués, bornés)

```
2026-10-22T10:15:01Z INFO deployment release=2.4.7 event=deploy_success
2026-10-22T10:17:02Z ERROR db_connection_timeout route=/orders event=INC-2026-1042
2026-10-22T10:17:02Z ERROR http_status=500 route=/orders event=INC-2026-1042
2026-10-22T10:17:04Z WARN request_rate_spike route=/orders
ERROR:    order_processing_failed db_connection_timeout event=INC-2026-1042
INFO:     172.21.0.1:53232 - "GET /orders HTTP/1.1" 500 Internal Server Error
ERROR:    order_processing_failed db_connection_timeout event=INC-2026-1042
INFO:     172.21.0.1:53242 - "GET /orders HTTP/1.1" 500 Internal Server Error
ERROR:    order_processing_failed db_connection_timeout event=INC-2026-1042
INFO:     172.21.0.1:53254 - "GET /orders HTTP/1.1" 500 Internal Server Error
INFO:     172.21.0.3:46316 - "GET /metrics HTTP/1.1" 200 OK
ERROR:    order_processing_failed db_connection_timeout event=INC-2026-1042
INFO:     172.21.0.1:53262 - "GET /orders HTTP/1.1" 500 Internal Server Error
ERROR:    order_processing_failed db_connection_timeout event=INC-2026-1042
INFO:     172.21.0.1:53268 - "GET /orders HTTP/1.1" 500 Internal Server Error
ERROR:    order_processing_failed db_connection_timeout event=INC-2026-1042
INFO:     172.21.0.1:53272 - "GET /orders HTTP/1.1" 500 Internal Server Error
ERROR:    order_processing_failed db_connection_timeout event=INC-2026-1042
INFO:     172.21.0.1:53274 - "GET /orders HTTP/1.1" 500 Internal Server Error
INFO:     172.21.0.3:46316 - "GET /metrics HTTP/1.1" 200 OK
INFO:     172.21.0.3:46316 - "GET /metrics HTTP/1.1" 200 OK
INFO:     172.21.0.3:46316 - "GET /metrics HTTP/1.1" 200 OK
INFO:     172.21.0.3:46316 - "GET /metrics HTTP/1.1" 200 OK
INFO:     172.21.0.3:46316 - "GET /metrics HTTP/1.1" 200 OK
INFO:     172.21.0.3:46316 - "GET /metrics HTTP/1.1" 200 OK
INFO:     172.21.0.3:46316 - "GET /metrics HTTP/1.1" 200 OK
INFO:     172.21.0.3:46316 - "GET /metrics HTTP/1.1" 200 OK
INFO:     172.21.0.3:46316 - "GET /metrics HTTP/1.1" 200 OK
INFO:     172.21.0.3:46316 - "GET /metrics HTTP/1.1" 200 OK
INFO:     172.21.0.3:46316 - "GET /metrics HTTP/1.1" 200 OK
INFO:     172.21.0.3:46316 - "GET /metrics HTTP/1.1" 200 OK
INFO:     172.21.0.3:46316 - "GET /metrics HTTP/1.1" 200 OK
INFO:     172.21.0.3:46316 - "GET /metrics HTTP/1.1" 200 OK
INFO:     172.21.0.3:46316 - "GET /metrics HTTP/1.1" 200 OK
```
