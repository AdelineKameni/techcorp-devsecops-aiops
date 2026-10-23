# B4 : seuil d'alerte contre détection d'anomalies

## Ce que fait la règle actuelle

`ElevatedHTTP500` se déclenche quand `sum(increase(techcorp_http_requests_total{status="500"}[1m])) >= 3`
pendant 15 secondes. C'est un **seuil statique** : un nombre fixé à la main, identique à toute heure
et pour tout niveau de trafic. La fonction `detect_anomaly(count, threshold=3)` du détecteur de départ
applique exactement le même test (`count >= threshold`), donc elle n'apporte aucune information de plus.

## Limites d'un seuil fixe

| Situation | Effet du seuil `>= 3` | Pourquoi c'est un problème |
|---|---|---|
| Fort trafic (par exemple 1000 requêtes par seconde) | 3 erreurs en une minute représentent un taux négligeable, mais l'alerte se déclenche | Faux positif : le seuil ignore le volume |
| Faible trafic (par exemple 2 requêtes, toutes en erreur) | 100 % d'erreurs, mais l'alerte ne se déclenche pas | Faux négatif : un compte absolu masque un taux de 100 % |
| Trafic qui évolue (heures creuses, pics) | Le même nombre est jugé normal ou grave selon le moment | Aucune notion de « normal » appris |
| Premier incident sur une nouvelle série | `increase()` ne voit pas l'apparition de la première valeur | L'alerte peut démarrer avec une erreur de retard |
| Verdict | Booléen sans explication | On ne sait ni de combien on dépasse, ni par rapport à quoi |

Autres points techniques : `increase()` extrapole sur la fenêtre et peut donner des valeurs non entières,
et la règle ne compare jamais le présent au passé.

## Ce qu'apporte une détection d'anomalies statistique

On compare l'observation à une **baseline apprise** sur un historique récent :

- on calcule la moyenne `m` et l'écart-type `s` du taux d'erreur sur une fenêtre glissante (par exemple 30 minutes) ;
- on calcule le **z-score** `z = (x - m) / s` : le nombre d'écarts-types qui séparent la valeur courante de la normale ;
- on signale une anomalie si `z` dépasse un seuil (par exemple 3), ce qui revient à dire « cette valeur est très inhabituelle pour ce service ».

| Critère | Seuil fixe | Anomalie statistique |
|---|---|---|
| Référence | Nombre choisi à la main | Comportement observé du service |
| S'adapte au trafic | Non | Oui, si on travaille sur un taux ou une baseline glissante |
| Explicable | Non (vrai ou faux) | Oui : valeur, moyenne, écart-type, z-score |
| Donnée nécessaire | Aucune | Un historique |

## Limites de la détection statistique (à ne pas passer sous silence)

- Elle exige un historique : au démarrage d'un service, la baseline n'existe pas.
- Si l'écart-type est nul (aucune erreur dans l'historique), le z-score n'est pas défini : il faut un plancher.
- Un pic légitime (promotion, fin de mois) est signalé comme anomalie : une anomalie n'est pas forcément une panne.
- Une baseline apprise pendant un incident long finit par le considérer comme normal.
- Le résultat reste une **hypothèse** : il doit être corroboré par les logs et le contexte du changement.

## Choix pour ce TP

Le détecteur Python (B5) utilise une fenêtre temporelle, le taux d'erreur plutôt que le compte brut,
une baseline glissante et un z-score, et renvoie un verdict explicable. La règle Prometheus reste
le filet de sécurité immédiat, et le détecteur apporte le contexte statistique.