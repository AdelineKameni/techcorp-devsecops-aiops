"""Détecteur d'anomalies pour TECHCORP Orders API.

- detect_anomaly : seuil statique d'origine (conservé, utilisé par les tests du starter).
- evaluate       : verdict explicable (fenêtre, baseline glissante, z-score).
- make_report    : rapport d'incident, approbation humaine toujours requise.
"""
import argparse
import json
import math
import statistics
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlencode

PROMETHEUS = "http://localhost:9090/api/v1/query"
PROMETHEUS_RANGE = "http://localhost:9090/api/v1/query_range"
QUERY = 'sum(increase(techcorp_http_requests_total{status="500"}[1m]))'


def parse_window(window):
    """Convertit '30s', '1m' ou '1h' en secondes. Refuse toute autre forme."""
    units = {"s": 1, "m": 60, "h": 3600}
    if not window or window[-1] not in units or not window[:-1].isdigit():
        raise ValueError(f"fenêtre invalide : {window!r} (exemples : 30s, 1m, 5m)")
    return int(window[:-1]) * units[window[-1]]


def build_query(window="1m"):
    """Requête PromQL du nombre d'erreurs 500 sur la fenêtre.

    'or vector(0)' renvoie 0 quand aucune erreur 500 n'a jamais existé :
    sans cela, la série n'existe pas et la baseline serait vide.
    """
    parse_window(window)
    return (
        'sum(increase(techcorp_http_requests_total{status="500"}'
        f"[{window}])) or vector(0)"
    )


def _get_json(url, params):
    with urllib.request.urlopen(url + "?" + urlencode(params), timeout=5) as response:
        return json.load(response)


def get_error_count(window="1m"):
    payload = _get_json(PROMETHEUS, {"query": build_query(window)})
    series = payload.get("data", {}).get("result", [])
    return float(series[0]["value"][1]) if series else 0.0


def get_history(window="1m", lookback="30m", step="15s"):
    """Série historique du nombre d'erreurs sur la fenêtre, pas après pas."""
    end = time.time()
    start = end - parse_window(lookback)
    payload = _get_json(
        PROMETHEUS_RANGE,
        {
            "query": build_query(window),
            "start": start,
            "end": end,
            "step": parse_window(step),
        },
    )
    series = payload.get("data", {}).get("result", [])
    if not series:
        return []
    values = [float(point[1]) for point in series[0]["values"]]
    return [v for v in values if not math.isnan(v)]


def baseline_of(history, window="1m", step="15s"):
    """Retire de l'historique les points couverts par la fenêtre courante.

    Sans cela, un incident en cours entrerait dans sa propre baseline.
    """
    excluded = math.ceil(parse_window(window) / parse_window(step))
    return history[:-excluded] if len(history) > excluded else []


def detect_anomaly(count, threshold=3):
    """Seuil statique d'origine : conservé pour comparaison avec evaluate()."""
    return count >= threshold


def evaluate(count, history, window="1m", threshold=3, z_threshold=3.0,
             min_history=8, min_std=1.0):
    """Verdict explicable : compare `count` à la baseline `history`.

    Anomalie si count >= threshold ET z-score >= z_threshold.
    L'écart-type est plafonné par le bas (min_std) pour éviter une division
    par zéro quand la baseline ne contient aucune erreur.
    """
    n = len(history)
    reasons = []

    if n < min_history:
        is_anomaly = count >= threshold
        reasons.append(
            f"Baseline insuffisante ({n} points, {min_history} requis) : "
            f"repli sur le seuil fixe {threshold}."
        )
        reasons.append(
            f"{count:g} erreur(s) HTTP 500 sur {window} "
            f"{'>=' if is_anomaly else '<'} seuil {threshold}."
        )
        return {
            "verdict": "ANOMALIE" if is_anomaly else "NORMAL",
            "is_anomaly": is_anomaly,
            "method": "static_threshold_fallback",
            "window": window,
            "observed": count,
            "baseline_points": n,
            "baseline_mean": None,
            "baseline_std": None,
            "z_score": None,
            "reasons": reasons,
        }

    mean = statistics.fmean(history)
    std = statistics.pstdev(history)
    effective_std = max(std, min_std)
    z = (count - mean) / effective_std
    above_floor = count >= threshold
    above_z = z >= z_threshold
    is_anomaly = above_floor and above_z

    reasons.append(
        f"Observé : {count:g} erreur(s) HTTP 500 sur {window}. "
        f"Baseline sur {n} points : moyenne {mean:.2f}, écart-type {std:.2f}."
    )
    reasons.append(
        f"Écart-type retenu : {effective_std:.2f} (plancher {min_std})."
    )
    reasons.append(
        f"z-score = ({count:g} - {mean:.2f}) / {effective_std:.2f} = {z:.2f} "
        f"({'>=' if above_z else '<'} seuil {z_threshold})."
    )
    reasons.append(
        f"Plancher absolu : {count:g} {'>=' if above_floor else '<'} {threshold}."
    )
    return {
        "verdict": "ANOMALIE" if is_anomaly else "NORMAL",
        "is_anomaly": is_anomaly,
        "method": "rolling_baseline_zscore",
        "window": window,
        "observed": count,
        "baseline_points": n,
        "baseline_mean": round(mean, 3),
        "baseline_std": round(std, 3),
        "z_score": round(z, 3),
        "reasons": reasons,
    }


def make_report(count, logs, hypothesis, verdict=None):
    observations = {"http_500_last_minute": count, "logs": logs}
    if verdict is not None:
        observations["verdict"] = verdict
    return {
        "incident_id": "INC-2026-1042",
        "observations": observations,
        "hypothesis": hypothesis,
        "checks_read_only": [],
        "confidence": "unverified",
        "human_approval_required": True,
    }


def main():
    parser = argparse.ArgumentParser(description="Détecteur d'anomalies HTTP 500")
    parser.add_argument("--window", default="1m", help="fenêtre d'observation (ex. 1m, 5m)")
    parser.add_argument("--lookback", default="30m", help="durée de la baseline")
    parser.add_argument("--step", default="15s", help="pas de l'historique")
    args = parser.parse_args()

    try:
        count = get_error_count(args.window)
        history = get_history(args.window, args.lookback, args.step)
    except (urllib.error.URLError, OSError) as error:
        print(f"Prometheus injoignable : {error}", file=sys.stderr)
        sys.exit(1)

    verdict = evaluate(
        count, baseline_of(history, args.window, args.step), window=args.window
    )
    report = make_report(
        count,
        [],
        "Hypothèse non vérifiée : à corroborer avec les logs et le changement 2.4.7.",
        verdict,
    )
    Path("report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    print(f"Verdict : {verdict['verdict']} (méthode : {verdict['method']})")
    for reason in verdict["reasons"]:
        print(f"  - {reason}")
    print("report.json généré")


if __name__ == "__main__":
    main()