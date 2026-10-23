from aiops.detector import (
    baseline_of,
    build_query,
    detect_anomaly,
    evaluate,
    make_report,
    parse_window,
)


def test_threshold():
    assert not detect_anomaly(2)
    assert detect_anomaly(3)


def test_approval_required():
    assert make_report(4, [], "pending")["human_approval_required"] is True


def test_spike_on_quiet_baseline_is_anomaly():
    verdict = evaluate(12, [0.0] * 20)
    assert verdict["is_anomaly"] is True
    assert verdict["method"] == "rolling_baseline_zscore"
    assert verdict["z_score"] == 12.0


def test_same_count_is_normal_on_noisy_baseline():
    history = [4, 5, 6, 5, 4, 6, 5, 5, 4, 6]
    assert detect_anomaly(7) is True  # le seuil fixe se déclencherait
    verdict = evaluate(7, history)
    assert verdict["is_anomaly"] is False  # la baseline dit que 7 est banal ici
    assert verdict["z_score"] < 3


def test_short_history_falls_back_to_static_threshold():
    verdict = evaluate(4, [0, 0])
    assert verdict["method"] == "static_threshold_fallback"
    assert verdict["is_anomaly"] is True
    assert verdict["z_score"] is None
    assert evaluate(1, [0, 0])["is_anomaly"] is False


def test_window_parsing_and_query():
    assert parse_window("30s") == 30
    assert parse_window("5m") == 300
    assert "[5m]" in build_query("5m")
    for invalid in ("", "abc", "5", "5x"):
        try:
            parse_window(invalid)
        except ValueError:
            continue
        raise AssertionError(f"{invalid!r} aurait dû être refusée")


def test_current_window_is_excluded_from_baseline():
    history = list(range(10))
    assert baseline_of(history, "1m", "15s") == list(range(6))
    assert baseline_of([1, 2], "1m", "15s") == []


def test_report_embeds_verdict():
    verdict = evaluate(12, [0.0] * 20)
    report = make_report(12, [], "hypothèse", verdict)
    assert report["observations"]["verdict"]["is_anomaly"] is True
    assert report["human_approval_required"] is True