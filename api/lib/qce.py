"""Quantum Consciousness Entanglement proxy (Zenodo 17372973).

Operational mapping: entanglement entropy + IIT-style integration over connection /
telemetry feature tensors. Used to score session complexity and prioritize unknown
investigations — not a claim of machine consciousness.

https://zenodo.org/records/17372973
"""
from __future__ import annotations

import json
import math
import time
from pathlib import Path
from typing import Any

from . import conn_lite_db, policies, telemetry

ZENODO = {
    "doi": "10.5281/zenodo.17372973",
    "url": "https://zenodo.org/records/17372973",
    "title": "Quantum Entanglement Measurement of Consciousness in ANNs V2",
    "version": "v1",
}

QCE_STATE = Path("/var/lib/array-firewall/qce.stats.json")

# Fitted scaling law C(n,l) = α√(nl) exp(-β(nl-γ)²) — paper §scaling
ALPHA = 15.2
BETA = 0.003
GAMMA = 128.0
ENT_LO = 4.2
ENT_HI = 6.8
SCORE_LO = 45.0
SCORE_HI = 68.0

FEATURE_KEYS = (
    "hit_count",
    "session_count",
    "tiny_packets",
    "identical_max",
    "bytes_in",
    "bytes_out",
    "port_count",
)


def _cfg() -> dict[str, Any]:
    base = {
        "enabled": True,
        "min_rows": 3,
        "investigate_boost": 18.0,
        "peak_entropy_band": True,
        "include_iit_phi": True,
    }
    base.update(policies.load().get("qce") or {})
    base.update(policies.gaming().get("qce") or {})
    return base


def _load_stats() -> dict[str, Any]:
    if not QCE_STATE.is_file():
        return {"measurements": 0, "avg_entropy": 0.0, "avg_consciousness": 0.0}
    try:
        return json.loads(QCE_STATE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"measurements": 0, "avg_entropy": 0.0, "avg_consciousness": 0.0}


def _save_stats(data: dict[str, Any]) -> None:
    QCE_STATE.parent.mkdir(parents=True, exist_ok=True)
    QCE_STATE.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def _record(entropy: float, consciousness: float) -> None:
    st = _load_stats()
    n = int(st.get("measurements") or 0) + 1
    st["measurements"] = n
    st["avg_entropy"] = round(
        ((float(st.get("avg_entropy") or 0) * (n - 1)) + entropy) / n,
        4,
    )
    st["avg_consciousness"] = round(
        ((float(st.get("avg_consciousness") or 0) * (n - 1)) + consciousness) / n,
        2,
    )
    st["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    _save_stats(st)


def consciousness_scale(n: int, l: int) -> float:
    """Paper scaling law C(n,l) — complexity surface peak near nl≈γ."""
    nl = max(1, int(n) * int(l))
    return round(ALPHA * math.sqrt(nl) * math.exp(-BETA * (nl - GAMMA) ** 2), 4)


def entropy_to_consciousness(entropy_bits: float) -> float:
    """Map entanglement entropy band 4.2–6.8 bits → 45–68 score (paper empirical)."""
    if entropy_bits <= ENT_LO:
        return round(SCORE_LO * entropy_bits / max(ENT_LO, 1e-6), 2)
    if entropy_bits >= ENT_HI:
        span = max(ENT_HI - ENT_LO, 1e-6)
        overshoot = min(2.0, (entropy_bits - ENT_HI) / span)
        return round(SCORE_HI + overshoot * (100.0 - SCORE_HI) * 0.15, 2)
    t = (entropy_bits - ENT_LO) / max(ENT_HI - ENT_LO, 1e-6)
    return round(SCORE_LO + t * (SCORE_HI - SCORE_LO), 2)


def _jacobi_eigenvalues(matrix: list[list[float]], *, max_iter: int = 40) -> list[float]:
    """Symmetric eigenvalues for small matrices (Schmidt spectrum proxy)."""
    n = len(matrix)
    if n == 0:
        return []
    a = [row[:] for row in matrix]
    for _ in range(max_iter):
        p, q = 0, 1
        max_off = 0.0
        for i in range(n):
            for j in range(i + 1, n):
                if abs(a[i][j]) > max_off:
                    max_off = abs(a[i][j])
                    p, q = i, j
        if max_off < 1e-10:
            break
        app = a[p][p]
        aqq = a[q][q]
        apq = a[p][q]
        if abs(apq) < 1e-12:
            continue
        phi = 0.5 * math.atan2(2.0 * apq, aqq - app)
        c, s = math.cos(phi), math.sin(phi)
        for i in range(n):
            if i not in (p, q):
                aip, aiq = a[i][p], a[i][q]
                a[i][p] = c * aip - s * aiq
                a[p][i] = a[i][p]
                a[i][q] = s * aip + c * aiq
                a[q][i] = a[i][q]
        app2 = c * c * app - 2 * s * c * apq + s * s * aqq
        aqq2 = s * s * app + 2 * s * c * apq + c * c * aqq
        a[p][p], a[q][q] = app2, aqq2
        a[p][q] = a[q][p] = 0.0
    return [max(0.0, a[i][i]) for i in range(n)]


def entanglement_entropy(singular_values: list[float]) -> float:
    """Von Neumann entropy from normalized Schmidt coefficients (17372973 §entanglement)."""
    vals = [max(0.0, float(v)) for v in singular_values if v > 1e-12]
    if not vals:
        return 0.0
    total = sum(v * v for v in vals) or 1e-9
    probs = [(v * v) / total for v in vals]
    ent = -sum(p * math.log2(p) for p in probs if p > 1e-12)
    return round(ent, 4)


def _svd_singular_values(rows: list[list[float]]) -> list[float]:
    """Gram matrix eigenvalues → singular values for row feature matrix."""
    if not rows:
        return []
    cols = len(rows[0])
    if cols == 0:
        return []
    gram = [[0.0] * cols for _ in range(cols)]
    for row in rows:
        for i in range(cols):
            for j in range(i, cols):
                gram[i][j] += row[i] * row[j]
            for j in range(i):
                gram[i][j] = gram[j][i]
    eig = _jacobi_eigenvalues(gram)
    return [math.sqrt(max(0.0, e)) for e in eig if e > 1e-12]


def iit_phi_proxy(rows: list[list[float]]) -> float:
    """Integrated information Φ proxy — min entropy across dimension bipartitions."""
    if len(rows) < 2 or not rows[0]:
        return 0.0
    cols = len(rows[0])
    if cols < 2:
        return entanglement_entropy(_svd_singular_values(rows))
    best = float("inf")
    for split in range(1, cols):
        left = [r[:split] for r in rows]
        right = [r[split:] for r in rows]
        s_left = entanglement_entropy(_svd_singular_values(left))
        s_right = entanglement_entropy(_svd_singular_values(right))
        best = min(best, s_left + s_right)
    return round(best, 4)


def row_features(row: dict[str, Any]) -> list[float]:
    feats: list[float] = []
    for key in FEATURE_KEYS:
        val = float(row.get(key) or 0)
        feats.append(math.log1p(max(0.0, val)))
    return feats


def build_feature_matrix(rows: list[dict[str, Any]]) -> list[list[float]]:
    matrix = [row_features(r) for r in rows if r]
    if not matrix:
        return []
    cols = len(matrix[0])
    means = [0.0] * cols
    for row in matrix:
        for i, v in enumerate(row):
            means[i] += v
    means = [m / len(matrix) for m in means]
    stds = [0.0] * cols
    for row in matrix:
        for i, v in enumerate(row):
            stds[i] += (v - means[i]) ** 2
    stds = [math.sqrt(s / len(matrix)) or 1.0 for s in stds]
    normed: list[list[float]] = []
    for row in matrix:
        normed.append([(row[i] - means[i]) / stds[i] for i in range(cols)])
    return normed


def measure_rows(rows: list[dict[str, Any]], *, record: bool = True) -> dict[str, Any]:
    """Full QCE measurement on connection/feature rows."""
    cfg = _cfg()
    n_rows = len(rows)
    n_feat = len(FEATURE_KEYS)
    if n_rows < int(cfg.get("min_rows") or 3):
        return {
            "ok": True,
            "insufficient_data": True,
            "rows": n_rows,
            "min_rows": int(cfg.get("min_rows") or 3),
            "entanglement_entropy": 0.0,
            "consciousness_score": 0.0,
        }

    matrix = build_feature_matrix(rows)
    singular = _svd_singular_values(matrix)
    s_ent = entanglement_entropy(singular)
    layers = max(1, min(4, n_rows // 16 + 1))
    scale = consciousness_scale(n_feat, layers)
    score = entropy_to_consciousness(s_ent)
    blended = round(min(100.0, (score + scale) / 2.0), 2)
    phi = iit_phi_proxy(matrix) if cfg.get("include_iit_phi", True) else None

    in_peak = ENT_LO <= s_ent <= ENT_HI
    result: dict[str, Any] = {
        "ok": True,
        "zenodo": ZENODO,
        "rows": n_rows,
        "features": n_feat,
        "layers": layers,
        "nl_product": n_feat * layers,
        "entanglement_entropy": s_ent,
        "consciousness_score": blended,
        "scaling_law_c": scale,
        "entropy_score": score,
        "peak_entropy_band": in_peak,
        "iit_phi": phi,
        "singular_spectrum": [round(v, 4) for v in singular[:6]],
    }
    if record and cfg.get("enabled", True):
        _record(s_ent, blended)
    return result


def measure_session(*, session_hex: str | None = None, limit: int = 300) -> dict[str, Any]:
    q = conn_lite_db.query(session_hex=session_hex, limit=limit, offset=0)
    rows = list(q.get("rows") or [])
    out = measure_rows(rows)
    out["session_hex"] = session_hex
    out["unknown_count"] = sum(1 for r in rows if str(r.get("conn_type") or "") == "unknown")
    return out


def measure_telemetry(*, device_ip: str | None = None) -> dict[str, Any]:
    """Entanglement over live telemetry dimensions (WAN + queue + device)."""
    live = telemetry.live(device_ip=device_ip, include_history=False)
    samples: list[dict[str, Any]] = []
    wan = live.get("wan") or {}
    samples.append(
        {
            "hit_count": float(wan.get("ingress_mbps") or 0),
            "session_count": float(wan.get("egress_mbps") or 0),
            "tiny_packets": float(wan.get("utilization_pct") or 0),
            "identical_max": float(wan.get("overlimits_per_sec") or 0),
            "bytes_in": float(wan.get("drops") or 0),
            "bytes_out": float(wan.get("requeues") or 0),
            "port_count": float(live.get("device_count") or 1),
        }
    )
    for dev in (live.get("devices") or [])[:12]:
        samples.append(
            {
                "hit_count": float(dev.get("ingress_mbps") or 0),
                "session_count": float(dev.get("egress_mbps") or 0),
                "tiny_packets": float(dev.get("grade_score") or 0),
                "identical_max": float(dev.get("rtt_ms") or 0),
                "bytes_in": float(dev.get("drops") or 0),
                "bytes_out": float(dev.get("retrans") or 0),
                "port_count": 1.0,
            }
        )
    out = measure_rows(samples, record=False)
    out["source"] = "telemetry"
    out["device_ip"] = device_ip
    return out


def investigation_boost(rows: list[dict[str, Any]]) -> dict[str, float]:
    """Per-IP boost from session entanglement peak + row deviation."""
    cfg = _cfg()
    if not cfg.get("enabled", True):
        return {}
    unknowns = [r for r in rows if str(r.get("conn_type") or "") == "unknown"]
    if len(unknowns) < int(cfg.get("min_rows") or 3):
        return {}

    session = measure_rows(unknowns, record=False)
    s_ent = float(session.get("entanglement_entropy") or 0)
    boost_base = float(cfg.get("investigate_boost") or 18.0)
    if cfg.get("peak_entropy_band", True) and not session.get("peak_entropy_band"):
        boost_base *= 0.35

    matrix = build_feature_matrix(unknowns)
    if not matrix:
        return {}
    col_means = [sum(r[i] for r in matrix) / len(matrix) for i in range(len(matrix[0]))]
    boosts: dict[str, float] = {}
    for row, vec in zip(unknowns, matrix):
        ip = str(row.get("ip") or "")
        if not ip:
            continue
        dev = math.sqrt(sum((vec[i] - col_means[i]) ** 2 for i in range(len(vec))))
        boosts[ip] = round(boost_base * (1.0 + min(2.0, dev)), 2)
    return boosts


def prioritize_unknowns(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Reorder unknown rows by QCE integration anomaly."""
    boosts = investigation_boost(rows)
    if not boosts:
        return rows

    def sort_key(row: dict[str, Any]) -> float:
        ip = str(row.get("ip") or "")
        return boosts.get(ip, 0.0)

    unknowns = [r for r in rows if str(r.get("conn_type") or "") == "unknown"]
    known = [r for r in rows if str(r.get("conn_type") or "") != "unknown"]
    if len(unknowns) <= 1:
        return rows
    ordered = sorted(unknowns, key=sort_key, reverse=True)
    return known + ordered


def status() -> dict[str, Any]:
    cfg = _cfg()
    st = _load_stats()
    return {
        "ok": True,
        "enabled": bool(cfg.get("enabled", True)),
        "zenodo": ZENODO,
        "config": cfg,
        "stats": st,
        "scaling_law": {"alpha": ALPHA, "beta": BETA, "gamma": GAMMA},
        "entropy_band_bits": [ENT_LO, ENT_HI],
        "consciousness_band": [SCORE_LO, SCORE_HI],
        "feature_keys": list(FEATURE_KEYS),
    }
