"""Information Flow Complexity (Zenodo 17373031) for array-firewall.

Flow(M,x,t) = H(State_t | State_{t-1}) — conditional Shannon entropy of state
transitions. TotalFlow aggregates per-step flow. Used for IDS anomaly detection,
folding lane metrics, and traffic classification (dynamic vs static barriers).
"""
from __future__ import annotations

import json
import math
import os
import subprocess
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

from . import folding

STATE_FILE = Path(os.environ.get("ARRAY_FW_IFC_STATE", "/var/lib/array-firewall/information-flow.state.json"))
HISTORY_FILE = Path(os.environ.get("ARRAY_FW_IFC_HISTORY", "/var/lib/array-firewall/information-flow-history.json"))
MAX_HISTORY = 120

ZENODO = {
    "doi": "10.5281/zenodo.17373031",
    "url": "https://zenodo.org/records/17373031",
    "title": "Information Flow Complexity Theory",
    "definition": "Flow(M,x,t) = H(State_t | State_{t-1})",
}


def shannon_entropy(counts: dict[Any, int]) -> float:
    n = sum(counts.values())
    if n <= 0:
        return 0.0
    ent = 0.0
    for c in counts.values():
        if c <= 0:
            continue
        p = c / n
        ent -= p * math.log2(p)
    return round(ent, 4)


def mutual_information(joint: dict[tuple[Any, Any], int]) -> float:
    """I(X;Y) = H(X) + H(Y) - H(X,Y) from joint counts."""
    if not joint:
        return 0.0
    x_counts: dict[Any, int] = defaultdict(int)
    y_counts: dict[Any, int] = defaultdict(int)
    for (x, y), c in joint.items():
        x_counts[x] += c
        y_counts[y] += c
    hxy = shannon_entropy(joint)
    hx = shannon_entropy(x_counts)
    hy = shannon_entropy(y_counts)
    return round(max(0.0, hx + hy - hxy), 4)


def conditional_entropy(joint: dict[tuple[Any, Any], int]) -> float:
    """H(X|Y) averaged over Y — Definition 2 (Flow)."""
    if not joint:
        return 0.0
    y_counts: dict[Any, int] = defaultdict(int)
    for (_, y), c in joint.items():
        y_counts[y] += c
    total = sum(y_counts.values())
    if total <= 0:
        return 0.0
    h_cond = 0.0
    for y, ny in y_counts.items():
        x_given_y: dict[Any, int] = {}
        for (x, y2), c in joint.items():
            if y2 == y:
                x_given_y[x] = x_given_y.get(x, 0) + c
        h_cond += (ny / total) * shannon_entropy(x_given_y)
    return round(h_cond, 4)


def flow_surprisal(transitions: dict[str, dict[str, int]], prev: str, cur: str) -> float:
    """Pointwise Flow(t) = -log2 P(cur|prev) — Theorem 2 / Definition 2."""
    bucket = transitions.get(prev) or {}
    total = sum(bucket.values())
    if total <= 0:
        return 8.0
    count = bucket.get(cur, 0)
    p = max(count, 1) / (total + 1)  # Laplace smoothing for unseen transitions
    return round(-math.log2(p), 4)


def flow_bounds(state_space_size: int) -> dict[str, float]:
    """Theorem 1: 0 <= Flow(t) <= log2|S_t|."""
    cap = math.log2(max(state_space_size, 2))
    return {"min": 0.0, "max": round(cap, 4), "log2_state_space": round(cap, 4)}


def compression_bound_bits(certificates: int) -> float:
    """SAT certificate entropy: log2(N) bits for N equally likely outcomes (§4.1)."""
    n = max(certificates, 1)
    return round(math.log2(n), 4)


def pigeonhole_min_flow(total_bits: float, steps: int) -> float:
    """§4.2: some step must carry >= total_bits / steps (pigeonhole)."""
    if steps <= 0:
        return total_bits
    return round(total_bits / steps, 4)


def prg_uniformity_score(data: bytes, *, sample: int = 512) -> dict[str, Any]:
    """PRG indistinguishability proxy (§4.3): high entropy + flat byte histogram."""
    if not data:
        return {"entropy_bits": 0.0, "uniformity": 0.0, "prg_like": False}
    chunk = data[:sample]
    counts: dict[int, int] = {}
    for b in chunk:
        counts[b] = counts.get(b, 0) + 1
    ent = shannon_entropy(counts)
    expected = len(chunk) / 256.0
    chi = sum((c - expected) ** 2 / max(expected, 1e-6) for c in counts.values())
    # Normalize chi: 256 bins, df=255; low chi => uniform
    uniformity = round(max(0.0, 1.0 - chi / 512.0), 4)
    prg_like = ent >= 7.2 and uniformity >= 0.65 and len(chunk) >= 64
    return {
        "entropy_bits": ent,
        "uniformity": uniformity,
        "prg_like": prg_like,
        "sample_bytes": len(chunk),
    }


def flow_transition_bytes(prev: bytes, cur: bytes) -> float:
    """Conditional entropy proxy on aligned XOR deltas (folding lane compat)."""
    if not cur:
        return 0.0
    n = min(len(prev), len(cur), 4096)
    if n == 0:
        return 8.0
    diffs = [cur[i] ^ (prev[i] if i < len(prev) else 0) for i in range(n)]
    counts: dict[int, int] = {}
    for d in diffs:
        counts[d] = counts.get(d, 0) + 1
    return shannon_entropy(counts)


def _discretize(value: float, buckets: list[float]) -> str:
    for i, edge in enumerate(buckets):
        if value <= edge:
            return f"b{i}"
    return f"b{len(buckets)}"


def state_from_metrics(
    *,
    flow_count: int = 0,
    unique_ports: int = 0,
    unique_hosts: int = 0,
    tcp_ratio: float = 0.0,
    udp_ratio: float = 0.0,
    conntrack_pct: float = 0.0,
    cpu_load: float = 0.0,
    mem_used_pct: float = 0.0,
) -> dict[str, str]:
    """Computational state fingerprint (Definition 1 operational slice)."""
    return {
        "flows": _discretize(float(flow_count), [10, 30, 60, 100, 200, 500]),
        "ports": _discretize(float(unique_ports), [3, 8, 16, 32, 64]),
        "hosts": _discretize(float(unique_hosts), [5, 15, 30, 60, 120]),
        "tcp": _discretize(tcp_ratio, [0.2, 0.4, 0.6, 0.8]),
        "udp": _discretize(udp_ratio, [0.2, 0.4, 0.6, 0.8]),
        "ct": _discretize(conntrack_pct, [0.25, 0.5, 0.75, 0.9]),
        "cpu": _discretize(cpu_load, [0.25, 0.5, 0.75, 0.95]),
        "mem": _discretize(mem_used_pct, [0.25, 0.5, 0.75, 0.95]),
    }


def state_key(state: dict[str, str]) -> str:
    return "|".join(f"{k}={state[k]}" for k in sorted(state))


def _parse_conntrack() -> list[dict[str, Any]]:
    flows: list[dict[str, Any]] = []
    try:
        raw = subprocess.check_output(
            ["conntrack", "-L"],
            text=True,
            timeout=10,
            stderr=subprocess.DEVNULL,
        )
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return flows
    import re

    for line in raw.splitlines():
        proto_m = re.match(r"^(tcp|udp|icmp)", line, re.I)
        if not proto_m:
            continue
        flows.append({"proto": proto_m.group(1).lower()})
        for m in re.finditer(r"\bdport=(\d+)", line):
            flows[-1].setdefault("dports", set()).add(int(m.group(1)))
        for m in re.finditer(r"\b(?:src|dst)=([\d.]+)", line):
            flows[-1].setdefault("hosts", set()).add(m.group(1))
    return flows


def _network_state() -> dict[str, str]:
    flows = _parse_conntrack()
    ports: set[int] = set()
    hosts: set[str] = set()
    tcp = udp = 0
    for f in flows:
        proto = f.get("proto", "")
        if proto == "tcp":
            tcp += 1
        elif proto == "udp":
            udp += 1
        for p in f.get("dports") or ():
            ports.add(p)
        for h in f.get("hosts") or ():
            hosts.add(h)
    total = max(len(flows), 1)
    sample = folding.system_sample()
    return state_from_metrics(
        flow_count=len(flows),
        unique_ports=len(ports),
        unique_hosts=len(hosts),
        tcp_ratio=tcp / total,
        udp_ratio=udp / total,
        conntrack_pct=float(sample.get("conntrack_pct") or 0),
        cpu_load=float(sample.get("cpu_load") or 0),
        mem_used_pct=float(sample.get("mem_used_pct") or 0),
    )


def _load_state() -> dict[str, Any]:
    if not STATE_FILE.is_file():
        return {"transitions": {}, "total_flow_bits": 0.0, "steps": 0, "last_key": ""}
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"transitions": {}, "total_flow_bits": 0.0, "steps": 0, "last_key": ""}


def _save_state(data: dict[str, Any]) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    tmp.replace(STATE_FILE)


def _append_history(entry: dict[str, Any]) -> None:
    hist: list[dict[str, Any]] = []
    if HISTORY_FILE.is_file():
        try:
            hist = list(json.loads(HISTORY_FILE.read_text(encoding="utf-8")).get("steps") or [])
        except (json.JSONDecodeError, OSError):
            hist = []
    hist.append(entry)
    hist = hist[-MAX_HISTORY:]
    HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
    HISTORY_FILE.write_text(
        json.dumps({"updated": entry.get("ts"), "steps": hist}, indent=2) + "\n",
        encoding="utf-8",
    )


def barrier_profile() -> dict[str, Any]:
    """Theorems 4–6: IFC is dynamic, non-boolean, non-algebraic (metadata for API)."""
    return {
        "natural_proofs_bypass": {
            "theorem": 4,
            "reason": "Real-valued measure on (machine, input, time) — not a boolean function property",
        },
        "relativization_bypass": {
            "theorem": 5,
            "reason": "Measures internal state transitions, not oracle black-box behavior",
        },
        "algebraization_bypass": {
            "theorem": 6,
            "reason": "Shannon entropy uses logarithms and real probabilities — not finite-field algebra",
        },
    }


def analyze_step(*, force: bool = False) -> dict[str, Any]:
    """Advance one IFC step from live network state."""
    stored = _load_state()
    transitions: dict[str, dict[str, int]] = stored.get("transitions") or {}
    cur = _network_state()
    cur_key = state_key(cur)
    prev_key = str(stored.get("last_key") or "")

    flow = 0.0
    if prev_key and prev_key != cur_key:
        flow = flow_surprisal(transitions, prev_key, cur_key)
        bucket = transitions.setdefault(prev_key, {})
        bucket[cur_key] = int(bucket.get(cur_key, 0)) + 1

    steps = int(stored.get("steps") or 0) + (1 if prev_key else 0)
    total_flow = round(float(stored.get("total_flow_bits") or 0) + flow, 4)

    # Joint transition entropy over recent window (Definition 2 aggregate view)
    joint: dict[tuple[str, str], int] = {}
    for p, outs in transitions.items():
        for c, cnt in outs.items():
            joint[(c, p)] = joint.get((c, p), 0) + cnt
    h_cond = conditional_entropy(joint) if joint else 0.0

    cert_bits = compression_bound_bits(max(len(transitions) * 8, 16))
    min_step = pigeonhole_min_flow(cert_bits, max(steps, 1))
    superlinear = flow > max(min_step * 2.0, 4.0) and steps >= 3

    bounds = flow_bounds(256 ** 8)
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    entry = {
        "ts": ts,
        "flow_bits": flow,
        "total_flow_bits": total_flow,
        "steps": steps,
        "state": cur,
        "prev_state_key": prev_key or None,
        "cur_state_key": cur_key,
        "conditional_entropy": h_cond,
        "compression_bound_bits": cert_bits,
        "pigeonhole_min_flow": min_step,
        "superlinear_flow": superlinear,
        "flow_bounds": bounds,
    }

    stored.update(
        {
            "transitions": transitions,
            "total_flow_bits": total_flow,
            "steps": steps,
            "last_key": cur_key,
            "last_flow_bits": flow,
            "last_analysis": entry,
            "updated_at": ts,
        }
    )
    _save_state(stored)
    if prev_key:
        _append_history(entry)

    alerts: list[str] = []
    if superlinear:
        alerts.append(
            f"Super-linear information flow {flow:.2f} bits/step exceeds pigeonhole bound {min_step:.2f}"
        )
    if flow >= bounds["max"] * 0.85:
        alerts.append(f"Flow {flow:.2f} bits near Theorem 1 upper bound {bounds['max']:.2f}")

    return {
        "ok": True,
        "zenodo": ZENODO,
        "barriers": barrier_profile(),
        "current": entry,
        "alerts": alerts,
        "forced": force,
    }


def status() -> dict[str, Any]:
    stored = _load_state()
    last = stored.get("last_analysis") or {}
    hist: list[dict[str, Any]] = []
    if HISTORY_FILE.is_file():
        try:
            hist = list(json.loads(HISTORY_FILE.read_text(encoding="utf-8")).get("steps") or [])[-20:]
        except (json.JSONDecodeError, OSError):
            pass
    recent_flows = [float(h.get("flow_bits") or 0) for h in hist if h.get("flow_bits")]
    avg_flow = round(sum(recent_flows) / len(recent_flows), 4) if recent_flows else 0.0
    peak_flow = round(max(recent_flows), 4) if recent_flows else 0.0

    return {
        "ok": True,
        "zenodo": ZENODO,
        "barriers": barrier_profile(),
        "steps": int(stored.get("steps") or 0),
        "total_flow_bits": float(stored.get("total_flow_bits") or 0),
        "last_flow_bits": float(stored.get("last_flow_bits") or 0),
        "avg_flow_bits": avg_flow,
        "peak_flow_bits": peak_flow,
        "last_analysis": last,
        "updated_at": stored.get("updated_at"),
        "recent_steps": hist[-8:],
    }


def history(limit: int = 40) -> dict[str, Any]:
    hist: list[dict[str, Any]] = []
    if HISTORY_FILE.is_file():
        try:
            hist = list(json.loads(HISTORY_FILE.read_text(encoding="utf-8")).get("steps") or [])
        except (json.JSONDecodeError, OSError):
            pass
    return {"ok": True, "zenodo": ZENODO, "steps": hist[-min(limit, MAX_HISTORY):]}


def ids_signals() -> list[dict[str, Any]]:
    """Signals for IDS integration."""
    st = status()
    signals: list[dict[str, Any]] = []
    last = st.get("last_analysis") or {}
    flow = float(last.get("flow_bits") or 0)
    if last.get("superlinear_flow"):
        signals.append(
            {
                "signal": "superlinear_information_flow",
                "severity": "high",
                "title": "Super-linear information flow",
                "detail": f"Network state transition carried {flow:.2f} bits (IFC pigeonhole violation proxy)",
                "meta": last,
            }
        )
    elif flow >= 5.0:
        signals.append(
            {
                "signal": "information_flow_spike",
                "severity": "medium",
                "title": "Information flow spike",
                "detail": f"State transition entropy {flow:.2f} bits — unusual network dynamics",
                "meta": {"flow_bits": flow},
            }
        )
    if float(st.get("peak_flow_bits") or 0) >= 6.5 and int(st.get("steps") or 0) >= 5:
        signals.append(
            {
                "signal": "sustained_high_flow",
                "severity": "medium",
                "title": "Sustained high information flow",
                "detail": f"Peak step flow {st['peak_flow_bits']:.2f} bits over {st['steps']} steps",
                "meta": {"peak": st["peak_flow_bits"], "steps": st["steps"]},
            }
        )
    return signals
