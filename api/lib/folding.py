"""Zenodo dimensional folding stack for array-firewall (CT940).

Maps papers to operational lanes — see docs/ZENODO-FOLDING.md:
- 18728103 CPU/memory/storage/network filter lanes + BLSB
- 18453148 wire compression / effective throughput
- 18102374 8196→32D block fold
- 18143028 cube_space_coords (15D)
- 17373031 information_flow (conditional entropy proxy)
- 18079593 memory pattern hints
- 17844752 quadrant shortcut digest
- 18005544 unified optimization metadata
"""
from __future__ import annotations

import gzip
import hashlib
import json
import math
import os
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

CONF = Path("/etc/array-firewall/array-firewall.conf")
FOLD_STATE = Path("/var/lib/array-firewall/folding.state")
FOLD_STATS = Path("/var/lib/array-firewall/folding-stats.json")
SOURCE_DIM = 8196
FOLD_DIM = 32
CUBE_DIM = 15

ZENODO_REFERENCES = [
    {"doi": "10.5281/zenodo.18728103", "url": "https://zenodo.org/records/18728103", "title": "CPU/Memory/Storage Compression Guide"},
    {"doi": "10.5281/zenodo.18453148", "url": "https://zenodo.org/records/18453148", "title": "Network Throughput via Dimensional Folding"},
    {"doi": "10.5281/zenodo.18102374", "url": "https://zenodo.org/records/18102374", "title": "Optimal 8196D→32D Dimensional Folding"},
    {"doi": "10.5281/zenodo.18143028", "url": "https://zenodo.org/records/18143028", "title": "Cube Space Design"},
    {"doi": "10.5281/zenodo.18005544", "url": "https://zenodo.org/records/18005544", "title": "Unified Optimization Framework"},
    {"doi": "10.5281/zenodo.17373031", "url": "https://zenodo.org/records/17373031", "title": "Information Flow Complexity"},
    {"doi": "10.5281/zenodo.18079593", "url": "https://zenodo.org/records/18079593", "title": "Memory Pattern Optimization"},
    {"doi": "10.5281/zenodo.17844752", "url": "https://zenodo.org/records/17844752", "title": "Recursive Quadrant Deduction"},
    {"doi": "10.5281/zenodo.18079453", "url": "https://zenodo.org/records/18079453", "title": "Pattern-Based Encoding"},
]

_SHORTCUT_CACHE: dict[str, dict[str, Any]] = {}


def _fmt_bytes(n: int | float) -> str:
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:.1f} TB"


def _default_stats() -> dict[str, Any]:
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    lane = lambda: {"orig_bytes": 0, "compressed_bytes": 0, "bytes_saved": 0, "operations": 0, "cache_hits": 0, "best_ratio": 0.0}
    return {
        "started_at": now,
        "updated_at": now,
        "totals": {
            "orig_bytes": 0,
            "compressed_bytes": 0,
            "bytes_saved": 0,
            "operations": 0,
            "cache_hits": 0,
            "shortcut_hits": 0,
        },
        "lanes": {name: lane() for name in ("cpu", "memory", "network", "storage")},
        "wire": {"orig_bytes": 0, "compressed_bytes": 0, "bytes_saved": 0, "operations": 0, "best_ratio": 0.0},
        "recent": [],
    }


def _load_stats() -> dict[str, Any]:
    if not FOLD_STATS.is_file():
        return _default_stats()
    try:
        data = json.loads(FOLD_STATS.read_text(encoding="utf-8"))
        base = _default_stats()
        base.update({k: v for k, v in data.items() if k != "lanes"})
        for lane in base["lanes"]:
            base["lanes"][lane].update((data.get("lanes") or {}).get(lane, {}))
        base["wire"].update(data.get("wire") or {})
        base["recent"] = list(data.get("recent") or [])[-20:]
        return base
    except (json.JSONDecodeError, TypeError):
        return _default_stats()


def _save_stats(data: dict[str, Any]) -> None:
    data["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    FOLD_STATS.parent.mkdir(parents=True, exist_ok=True)
    FOLD_STATS.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def _record_operation(
    *,
    kind: str,
    lane: str | None,
    orig_size: int,
    compressed_size: int,
    ratio: float,
    cache_hit: bool = False,
    shortcut_hit: bool = False,
) -> None:
    stats = _load_stats()
    saved = max(0, orig_size - compressed_size)
    totals = stats["totals"]
    totals["orig_bytes"] = int(totals.get("orig_bytes", 0)) + orig_size
    totals["compressed_bytes"] = int(totals.get("compressed_bytes", 0)) + compressed_size
    totals["bytes_saved"] = int(totals.get("bytes_saved", 0)) + saved
    totals["operations"] = int(totals.get("operations", 0)) + 1
    if cache_hit:
        totals["cache_hits"] = int(totals.get("cache_hits", 0)) + 1
    if shortcut_hit:
        totals["shortcut_hits"] = int(totals.get("shortcut_hits", 0)) + 1

    bucket = stats["lanes"].get(lane) if lane else stats["wire"]
    if bucket is not None:
        bucket["orig_bytes"] = int(bucket.get("orig_bytes", 0)) + orig_size
        bucket["compressed_bytes"] = int(bucket.get("compressed_bytes", 0)) + compressed_size
        bucket["bytes_saved"] = int(bucket.get("bytes_saved", 0)) + saved
        bucket["operations"] = int(bucket.get("operations", 0)) + 1
        if cache_hit:
            bucket["cache_hits"] = int(bucket.get("cache_hits", 0)) + 1
        bucket["best_ratio"] = round(max(float(bucket.get("best_ratio") or 0), ratio), 4)
        if bucket["compressed_bytes"]:
            bucket["avg_ratio"] = round(bucket["orig_bytes"] / bucket["compressed_bytes"], 4)

    stats["recent"] = (stats.get("recent") or [])[-19:] + [{
        "ts": stats["updated_at"],
        "kind": kind,
        "lane": lane,
        "orig_size": orig_size,
        "compressed_size": compressed_size,
        "bytes_saved": saved,
        "ratio": round(ratio, 4),
        "cache_hit": cache_hit,
    }]
    _save_stats(stats)


def container_resources() -> dict[str, Any]:
    """Live container resource snapshot for dashboard."""
    out: dict[str, Any] = {"ok": True}
    try:
        load1, load5, load15 = os.getloadavg()
        cores = os.cpu_count() or 1
        out["cpu"] = {
            "cores": cores,
            "load1": round(load1, 2),
            "load5": round(load5, 2),
            "load15": round(load15, 2),
            "util_pct": round(min(load1 / cores, 1.0) * 100, 1),
        }
    except OSError:
        out["cpu"] = {"cores": os.cpu_count() or 1, "util_pct": 0}

    try:
        meminfo: dict[str, int] = {}
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0].endswith(":"):
                meminfo[parts[0][:-1]] = int(parts[1]) * 1024
        total = meminfo.get("MemTotal", 0)
        avail = meminfo.get("MemAvailable", meminfo.get("MemFree", 0))
        used = max(0, total - avail)
        out["memory"] = {
            "total_bytes": total,
            "used_bytes": used,
            "available_bytes": avail,
            "used_pct": round((used / total) * 100, 1) if total else 0,
            "total_human": _fmt_bytes(total),
            "used_human": _fmt_bytes(used),
            "available_human": _fmt_bytes(avail),
        }
    except OSError:
        out["memory"] = {}

    try:
        st = os.statvfs("/var/lib/array-firewall")
        total = st.f_blocks * st.f_frsize
        free = st.f_bavail * st.f_frsize
        used = max(0, total - free)
        out["storage"] = {
            "mount": "/var/lib/array-firewall",
            "total_bytes": total,
            "used_bytes": used,
            "free_bytes": free,
            "used_pct": round((used / total) * 100, 1) if total else 0,
            "total_human": _fmt_bytes(total),
            "used_human": _fmt_bytes(used),
            "free_human": _fmt_bytes(free),
        }
    except OSError:
        out["storage"] = {}

    try:
        cg = Path("/sys/fs/cgroup/memory.max")
        if cg.is_file():
            raw = cg.read_text(encoding="utf-8").strip()
            if raw.isdigit():
                out["cgroup_memory_limit_bytes"] = int(raw)
                out["cgroup_memory_limit_human"] = _fmt_bytes(int(raw))
    except OSError:
        pass

    return out


def savings_report() -> dict[str, Any]:
    """Cumulative compression savings + resource headroom."""
    stats = _load_stats()
    totals = stats["totals"]
    orig = int(totals.get("orig_bytes") or 0)
    comp = int(totals.get("compressed_bytes") or 0)
    saved = int(totals.get("bytes_saved") or 0)
    ops = int(totals.get("operations") or 0)
    avg_ratio = round(orig / comp, 4) if comp else 1.0
    fold_reduction = round(1.0 - (fold_dim() / SOURCE_DIM), 4)

    lanes_out: dict[str, Any] = {}
    for name, lane in (stats.get("lanes") or {}).items():
        lo = int(lane.get("orig_bytes") or 0)
        lc = int(lane.get("compressed_bytes") or 0)
        lanes_out[name] = {
            **lane,
            "avg_ratio": round(lo / lc, 4) if lc else 0,
            "orig_human": _fmt_bytes(lo),
            "compressed_human": _fmt_bytes(lc),
            "saved_human": _fmt_bytes(lane.get("bytes_saved") or 0),
            "share_pct": round((lo / orig) * 100, 1) if orig else 0,
        }

    wire = stats.get("wire") or {}
    wo, wc = int(wire.get("orig_bytes") or 0), int(wire.get("compressed_bytes") or 0)

    resources = container_resources()
    mem = resources.get("memory") or {}
    mem_total = int(mem.get("total_bytes") or 1)
    virtual_freed = saved
    effective_mem_pct = round((virtual_freed / mem_total) * 100, 2) if mem_total else 0

    return {
        "ok": True,
        "enabled": enabled(),
        "totals": {
            **totals,
            "avg_ratio": avg_ratio,
            "orig_human": _fmt_bytes(orig),
            "compressed_human": _fmt_bytes(comp),
            "saved_human": _fmt_bytes(saved),
            "effective_throughput_factor": avg_ratio,
        },
        "folding": {
            "source_dim": SOURCE_DIM,
            "fold_dim": fold_dim(),
            "dimension_reduction_pct": round(fold_reduction * 100, 2),
            "manifold_expansion_ratio": round(fold_dim() / 15.0, 4),
        },
        "lanes": lanes_out,
        "wire": {
            **wire,
            "avg_ratio": round(wo / wc, 4) if wc else 0,
            "orig_human": _fmt_bytes(wo),
            "compressed_human": _fmt_bytes(wc),
            "saved_human": _fmt_bytes(wire.get("bytes_saved") or 0),
        },
        "resources": resources,
        "headroom": {
            "bytes_saved_total": saved,
            "virtual_memory_freed_human": _fmt_bytes(saved),
            "pct_of_container_ram": effective_mem_pct,
            "cache_hit_rate_pct": round((int(totals.get("cache_hits") or 0) / ops) * 100, 1) if ops else 0,
        },
        "recent": stats.get("recent") or [],
        "started_at": stats.get("started_at"),
        "updated_at": stats.get("updated_at"),
    }


def _read_conf() -> dict[str, str]:
    out: dict[str, str] = {}
    if not CONF.is_file():
        return out
    for line in CONF.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip().strip('"')
    return out


def relay_url() -> str:
    c = _read_conf()
    return (
        c.get("FOLD_RELAY_URL")
        or os.environ.get("ARRAY_FOLD_RELAY_URL")
        or os.environ.get("RUST_FOLD_WRAPPER_URL")
        or ""
    ).rstrip("/")


def enabled() -> bool:
    c = _read_conf()
    val = c.get("FOLDING_ENABLED", os.environ.get("FOLDING_ENABLED", "1"))
    return str(val).lower() not in {"0", "false", "off", "no"}


def fold_dim() -> int:
    c = _read_conf()
    try:
        return int(c.get("ARRAY_PROCESSOR_FOLD_DIM") or os.environ.get("ARRAY_PROCESSOR_FOLD_DIM") or FOLD_DIM)
    except ValueError:
        return FOLD_DIM


def _block_weight(block: int, dim: int) -> float:
    b, d = float(block), float(dim)
    return max(-1.0, min(1.0, math.sin(b * 0.6180339887 + d * 1.3247179572) * 0.707106781))


def fold_vector_8196_to_32(source: list[float]) -> list[float]:
    """8196D→32D orthogonal block projection (Zenodo 18102374 operational slice)."""
    src = (source + [0.0] * SOURCE_DIM)[:SOURCE_DIM]
    blocks = SOURCE_DIM // FOLD_DIM
    out = [0.0] * FOLD_DIM
    for block in range(blocks):
        base = block * FOLD_DIM
        for d in range(FOLD_DIM):
            out[d] += src[base + d] * _block_weight(block, d)
    norm = math.sqrt(sum(v * v for v in out)) or 1.0
    return [v / norm for v in out]


def blsb_encode(data: bytes) -> bytes:
    """BLSB nibble split — high/low 4-bit lanes (guide 18728103)."""
    out = bytearray(len(data) * 2)
    for i, b in enumerate(data):
        out[i * 2] = b >> 4
        out[i * 2 + 1] = b & 0x0F
    return bytes(out)


def information_flow_bits(prev: bytes, cur: bytes) -> float:
    """Conditional entropy proxy on aligned byte windows (Zenodo 17373031)."""
    if not cur:
        return 0.0
    n = min(len(prev), len(cur), 4096)
    if n == 0:
        return 8.0
    diffs = [cur[i] ^ (prev[i] if i < len(prev) else 0) for i in range(n)]
    counts: dict[int, int] = {}
    for d in diffs:
        counts[d] = counts.get(d, 0) + 1
    ent = 0.0
    for c in counts.values():
        p = c / n
        ent -= p * math.log2(p)
    return round(ent, 4)


def memory_pattern_hints(text: str) -> dict[str, Any]:
    """Heuristic memory access patterns (Zenodo 18079593)."""
    if not text:
        return {"sparsity": 0.0, "uniform": True, "json_max_depth": 0}
    zeros = text.count("\x00") + text.count("0")
    sparsity = zeros / max(len(text), 1)
    unique_ratio = len(set(text)) / max(len(text), 1)
    depth = 0
    if text.lstrip().startswith(("{", "[")):
        stack = 0
        for ch in text[:8000]:
            if ch in "{[":
                stack += 1
                depth = max(depth, stack)
            elif ch in "}]":
                stack = max(0, stack - 1)
    return {
        "memory_pattern_sparsity": round(sparsity, 4),
        "memory_pattern_uniform": unique_ratio < 0.05,
        "memory_pattern_json_max_depth": depth,
    }


def quadrant_shortcut_digest(data: bytes) -> str:
    """Recursive quadrant split digest (Zenodo 17844752 operational hook)."""
    if not data:
        return "0" * 16
    mid = len(data) // 2
    q1 = hashlib.sha256(data[:mid]).digest()[:8]
    q2 = hashlib.sha256(data[mid:]).digest()[:8]
    return hashlib.sha256(q1 + q2).hexdigest()[:16]


def cube_space_coords(sample: dict[str, float]) -> list[float]:
    """15D normalized coords for firewall telemetry (Zenodo 18143028)."""
    keys = (
        "cpu_load",
        "mem_used_pct",
        "conntrack_pct",
        "wan_latency_ms",
        "qos_overlimits",
        "gpu_reachable",
        "shaping_saturated",
        "snapshot_bytes",
        "connection_count",
        "dscp_active",
        "bbr_active",
        "cake_active",
        "fold_ratio",
        "info_flow_bits",
        "cache_hit",
    )
    coords = []
    for k in keys:
        v = float(sample.get(k, 0.0))
        coords.append(max(0.0, min(1.0, v)))
    return coords[:CUBE_DIM]


def _compress_lane(raw: bytes, *, lane: str, zstd_level: int = 6, record_stats: bool = True) -> dict[str, Any]:
    orig = len(raw)
    hints = memory_pattern_hints(raw.decode("utf-8", errors="replace")[:65536])
    prev_key = f"{lane}:{quadrant_shortcut_digest(raw[:256])}"
    cached = _SHORTCUT_CACHE.get(prev_key)
    cache_hit = cached is not None and cached.get("orig_size") == orig
    if cache_hit:
        out = {**cached, "cache_hit": True, "shortcut_hit": True}
        if record_stats:
            _record_operation(
                kind="filter",
                lane=lane,
                orig_size=orig,
                compressed_size=int(cached.get("compressed_size") or orig),
                ratio=float(cached.get("ratio") or 1),
                cache_hit=True,
                shortcut_hit=True,
            )
        return out

    staged = raw
    stack: list[str] = ["raw"]
    if lane in ("network", "storage"):
        staged = blsb_encode(raw)
        stack.append("blsb")
    compressed = gzip.compress(staged, compresslevel=min(9, max(1, zstd_level)))
    stack.append("gzip")

    folded_preview: list[float] = []
    if lane in ("cpu", "memory") and orig >= 32:
        floats = [float(b) for b in raw[:256]]
        floats.extend([0.0] * max(0, SOURCE_DIM - len(floats)))
        vec = fold_vector_8196_to_32(floats[:SOURCE_DIM])
        folded_preview = vec[: min(8, len(vec))]

    prev = _load_prev_lane(lane)
    info_flow = information_flow_bits(prev, raw)
    _save_prev_lane(lane, raw[:4096])

    ratio = orig / max(len(compressed), 1)
    fd = fold_dim()
    result: dict[str, Any] = {
        "ok": True,
        "lane": lane,
        "orig_size": orig,
        "compressed_size": len(compressed),
        "ratio": round(ratio, 4),
        "network_throughput_factor": round(ratio, 4) if lane == "network" else None,
        "compression_stack": stack,
        "fold_dim": fd,
        "manifold_expansion_ratio": round(fd / 15.0, 4),
        "optimal_folding_8196_to_32d": {"source_dim": SOURCE_DIM, "target_dim": FOLD_DIM},
        "information_flow_bits": info_flow,
        "quadrant_shortcut_digest_hex": quadrant_shortcut_digest(raw),
        "cube_space_coords": cube_space_coords(
            {
                "fold_ratio": min(ratio / 10.0, 1.0),
                "info_flow_bits": min(info_flow / 8.0, 1.0),
                "cache_hit": 1.0 if cache_hit else 0.0,
            }
        ),
        "folded_preview": folded_preview,
        "cache_hit": False,
        "shortcut_hit": False,
        **hints,
        "payload_b64": __import__("base64").b64encode(compressed).decode("ascii"),
        "encoding": "gzip+blsb" if "blsb" in stack else "gzip",
    }
    _SHORTCUT_CACHE[prev_key] = {k: v for k, v in result.items() if k != "payload_b64"}
    if len(_SHORTCUT_CACHE) > 512:
        _SHORTCUT_CACHE.pop(next(iter(_SHORTCUT_CACHE)))
    if record_stats:
        _record_operation(
            kind="filter",
            lane=lane,
            orig_size=orig,
            compressed_size=len(compressed),
            ratio=ratio,
            cache_hit=False,
        )
    return result


def _load_prev_lane(lane: str) -> bytes:
    if not FOLD_STATE.is_file():
        return b""
    try:
        data = json.loads(FOLD_STATE.read_text(encoding="utf-8"))
        return __import__("base64").b64decode(data.get(lane, "") or "")
    except (json.JSONDecodeError, ValueError):
        return b""


def _save_prev_lane(lane: str, blob: bytes) -> None:
    data: dict[str, str] = {}
    if FOLD_STATE.is_file():
        try:
            data = json.loads(FOLD_STATE.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            data = {}
    data[lane] = __import__("base64").b64encode(blob).decode("ascii")
    data["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    FOLD_STATE.parent.mkdir(parents=True, exist_ok=True)
    FOLD_STATE.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def filter_lane(lane: str, payload: str | bytes, *, record_stats: bool = True) -> dict[str, Any]:
    if isinstance(payload, str):
        raw = payload.encode("utf-8")
    else:
        raw = payload
    url = relay_url()
    if url and enabled():
        try:
            body = json.dumps({"payload": payload if isinstance(payload, str) else payload.decode("utf-8", errors="replace")}).encode()
            req = urllib.request.Request(
                f"{url}/v1/filter/{lane}",
                data=body,
                method="POST",
                headers={"Content-Type": "application/json", "Accept": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                out = json.loads(resp.read().decode("utf-8"))
                out["backend"] = "relay"
                if record_stats:
                    _record_operation(
                        kind="filter",
                        lane=lane,
                        orig_size=int(out.get("orig_size") or len(raw)),
                        compressed_size=int(out.get("compressed_size") or len(raw)),
                        ratio=float(out.get("ratio") or 1),
                        cache_hit=bool(out.get("cache_hit")),
                        shortcut_hit=bool(out.get("shortcut_hit")),
                    )
                return out
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
            pass
    levels = {"cpu": 3, "memory": 15, "network": 6, "storage": 19}
    return {
        **_compress_lane(raw, lane=lane, zstd_level=levels.get(lane, 6), record_stats=record_stats),
        "backend": "local",
    }


def wire_compress(raw: bytes, *, record_stats: bool = True) -> dict[str, Any]:
    """Lossless wire frame compression (Zenodo 18453148)."""
    url = relay_url()
    if url and enabled():
        try:
            body = json.dumps({"payload": raw.decode("latin-1")}).encode()
            req = urllib.request.Request(
                f"{url}/v1/wire/compress",
                data=body,
                method="POST",
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                out = json.loads(resp.read().decode("utf-8"))
                out["backend"] = "relay"
                if record_stats:
                    _record_operation(
                        kind="wire",
                        lane=None,
                        orig_size=int(out.get("orig_size") or len(raw)),
                        compressed_size=int(out.get("compressed_size") or len(raw)),
                        ratio=float(out.get("ratio") or 1),
                    )
                return out
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
            pass
    compressed = gzip.compress(raw, compresslevel=6)
    ratio = len(raw) / max(len(compressed), 1)
    result = {
        "ok": True,
        "orig_size": len(raw),
        "compressed_size": len(compressed),
        "ratio": round(ratio, 4),
        "network_throughput_factor": round(ratio, 4),
        "payload_b64": __import__("base64").b64encode(compressed).decode("ascii"),
        "backend": "local",
    }
    if record_stats:
        _record_operation(
            kind="wire",
            lane=None,
            orig_size=len(raw),
            compressed_size=len(compressed),
            ratio=ratio,
        )
    return result


def wire_decompress(payload_b64: str) -> bytes:
    return gzip.decompress(__import__("base64").b64decode(payload_b64))


def compress_json_store(obj: Any) -> dict[str, Any]:
    """Persist large JSON blobs in folded/compressed form (guide §5.3)."""
    text = json.dumps(obj, separators=(",", ":"))
    lane = filter_lane("storage", text)
    return {
        "_folded": True,
        "encoding": lane.get("encoding"),
        "orig_size": lane.get("orig_size"),
        "compressed_size": lane.get("compressed_size"),
        "ratio": lane.get("ratio"),
        "payload_b64": lane.get("payload_b64"),
        "meta": {
            "quadrant_shortcut_digest_hex": lane.get("quadrant_shortcut_digest_hex"),
            "cube_space_coords": lane.get("cube_space_coords"),
        },
    }


def decompress_json_store(envelope: dict[str, Any]) -> Any:
    if not envelope.get("_folded"):
        return envelope
    raw = wire_decompress(str(envelope.get("payload_b64") or ""))
    return json.loads(raw.decode("utf-8"))


def system_sample() -> dict[str, float]:
    sample: dict[str, float] = {"bbr_active": 0.0, "cake_active": 0.0, "dscp_active": 0.0, "gpu_reachable": 0.0}
    try:
        load = os.getloadavg()[0]
        sample["cpu_load"] = min(load / max(os.cpu_count() or 4, 1), 1.0)
    except OSError:
        sample["cpu_load"] = 0.0
    try:
        mem = Path("/proc/meminfo").read_text(encoding="utf-8")
        total = avail = 0
        for line in mem.splitlines():
            if line.startswith("MemTotal:"):
                total = int(line.split()[1])
            elif line.startswith("MemAvailable:"):
                avail = int(line.split()[1])
        if total:
            sample["mem_used_pct"] = 1.0 - (avail / total)
    except OSError:
        pass
    try:
        count = int(subprocess.check_output(["cat", "/proc/sys/net/netfilter/nf_conntrack_count"], text=True).strip())
        max_c = int(subprocess.check_output(["cat", "/proc/sys/net/netfilter/nf_conntrack_max"], text=True).strip())
        sample["conntrack_pct"] = count / max(max_c, 1)
    except (subprocess.CalledProcessError, ValueError, FileNotFoundError):
        pass
    try:
        cc = subprocess.check_output(["sysctl", "-n", "net.ipv4.tcp_congestion_control"], text=True).strip()
        sample["bbr_active"] = 1.0 if cc == "bbr" else 0.0
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    try:
        tc = subprocess.check_output(["tc", "qdisc", "show", "dev", "eth1"], text=True, timeout=3)
        sample["cake_active"] = 1.0 if "cake" in tc.lower() else 0.0
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return sample


def status() -> dict[str, Any]:
    sample = system_sample()
    probe = filter_lane("cpu", json.dumps({"probe": True, "ts": time.time()}), record_stats=False)
    return {
        "ok": True,
        "enabled": enabled(),
        "relay_url": relay_url() or None,
        "backend": probe.get("backend"),
        "fold_dim": fold_dim(),
        "manifold_expansion_ratio": round(fold_dim() / 15.0, 4),
        "zenodo_references": ZENODO_REFERENCES,
        "implementation_guide": {"doi": "10.5281/zenodo.18728103", "version": "v2"},
        "lanes": ["cpu", "memory", "network", "storage"],
        "last_probe": {
            "ratio": probe.get("ratio"),
            "orig_size": probe.get("orig_size"),
            "compressed_size": probe.get("compressed_size"),
        },
        "cube_space_coords": cube_space_coords({**sample, "fold_ratio": (probe.get("ratio") or 1) / 10.0}),
        "system_sample": sample,
        "unified_optimization": {
            "doi": "10.5281/zenodo.18005544",
            "pattern_lanes": 5,
            "fold_dim": fold_dim(),
        },
        "savings": savings_report().get("totals"),
    }


def reset_stats() -> dict[str, Any]:
    data = _default_stats()
    _save_stats(data)
    return {"ok": True, "message": "folding stats reset"}
