"""Network throughput via dimensional folding + BLSB (Zenodo 18453148).

Effective throughput = link_mbps × compression_ratio.
Preservation ratio ≈ σ_min of the fold projection (energy-retention proxy without numpy).

https://zenodo.org/records/18453148
"""
from __future__ import annotations

import base64
import gzip
import json
import math
import re
import time
from pathlib import Path
from typing import Any

from . import folding, policies, stability

ZENODO = {
    "doi": "10.5281/zenodo.18453148",
    "url": "https://zenodo.org/records/18453148",
    "title": "Network Throughput via Dimensional Folding and Bit-Level Compression",
    "version": "v1",
}

THROUGHPUT_STATE = Path("/var/lib/array-firewall/throughput-fold.stats.json")
SOURCE_DIM = folding.SOURCE_DIM
FOLD_DIM = folding.FOLD_DIM


def _cfg() -> dict[str, Any]:
    base = {
        "enabled": True,
        "wire_min_bytes": 512,
        "auto_wire_sentinel": True,
        "blsb_before_gzip": True,
        "include_fold_sidecar": True,
        "pattern_rle_before_blsb": True,
    }
    base.update(policies.load().get("throughput_fold") or {})
    base.update(policies.gaming().get("throughput_fold") or {})
    return base


def _load_stats() -> dict[str, Any]:
    if not THROUGHPUT_STATE.is_file():
        return {"operations": 0, "bytes_in": 0, "bytes_out": 0, "avg_ratio": 1.0}
    try:
        return json.loads(THROUGHPUT_STATE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"operations": 0, "bytes_in": 0, "bytes_out": 0, "avg_ratio": 1.0}


def _save_stats(data: dict[str, Any]) -> None:
    THROUGHPUT_STATE.parent.mkdir(parents=True, exist_ok=True)
    THROUGHPUT_STATE.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def _record(orig: int, compressed: int, ratio: float) -> None:
    st = _load_stats()
    st["operations"] = int(st.get("operations") or 0) + 1
    st["bytes_in"] = int(st.get("bytes_in") or 0) + orig
    st["bytes_out"] = int(st.get("bytes_out") or 0) + compressed
    ops = max(int(st["operations"]), 1)
    prev = float(st.get("avg_ratio") or 1.0)
    st["avg_ratio"] = round((prev * (ops - 1) + ratio) / ops, 4)
    st["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    _save_stats(st)


def bytes_to_source_vector(data: bytes, *, dim: int = SOURCE_DIM) -> list[float]:
    """Map payload bytes into fold source vector (protocol-agnostic)."""
    if not data:
        return [0.0] * dim
    floats = [float(b) / 255.0 for b in data[:dim]]
    if len(floats) < dim:
        floats.extend([0.0] * (dim - len(floats)))
    return floats[:dim]


def preservation_ratio(source: list[float], folded: list[float]) -> float:
    """σ_min proxy — energy retained by 8196→32D projection (18453148 §SVD)."""
    src_energy = sum(v * v for v in source) or 1e-9
    fold_energy = sum(v * v for v in folded)
    ratio = math.sqrt(fold_energy / src_energy)
    block_floor = 0.707106781  # theoretical min block weight magnitude
    return round(max(block_floor * 0.5, min(1.0, ratio)), 4)


def fold_sidecar(data: bytes) -> dict[str, Any]:
    """Dimensional fold metadata sidecar (lossless original preserved separately)."""
    src = bytes_to_source_vector(data)
    folded = folding.fold_vector_8196_to_32(src)
    pres = preservation_ratio(src, folded)
    packed = struct_pack_f32(folded)
    return {
        "source_dim": SOURCE_DIM,
        "fold_dim": FOLD_DIM,
        "preservation_ratio": pres,
        "folded_preview": [round(x, 4) for x in folded[:8]],
        "fold_b64": base64.b64encode(packed).decode("ascii"),
    }


def struct_pack_f32(values: list[float]) -> bytes:
    import struct

    return struct.pack(f"<{len(values)}f", *values[:FOLD_DIM])


def compression_ratio(orig: int, compressed: int) -> float:
    return round(orig / max(compressed, 1), 4)


def effective_throughput_mbps(link_mbps: float, ratio: float, preservation: float = 1.0) -> float:
    """Effective throughput = physical × ratio × preservation bound (18453148)."""
    return round(float(link_mbps) * float(ratio) * float(preservation), 2)


def fold_wire_pipeline(raw: bytes, *, record_stats: bool = True) -> dict[str, Any]:
    """Full stack: pattern RLE → fold analysis → BLSB → gzip (lossless wire frame)."""
    cfg = _cfg()
    orig = len(raw)
    if orig == 0:
        return {"ok": True, "orig_size": 0, "compressed_size": 0, "ratio": 1.0}

    sidecar: dict[str, Any] = {}
    pattern_meta: dict[str, Any] = {}
    pres = 1.0
    if cfg.get("include_fold_sidecar", True) and orig >= 64:
        sidecar = fold_sidecar(raw)
        pres = float(sidecar.get("preservation_ratio") or 1.0)

    stack: list[str] = ["raw"]
    staged = raw
    if cfg.get("pattern_rle_before_blsb", True):
        try:
            from . import pattern_encode

            staged, pattern_meta = pattern_encode.encode_for_wire(raw, record_stats=record_stats)
            if pattern_meta.get("applied"):
                stack.append("pattern_rle")
        except Exception:
            staged = raw
    if cfg.get("blsb_before_gzip", True):
        staged = folding.blsb_encode(staged)
        stack.append("blsb")
    compressed = gzip.compress(staged, compresslevel=6)
    stack.append("gzip")
    if sidecar:
        stack.insert(1, "fold8196→32")

    ratio = compression_ratio(orig, len(compressed))
    composed = round(ratio * pres, 4)

    link_mbps = _link_mbps()
    result: dict[str, Any] = {
        "ok": True,
        "zenodo": ZENODO,
        "orig_size": orig,
        "compressed_size": len(compressed),
        "ratio": ratio,
        "compression_ratio": ratio,
        "preservation_ratio": pres,
        "composed_ratio": composed,
        "network_throughput_factor": composed,
        "effective_throughput_factor": composed,
        "link_mbps": link_mbps,
        "effective_throughput_mbps": effective_throughput_mbps(link_mbps, ratio, pres),
        "transfer_time_reduction_pct": round((1.0 - 1.0 / max(ratio, 1.0)) * 100.0, 1),
        "compression_stack": stack,
        "encoding": "+".join(stack),
        "payload_b64": base64.b64encode(compressed).decode("ascii"),
        "fold_sidecar": sidecar or None,
        "pattern_encode": pattern_meta or None,
        "backend": "throughput_fold",
    }

    if record_stats:
        _record(orig, len(compressed), composed)
        folding._record_operation(  # noqa: SLF001
            kind="wire",
            lane=None,
            orig_size=orig,
            compressed_size=len(compressed),
            ratio=composed,
        )

    return result


def fold_wire_decompress(payload_b64: str, *, encoding: str | None = None) -> bytes:
    raw = base64.b64decode(payload_b64.encode("ascii"))
    enc = (encoding or "gzip").lower()
    staged = gzip.decompress(raw)
    if "blsb" in enc:
        staged = _blsb_decode(staged)
    if "pattern" in enc:
        try:
            from . import pattern_encode

            staged = pattern_encode.pattern_decode(staged)
        except Exception:
            pass
    elif staged[:4] == b"PBEN":
        try:
            from . import pattern_encode

            staged = pattern_encode.pattern_decode(staged)
        except Exception:
            pass
    return staged


def _blsb_decode(staged: bytes) -> bytes:
    if len(staged) % 2 != 0:
        return staged
    out = bytearray(len(staged) // 2)
    for i in range(len(out)):
        hi = staged[i * 2] & 0x0F
        lo = staged[i * 2 + 1] & 0x0F
        out[i] = (hi << 4) | lo
    return bytes(out)


def _link_mbps() -> float:
    try:
        contract = stability.contract_rates()
        up = str(contract.get("wan_up") or contract.get("shaped_up") or "")
        m = re.match(r"([\d.]+)", up)
        if m:
            return float(m.group(1))
    except Exception:
        pass
    try:
        q = policies.load().get("qos") or {}
        up = str(q.get("wan_up") or "950mbit")
        m = re.match(r"([\d.]+)", up.lower())
        if m:
            return float(m.group(1))
    except Exception:
        pass
    return 950.0


def estimate_for_payload(payload: bytes | str, *, link_mbps: float | None = None) -> dict[str, Any]:
    if isinstance(payload, str):
        raw = payload.encode("utf-8")
    else:
        raw = payload
    est = fold_wire_pipeline(raw, record_stats=False)
    if link_mbps is not None:
        est["link_mbps"] = link_mbps
        est["effective_throughput_mbps"] = effective_throughput_mbps(
            link_mbps,
            float(est.get("ratio") or 1),
            float(est.get("preservation_ratio") or 1),
        )
    return est


def maybe_compress_json(obj: Any, *, min_bytes: int = 512) -> dict[str, Any]:
    """Wrap large JSON for wire transport — returns plain or folded envelope."""
    text = json.dumps(obj, separators=(",", ":"))
    raw = text.encode("utf-8")
    if len(raw) < min_bytes or not _cfg().get("enabled", True):
        return {"_wire": False, "data": obj}
    wire = fold_wire_pipeline(raw)
    return {
        "_wire": True,
        "encoding": wire.get("encoding"),
        "orig_size": wire.get("orig_size"),
        "compressed_size": wire.get("compressed_size"),
        "ratio": wire.get("ratio"),
        "effective_throughput_factor": wire.get("effective_throughput_factor"),
        "preservation_ratio": wire.get("preservation_ratio"),
        "payload_b64": wire.get("payload_b64"),
        "fold_sidecar": wire.get("fold_sidecar"),
    }


def unwrap_wire_envelope(envelope: dict[str, Any]) -> Any:
    if not envelope.get("_wire"):
        return envelope.get("data", envelope)
    raw = fold_wire_decompress(
        str(envelope.get("payload_b64") or ""),
        encoding=str(envelope.get("encoding") or "gzip+blsb"),
    )
    return json.loads(raw.decode("utf-8"))


def status() -> dict[str, Any]:
    cfg = _cfg()
    st = _load_stats()
    link = _link_mbps()
    avg = float(st.get("avg_ratio") or 1.0)
    pattern_status: dict[str, Any] = {}
    try:
        from . import pattern_encode

        pattern_status = pattern_encode.status()
    except Exception:
        pattern_status = {"ok": False}
    return {
        "ok": True,
        "enabled": bool(cfg.get("enabled", True)),
        "zenodo": ZENODO,
        "config": cfg,
        "link_mbps": link,
        "effective_throughput_mbps": effective_throughput_mbps(link, avg),
        "stats": st,
        "pipeline": ["pattern_rle", "fold8196→32", "blsb", "gzip"],
        "pattern_encode": pattern_status,
    }
