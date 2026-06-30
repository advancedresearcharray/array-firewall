#!/usr/bin/env python3
"""GPU-accelerated packet + peer-vector analyzer for array-firewall (fleet GPU host .221)."""
from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

BIND = os.environ.get("GPU_PERF_BIND", "0.0.0.0")
PORT = int(os.environ.get("GPU_PERF_PORT", "8795"))

try:
    import torch

    HAS_TORCH = True
    DEVICE = "cuda" if torch.cuda.is_available() else "cpu"
except ImportError:
    HAS_TORCH = False
    DEVICE = "cpu"


def analyze_cpu(packets: list[dict[str, Any]]) -> dict[str, Any]:
    sizes = [int(p.get("len") or p.get("size") or 0) for p in packets]
    dirs = [str(p.get("dir") or p.get("direction") or "") for p in packets]
    if not sizes:
        return {"ok": True, "device": "cpu", "count": 0, "flood_score": 0.0, "anomaly": False}
    tiny = sum(1 for s in sizes if 0 < s <= 79)
    inbound = sum(1 for d in dirs if d.startswith("in"))
    outbound = max(len(sizes) - inbound, 1)
    avg = sum(sizes) / len(sizes)
    flood = min(100.0, (tiny / len(sizes)) * 120 + (inbound / outbound) * 15)
    return {
        "ok": True,
        "device": "cpu",
        "count": len(sizes),
        "tiny_packets": tiny,
        "inbound": inbound,
        "outbound": len(sizes) - inbound,
        "avg_size": round(avg, 1),
        "flood_score": round(flood, 2),
        "anomaly": flood >= 35,
    }


def analyze_gpu(packets: list[dict[str, Any]]) -> dict[str, Any]:
    if not HAS_TORCH or DEVICE != "cuda":
        out = analyze_cpu(packets)
        out["device"] = DEVICE
        return out

    sizes = torch.tensor(
        [float(p.get("len") or p.get("size") or 0) for p in packets],
        device=DEVICE,
        dtype=torch.float32,
    )
    dirs = [str(p.get("dir") or p.get("direction") or "") for p in packets]
    inbound_mask = torch.tensor(
        [1.0 if d.startswith("in") else 0.0 for d in dirs],
        device=DEVICE,
        dtype=torch.float32,
    )
    count = max(int(sizes.numel()), 1)
    tiny = int((sizes.gt(0) & sizes.le(79)).sum().item())
    inbound = int(inbound_mask.sum().item())
    outbound = max(count - inbound, 1)
    avg = float(sizes.mean().item()) if count else 0.0
    tiny_ratio = tiny / count
    in_ratio = inbound / outbound
    flood = min(100.0, tiny_ratio * 120.0 + in_ratio * 15.0)
    var = float(sizes.var(unbiased=False).item()) if count > 1 else 0.0
    return {
        "ok": True,
        "device": torch.cuda.get_device_name(0),
        "count": count,
        "tiny_packets": tiny,
        "inbound": inbound,
        "outbound": count - inbound,
        "avg_size": round(avg, 1),
        "size_variance": round(var, 1),
        "flood_score": round(flood, 2),
        "anomaly": flood >= 35 or var > 50000,
    }


def _peer_score_row(peer: dict[str, Any]) -> tuple[str, float, dict[str, Any]]:
    ip = str(peer.get("ip") or peer.get("remote") or "").split(":")[0].strip()
    identical = int(peer.get("identical_count") or peer.get("max_burst") or 0)
    tiny = int(peer.get("tiny_packets") or 0)
    total = int(peer.get("total_packets") or peer.get("packets") or 0)
    spread = peer.get("size_spread")
    if spread is None:
        mn = peer.get("packet_size_min") or peer.get("identical_size")
        mx = peer.get("packet_size_max") or peer.get("identical_size")
        if mn is not None and mx is not None:
            try:
                spread = float(mx) - float(mn)
            except (TypeError, ValueError):
                spread = None
    vps = bool(peer.get("vps_probe"))
    score = 0.0
    if vps:
        score += 0.45
    if identical >= 20:
        score += 0.35
    elif identical >= 8:
        score += 0.2
    elif 6 <= identical <= 19:
        score += 0.12
    if spread is not None and spread <= 4.0:
        score += 0.22
    if total and tiny / max(total, 1) >= 0.5:
        score += 0.15
    score = round(min(1.0, score), 3)
    row = {
        "ip": ip,
        "score": score,
        "identical": identical,
        "size_spread": spread,
        "vps_probe": vps,
    }
    return ip, score, row


def analyze_peers_cpu(
    peers: list[dict[str, Any]],
    *,
    phase: str = "",
    metrics: dict[str, Any] | None = None,
) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    strict: list[str] = []
    throttle: list[str] = []
    forming = 0
    low_spread = 0
    for peer in peers:
        ip, score, row = _peer_score_row(peer)
        if not ip or ip.startswith(("10.", "192.168.", "127.")):
            continue
        identical = row["identical"]
        if 6 <= identical <= 19:
            forming += 1
        if row.get("size_spread") is not None and row["size_spread"] <= 4.0:
            low_spread += 1
        rows.append(row)
        if score >= 0.65 or (row["vps_probe"] and identical >= 10):
            strict.append(ip)
        elif score >= 0.38:
            throttle.append(ip)

    metrics = metrics or {}
    tiny_in = int(metrics.get("tiny_inbound") or metrics.get("tiny_packets") or 0)
    inbound = int(metrics.get("inbound") or metrics.get("inbound_packets") or 0)
    flood = min(
        100.0,
        len(strict) * 8.0 + len(throttle) * 3.0 + forming * 4.0 + (tiny_in / max(inbound, 1)) * 40.0,
    )
    return {
        "ok": True,
        "device": "cpu",
        "phase": phase,
        "peer_count": len(rows),
        "forming_peers": forming,
        "low_spread_peers": low_spread,
        "flood_score": round(flood, 2),
        "flow_score": round(min(1.0, flood / 100.0), 3),
        "anomaly": flood >= 35,
        "strict_ips": strict[:24],
        "throttle_ips": throttle[:32],
        "strict_peers": [r for r in rows if r["ip"] in strict[:24]],
        "throttle_peers": [r for r in rows if r["ip"] in throttle[:32]],
        "peers": rows[:48],
    }


def analyze_peers_gpu(
    peers: list[dict[str, Any]],
    *,
    phase: str = "",
    metrics: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not HAS_TORCH or DEVICE != "cuda" or len(peers) < 2:
        out = analyze_peers_cpu(peers, phase=phase, metrics=metrics)
        out["device"] = DEVICE
        return out

    ips: list[str] = []
    identical_t: list[float] = []
    tiny_t: list[float] = []
    total_t: list[float] = []
    spread_t: list[float] = []
    vps_t: list[float] = []
    rows_meta: list[dict[str, Any]] = []

    for peer in peers:
        ip, _score, row = _peer_score_row(peer)
        if not ip or ip.startswith(("10.", "192.168.", "127.")):
            continue
        ips.append(ip)
        identical_t.append(float(row["identical"]))
        tiny_t.append(float(peer.get("tiny_packets") or 0))
        total_t.append(float(peer.get("total_packets") or peer.get("packets") or 0))
        spread = row.get("size_spread")
        spread_t.append(float(spread) if spread is not None else 999.0)
        vps_t.append(1.0 if row["vps_probe"] else 0.0)
        rows_meta.append(row)

    if len(ips) < 2:
        out = analyze_peers_cpu(peers, phase=phase, metrics=metrics)
        out["device"] = DEVICE
        return out

    identical = torch.tensor(identical_t, device=DEVICE, dtype=torch.float32)
    tiny = torch.tensor(tiny_t, device=DEVICE, dtype=torch.float32)
    total = torch.clamp(torch.tensor(total_t, device=DEVICE, dtype=torch.float32), min=1.0)
    spread = torch.tensor(spread_t, device=DEVICE, dtype=torch.float32)
    vps = torch.tensor(vps_t, device=DEVICE, dtype=torch.float32)

    score = torch.zeros(len(ips), device=DEVICE, dtype=torch.float32)
    score = score + vps * 0.45
    score = score + torch.where(identical >= 20, 0.35, torch.where(identical >= 8, 0.2, torch.where(identical >= 6, 0.12, 0.0)))
    score = score + torch.where(spread <= 4.0, 0.22, 0.0)
    score = score + torch.where(tiny / total >= 0.5, 0.15, 0.0)
    score = torch.clamp(score, max=1.0)

    scores = score.detach().cpu().tolist()
    strict: list[str] = []
    throttle: list[str] = []
    rows: list[dict[str, Any]] = []
    forming = 0
    low_spread = 0
    for idx, ip in enumerate(ips):
        s = round(float(scores[idx]), 3)
        meta = dict(rows_meta[idx])
        meta["score"] = s
        rows.append(meta)
        identical_i = int(meta["identical"])
        if 6 <= identical_i <= 19:
            forming += 1
        if meta.get("size_spread") is not None and meta["size_spread"] <= 4.0:
            low_spread += 1
        if s >= 0.65 or (meta["vps_probe"] and identical_i >= 10):
            strict.append(ip)
        elif s >= 0.38:
            throttle.append(ip)

    metrics = metrics or {}
    tiny_in = int(metrics.get("tiny_inbound") or metrics.get("tiny_packets") or 0)
    inbound = int(metrics.get("inbound") or metrics.get("inbound_packets") or 0)
    flood = min(
        100.0,
        len(strict) * 8.0 + len(throttle) * 3.0 + forming * 4.0 + (tiny_in / max(inbound, 1)) * 40.0,
    )
    return {
        "ok": True,
        "device": torch.cuda.get_device_name(0),
        "phase": phase,
        "peer_count": len(rows),
        "forming_peers": forming,
        "low_spread_peers": low_spread,
        "flood_score": round(flood, 2),
        "flow_score": round(min(1.0, flood / 100.0), 3),
        "anomaly": flood >= 35,
        "strict_ips": strict[:24],
        "throttle_ips": throttle[:32],
        "strict_peers": [r for r in rows if r["ip"] in strict[:24]],
        "throttle_peers": [r for r in rows if r["ip"] in throttle[:32]],
        "peers": rows[:48],
    }


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: object) -> None:
        print(f"[gpu-perf] {self.address_string()} {fmt % args}")

    def _json(self, status: int, body: dict[str, Any]) -> None:
        payload = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802
        if self.path.rstrip("/") in {"", "/health"}:
            gpu_name = None
            if HAS_TORCH and DEVICE == "cuda":
                gpu_name = torch.cuda.get_device_name(0)
            self._json(
                200,
                {
                    "ok": True,
                    "service": "array-firewall-gpu-perf",
                    "device": gpu_name or DEVICE,
                    "cuda": DEVICE == "cuda",
                    "port": PORT,
                },
            )
            return
        self.send_error(404)

    def do_POST(self) -> None:  # noqa: N802
        path = self.path.rstrip("/")
        if path not in {"/v1/analyze", "/v1/analyze-peers"}:
            self.send_error(404)
            return
        n = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(n) if n else b"{}"
        try:
            data = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            self._json(400, {"ok": False, "error": "invalid json"})
            return
        if path == "/v1/analyze":
            packets = list(data.get("packets") or [])
            result = analyze_gpu(packets[:512])
        else:
            peers = list(data.get("peers") or [])
            result = analyze_peers_gpu(
                peers[:128],
                phase=str(data.get("phase") or ""),
                metrics=data.get("metrics") if isinstance(data.get("metrics"), dict) else {},
            )
        self._json(200, result)


def main() -> None:
    print(f"[gpu-perf] listening on {BIND}:{PORT} device={DEVICE}")
    if HAS_TORCH and DEVICE == "cuda":
        print(f"[gpu-perf] GPU: {torch.cuda.get_device_name(0)}")
    ThreadingHTTPServer((BIND, PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
