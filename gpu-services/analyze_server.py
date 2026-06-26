#!/usr/bin/env python3
"""GPU-accelerated packet batch analyzer for array-firewall (runs on fleet GPU host .221)."""
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
        if self.path.rstrip("/") != "/v1/analyze":
            self.send_error(404)
            return
        n = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(n) if n else b"{}"
        try:
            data = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            self._json(400, {"ok": False, "error": "invalid json"})
            return
        packets = list(data.get("packets") or [])
        result = analyze_gpu(packets[:512])
        self._json(200, result)


def main() -> None:
    print(f"[gpu-perf] listening on {BIND}:{PORT} device={DEVICE}")
    if HAS_TORCH and DEVICE == "cuda":
        print(f"[gpu-perf] GPU: {torch.cuda.get_device_name(0)}")
    ThreadingHTTPServer((BIND, PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
