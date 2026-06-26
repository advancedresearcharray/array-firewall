#!/usr/bin/env python3
from __future__ import annotations

import json
import mimetypes
import os
import secrets
import socketserver
import subprocess
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from lib.auth import check_bearer, check_token, ip_allowed, token_configured
from lib import cutover, devices, dhcp, folding, gaming, groups, ids, nat, nft, perf, policies, qos, sentinel, stability, telemetry, zones

PORT = int(os.environ.get("ARRAY_FW_API_PORT", "8090"))
BIND = os.environ.get("ARRAY_FW_BIND", "0.0.0.0")
STATIC = Path(__file__).resolve().parent / "static"
SHIELD = Path("/opt/array-firewall/scripts/packet-shield-nft.sh")


def json_response(handler: BaseHTTPRequestHandler, status: int, body: Any) -> None:
    payload = json.dumps(body, indent=2).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("Content-Length", str(len(payload)))
    handler.end_headers()
    handler.wfile.write(payload)


class Handler(BaseHTTPRequestHandler):
    server_version = "array-firewall-api/1.0"

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"[array-firewall-api] {self.address_string()} {fmt % args}")

    def _path(self) -> tuple[str, dict[str, list[str]]]:
        p = urllib.parse.urlparse(self.path)
        return p.path.rstrip("/") or "/", urllib.parse.parse_qs(p.query)

    def _read_json(self) -> dict[str, Any]:
        n = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(n) if n else b""
        return json.loads(raw.decode("utf-8")) if raw else {}

    def _device_mac_from_path(self, path: str, suffix: str) -> str:
        if not path.startswith("/api/v1/devices/") or not path.endswith(suffix):
            raise ValueError("bad device path")
        mac = urllib.parse.unquote(path.split("/")[4])
        return devices.norm_mac(mac)

    def _group_id_from_path(self, path: str, suffix: str = "") -> str:
        parts = path.split("/")
        if len(parts) < 5 or parts[1] != "api" or parts[2] != "v1" or parts[3] != "groups":
            raise ValueError("bad group path")
        gid = urllib.parse.unquote(parts[4])
        if suffix and not path.endswith(suffix):
            raise ValueError("bad group path")
        return groups._validate_id(gid)

    def _guard(self, *, auth: bool = True) -> bool:
        if not ip_allowed(self.client_address[0]):
            json_response(self, 403, {"error": "forbidden", "clientIp": self.client_address[0]})
            return False
        if auth and not check_bearer(self.headers.get("Authorization")):
            json_response(self, 401, {"error": "unauthorized"})
            return False
        return True

    def _static(self, rel: str) -> None:
        path = (STATIC / rel.lstrip("/")).resolve()
        if not str(path).startswith(str(STATIC.resolve())) or not path.is_file():
            self.send_error(404)
            return
        ctype = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        data = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        if path.suffix.lower() in {".html", ".htm"}:
            self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _telemetry_stream(self, qs: dict[str, list[str]]) -> None:
        if not ip_allowed(self.client_address[0]):
            json_response(self, 403, {"error": "forbidden", "clientIp": self.client_address[0]})
            return
        query_token = (qs.get("token") or [None])[0]
        if not check_token(self.headers.get("Authorization"), query_token):
            json_response(self, 401, {"error": "unauthorized"})
            return
        device_ip = (qs.get("device") or [None])[0]
        try:
            interval = max(0.25, min(float((qs.get("interval") or ["0.5"])[0]), 2.0))
        except ValueError:
            interval = telemetry.LIVE_POLL_INTERVAL_SEC

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()

        tick = 0
        try:
            while True:
                tick += 1
                body = telemetry.live(
                    device_ip=device_ip,
                    include_history=tick % 20 == 0,
                    include_queues=tick % 2 == 0,
                    include_device_history=tick % 20 == 0,
                )
                chunk = f"data: {json.dumps(body, separators=(',', ':'))}\n\n"
                self.wfile.write(chunk.encode("utf-8"))
                self.wfile.flush()
                time.sleep(interval)
        except (BrokenPipeError, ConnectionResetError, OSError):
            return

    def do_GET(self) -> None:  # noqa: N802
        path, qs = self._path()
        if path in {"/", "/dashboard"}:
            return self._static("dashboard.html")
        if path == "/sentinel":
            host = (self.headers.get("Host") or f"localhost:{PORT}").split(":")[0]
            port = int(sentinel._read_conf().get("SENTINEL_PORT") or sentinel.DEFAULT_PORT)
            loc = f"http://{host}:{port}/v1/dashboard"
            self.send_response(302)
            self.send_header("Location", loc)
            self.end_headers()
            return
        if path == "/api/health":
            if not ip_allowed(self.client_address[0]):
                json_response(self, 403, {"error": "forbidden"})
                return
            json_response(
                self,
                200,
                {
                    "ok": True,
                    "service": "array-firewall-api",
                    "port": PORT,
                    "tokenRequired": token_configured(),
                },
            )
            return
        # Read-only LAN status — no token required from allowed subnets
        if path in {"/api/v1/zones", "/api/v1/firewall/status"}:
            if not ip_allowed(self.client_address[0]):
                json_response(self, 403, {"error": "forbidden", "clientIp": self.client_address[0]})
                return
            if path == "/api/v1/zones":
                json_response(self, 200, {"ok": True, **zones.status()})
            else:
                json_response(self, 200, {"ok": True, **nft.status()})
            return
        if path == "/api/v1/telemetry/stream":
            return self._telemetry_stream(qs)
        if not self._guard():
            return
        if path == "/api/v1/nat/status":
            json_response(self, 200, {"ok": True, **nat.status()})
            return
        if path == "/api/v1/nat/upnp":
            json_response(self, 200, {"ok": True, **nat.upnp_status()})
            return
        if path == "/api/v1/policies":
            json_response(self, 200, {"ok": True, "policies": policies.load()})
            return
        if path == "/api/v1/gaming/snapshot":
            ip = (qs.get("xbox_ip") or [None])[0]
            json_response(self, 200, gaming.snapshot(ip))
            return
        if path == "/api/v1/gaming/link-status":
            json_response(self, 200, gaming.run_script("gaming-link-status.sh"))
            return
        if path == "/api/v1/sentinel/health":
            json_response(self, 200, {"ok": True, **sentinel.health()})
            return
        if path == "/api/v1/sentinel/status":
            json_response(self, 200, {"ok": True, **sentinel.status()})
            return
        if path == "/api/v1/sentinel/summary":
            json_response(self, 200, {"ok": True, **sentinel.summary()})
            return
        if path == "/api/v1/sentinel/dashboard-data":
            json_response(self, 200, {"ok": True, "data": sentinel.dashboard_data()})
            return
        if path == "/api/v1/cutover/status":
            json_response(self, 200, cutover.status())
            return
        if path == "/api/v1/cutover/preflight":
            json_response(self, 200, cutover.preflight())
            return
        if path == "/api/v1/dhcp":
            json_response(self, 200, dhcp.status())
            return
        if path == "/api/v1/devices":
            json_response(self, 200, {"ok": True, "devices": devices.list_devices()})
            return
        if path == "/api/v1/qos/status":
            json_response(self, 200, qos.status())
            return
        if path == "/api/v1/qos/shaping":
            json_response(self, 200, {"ok": True, **stability.shaping_stats()})
            return
        if path == "/api/v1/stability/status":
            json_response(self, 200, stability.status())
            return
        if path == "/api/v1/folding/status":
            json_response(self, 200, folding.status())
            return
        if path == "/api/v1/folding/savings":
            json_response(self, 200, folding.savings_report())
            return
        if path == "/api/v1/telemetry/summary":
            _path_only, qs = self._path()
            device_ip = (qs.get("device") or [None])[0]
            json_response(self, 200, telemetry.summary(device_ip=device_ip))
            return
        if path == "/api/v1/telemetry/live":
            _path_only, qs = self._path()
            device_ip = (qs.get("device") or [None])[0]
            include_history = (qs.get("history") or ["0"])[0] in ("1", "true", "yes")
            json_response(self, 200, telemetry.live(device_ip=device_ip, include_history=include_history))
            return
        if path == "/api/v1/telemetry/wan":
            prev = telemetry._load_state()
            now = time.time()
            prev_ts = float(prev.get("ts") or 0)
            dt = max(now - prev_ts, 0.001) if prev_ts else 0.0
            body = telemetry.wan_telemetry()
            queues = telemetry.queue_stats(prev=prev, dt=dt)
            telemetry.record_sample(queues=queues)
            json_response(self, 200, body)
            return
        if path == "/api/v1/telemetry/devices":
            prev = telemetry._load_state()
            now = time.time()
            prev_ts = float(prev.get("ts") or 0)
            dt = max(now - prev_ts, 0.001) if prev_ts else 0.0
            body = telemetry.devices_telemetry()
            queues = telemetry.queue_stats(prev=prev, dt=dt)
            telemetry.record_sample(queues=queues)
            json_response(self, 200, body)
            return
        if path == "/api/v1/telemetry/queues":
            prev = telemetry._load_state()
            prev_ts = float(prev.get("ts") or 0)
            dt = max(time.time() - prev_ts, 0.001) if prev_ts else 0.0
            body = telemetry.queue_stats(prev=prev, dt=dt)
            telemetry.record_sample(queues=body)
            json_response(self, 200, body)
            return
        if path == "/api/v1/telemetry/history":
            _path_only, qs = self._path()
            device_ip = (qs.get("device") or [None])[0]
            json_response(self, 200, telemetry.history_report(device_ip=device_ip))
            return
        if path == "/api/v1/ids/summary":
            json_response(self, 200, ids.summary())
            return
        if path == "/api/v1/ids/events":
            _path_only, qs = self._path()
            limit = int((qs.get("limit") or ["100"])[0])
            severity = (qs.get("severity") or [None])[0]
            json_response(self, 200, ids.events(limit=limit, severity=severity))
            return
        if path == "/api/v1/ids/nist":
            json_response(self, 200, ids.nist_catalog())
            return
        if path == "/api/v1/traffic/priority":
            json_response(self, 200, {"ok": True, **qos.priority_summary()})
            return
        if path == "/api/v1/perf/status":
            json_response(self, 200, {"ok": True, **perf.tune_status()})
            return
        if path == "/api/v1/perf/gpu":
            json_response(self, 200, {"ok": True, **perf.gpu_status()})
            return
        if path == "/api/v1/groups":
            json_response(self, 200, {"ok": True, "groups": groups.list_groups()})
            return
        if path.startswith("/api/v1/groups/"):
            parts = path.split("/")
            if len(parts) == 5 and parts[4]:
                try:
                    gid = groups._validate_id(urllib.parse.unquote(parts[4]))
                    json_response(self, 200, {"ok": True, "group": groups.get_group(gid)})
                except ValueError as exc:
                    json_response(self, 400, {"error": str(exc)})
                return
        if path.startswith("/api/v1/devices/") and path.endswith("/status"):
            try:
                mac = self._device_mac_from_path(path, "/status")
            except ValueError as exc:
                json_response(self, 400, {"error": str(exc)})
                return
            for d in devices.list_devices():
                if d["mac"] == mac:
                    json_response(self, 200, {"ok": True, "device": d})
                    return
            json_response(self, 404, {"error": "device not found"})
            return
        self.send_error(404)

    def do_POST(self) -> None:  # noqa: N802
        if not self._guard():
            return
        path, _qs = self._path()
        body = self._read_json()

        if path == "/api/v1/firewall/reload":
            try:
                result = nft.apply_ruleset()
                json_response(self, 200, result)
            except Exception as exc:  # noqa: BLE001
                json_response(self, 500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/nat/port-forwards/add":
            try:
                json_response(self, 200, nat.add_port_forward(body))
            except Exception as exc:  # noqa: BLE001
                json_response(self, 500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/nat/port-forwards/remove":
            try:
                json_response(self, 200, nat.remove_port_forward(str(body.get("id") or "")))
            except Exception as exc:  # noqa: BLE001
                json_response(self, 500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/nat/dmz":
            try:
                json_response(
                    self,
                    200,
                    nat.set_dmz(
                        enabled=bool(body.get("enabled")),
                        host_ip=body.get("host_ip"),
                        host_mac=body.get("host_mac"),
                        name=body.get("name"),
                    ),
                )
            except Exception as exc:  # noqa: BLE001
                json_response(self, 500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/nat/upnp":
            try:
                enabled = body.get("enabled")
                json_response(
                    self,
                    200,
                    nat.set_upnp(
                        enabled=enabled if enabled is not None else None,
                        secure_mode=body.get("secure_mode"),
                    ),
                )
            except Exception as exc:  # noqa: BLE001
                json_response(self, 500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/nat/xbox-preset":
            try:
                json_response(self, 200, nat.xbox_preset_forwards())
            except Exception as exc:  # noqa: BLE001
                json_response(self, 500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/nat/xbox-dmz":
            try:
                json_response(self, 200, nat.enable_xbox_dmz())
            except Exception as exc:  # noqa: BLE001
                json_response(self, 500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/firewall/discover":
            data = devices.discover()
            nft.apply_ruleset()
            json_response(self, 200, {"ok": True, "devices": list(data.get("devices", {}).values())})
            return

        if path == "/api/v1/devices/probe-hostnames":
            try:
                from lib import hostname_probe

                payload = hostname_probe.refresh()
                applied = hostname_probe.apply_to_dhcp_reservations()
                devices.discover()
                json_response(
                    self,
                    200,
                    {"ok": True, "probed": len(payload.get("by_mac") or {}), "reservations": applied},
                )
            except Exception as exc:  # noqa: BLE001
                json_response(self, 500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/cutover/backup":
            json_response(self, 200, cutover.backup_state())
            return

        if path == "/api/v1/dhcp/config":
            try:
                json_response(self, 200, dhcp.update(body))
            except Exception as exc:  # noqa: BLE001
                json_response(self, 500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/dhcp/restart":
            try:
                json_response(self, 200, dhcp.apply())
            except Exception as exc:  # noqa: BLE001
                json_response(self, 500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/dhcp/reservations/add":
            try:
                result = dhcp.add_reservation(
                    body.get("mac", ""),
                    body.get("ip", ""),
                    body.get("hostname"),
                )
                json_response(self, 200, result)
            except Exception as exc:  # noqa: BLE001
                json_response(self, 500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/dhcp/reservations/remove":
            try:
                json_response(self, 200, dhcp.remove_reservation(body.get("mac", "")))
            except Exception as exc:  # noqa: BLE001
                json_response(self, 500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/policies":
            data = policies.load()
            if body:
                net = data.setdefault("network", {})
                net.update(body.get("network", {}))
                if "defaults" in body:
                    data.setdefault("defaults", {}).update(body["defaults"])
                policies.save(data)
                nft.apply_ruleset()
                subprocess.run(["/opt/array-firewall/scripts/setup-dnsmasq.sh"], check=False, timeout=30)
            json_response(self, 200, {"ok": True, "policies": policies.load()})
            return

        if path == "/api/v1/cutover/prepare":
            data = policies.load()
            data.setdefault("network", {}).update({"role": "gateway", "cutover": False})
            policies.save(data)
            cutover.backup_state()
            json_response(
                self,
                200,
                {
                    "ok": True,
                    "message": "Gateway staged; run cutover-gateway.sh when ISP/LAN wired",
                    "doc": "/opt/array-firewall/docs/CUTOVER.md",
                },
            )
            return

        if path == "/api/v1/ids/scan":
            try:
                json_response(self, 200, ids.analyze(force=True))
            except Exception as exc:  # noqa: BLE001
                json_response(self, 500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/qos/apply":
            try:
                json_response(self, 200, qos.apply())
            except Exception as exc:  # noqa: BLE001
                json_response(self, 500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/qos/bandwidth":
            try:
                wan_up = str(body.get("wan_up") or "")
                wan_down = str(body.get("wan_down") or "")
                if not wan_up or not wan_down:
                    json_response(self, 400, {"ok": False, "error": "wan_up and wan_down required"})
                    return
                json_response(
                    self,
                    200,
                    qos.update_bandwidth(wan_up, wan_down, apply_now=body.get("apply", True) is not False),
                )
            except Exception as exc:  # noqa: BLE001
                json_response(self, 500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/qos/autorate":
            try:
                factor = body.get("factor")
                json_response(
                    self,
                    200,
                    qos.autorate_bandwidth(
                        factor=float(factor) if factor is not None else None,
                        apply_qos=body.get("apply", True) is not False,
                    ),
                )
            except Exception as exc:  # noqa: BLE001
                json_response(self, 500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/stability/apply":
            try:
                json_response(
                    self,
                    200,
                    stability.apply_stability_stack(autorate_first=bool(body.get("autorate_first"))),
                )
            except Exception as exc:  # noqa: BLE001
                json_response(self, 500, {"ok": False, "error": str(exc)})
            return

        if path.startswith("/api/v1/folding/filter/"):
            lane = path.rsplit("/", 1)[-1]
            if lane not in ("cpu", "memory", "network", "storage"):
                json_response(self, 400, {"ok": False, "error": "lane must be cpu|memory|network|storage"})
                return
            try:
                payload = body.get("payload")
                if payload is None:
                    json_response(self, 400, {"ok": False, "error": "payload required"})
                    return
                json_response(self, 200, folding.filter_lane(lane, str(payload)))
            except Exception as exc:  # noqa: BLE001
                json_response(self, 500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/folding/wire/compress":
            try:
                import base64

                raw_b64 = body.get("payload_b64") or body.get("payload")
                if not raw_b64:
                    json_response(self, 400, {"ok": False, "error": "payload_b64 required"})
                    return
                raw = base64.b64decode(str(raw_b64))
                json_response(self, 200, folding.wire_compress(raw))
            except Exception as exc:  # noqa: BLE001
                json_response(self, 500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/folding/wire/decompress":
            try:
                out = folding.wire_decompress(str(body.get("payload_b64") or ""))
                import base64

                json_response(
                    self,
                    200,
                    {"ok": True, "payload_b64": base64.b64encode(out).decode("ascii"), "bytes": len(out)},
                )
            except Exception as exc:  # noqa: BLE001
                json_response(self, 500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/folding/stats/reset":
            json_response(self, 200, folding.reset_stats())
            return

        if path == "/api/v1/perf/apply":
            try:
                json_response(self, 200, perf.apply_all())
            except Exception as exc:  # noqa: BLE001
                json_response(self, 500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/perf/tune":
            json_response(self, 200, perf.apply_tune())
            return

        if path == "/api/v1/perf/analyze":
            records = list(body.get("packets") or [])
            json_response(self, 200, perf.analyze_packets_gpu(records))
            return

        if path == "/api/v1/groups/create":
            try:
                gid = body.get("id") or body.get("name", "")
                result = groups.create_group(
                    gid,
                    body.get("name", gid),
                    description=body.get("description", ""),
                    config=body.get("config"),
                )
                json_response(self, 200, {"ok": True, "group": result})
            except ValueError as exc:
                json_response(self, 400, {"error": str(exc)})
            return

        if path == "/api/v1/groups/apply-all":
            json_response(self, 200, groups.apply_all_groups())
            return

        if path.startswith("/api/v1/groups/") and path.endswith("/update"):
            try:
                gid = self._group_id_from_path(path, "/update")
                result = groups.update_group(gid, body)
                json_response(self, 200, {"ok": True, "group": result})
            except ValueError as exc:
                json_response(self, 400, {"error": str(exc)})
            return

        if path.startswith("/api/v1/groups/") and path.endswith("/delete"):
            try:
                gid = self._group_id_from_path(path, "/delete")
                json_response(self, 200, groups.delete_group(gid))
            except ValueError as exc:
                json_response(self, 400, {"error": str(exc)})
            return

        if path.startswith("/api/v1/groups/") and path.endswith("/apply"):
            try:
                gid = self._group_id_from_path(path, "/apply")
                json_response(self, 200, groups.apply_group_config(gid))
            except ValueError as exc:
                json_response(self, 400, {"error": str(exc)})
            return

        if path.startswith("/api/v1/groups/") and path.endswith("/members/add"):
            try:
                gid = self._group_id_from_path(path, "/members/add")
                result = groups.add_member(gid, body.get("mac", ""), apply=body.get("apply", True))
                json_response(self, 200, {"ok": True, "group": result})
            except ValueError as exc:
                json_response(self, 400, {"error": str(exc)})
            return

        if path.startswith("/api/v1/groups/") and path.endswith("/members/remove"):
            try:
                gid = self._group_id_from_path(path, "/members/remove")
                result = groups.remove_member(gid, body.get("mac", ""))
                json_response(self, 200, {"ok": True, "group": result})
            except ValueError as exc:
                json_response(self, 400, {"error": str(exc)})
            return

        if path.startswith("/api/v1/devices/") and path.endswith("/dhcp"):
            try:
                mac = self._device_mac_from_path(path, "/dhcp")
                dev = devices.set_dhcp(
                    mac,
                    allocate=body.get("allocate") if "allocate" in body else None,
                    reserve=body.get("reserve") if "reserve" in body else None,
                    ip=body.get("ip"),
                )
                json_response(self, 200, {"ok": True, "device": dev})
            except ValueError as exc:
                json_response(self, 400, {"error": str(exc)})
            return

        if path.startswith("/api/v1/devices/") and path.endswith("/allow"):
            try:
                mac = self._device_mac_from_path(path, "/allow")
                dev = devices.set_allowed(mac, True, body.get("label"))
                nft.apply_ruleset()
                json_response(self, 200, {"ok": True, "device": dev})
            except ValueError as exc:
                json_response(self, 400, {"error": str(exc)})
            return

        if path.startswith("/api/v1/devices/") and path.endswith("/deny"):
            try:
                mac = self._device_mac_from_path(path, "/deny")
                if mac == devices.admin_mac():
                    json_response(self, 403, {"error": "cannot deny admin laptop"})
                    return
                dev = devices.set_allowed(mac, False, body.get("label"))
                nft.apply_ruleset()
                json_response(self, 200, {"ok": True, "device": dev})
            except ValueError as exc:
                json_response(self, 400, {"error": str(exc)})
            return

        if path == "/api/v1/shield/relax":
            subprocess.run([str(SHIELD), "relax"], check=False, timeout=30)
            json_response(self, 200, {"ok": True, "shield": "relax"})
            return

        if path == "/api/v1/shield/enable":
            level = body.get("level", "normal")
            subprocess.run([str(SHIELD), "shield", level], check=False, timeout=30)
            json_response(self, 200, {"ok": True, "shield": level})
            return

        if path == "/api/v1/sentinel/sync":
            restart = bool(body.get("restart", True))
            json_response(self, 200, sentinel.sync_all(restart=restart))
            return

        if path == "/api/v1/run":
            try:
                json_response(
                    self,
                    200,
                    gaming.run_script_api(body.get("script", ""), list(body.get("args") or [])),
                )
            except Exception as exc:  # noqa: BLE001
                json_response(self, 400, {"ok": False, "error": str(exc), "stderr": str(exc)})
            return

        self.send_error(404)


def main() -> None:
    os.chdir(Path(__file__).resolve().parent)
    with ThreadingHTTPServer((BIND, PORT), Handler) as httpd:
        print(f"[array-firewall-api] listening on {BIND}:{PORT}")
        httpd.serve_forever()


if __name__ == "__main__":
    main()
