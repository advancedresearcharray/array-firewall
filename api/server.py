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
from lib import cutover, devices, dhcp, dns_filter, folding, gaming, gaming_mitigate, groups, ids, information_flow, lobby_intel, nat, nft, pattern_encode, peer_blocklist, perf, policies, qce, qos, rqd, asvi, sentinel, stability, subnet_blocklist, telemetry, throughput_fold, zones, arp_watch, afld, wan_scan_block
from lib import abuse_report, conn_lite_db, probe_sink, unknown_investigator

PORT = int(os.environ.get("ARRAY_FW_API_PORT", "8090"))
BIND = os.environ.get("ARRAY_FW_BIND", "0.0.0.0")
STATIC = Path(__file__).resolve().parent / "static"


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
        if path.startswith("/static/"):
            return self._static(path[len("/static/"):])
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
        if path in {
            "/api/v1/zones",
            "/api/v1/firewall/status",
            "/api/v1/information-flow/status",
        }:
            if not ip_allowed(self.client_address[0]):
                json_response(self, 403, {"error": "forbidden", "clientIp": self.client_address[0]})
                return
            if path == "/api/v1/zones":
                json_response(self, 200, {"ok": True, **zones.status()})
            elif path == "/api/v1/information-flow/status":
                json_response(self, 200, information_flow.status())
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
        if path == "/api/v1/gaming/arp-watch":
            json_response(self, 200, arp_watch.status())
            return
        if path == "/api/v1/gaming/peers":
            json_response(self, 200, peer_blocklist.status())
            return
        if path == "/api/v1/gaming/connections":
            _path_only, qs = self._path()
            json_response(
                self,
                200,
                conn_lite_db.query(
                    session_hex=(qs.get("session_hex") or [None])[0],
                    ip=(qs.get("ip") or [None])[0],
                    conn_type=(qs.get("type") or qs.get("conn_type") or [None])[0],
                    policy=(qs.get("policy") or [None])[0],
                    min_sessions=int((qs.get("min_sessions") or ["0"])[0] or 0) or None,
                    offenders_only=(qs.get("offenders") or ["0"])[0] in ("1", "true", "yes"),
                    limit=int((qs.get("limit") or ["100"])[0]),
                    offset=int((qs.get("offset") or ["0"])[0]),
                ),
            )
            return
        if path == "/api/v1/gaming/connections/sessions":
            _path_only, qs = self._path()
            json_response(
                self,
                200,
                conn_lite_db.list_sessions(limit=int((qs.get("limit") or ["40"])[0])),
            )
            return
        if path == "/api/v1/gaming/connections/offenders":
            _path_only, qs = self._path()
            json_response(
                self,
                200,
                conn_lite_db.offenders(
                    min_sessions=int((qs.get("min_sessions") or ["2"])[0]),
                    limit=int((qs.get("limit") or ["50"])[0]),
                ),
            )
            return
        if path == "/api/v1/gaming/intel/export":
            json_response(self, 200, lobby_intel.export_intel())
            return
        if path == "/api/v1/gaming/intel/status":
            json_response(self, 200, lobby_intel.status())
            return
        if path == "/api/v1/gaming/investigate":
            _path_only, qs = self._path()
            ip = (qs.get("ip") or [None])[0]
            if ip:
                ctx = (conn_lite_db.query(ip=ip, limit=1).get("rows") or [{}])[0]
                intel = unknown_investigator.investigate_ip(ip, context=ctx)
                applied = unknown_investigator.apply_intel_to_db(ip, intel)
                json_response(self, 200, {"ok": True, "intel": intel, "applied": applied})
            else:
                json_response(self, 200, unknown_investigator.list_intel(limit=int((qs.get("limit") or ["50"])[0])))
            return
        if path == "/api/v1/gaming/probe-sink":
            json_response(self, 200, probe_sink.status())
            return
        if path == "/api/v1/afld/status":
            json_response(self, 200, afld.status())
            return
        if path == "/api/v1/wan-scanners":
            json_response(self, 200, wan_scan_block.status())
            return
        if path == "/api/v1/subnets":
            json_response(self, 200, subnet_blocklist.status())
            return
        if path == "/api/v1/wan-scans":
            hours = float((qs.get("hours") or ["24"])[0])
            since = time.time() - (hours * 3600.0)
            kind = (qs.get("kind") or [None])[0]
            ip = (qs.get("ip") or [None])[0]
            limit = int((qs.get("limit") or ["200"])[0])
            if (qs.get("summary") or ["0"])[0] in {"1", "true", "yes"}:
                json_response(
                    self,
                    200,
                    {
                        "ok": True,
                        "hours": hours,
                        "scanners": afld.scanner_summary(hours=hours, limit=limit),
                        "afld": afld.status(),
                    },
                )
                return
            json_response(
                self,
                200,
                {
                    "ok": True,
                    "hours": hours,
                    "events": afld.query(
                        kind=str(kind) if kind else None,
                        ip=str(ip) if ip else None,
                        since_ts=since,
                        limit=limit,
                    ),
                    "afld": afld.status(),
                },
            )
            return
        if path == "/api/v1/gaming/abuse-reports":
            json_response(self, 200, abuse_report.list_incidents())
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
        if path == "/api/v1/qos/upload-boost":
            json_response(self, 200, qos.upload_boost_status())
            return
        if path == "/api/v1/qos/download-boost":
            json_response(self, 200, qos.download_boost_status())
            return
        if path == "/api/v1/qos/buffer":
            json_response(self, 200, qos.buffer_tune_status())
            return
        if path.startswith("/api/v1/gaming/sessions/") and path.endswith("/timeline"):
            session_hex = path.removeprefix("/api/v1/gaming/sessions/").removesuffix("/timeline").strip("/")
            _path_only, qs = self._path()
            limit = int((qs.get("limit") or ["150"])[0])
            json_response(self, 200, gaming.session_timeline(session_hex, limit=limit))
            return
        if path == "/api/v1/gaming/route-pref":
            json_response(self, 200, gaming.route_pref_status())
            return
        if path == "/api/v1/gaming/allowlist-learn":
            json_response(self, 200, gaming.allowlist_learn_status())
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
        if path == "/api/v1/folding/throughput":
            json_response(self, 200, throughput_fold.status())
            return
        if path == "/api/v1/folding/pattern/status":
            json_response(self, 200, pattern_encode.status())
            return
        if path == "/api/v1/rqd/status":
            json_response(self, 200, rqd.status())
            return
        if path == "/api/v1/rqd/buffer-profile":
            json_response(self, 200, qos.rqd_buffer_recommendation())
            return
        if path == "/api/v1/asvi/status":
            json_response(self, 200, asvi.status())
            return
        if path == "/api/v1/asvi/scan":
            _path_only, qs = self._path()
            session_hex = (qs.get("session_hex") or [None])[0]
            limit = int((qs.get("limit") or ["300"])[0])
            json_response(self, 200, asvi.scan_session(session_hex=session_hex, limit=limit))
            return
        if path == "/api/v1/asvi/unknown-voids":
            _path_only, qs = self._path()
            limit = int((qs.get("limit") or ["200"])[0])
            json_response(self, 200, asvi.scan_unknown_voids(limit=limit))
            return
        if path == "/api/v1/qce/status":
            json_response(self, 200, qce.status())
            return
        if path == "/api/v1/qce/measure":
            _path_only, qs = self._path()
            session_hex = (qs.get("session_hex") or [None])[0]
            device_ip = (qs.get("device") or [None])[0]
            limit = int((qs.get("limit") or ["300"])[0])
            if device_ip:
                json_response(self, 200, qce.measure_telemetry(device_ip=device_ip))
                return
            json_response(self, 200, qce.measure_session(session_hex=session_hex, limit=limit))
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
        if path == "/api/v1/information-flow/history":
            _path_only, qs = self._path()
            limit = int((qs.get("limit") or ["40"])[0])
            json_response(self, 200, information_flow.history(limit=limit))
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
        if path == "/api/v1/dns/status":
            json_response(self, 200, dns_filter.status())
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
                        xbox_only=body.get("xbox_only"),
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

        if path == "/api/v1/nat/upnp/xbox-secure":
            try:
                json_response(self, 200, nat.enable_xbox_secure_upnp())
            except Exception as exc:  # noqa: BLE001
                json_response(self, 500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/nat/xbox-wan-dmz":
            try:
                json_response(self, 200, nat.enable_xbox_wan_dmz())
            except Exception as exc:  # noqa: BLE001
                json_response(self, 500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/gaming/xbox-secure-stack":
            try:
                level = str(body.get("shield_level") or body.get("level") or "console")
                buffer_profile = str(body.get("buffer_profile") or "desync")
                json_response(
                    self,
                    200,
                    gaming.apply_xbox_secure_stack(
                        shield_level=level,
                        buffer_profile=buffer_profile,
                        apply_upload_boost=body.get("upload_boost", True) is not False,
                    ),
                )
            except Exception as exc:  # noqa: BLE001
                json_response(self, 500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/dns/sync":
            try:
                json_response(self, 200, dns_filter.sync())
            except Exception as exc:  # noqa: BLE001
                json_response(self, 500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/dns/config":
            try:
                json_response(
                    self,
                    200,
                    dns_filter.set_config(
                        enabled=body.get("enabled"),
                        force_lan_dns=body.get("force_lan_dns"),
                        block_doh_dot=body.get("block_doh_dot"),
                        custom_domains=body.get("custom_domains"),
                        feeds=body.get("feeds"),
                    ),
                )
            except Exception as exc:  # noqa: BLE001
                json_response(self, 500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/ids/mode":
            try:
                json_response(self, 200, ids.set_mode(str(body.get("mode") or "log_only")))
            except Exception as exc:  # noqa: BLE001
                json_response(self, 500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/ids/clear-blocks":
            try:
                json_response(self, 200, ids.clear_enforcement())
            except Exception as exc:  # noqa: BLE001
                json_response(self, 500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/gaming/mitigate":
            try:
                payload = body
                if body.get("_wire"):
                    payload = throughput_fold.unwrap_wire_envelope(body)
                json_response(self, 200, gaming_mitigate.mitigate(payload))
            except Exception as exc:  # noqa: BLE001
                json_response(self, 500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/gaming/peers/block":
            try:
                json_response(
                    self,
                    200,
                    peer_blocklist.add_peers(
                        list(body.get("ips") or []),
                        reason=str(body.get("reason") or "api"),
                        ttl_sec=body.get("ttl_sec"),
                    ),
                )
            except Exception as exc:  # noqa: BLE001
                json_response(self, 500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/gaming/peers/clear":
            try:
                json_response(self, 200, peer_blocklist.clear_all())
            except Exception as exc:  # noqa: BLE001
                json_response(self, 500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/gaming/peers/remove":
            try:
                json_response(
                    self,
                    200,
                    peer_blocklist.remove_peers(list(body.get("ips") or [])),
                )
            except Exception as exc:  # noqa: BLE001
                json_response(self, 500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/gaming/peers/sync-shield":
            try:
                json_response(
                    self,
                    200,
                    peer_blocklist.sync_shield(
                        level=body.get("level"),
                        extra_peers=list(body.get("ips") or []),
                    ),
                )
            except Exception as exc:  # noqa: BLE001
                json_response(self, 500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/gaming/peers/decay":
            try:
                json_response(self, 200, peer_blocklist.decay_stale())
            except Exception as exc:  # noqa: BLE001
                json_response(self, 500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/subnets/block":
            try:
                ips = list(body.get("ips") or [])
                cidrs = list(body.get("cidrs") or [])
                reason = str(body.get("reason") or "api")
                ttl_days = body.get("ttl_days")
                results: list[dict[str, Any]] = []
                for cidr in cidrs:
                    results.append(
                        subnet_blocklist.add_subnet(
                            str(cidr),
                            reason=reason,
                            tier=str(body.get("tier") or "manual"),
                            source="api",
                            ttl_days=int(ttl_days) if ttl_days is not None else None,
                        )
                    )
                if ips:
                    results.append(
                        subnet_blocklist.block_from_ips(
                            [str(i) for i in ips],
                            reason=reason,
                            source="api",
                        )
                    )
                json_response(self, 200, {"ok": True, "results": results})
            except Exception as exc:  # noqa: BLE001
                json_response(self, 500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/subnets/remove":
            try:
                removed = [
                    subnet_blocklist.remove_subnet(str(c))
                    for c in list(body.get("cidrs") or [])
                ]
                json_response(self, 200, {"ok": True, "removed": removed})
            except Exception as exc:  # noqa: BLE001
                json_response(self, 500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/subnets/apply":
            try:
                json_response(self, 200, subnet_blocklist.apply_all())
            except Exception as exc:  # noqa: BLE001
                json_response(self, 500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/subnets/refresh-providers":
            try:
                json_response(self, 200, subnet_blocklist.refresh_providers())
            except Exception as exc:  # noqa: BLE001
                json_response(self, 500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/gaming/intel/export":
            try:
                json_response(self, 200, lobby_intel.export_intel())
            except Exception as exc:  # noqa: BLE001
                json_response(self, 500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/gaming/intel/import":
            try:
                json_response(
                    self,
                    200,
                    lobby_intel.import_intel(body, merge_peers=bool(body.get("merge_peers", True))),
                )
            except Exception as exc:  # noqa: BLE001
                json_response(self, 500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/gaming/probe-sink/correlate":
            try:
                from lib import probe_sink as probe_sink_mod

                json_response(
                    self,
                    200,
                    probe_sink_mod.correlate_session(str(body.get("session_hex") or "")),
                )
            except Exception as exc:  # noqa: BLE001
                json_response(self, 500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/gaming/connections/ingest":
            try:
                payload = body
                if body.get("_wire"):
                    payload = throughput_fold.unwrap_wire_envelope(body)
                json_response(
                    self,
                    200,
                    conn_lite_db.ingest(
                        session_hex=str(payload.get("session_hex") or ""),
                        phase=str(payload.get("phase") or ""),
                        xbox_ip=payload.get("xbox_ip"),
                        snapshot=payload.get("snapshot") if isinstance(payload.get("snapshot"), dict) else None,
                        peers=list(payload.get("peers") or []),
                        connections=list(payload.get("connections") or []),
                    ),
                )
            except Exception as exc:  # noqa: BLE001
                json_response(self, 500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/gaming/connections/end-session":
            try:
                json_response(
                    self,
                    200,
                    conn_lite_db.end_session(str(body.get("session_hex") or "")),
                )
            except Exception as exc:  # noqa: BLE001
                json_response(self, 500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/gaming/connections/action":
            try:
                json_response(
                    self,
                    200,
                    conn_lite_db.apply_action(
                        ips=list(body.get("ips") or []),
                        action=str(body.get("action") or ""),
                        session_hex=body.get("session_hex"),
                        reason=body.get("reason"),
                    ),
                )
            except Exception as exc:  # noqa: BLE001
                json_response(self, 500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/gaming/investigate/run":
            try:
                json_response(
                    self,
                    200,
                    unknown_investigator.run_pending(limit=int(body.get("limit") or 20)),
                )
            except Exception as exc:  # noqa: BLE001
                json_response(self, 500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/gaming/probe-sink/ingest":
            try:
                json_response(
                    self,
                    200,
                    {
                        "listener": probe_sink.ingest_listener_log(),
                        "counters": probe_sink.poll_counters(),
                        "afld": afld.rollup(force=False),
                    },
                )
            except Exception as exc:  # noqa: BLE001
                json_response(self, 500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/afld/rollup":
            try:
                json_response(
                    self,
                    200,
                    {
                        "rollup": afld.rollup(force=bool(body.get("force"))),
                        "prune": afld.prune(),
                        "status": afld.status(),
                    },
                )
            except Exception as exc:  # noqa: BLE001
                json_response(self, 500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/gaming/abuse-reports/generate":
            try:
                ip = str(body.get("ip") or "").strip()
                if not ip:
                    json_response(self, 400, {"ok": False, "error": "ip required"})
                    return
                json_response(self, 200, abuse_report.generate_report(ip))
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
                if isinstance(body.get("policies"), dict):
                    data = body["policies"]
                elif any(k in body for k in ("gaming", "qos", "zones", "ids", "dhcp", "device_groups", "perf")):
                    for section, val in body.items():
                        if section in {"ok", "policies"}:
                            continue
                        if isinstance(val, dict) and isinstance(data.get(section), dict):
                            merged = dict(data.get(section) or {})
                            merged.update(val)
                            data[section] = merged
                        else:
                            data[section] = val
                else:
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

        if path == "/api/v1/information-flow/analyze":
            try:
                json_response(self, 200, information_flow.analyze_step(force=True))
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

        if path == "/api/v1/qos/upload-boost":
            try:
                action = str(body.get("action") or "apply").lower()
                session_hex = str(body.get("session_hex") or "").strip() or None
                phase = str(body.get("phase") or "").strip() or None
                if action in ("relax", "off"):
                    json_response(self, 200, qos.upload_boost_relax(session_hex=session_hex, phase=phase))
                else:
                    json_response(self, 200, qos.upload_boost_apply(session_hex=session_hex, phase=phase))
            except Exception as exc:  # noqa: BLE001
                json_response(self, 500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/qos/download-boost":
            try:
                action = str(body.get("action") or "apply").lower()
                session_hex = str(body.get("session_hex") or "").strip() or None
                phase = str(body.get("phase") or "").strip() or None
                if action in ("relax", "off"):
                    json_response(self, 200, qos.download_boost_relax(session_hex=session_hex, phase=phase))
                else:
                    json_response(self, 200, qos.download_boost_apply(session_hex=session_hex, phase=phase))
            except Exception as exc:  # noqa: BLE001
                json_response(self, 500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/qos/buffer":
            try:
                action = str(body.get("action") or "apply").lower()
                profile = str(body.get("profile") or body.get("mode") or "gaming").lower()
                session_hex = str(body.get("session_hex") or "").strip() or None
                phase = str(body.get("phase") or "").strip() or None
                auto_rqd = profile in ("auto", "rqd") or bool(body.get("auto_rqd"))
                sample = body.get("sample") if isinstance(body.get("sample"), dict) else None
                if action in ("off", "relax", "idle"):
                    json_response(self, 200, qos.buffer_tune_apply("off", session_hex=session_hex, phase=phase))
                else:
                    json_response(
                        self,
                        200,
                        qos.buffer_tune_apply(
                            profile,
                            session_hex=session_hex,
                            phase=phase,
                            sample=sample,
                            auto_rqd=auto_rqd,
                        ),
                    )
            except Exception as exc:  # noqa: BLE001
                json_response(self, 500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/rqd/buffer-profile":
            try:
                sample = body.get("sample") if isinstance(body.get("sample"), dict) else None
                apply_profile = bool(body.get("apply"))
                rec = qos.rqd_buffer_recommendation(sample)
                if apply_profile and rec.get("profile"):
                    rec["applied"] = qos.buffer_tune_apply(
                        str(rec["profile"]),
                        auto_rqd=True,
                        sample=sample or {},
                    )
                json_response(self, 200, rec)
            except Exception as exc:  # noqa: BLE001
                json_response(self, 500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/rqd/search":
            try:
                items = body.get("items") or []
                if not isinstance(items, list) or not items:
                    json_response(self, 400, {"ok": False, "error": "items[] required"})
                    return
                key_field = str(body.get("key_field") or "key")
                score_field = str(body.get("score_field") or "score")
                context = str(body.get("context") or "api")

                def key_fn(x: Any) -> float:
                    return float(x.get(key_field, 0) if isinstance(x, dict) else x)

                def score_fn(x: Any) -> float:
                    return float(x.get(score_field, 0) if isinstance(x, dict) else x)

                json_response(
                    self,
                    200,
                    rqd.recursive_search(items, key_fn=key_fn, score_fn=score_fn, context=context),
                )
            except Exception as exc:  # noqa: BLE001
                json_response(self, 500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/asvi/scan":
            try:
                session_hex = str(body.get("session_hex") or "").strip() or None
                limit = int(body.get("limit") or 300)
                json_response(self, 200, asvi.scan_session(session_hex=session_hex, limit=limit))
            except Exception as exc:  # noqa: BLE001
                json_response(self, 500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/qce/measure":
            try:
                session_hex = str(body.get("session_hex") or "").strip() or None
                device_ip = str(body.get("device") or "").strip() or None
                limit = int(body.get("limit") or 300)
                rows = body.get("rows")
                if isinstance(rows, list) and rows:
                    json_response(self, 200, qce.measure_rows(rows))
                    return
                if device_ip:
                    json_response(self, 200, qce.measure_telemetry(device_ip=device_ip))
                    return
                json_response(self, 200, qce.measure_session(session_hex=session_hex, limit=limit))
            except Exception as exc:  # noqa: BLE001
                json_response(self, 500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/gaming/route-pref":
            try:
                action = str(body.get("action") or "apply").lower()
                session_hex = str(body.get("session_hex") or "").strip() or None
                phase = str(body.get("phase") or "").strip() or None
                if action in ("clear", "off"):
                    json_response(self, 200, gaming.clear_route_pref(session_hex=session_hex, phase=phase))
                else:
                    gw = str(body.get("gateway") or body.get("gw") or "").strip() or None
                    json_response(self, 200, gaming.apply_route_pref(gateway=gw, session_hex=session_hex, phase=phase))
            except Exception as exc:  # noqa: BLE001
                json_response(self, 500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/gaming/allowlist-learn/analyze":
            try:
                session_hex = str(body.get("session_hex") or "").strip() or None
                json_response(self, 200, gaming.allowlist_learn_analyze(session_hex=session_hex))
            except Exception as exc:  # noqa: BLE001
                json_response(self, 500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/gaming/allowlist-learn/apply":
            try:
                reload_shield = bool(body.get("reload_shield"))
                json_response(self, 200, gaming.allowlist_learn_apply(reload_shield=reload_shield))
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
                if body.get("payload_b64"):
                    raw = base64.b64decode(str(raw_b64))
                else:
                    raw = str(raw_b64).encode("latin-1")
                json_response(self, 200, folding.wire_compress(raw))
            except Exception as exc:  # noqa: BLE001
                json_response(self, 500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/folding/wire/decompress":
            try:
                out = folding.wire_decompress(
                    str(body.get("payload_b64") or ""),
                    encoding=str(body.get("encoding") or "") or None,
                )
                import base64

                json_response(
                    self,
                    200,
                    {"ok": True, "payload_b64": base64.b64encode(out).decode("ascii"), "bytes": len(out)},
                )
            except Exception as exc:  # noqa: BLE001
                json_response(self, 500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/folding/throughput/estimate":
            try:
                raw_b64 = body.get("payload_b64")
                text = body.get("payload")
                link = body.get("link_mbps")
                if raw_b64:
                    import base64

                    raw = base64.b64decode(str(raw_b64))
                elif text is not None:
                    raw = str(text).encode("utf-8")
                else:
                    json_response(self, 400, {"ok": False, "error": "payload or payload_b64 required"})
                    return
                json_response(
                    self,
                    200,
                    throughput_fold.estimate_for_payload(
                        raw,
                        link_mbps=float(link) if link is not None else None,
                    ),
                )
            except Exception as exc:  # noqa: BLE001
                json_response(self, 500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/folding/pattern/encode":
            try:
                import base64

                raw_b64 = body.get("payload_b64")
                text = body.get("payload")
                analyze_only = bool(body.get("analyze_only"))
                if raw_b64:
                    raw = base64.b64decode(str(raw_b64))
                elif text is not None:
                    raw = str(text).encode("utf-8")
                else:
                    json_response(self, 400, {"ok": False, "error": "payload or payload_b64 required"})
                    return
                if analyze_only:
                    json_response(
                        self,
                        200,
                        {"ok": True, "zenodo": pattern_encode.ZENODO, "analysis": pattern_encode.analyze_patterns(raw)},
                    )
                    return
                staged, meta = pattern_encode.pattern_encode(raw)
                out = {
                    "ok": True,
                    "zenodo": pattern_encode.ZENODO,
                    **meta,
                    "payload_b64": base64.b64encode(staged).decode("ascii"),
                }
                if meta.get("applied"):
                    roundtrip = pattern_encode.pattern_decode(staged)
                    out["lossless_ok"] = roundtrip == raw
                json_response(self, 200, out)
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
            session_hex = str(body.get("session_hex") or "").strip() or None
            phase = str(body.get("phase") or "").strip() or None
            result = gaming.apply_packet_shield("relax", session_hex=session_hex, phase=phase)
            status = 200 if result.get("ok") else 500
            json_response(
                self,
                status,
                {
                    "ok": bool(result.get("ok")),
                    "shield": "relax",
                    "packet_shield": result.get("packet_shield"),
                    "error": result.get("error"),
                    "stderr": result.get("stderr"),
                },
            )
            return

        if path == "/api/v1/shield/enable":
            level = policies.effective_shield_level(str(body.get("level") or "normal"))
            peer_ips = list(body.get("ips") or [])
            session_hex = str(body.get("session_hex") or "").strip() or None
            phase = str(body.get("phase") or "").strip() or None
            if level == "console":
                result = gaming.apply_console_mode(
                    enabled=True,
                    peer_ips=peer_ips,
                    session_hex=session_hex,
                    phase=phase,
                )
            elif level == "in-match":
                result = gaming.apply_in_match_mode(
                    enabled=True,
                    peer_ips=peer_ips,
                    session_hex=session_hex,
                    phase=phase or "in-match",
                )
            else:
                result = gaming.apply_packet_shield(
                    level,
                    session_hex=session_hex,
                    phase=phase,
                    peer_ips=peer_ips,
                )
            status = 200 if result.get("ok") else 500
            json_response(
                self,
                status,
                {
                    "ok": bool(result.get("ok")),
                    "shield": level,
                    "packet_shield": result.get("packet_shield"),
                    "console_mode": level in ("console", "in-match"),
                    "in_match_mode": level == "in-match",
                    "error": result.get("error"),
                    "stderr": result.get("stderr"),
                },
            )
            return

        if path == "/api/v1/shield/sync-fast":
            try:
                json_response(
                    self,
                    200,
                    nft.sync_shield_fast(
                        level=str(body.get("level") or "normal"),
                        peers=list(body.get("ips") or []),
                    ),
                )
            except Exception as exc:  # noqa: BLE001
                json_response(self, 500, {"ok": False, "error": str(exc)})
            return

        if path == "/api/v1/gaming/console-mode":
            try:
                enabled = body.get("enabled", True)
                if isinstance(enabled, str):
                    enabled = enabled.lower() not in ("0", "false", "off", "no")
                json_response(
                    self,
                    200,
                    gaming.apply_console_mode(
                        enabled=bool(enabled),
                        peer_ips=list(body.get("ips") or []),
                    ),
                )
            except Exception as exc:  # noqa: BLE001
                json_response(self, 500, {"ok": False, "error": str(exc)})
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
