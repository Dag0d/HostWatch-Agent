#!/usr/bin/env python3
"""Dependency-free HostWatch agent for Ubuntu-style Linux hosts."""

from __future__ import annotations

import argparse
import calendar
import fcntl
import hashlib
import json
import logging
import os
import re
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time
import tarfile
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib import error, request
from urllib.parse import quote, urlparse

AGENT_VERSION = "2026.4.4"
DEFAULT_CONFIG_PATH = Path(os.environ.get("HOSTWATCH_CONFIG_PATH", "/etc/hostwatch/agent.json"))
DEFAULT_STATE_PATH = Path(os.environ.get("HOSTWATCH_STATE_PATH", str(DEFAULT_CONFIG_PATH.with_suffix(".state.json"))))
DEFAULT_SERVICE_NAME = os.environ.get("HOSTWATCH_SERVICE_NAME", "hostwatch-agent.service")
DEFAULT_PAIRING_PORT = int(os.environ.get("HOSTWATCH_PAIRING_PORT", "48221"))
HEARTBEAT_INTERVAL_SECONDS = int(os.environ.get("HOSTWATCH_HEARTBEAT_INTERVAL_SECONDS", "30"))
METRICS_INTERVAL_SECONDS = int(os.environ.get("HOSTWATCH_METRICS_INTERVAL_SECONDS", "60"))
COMMAND_POLL_INTERVAL_SECONDS = int(os.environ.get("HOSTWATCH_COMMAND_POLL_INTERVAL_SECONDS", "15"))
PAIRING_TIMEOUT_SECONDS = 300
BOOTLOADER_CHECK_INTERVAL_SECONDS = 7 * 24 * 60 * 60
APT_UPDATE_FRESH_SECONDS = 30 * 60
RPI_NOTES_URL_TEMPLATE = "https://raw.githubusercontent.com/raspberrypi/rpi-eeprom/refs/heads/master/firmware-{chip}/release-notes.md"
RPI_EEPROM_TARBALL_URL = "https://github.com/raspberrypi/rpi-eeprom/archive/refs/heads/master.tar.gz"
RPI_EEPROM_DEST_ROOT = Path("/lib/firmware/raspberrypi")
RPI_EEPROM_TRACKS = ("latest", "default")
RPI_EEPROM_CONFIG_PATH = Path("/etc/default/rpi-eeprom-update")
RPI_EEPROM_TRACK_VAR = "FIRMWARE_RELEASE_STATUS"
RPI_EEPROM_TRACK_ALIASES = ("FIRMWARE_RELEASE",)
RPI_EEPROM_FLASHROM_VAR = "RPI_EEPROM_USE_FLASHROM"
RELEASE_REPOSITORY = "Dag0d/HostWatch-Agent"
RELEASE_API_LATEST_URL = f"https://api.github.com/repos/{RELEASE_REPOSITORY}/releases/latest"
RELEASE_API_TAG_URL_TEMPLATE = f"https://api.github.com/repos/{RELEASE_REPOSITORY}/releases/tags/{{tag}}"
RELEASE_ALLOWED_HOSTS = {"api.github.com", "github.com", "objects.githubusercontent.com"}
RELEASE_MANIFEST_PREFIX = "hostwatch-agent-manifest-"
RELEASE_TARBALL_PREFIX = "hostwatch-agent-"
RELEASE_ARTIFACT_TYPE = "agent"
RELEASE_BACKUP_DIR = DEFAULT_STATE_PATH.parent / "updates"
RELEASE_PUBLIC_KEY_PATH = Path(__file__).resolve().with_name("release_signing_public.pem")
RELEASE_REQUIRED_FILES = {
    "hostwatch_agent.py",
    "install.sh",
    "release_signing_public.pem",
}
LOG_FORMAT = "%(asctime)s %(levelname)s [hostwatch-agent] %(message)s"

logging.basicConfig(level=os.environ.get("HOSTWATCH_LOG_LEVEL", "INFO").upper(), format=LOG_FORMAT)
LOGGER = logging.getLogger("hostwatch-agent")
SHUTDOWN_EVENT = threading.Event()


@dataclass
class AgentConfig:
    node_name: str
    node_uid: str
    ha_url: str | None = None
    ha_url_mode: str = "local"
    heartbeat_webhook_url: str | None = None
    metrics_webhook_url: str | None = None
    command_result_webhook_url: str | None = None
    command_poll_webhook_url: str | None = None
    node_id: str | None = None
    node_secret: str | None = None
    allowed_ha_name: str | None = None
    hardware_profile: str = "auto"
    raspberry_model_override: str | None = None
    temperature_source: str = "auto"
    temperature_path: str | None = None
    primary_interface: str = "auto"
    extra_interfaces: list[str] | None = None


@dataclass
class PairingSession:
    code: str
    expires_at: float
    approved: bool = False
    request_id: str | None = None
    requested_ha_name: str | None = None
    requested_ha_url: str | None = None
    requester_ip: str | None = None


class AgentStateStore:
    def __init__(self) -> None:
        self.path = DEFAULT_STATE_PATH
        self._data = self._load()

    def _load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {}
        try:
            return json.loads(self.path.read_text(encoding="utf8"))
        except (OSError, ValueError):
            return {}

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)

    def set(self, key: str, value: Any) -> None:
        self._data[key] = value
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self._data, indent=2), encoding="utf8")
        os.chmod(self.path, 0o600)


class CommandOutputStore:
    """Store recent command output locally on the node."""

    def __init__(self) -> None:
        self.path = DEFAULT_STATE_PATH.parent / "command-runs"
        self.path.mkdir(parents=True, exist_ok=True)
        os.chmod(self.path, 0o700)

    def append(self, command: dict[str, Any], output: str) -> None:
        run_id = command.get("run_id")
        command_type = command.get("type")
        if not isinstance(run_id, str) or not isinstance(command_type, str):
            return
        log_path = self.path / f"{run_id}.log"
        meta_path = self.path / f"{run_id}.json"
        with log_path.open("a", encoding="utf8") as handle:
            handle.write(output)
        os.chmod(log_path, 0o600)
        if not meta_path.exists():
            meta = {
                "run_id": run_id,
                "command_type": command_type,
                "created_at": command.get("requested_at") or iso_timestamp(time.time()),
            }
            meta_path.write_text(json.dumps(meta, indent=2), encoding="utf8")
            os.chmod(meta_path, 0o600)
        self._prune(command_type)

    def read(self, run_id: Any) -> str | None:
        if not isinstance(run_id, str):
            return None
        log_path = self.path / f"{run_id}.log"
        if not log_path.exists():
            return None
        return log_path.read_text(encoding="utf8", errors="replace")

    def _prune(self, command_type: str) -> None:
        items: list[dict[str, Any]] = []
        for meta_path in self.path.glob("*.json"):
            try:
                meta = json.loads(meta_path.read_text(encoding="utf8"))
            except (OSError, ValueError):
                continue
            if meta.get("command_type") == command_type:
                meta["_meta_path"] = meta_path
                items.append(meta)
        items.sort(key=lambda item: item.get("created_at", ""), reverse=True)
        for item in items[2:]:
            meta_path = item["_meta_path"]
            run_id = item.get("run_id")
            if isinstance(run_id, str):
                (self.path / f"{run_id}.log").unlink(missing_ok=True)
            meta_path.unlink(missing_ok=True)


class DiscoveryHandle:
    def __init__(self, process: subprocess.Popen[str] | None, service_name: str | None) -> None:
        self._process = process
        self.service_name = service_name

    def stop(self) -> None:
        if self._process and self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self._process.kill()


class HostWatchRequestError(Exception):
    """Raised when a webhook request returns an unexpected HTTP response."""


class SystemMetricsCollector:
    def __init__(self, config: AgentConfig) -> None:
        self.config = config
        self._state = AgentStateStore()
        self._previous_cpu: tuple[int, int] | None = None
        self._apt_cache_checked_at = 0.0
        self._apt_cache_count: int | None = None

    def collect(self) -> dict[str, Any]:
        platform = detect_platform(self.config)
        metrics = {
            "cpu": self._collect_cpu(),
            "memory": self._collect_memory(),
            "filesystem": self._collect_filesystem(),
            "temperature": self._collect_temperature(),
            "updates": self._collect_updates(platform["capabilities"]["apt"]),
            "uptime_seconds": self._collect_uptime(),
            "bootloader": self._collect_bootloader(platform["capabilities"]["raspberryPiBootloader"]),
        }
        return {"metrics": metrics, "platform": platform["platform"]}

    def _collect_cpu(self) -> dict[str, Any]:
        with Path("/proc/stat").open("r", encoding="utf8") as handle:
            first = handle.readline().strip().split()
        values = [int(value) for value in first[1:]]
        idle = values[3] + values[4]
        total = sum(values)
        usage_percent = 0.0
        if self._previous_cpu:
            total_diff = total - self._previous_cpu[1]
            idle_diff = idle - self._previous_cpu[0]
            if total_diff > 0:
                usage_percent = round(((total_diff - idle_diff) / total_diff) * 100, 2)
        self._previous_cpu = (idle, total)
        load1, load5, load15 = os.getloadavg()
        return {
            "usage_percent": usage_percent,
            "load_1m": round(load1, 2),
            "load_5m": round(load5, 2),
            "load_15m": round(load15, 2),
            "cores": os.cpu_count() or 1,
        }

    def _collect_memory(self) -> dict[str, Any]:
        meminfo: dict[str, int] = {}
        with Path("/proc/meminfo").open("r", encoding="utf8") as handle:
            for line in handle:
                key, raw_value = line.split(":", 1)
                meminfo[key] = int(raw_value.strip().split()[0]) * 1024
        total = meminfo.get("MemTotal", 0)
        available = meminfo.get("MemAvailable", meminfo.get("MemFree", 0))
        used = max(total - available, 0)
        return {
            "total_bytes": total,
            "used_bytes": used,
            "available_bytes": available,
            "used_percent": round((used / total) * 100, 2) if total else 0,
        }

    def _collect_filesystem(self) -> dict[str, Any]:
        usage = shutil.disk_usage("/")
        return {
            "root": {
                "total_bytes": usage.total,
                "used_bytes": usage.used,
                "available_bytes": usage.free,
                "used_percent": round((usage.used / usage.total) * 100, 2) if usage.total else 0,
            }
        }

    def _collect_temperature(self) -> dict[str, Any]:
        cpu_celsius = read_cpu_temperature_celsius(self.config)
        return {"cpu_celsius": cpu_celsius}

    def _collect_updates(self, apt_supported: bool) -> dict[str, Any]:
        if not apt_supported:
            return {"apt": {"supported": False, "upgradable_count": None, "checked_at": None}}
        cached = self._state.get("apt", {})
        cached_checked_at = cached.get("checked_at")
        checked_epoch = parse_iso_timestamp(cached_checked_at) if isinstance(cached_checked_at, str) else 0.0
        if cached and checked_epoch:
            self._apt_cache_checked_at = checked_epoch
            self._apt_cache_count = cached.get("upgradable_count")
        if cached and not is_apt_check_due(cached_checked_at):
            return {"apt": cached}
        now = time.time()
        if self._apt_cache_checked_at and not is_apt_check_due(iso_timestamp(self._apt_cache_checked_at)):
            return {
                "apt": {
                    "supported": True,
                    "upgradable_count": self._apt_cache_count,
                    "checked_at": iso_timestamp(self._apt_cache_checked_at),
                }
            }
        try:
            result = subprocess.run(
                ["apt", "list", "--upgradable"],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
            lines = [
                line.strip()
                for line in result.stdout.splitlines()
                if line.strip() and not line.startswith("Listing...")
            ]
            self._apt_cache_count = len(lines)
        except (subprocess.SubprocessError, FileNotFoundError):
            self._apt_cache_count = None
        self._apt_cache_checked_at = now
        payload = {
            "supported": True,
            "upgradable_count": self._apt_cache_count,
            "checked_at": iso_timestamp(self._apt_cache_checked_at),
        }
        self._state.set("apt", payload)
        LOGGER.info("APT check completed: %s upgradable package(s)", self._apt_cache_count)
        return {"apt": payload}

    def _collect_uptime(self) -> float:
        with Path("/proc/uptime").open("r", encoding="utf8") as handle:
            return round(float(handle.read().split()[0]), 2)

    def _collect_bootloader(self, bootloader_supported: bool) -> dict[str, Any]:
        if not bootloader_supported:
            return {"supported": False, "status": None, "checked_at": None}
        return collect_raspberry_bootloader_status(self.config, self._state)


class PairingServer:
    def __init__(self, config: AgentConfig, port: int, ssdp_uuid: str, description_port: int) -> None:
        self.config = config
        self.description_port = description_port
        self.port = port
        self.ssdp_uuid = ssdp_uuid
        self.session = PairingSession(code=create_pairing_code(), expires_at=time.time() + PAIRING_TIMEOUT_SECONDS)
        self._request_event = threading.Event()
        self._closed_event = threading.Event()
        self._cert_dir = Path(tempfile.mkdtemp(prefix="hostwatch-pairing-"))
        self._httpd = self._build_server()
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        shutil.rmtree(self._cert_dir, ignore_errors=True)
        self._closed_event.set()

    def wait_for_request(self, timeout: int = PAIRING_TIMEOUT_SECONDS) -> PairingSession:
        if not self._request_event.wait(timeout=timeout):
            raise TimeoutError("Pairing request timed out")
        return self.session

    def wait_until_closed(self, timeout: int = 10) -> None:
        self._closed_event.wait(timeout=timeout)

    def approve(self) -> None:
        self.session.approved = True

    def _build_server(self) -> ThreadingHTTPServer:
        generate_self_signed_cert(self._cert_dir)

        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                if self.path == "/description.xml":
                    self._send_xml(device_description_xml(outer))
                    return
                if self.path != "/api/hostwatch/pairing/info":
                    self.send_error(404)
                    return
                self._send_json(
                    200,
                    {
                        "node_uid": outer.config.node_uid,
                        "node_name": outer.config.node_name,
                        "ha_url_mode": outer.config.ha_url_mode,
                        "pairing_code": outer.session.code,
                        "expires_at": iso_timestamp(outer.session.expires_at),
                        **detect_platform(outer.config),
                    },
                )

            def do_POST(self) -> None:  # noqa: N802
                payload = self._read_json()
                if self.path == "/api/hostwatch/pairing/request":
                    outer.session.request_id = str(uuid.uuid4())
                    outer.session.requested_ha_name = payload.get("ha_name")
                    outer.session.requested_ha_url = payload.get("ha_url")
                    outer.session.requester_ip = self.client_address[0]
                    outer._request_event.set()
                    self._send_json(
                        200,
                        {
                            "request_id": outer.session.request_id,
                            "status": "pending_approval",
                            "pairing_code": outer.session.code,
                        },
                    )
                    return
                if self.path == "/api/hostwatch/pairing/complete":
                    if not outer.session.approved:
                        self._send_json(409, {"error": "approval_required"})
                        return
                    if payload.get("request_id") != outer.session.request_id:
                        self._send_json(400, {"error": "request_mismatch"})
                        return
                    next_config = AgentConfig(
                        node_name=outer.config.node_name,
                        node_uid=outer.config.node_uid,
                        ha_url=payload.get("ha_url"),
                        ha_url_mode=outer.config.ha_url_mode,
                        heartbeat_webhook_url=payload.get("heartbeat_webhook_url"),
                        metrics_webhook_url=payload.get("metrics_webhook_url"),
                        command_result_webhook_url=payload.get("command_result_webhook_url"),
                        command_poll_webhook_url=payload.get("command_poll_webhook_url"),
                        node_id=payload.get("node_id"),
                        node_secret=payload.get("node_secret"),
                        allowed_ha_name=payload.get("ha_name"),
                        hardware_profile=outer.config.hardware_profile,
                        raspberry_model_override=outer.config.raspberry_model_override,
                        temperature_source=outer.config.temperature_source,
                        temperature_path=outer.config.temperature_path,
                        primary_interface=outer.config.primary_interface,
                        extra_interfaces=outer.config.extra_interfaces,
                    )
                    save_config(next_config)
                    self._send_json(
                        200,
                        {
                            "status": "paired",
                            **detect_platform(next_config),
                        },
                    )
                    threading.Thread(target=outer._delayed_stop, daemon=True).start()
                    return
                self.send_error(404)

            def log_message(self, format: str, *args: object) -> None:
                return

            def _read_json(self) -> dict[str, Any]:
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length) if length else b"{}"
                return json.loads(raw.decode("utf8"))

            def _send_json(self, status: int, payload: dict[str, Any]) -> None:
                body = json.dumps(payload).encode("utf8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _send_xml(self, body: str) -> None:
                encoded = body.encode("utf8")
                self.send_response(200)
                self.send_header("Content-Type", "text/xml")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

        httpd = ThreadingHTTPServer(("0.0.0.0", self.port), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self._cert_dir / "pairing.crt", self._cert_dir / "pairing.key")
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        return httpd

    def _delayed_stop(self) -> None:
        time.sleep(0.25)
        self.stop()


def load_config() -> AgentConfig:
    if not DEFAULT_CONFIG_PATH.exists():
        return AgentConfig(node_name=default_node_name(), node_uid=stable_node_uid())
    data = json.loads(DEFAULT_CONFIG_PATH.read_text(encoding="utf8"))
    return AgentConfig(
        node_name=data.get("nodeName", default_node_name()),
        node_uid=data.get("nodeUid", stable_node_uid()),
        ha_url=data.get("haUrl"),
        ha_url_mode=data.get("haUrlMode", "local"),
        heartbeat_webhook_url=data.get("heartbeatWebhookUrl"),
        metrics_webhook_url=data.get("metricsWebhookUrl"),
        command_result_webhook_url=data.get("commandResultWebhookUrl"),
        command_poll_webhook_url=data.get("commandPollWebhookUrl"),
        node_id=data.get("nodeId"),
        node_secret=data.get("nodeSecret"),
        allowed_ha_name=data.get("allowedHaName"),
        hardware_profile=data.get("hardwareProfile", "auto"),
        raspberry_model_override=data.get("raspberryModelOverride"),
        temperature_source=data.get("temperatureSource", "auto"),
        temperature_path=data.get("temperaturePath"),
        primary_interface=data.get("primaryInterface", "auto"),
        extra_interfaces=data.get("extraInterfaces", []),
    )


def save_config(config: AgentConfig) -> None:
    DEFAULT_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "nodeName": config.node_name,
        "nodeUid": config.node_uid,
        "haUrl": config.ha_url,
        "haUrlMode": config.ha_url_mode,
        "heartbeatWebhookUrl": config.heartbeat_webhook_url,
        "metricsWebhookUrl": config.metrics_webhook_url,
        "commandResultWebhookUrl": config.command_result_webhook_url,
        "commandPollWebhookUrl": config.command_poll_webhook_url,
        "nodeId": config.node_id,
        "nodeSecret": config.node_secret,
        "allowedHaName": config.allowed_ha_name,
        "hardwareProfile": config.hardware_profile,
        "raspberryModelOverride": config.raspberry_model_override,
        "temperatureSource": config.temperature_source,
        "temperaturePath": config.temperature_path,
        "primaryInterface": config.primary_interface,
        "extraInterfaces": config.extra_interfaces or [],
    }
    DEFAULT_CONFIG_PATH.write_text(json.dumps(payload, indent=2), encoding="utf8")
    os.chmod(DEFAULT_CONFIG_PATH, 0o600)


def normalize_version(value: str | None) -> str | None:
    """Normalize a release version or tag to a bare version string."""
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    if normalized.startswith("v"):
        normalized = normalized[1:]
    return normalized or None


def parse_version_components(value: str | None) -> tuple[int, ...] | None:
    """Parse dotted integer version strings like 2026.4.1."""
    normalized = normalize_version(value)
    if not normalized:
        return None
    parts = normalized.split(".")
    try:
        return tuple(int(part) for part in parts)
    except ValueError:
        return None


def compare_versions(left: str | None, right: str | None) -> int:
    """Compare two dotted integer versions."""
    left_parts = parse_version_components(left)
    right_parts = parse_version_components(right)
    if left_parts is None or right_parts is None:
        left_text = normalize_version(left) or ""
        right_text = normalize_version(right) or ""
        return (left_text > right_text) - (left_text < right_text)
    length = max(len(left_parts), len(right_parts))
    padded_left = left_parts + (0,) * (length - len(left_parts))
    padded_right = right_parts + (0,) * (length - len(right_parts))
    return (padded_left > padded_right) - (padded_left < padded_right)


def detect_platform(config: AgentConfig) -> dict[str, Any]:
    raspberry_model = read_raspberry_model(config)
    virtualization = detect_virtualization(config)
    cpu_temperature = read_cpu_temperature_celsius(config)
    network = collect_configured_ip_addresses(config)
    raspberry_pi_5 = is_raspberry_pi_5_model(raspberry_model)
    raspberry_bootloader_supported = is_raspberry_bootloader_supported_model(raspberry_model)
    cpu_model = "unknown"
    for line in Path("/proc/cpuinfo").read_text(encoding="utf8").splitlines():
        if ":" in line and line.lower().startswith("model name"):
            cpu_model = line.split(":", 1)[1].strip()
            break
    return {
        "capabilities": {
            "apt": shutil.which("apt") is not None,
            "powerControl": os.name == "posix",
            "raspberryPi": raspberry_model is not None,
            "raspberryPiBootloader": raspberry_bootloader_supported,
            "raspberryPi5": raspberry_pi_5,
            "temperatures": cpu_temperature is not None,
        },
        "platform": {
            "arch": os.uname().machine,
            "cpuModel": cpu_model,
            "cpuCores": os.cpu_count() or 1,
            "hostname": socket.gethostname(),
            "ipAddress": network["primary"],
            "ipAddresses": network["addresses"],
            "os": "linux",
            "osRelease": os.uname().release,
            "totalMemoryBytes": read_total_memory(),
            "virtualization": virtualization,
            "raspberry_model": raspberry_model,
        },
    }


def is_raspberry_pi_5_model(model: str | None) -> bool:
    """Return whether a Raspberry Pi model string describes a Raspberry Pi 5."""
    return bool(model and "raspberry pi 5" in model.lower())


def raspberry_bootloader_chip_from_model(model: str | None) -> str | None:
    """Map Raspberry Pi model strings to EEPROM bootloader chip identifiers."""
    if not model:
        return None
    lowered = model.lower()
    if "raspberry pi 5" in lowered or "compute module 5" in lowered:
        return "2712"
    if (
        "raspberry pi 4" in lowered
        or "raspberry pi 400" in lowered
        or "compute module 4" in lowered
    ):
        return "2711"
    return None


def is_raspberry_bootloader_supported_model(model: str | None) -> bool:
    """Return whether this Raspberry Pi model has an updateable EEPROM bootloader."""
    return raspberry_bootloader_chip_from_model(model) is not None


def start_discovery(node_name: str, port: int) -> DiscoveryHandle:
    avahi = shutil.which("avahi-publish-service")
    if not avahi:
        return DiscoveryHandle(None, None)
    service_name = f"{node_name}-{port}-{uuid.uuid4().hex[:6]}"
    process = subprocess.Popen(
        [
            avahi,
            service_name,
            "_hostwatch._tcp",
            str(port),
            f"display_name={node_name}",
            "pairing=active",
            f"version={AGENT_VERSION}",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    return DiscoveryHandle(process, service_name)


class SsdpAnnouncer:
    ST = "urn:hostwatch:device:HostWatchNode:1"
    MULTICAST_HOST = "239.255.255.250"
    MULTICAST_PORT = 1900

    def __init__(
        self,
        node_name: str,
        port: int,
        description_port: int,
        device_uuid: str,
        primary_interface: str = "auto",
    ) -> None:
        self.node_name = node_name
        self.port = port
        self.description_port = description_port
        self.device_uuid = device_uuid
        self.location = f"http://{detect_local_ip(primary_interface)}:{description_port}/description.xml"
        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        self._send_notify("ssdp:byebye")
        self._thread.join(timeout=2)

    def _run(self) -> None:
        self._send_notify("ssdp:alive")
        while not self._stop_event.wait(10):
            self._send_notify("ssdp:alive")

    def _send_notify(self, nts: str) -> None:
        payload = "\r\n".join(
            [
                "NOTIFY * HTTP/1.1",
                f"HOST: {self.MULTICAST_HOST}:{self.MULTICAST_PORT}",
                "CACHE-CONTROL: max-age=300",
                f"LOCATION: {self.location}",
                f"NT: {self.ST}",
                f"NTS: {nts}",
                f"SERVER: HostWatch/{AGENT_VERSION} UPnP/1.1 Python/{platform_python_version()}",
                f"USN: uuid:{self.device_uuid}::{self.ST}",
                f"X-HOSTWATCH-NAME: {self.node_name}",
                "",
                "",
            ]
        ).encode("utf8")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            sock.sendto(payload, (self.MULTICAST_HOST, self.MULTICAST_PORT))


class SsdpResponder:
    ST = "urn:hostwatch:device:HostWatchNode:1"
    MULTICAST_HOST = "239.255.255.250"
    MULTICAST_PORT = 1900

    def __init__(
        self,
        node_name: str,
        port: int,
        description_port: int,
        device_uuid: str,
        primary_interface: str = "auto",
    ) -> None:
        self.node_name = node_name
        self.port = port
        self.description_port = description_port
        self.device_uuid = device_uuid
        self.location = f"http://{detect_local_ip(primary_interface)}:{description_port}/description.xml"
        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._socket: socket.socket | None = None

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._socket is not None:
            try:
                self._socket.close()
            except OSError:
                pass
        self._thread.join(timeout=2)

    def _run(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self._socket = sock
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("", self.MULTICAST_PORT))
        except OSError:
            return

        membership = socket.inet_aton(self.MULTICAST_HOST) + socket.inet_aton("0.0.0.0")
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)
        sock.settimeout(1)

        while not self._stop_event.is_set():
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break

            text = data.decode("utf8", "ignore")
            if "M-SEARCH * HTTP/1.1" not in text:
                continue
            if self.ST not in text and "ssdp:all" not in text:
                continue

            response = "\r\n".join(
                [
                    "HTTP/1.1 200 OK",
                    "CACHE-CONTROL: max-age=300",
                    "EXT:",
                    f"LOCATION: {self.location}",
                    f"SERVER: HostWatch/{AGENT_VERSION} UPnP/1.1 Python/{platform_python_version()}",
                    f"ST: {self.ST}",
                    f"USN: uuid:{self.device_uuid}::{self.ST}",
                    "",
                    "",
                ]
            ).encode("utf8")
            try:
                sock.sendto(response, addr)
            except OSError:
                continue


class DescriptionServer:
    def __init__(
        self,
        node_name: str,
        description_port: int,
        device_uuid: str,
        primary_interface: str = "auto",
    ) -> None:
        self.node_name = node_name
        self.description_port = description_port
        self.device_uuid = device_uuid
        self.primary_interface = primary_interface
        self._httpd = self._build_server()
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()

    def _build_server(self) -> ThreadingHTTPServer:
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                if self.path != "/description.xml":
                    self.send_error(404)
                    return
                body = description_xml_for(
                    node_name=outer.node_name,
                    device_uuid=outer.device_uuid,
                    description_port=outer.description_port,
                    primary_interface=outer.primary_interface,
                ).encode("utf8")
                self.send_response(200)
                self.send_header("Content-Type", "text/xml")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args: object) -> None:
                return

        return ThreadingHTTPServer(("0.0.0.0", self.description_port), Handler)


def generate_self_signed_cert(cert_dir: Path) -> None:
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(cert_dir / "pairing.key"),
            "-out",
            str(cert_dir / "pairing.crt"),
            "-sha256",
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=hostwatch-pairing",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
    )


def send_json(url: str, payload: dict[str, Any]) -> dict[str, Any]:
    data = json.dumps(payload).encode("utf8")
    req = request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": f"HostWatch-Agent/{AGENT_VERSION}",
        },
        method="POST",
    )
    try:
        with request.urlopen(req, timeout=15) as response:
            body = response.read().decode("utf8", errors="replace")
            content_type = response.headers.get("Content-Type", "")
            try:
                return json.loads(body)
            except ValueError as exc:
                snippet = body.strip().replace("\n", " ")[:240]
                raise HostWatchRequestError(
                    f"non-JSON response from {url} "
                    f"(status={response.status}, content-type={content_type or 'unknown'}): {snippet}"
                ) from exc
    except error.HTTPError as exc:
        body = exc.read().decode("utf8", errors="replace")
        snippet = body.strip().replace("\n", " ")[:240]
        content_type = exc.headers.get("Content-Type", "") if exc.headers else ""
        server = exc.headers.get("Server", "") if exc.headers else ""
        cf_ray = exc.headers.get("CF-RAY", "") if exc.headers else ""
        details = [
            f"HTTP {exc.code} {exc.reason}",
            f"url={url}",
        ]
        if content_type:
            details.append(f"content-type={content_type}")
        if server:
            details.append(f"server={server}")
        if cf_ray:
            details.append(f"cf-ray={cf_ray}")
        if snippet:
            details.append(f"body={snippet}")
        raise HostWatchRequestError(", ".join(details)) from exc


def ensure_allowed_release_url(url: str) -> None:
    """Reject unexpected release hosts and non-HTTPS URLs."""
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError(f"release URL must use https: {url}")
    if parsed.hostname not in RELEASE_ALLOWED_HOSTS:
        raise ValueError(f"release URL host is not allowed: {parsed.hostname}")


def fetch_url_bytes(url: str, *, timeout: int = 30, accept: str | None = None) -> bytes:
    """Fetch raw bytes from a release URL with a fixed user agent."""
    ensure_allowed_release_url(url)
    headers = {"User-Agent": f"HostWatch-Agent/{AGENT_VERSION}"}
    if accept:
        headers["Accept"] = accept
    req = request.Request(url, headers=headers, method="GET")
    with request.urlopen(req, timeout=timeout) as response:
        return response.read()


def fetch_release_json(url: str) -> dict[str, Any]:
    """Fetch and parse a JSON document from an allowed release endpoint."""
    body = fetch_url_bytes(url, accept="application/vnd.github+json")
    return json.loads(body.decode("utf8"))


def run_pair(config: AgentConfig, port: int) -> None:
    ssdp_uuid = config.node_uid
    description_port = port + 1
    discovery = start_discovery(config.node_name, port)
    description_server = DescriptionServer(
        config.node_name,
        description_port,
        ssdp_uuid,
        config.primary_interface,
    )
    ssdp = SsdpAnnouncer(config.node_name, port, description_port, ssdp_uuid, config.primary_interface)
    ssdp_responder = SsdpResponder(config.node_name, port, description_port, ssdp_uuid, config.primary_interface)
    pairing = PairingServer(config, port, ssdp_uuid, description_port)
    description_server.start()
    pairing.start()
    ssdp.start()
    ssdp_responder.start()
    print(f"HostWatch pairing active on port {port}")
    print(f"Node: {config.node_name}")
    print(f"Code: {pairing.session.code}")
    if discovery.service_name:
        print(f"Discovery active via avahi as {discovery.service_name}")
    else:
        print("Discovery unavailable: avahi-publish-service not found, manual add remains available.")
    print(f"SSDP active with UUID {ssdp_uuid}")
    print("Waiting for a Home Assistant pairing request...")
    LOGGER.info("Pairing mode active on port %s with SSDP UUID %s", port, ssdp_uuid)

    try:
        request_info = pairing.wait_for_request()
    except TimeoutError as exc:
        ssdp.stop()
        ssdp_responder.stop()
        discovery.stop()
        pairing.stop()
        description_server.stop()
        raise SystemExit(str(exc)) from exc

    print(f"Incoming request from HA: {request_info.requested_ha_name or 'unknown'}")
    print(f"HA URL: {request_info.requested_ha_url or 'unknown'}")
    print(f"HA IP: {request_info.requester_ip or 'unknown'}")
    print(f"Code: {request_info.code}")
    LOGGER.info(
        "Pairing request received from HA '%s' at %s",
        request_info.requested_ha_name or "unknown",
        request_info.requester_ip or "unknown",
    )
    answer = input("Approve this pairing request? [y/N] ").strip().lower()
    if answer != "y":
        ssdp.stop()
        ssdp_responder.stop()
        discovery.stop()
        pairing.stop()
        description_server.stop()
        print("Pairing cancelled.")
        LOGGER.info("Pairing request rejected locally")
        return

    pairing.approve()
    print("Pairing approved. Waiting for completion.")
    pairing.wait_until_closed()
    LOGGER.info("Pairing approved and completed")
    ssdp.stop()
    ssdp_responder.stop()
    discovery.stop()
    description_server.stop()


def get_agent_install_dir() -> Path:
    """Return the install directory that contains the running agent."""
    return Path(__file__).resolve().parent


def get_agent_script_path() -> Path:
    """Return the currently running agent script path."""
    return Path(__file__).resolve()


def get_public_key_path() -> Path:
    """Return the trusted public key path for release verification."""
    return RELEASE_PUBLIC_KEY_PATH


def fetch_github_release(version: str | None = None) -> dict[str, Any]:
    """Fetch GitHub release metadata for the latest or a tagged release."""
    if version:
        url = RELEASE_API_TAG_URL_TEMPLATE.format(tag=quote(normalize_version(version) or version, safe=""))
    else:
        url = RELEASE_API_LATEST_URL
    return fetch_release_json(url)


def select_release_asset(release: dict[str, Any], prefix: str, suffix: str) -> dict[str, Any]:
    """Return a matching release asset from GitHub release metadata."""
    for asset in release.get("assets", []):
        name = asset.get("name")
        if isinstance(name, str) and name.startswith(prefix) and name.endswith(suffix):
            return asset
    raise ValueError(f"missing release asset matching {prefix}*{suffix}")


def verify_release_manifest_signature(manifest_path: Path, signature_path: Path) -> None:
    """Verify a detached manifest signature with OpenSSL."""
    public_key_path = get_public_key_path()
    if not public_key_path.exists():
        raise ValueError(f"release signing public key not found: {public_key_path}")
    if not shutil.which("openssl"):
        raise ValueError("openssl is required for release signature verification")
    result = subprocess.run(
        [
            "openssl",
            "dgst",
            "-sha256",
            "-verify",
            str(public_key_path),
            "-signature",
            str(signature_path),
            str(manifest_path),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        raise ValueError(summarize_command_output(result.stdout, result.stderr, "manifest signature verification failed"))


def load_and_verify_release_manifest(
    manifest_path: Path,
    signature_path: Path,
    *,
    expected_version: str,
) -> dict[str, Any]:
    """Verify and load a signed release manifest."""
    verify_release_manifest_signature(manifest_path, signature_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf8"))
    version = normalize_version(manifest.get("version"))
    if version != normalize_version(expected_version):
        raise ValueError(f"manifest version mismatch: expected {expected_version}, got {version}")
    if manifest.get("artifact_type") != RELEASE_ARTIFACT_TYPE:
        raise ValueError(f"unexpected manifest artifact type: {manifest.get('artifact_type')}")
    artifact = manifest.get("artifact")
    if not isinstance(artifact, dict):
        raise ValueError("manifest artifact block is missing")
    artifact_url = artifact.get("url")
    artifact_sha256 = artifact.get("sha256")
    if not isinstance(artifact_url, str) or not isinstance(artifact_sha256, str):
        raise ValueError("manifest artifact url/sha256 is missing")
    ensure_allowed_release_url(artifact_url)
    minimum_agent_version = manifest.get("minimum_agent_version")
    if minimum_agent_version and compare_versions(AGENT_VERSION, minimum_agent_version) < 0:
        raise ValueError(
            f"this update requires at least agent {minimum_agent_version}, current agent is {AGENT_VERSION}"
        )
    return manifest


def download_release_assets(version: str, temp_dir: Path) -> tuple[dict[str, Any], Path, Path, Path]:
    """Download and verify signed release assets for one version."""
    release = fetch_github_release(version)
    manifest_asset = select_release_asset(release, RELEASE_MANIFEST_PREFIX, ".json")
    signature_asset = select_release_asset(release, RELEASE_MANIFEST_PREFIX, ".sig")
    tarball_asset = select_release_asset(release, RELEASE_TARBALL_PREFIX, ".tar.gz")

    manifest_path = temp_dir / str(manifest_asset["name"])
    signature_path = temp_dir / str(signature_asset["name"])
    tarball_path = temp_dir / str(tarball_asset["name"])
    manifest_path.write_bytes(fetch_url_bytes(str(manifest_asset["browser_download_url"])))
    signature_path.write_bytes(fetch_url_bytes(str(signature_asset["browser_download_url"])))
    manifest = load_and_verify_release_manifest(manifest_path, signature_path, expected_version=version)

    tarball_path.write_bytes(fetch_url_bytes(str(manifest["artifact"]["url"]), timeout=120))
    digest = hashlib.sha256(tarball_path.read_bytes()).hexdigest()
    if digest != manifest["artifact"]["sha256"]:
        raise ValueError("release tarball sha256 does not match the signed manifest")
    return manifest, manifest_path, signature_path, tarball_path


def extract_release_archive(tarball_path: Path, destination: Path) -> None:
    """Safely extract the expected HostWatch release files from a tarball."""
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tarball_path, "r:gz") as archive:
        members = archive.getmembers()
        names = {Path(member.name).name for member in members if member.isfile()}
        if names != RELEASE_REQUIRED_FILES:
            raise ValueError(f"unexpected release archive contents: {sorted(names)}")
        for member in members:
            if not member.isfile():
                raise ValueError("release archive contains unsupported non-file members")
            member_name = Path(member.name).name
            if member_name not in RELEASE_REQUIRED_FILES:
                raise ValueError(f"release archive contains an unexpected file: {member.name}")
            source = archive.extractfile(member)
            if source is None:
                raise ValueError(f"failed to extract {member.name}")
            target = destination / member_name
            with target.open("wb") as handle:
                shutil.copyfileobj(source, handle)
            os.chmod(target, 0o755 if member_name.endswith(".py") or member_name.endswith(".sh") else 0o644)


def backup_current_agent_files(version: str) -> Path:
    """Save a small backup of the currently installed agent files."""
    backup_dir = RELEASE_BACKUP_DIR / f"{iso_timestamp(time.time()).replace(':', '-')}--{version}"
    backup_dir.mkdir(parents=True, exist_ok=True)
    install_dir = get_agent_install_dir()
    for filename in RELEASE_REQUIRED_FILES:
        source = install_dir / filename
        if source.exists():
            shutil.copy2(source, backup_dir / filename)
    return backup_dir


def replace_file_atomically(source: Path, destination: Path, mode: int) -> None:
    """Replace one file atomically while preserving strict permissions."""
    temp_path = destination.with_suffix(destination.suffix + ".tmp")
    shutil.copy2(source, temp_path)
    os.chmod(temp_path, mode)
    os.replace(temp_path, destination)


def install_release_files(extracted_dir: Path) -> None:
    """Install extracted release files into the current agent directory."""
    install_dir = get_agent_install_dir()
    replace_file_atomically(extracted_dir / "hostwatch_agent.py", get_agent_script_path(), 0o755)
    replace_file_atomically(extracted_dir / "install.sh", install_dir / "install.sh", 0o755)
    replace_file_atomically(extracted_dir / "release_signing_public.pem", install_dir / "release_signing_public.pem", 0o644)


def run_agent_update(config: AgentConfig, command_info: dict[str, Any]) -> dict[str, Any]:
    """Download, verify, install, and restart into a signed agent release."""
    requested_version = normalize_version(str(command_info.get("version") or "")) or None
    try:
        release = fetch_github_release(requested_version)
        target_version = normalize_version(release.get("tag_name") or release.get("name") or requested_version)
        if not target_version:
            return {"status": "error", "message": "Could not determine the requested release version\n", "returncode": 1}
        if compare_versions(target_version, AGENT_VERSION) <= 0:
            return {
                "status": "completed",
                "message": f"Agent is already on {AGENT_VERSION}; no update required\n",
                "returncode": 0,
            }
        send_command_event(config, command_info, "chunk", "running", f"Preparing signed agent update {AGENT_VERSION} -> {target_version}\n")
        release_notes = release.get("body")
        if isinstance(release_notes, str) and release_notes.strip():
            send_command_event(config, command_info, "chunk", "running", "Release notes\n-------------\n" + release_notes.strip() + "\n")
        with tempfile.TemporaryDirectory(prefix="hostwatch-agent-update-") as temp_dir_raw:
            temp_dir = Path(temp_dir_raw)
            send_command_event(config, command_info, "chunk", "running", f"Downloading signed release assets for {target_version}\n")
            manifest, _manifest_path, _signature_path, tarball_path = download_release_assets(target_version, temp_dir)
            send_command_event(config, command_info, "chunk", "running", "Verified manifest signature and archive checksum\n")
            extracted_dir = temp_dir / "release"
            extract_release_archive(tarball_path, extracted_dir)
            backup_dir = backup_current_agent_files(target_version)
            send_command_event(config, command_info, "chunk", "running", f"Backup saved to {backup_dir}\n")
            install_release_files(extracted_dir)
        send_command_event(config, command_info, "chunk", "running", f"Installed agent files for {target_version}\n")
        LOGGER.info("Agent updated from %s to %s", AGENT_VERSION, target_version)
        return {
            "status": "completed",
            "message": f"Agent updated to {target_version}. Restart scheduled.\n",
            "returncode": 0,
            "restart_service": True,
            "target_version": target_version,
        }
    except (ValueError, OSError, error.URLError, TimeoutError, json.JSONDecodeError, tarfile.TarError, subprocess.SubprocessError) as exc:
        LOGGER.exception("Signed agent update failed")
        return {"status": "error", "message": f"Agent update failed: {exc}\n", "returncode": 1}


def run_agent(config: AgentConfig) -> None:
    if not config.node_id or not config.node_secret:
        raise SystemExit("Agent is not paired. Run `python3 hostwatch_agent.py pair` first.")
    if not config.heartbeat_webhook_url or not config.metrics_webhook_url or not config.command_poll_webhook_url:
        raise SystemExit("Agent is paired with an old configuration. Pair it again to receive webhook URLs.")

    stop_event = threading.Event()
    SHUTDOWN_EVENT.clear()

    def stop_handler(_signum: int, _frame: Any) -> None:
        SHUTDOWN_EVENT.set()
        stop_event.set()

    signal.signal(signal.SIGINT, stop_handler)
    signal.signal(signal.SIGTERM, stop_handler)

    collector = SystemMetricsCollector(config)
    LOGGER.info("Agent started for node '%s'", config.node_name)
    send_heartbeat(config)
    send_metrics(config, collector.collect())
    poll_commands(config, collector)

    next_heartbeat = time.monotonic() + HEARTBEAT_INTERVAL_SECONDS
    next_metrics = time.monotonic() + METRICS_INTERVAL_SECONDS
    next_command_poll = time.monotonic() + COMMAND_POLL_INTERVAL_SECONDS

    while not stop_event.is_set():
        now = time.monotonic()
        if now >= next_heartbeat:
            send_heartbeat(config)
            next_heartbeat = now + HEARTBEAT_INTERVAL_SECONDS
        if now >= next_metrics:
            send_metrics(config, collector.collect())
            next_metrics = now + METRICS_INTERVAL_SECONDS
        if now >= next_command_poll:
            poll_commands(config, collector)
            next_command_poll = now + COMMAND_POLL_INTERVAL_SECONDS
        stop_event.wait(1)
    LOGGER.info("Agent stopped")


def send_heartbeat(config: AgentConfig) -> None:
    try:
        send_json(
            config.heartbeat_webhook_url,
            {"node_secret": config.node_secret},
        )
    except (error.URLError, TimeoutError, OSError, HostWatchRequestError) as exc:
        report_request_failure("heartbeat", exc)


def send_metrics(config: AgentConfig, snapshot: dict[str, Any]) -> None:
    try:
        send_json(
            config.metrics_webhook_url,
            {
                "node_secret": config.node_secret,
                "metrics": snapshot["metrics"],
                "platform": snapshot["platform"],
                "agent_version": AGENT_VERSION,
            },
        )
    except (error.URLError, TimeoutError, OSError, HostWatchRequestError) as exc:
        report_request_failure("metrics", exc)


def poll_commands(config: AgentConfig, collector: SystemMetricsCollector) -> None:
    try:
        response = send_json(config.command_poll_webhook_url, {"node_secret": config.node_secret})
    except (error.URLError, TimeoutError, OSError, HostWatchRequestError) as exc:
        report_request_failure("command poll", exc)
        return

    command = response.get("command")
    if not command:
        return

    command_type = command.get("type")
    LOGGER.info("Command received: %s", command_type)
    if command_type == "fetch_command_output":
        output = CommandOutputStore().read(command.get("target_run_id"))
        if output is None:
            output = "Output is no longer available on this node.\n"
        send_command_event(
            config,
            {"id": command.get("id"), "run_id": command.get("target_run_id"), "type": "fetch_command_output"},
            "output_snapshot",
            "completed",
            output,
        )
        LOGGER.info("Command completed: fetch_command_output")
        return
    send_command_event(config, command, "started", "running", "Command started\n")
    if command_type == "refresh_apt_check":
        result = run_refresh_apt_check(config, command, collector)
        send_metrics(config, collector.collect())
        send_command_event(
            config,
            command,
            "finished",
            result["status"],
            result["message"],
            returncode=result.get("returncode"),
        )
        LOGGER.info("Command completed: refresh_apt_check")
        return
    if command_type == "refresh_bootloader_check":
        collector._state.set("bootloader", {})
        snapshot = collector.collect()
        send_metrics(config, snapshot)
        send_command_event(
            config,
            command,
            "chunk",
            "running",
            format_bootloader_check_output(snapshot["metrics"].get("bootloader", {})),
        )
        send_command_event(config, command, "finished", "completed", "Bootloader check refreshed\n", returncode=0)
        LOGGER.info("Command completed: refresh_bootloader_check")
        return
    if command_type == "set_eeprom_track":
        result = run_set_eeprom_track(config, command)
        collector._state.set("bootloader", {})
        send_metrics(config, collector.collect())
        send_command_event(
            config,
            command,
            "finished",
            result["status"],
            result["message"],
            returncode=result.get("returncode"),
        )
        LOGGER.info("Command completed: set_eeprom_track status=%s", result["status"])
        return
    if command_type == "set_eeprom_flashrom":
        result = run_set_eeprom_flashrom(config, command)
        collector._state.set("bootloader", {})
        send_metrics(config, collector.collect())
        send_command_event(
            config,
            command,
            "finished",
            result["status"],
            result["message"],
            returncode=result.get("returncode"),
        )
        LOGGER.info("Command completed: set_eeprom_flashrom status=%s", result["status"])
        return
    if command_type == "apt_upgrade":
        result = run_apt_upgrade(config, command)
        if result["status"] == "completed":
            mark_apt_no_updates(collector)
        else:
            collector._apt_cache_checked_at = 0.0
        send_metrics(config, collector.collect())
        send_command_event(
            config,
            command,
            "finished",
            result["status"],
            result["message"],
            returncode=result.get("returncode"),
        )
        LOGGER.info("Command completed: apt_upgrade status=%s", result["status"])
        return
    if command_type == "bootloader_upgrade":
        result = run_bootloader_upgrade(config, command)
        if result["status"] == "completed":
            mark_bootloader_no_pending(collector, reboot_required=True)
        else:
            collector._state.set("bootloader", {})
        send_metrics(config, collector.collect())
        if result["status"] == "completed":
            send_command_event(config, command, "chunk", "running", "Triggering required reboot...\n")
            reboot_result = run_power_command(privileged_command(["systemctl", "reboot", "--no-block"]), "Reboot triggered")
            if reboot_result["status"] != "completed":
                result = {
                    "status": "error",
                    "message": f"Bootloader upgrade completed, but reboot failed:\n{reboot_result['message']}",
                    "returncode": reboot_result.get("returncode"),
                }
            else:
                result = {
                    "status": "completed",
                    "message": "Bootloader upgrade completed. Reboot triggered.\n",
                    "returncode": 0,
                }
        send_command_event(
            config,
            command,
            "finished",
            result["status"],
            result["message"],
            returncode=result.get("returncode"),
        )
        LOGGER.info("Command completed: bootloader_upgrade status=%s", result["status"])
        return
    if command_type == "agent_update":
        result = run_agent_update(config, command)
        if result.get("status") == "completed" and result.get("restart_service"):
            restart_result = schedule_service_restart(DEFAULT_SERVICE_NAME, delay_seconds=1)
            if restart_result["status"] != "completed":
                result = {
                    "status": "error",
                    "message": (
                        f"Agent files were updated to {result.get('target_version') or 'the requested version'}, "
                        f"but restart scheduling failed:\n{restart_result['message']}"
                    ),
                    "returncode": restart_result.get("returncode"),
                }
        send_command_event(
            config,
            command,
            "finished",
            result["status"],
            result["message"],
            returncode=result.get("returncode"),
        )
        LOGGER.info("Command completed: agent_update status=%s", result["status"])
        return
    if command_type == "reboot":
        send_command_event(config, command, "chunk", "running", "Triggering reboot...\n")
        result = run_power_command(privileged_command(["systemctl", "reboot"]), "Reboot triggered")
        send_command_event(config, command, "finished", result["status"], result["message"], returncode=result.get("returncode"))
        LOGGER.info("Command completed: reboot status=%s", result["status"])
        return
    if command_type == "shutdown":
        send_command_event(config, command, "chunk", "running", "Triggering shutdown...\n")
        result = run_power_command(privileged_command(["systemctl", "poweroff"]), "Shutdown triggered")
        send_command_event(config, command, "finished", result["status"], result["message"], returncode=result.get("returncode"))
        LOGGER.info("Command completed: shutdown status=%s", result["status"])
        return

    send_command_event(config, command, "finished", "unsupported", f"Unsupported command: {command_type}\n", returncode=127)
    LOGGER.warning("Unsupported command received: %s", command_type)


def send_command_result(
    config: AgentConfig, command: dict[str, Any], status: str, message: str
) -> None:
    send_command_event(config, command, "finished", status, message)


def send_command_event(
    config: AgentConfig,
    command: dict[str, Any],
    event: str,
    status: str,
    output: str,
    returncode: int | None = None,
) -> None:
    if not config.command_result_webhook_url:
        return
    if event in {"started", "chunk", "finished"} and command.get("type") != "fetch_command_output":
        CommandOutputStore().append(command, output)
    payload: dict[str, Any] = {
        "node_secret": config.node_secret,
        "command_id": command.get("id"),
        "run_id": command.get("run_id"),
        "command_type": command.get("type"),
        "event": event,
        "status": status,
        "output": output,
    }
    if returncode is not None:
        payload["returncode"] = returncode
    try:
        send_json(config.command_result_webhook_url, payload)
    except (error.URLError, TimeoutError, OSError, HostWatchRequestError) as exc:
        report_request_failure("command result", exc)


def run_refresh_apt_check(
    config: AgentConfig,
    command: dict[str, Any],
    collector: SystemMetricsCollector,
) -> dict[str, Any]:
    env = os.environ.copy()
    env["DEBIAN_FRONTEND"] = "noninteractive"
    send_command_event(config, command, "chunk", "running", "Refreshing APT package indexes\n")
    update = run_streamed_command(config, command, privileged_command(["apt-get", "update"]), timeout=600, env=env)
    if update["returncode"] != 0:
        collector._apt_cache_checked_at = 0.0
        collector._state.set("apt", {})
        return {"status": "error", "message": "APT check failed during apt-get update\n", "returncode": update["returncode"]}

    collector._apt_cache_checked_at = 0.0
    collector._state.set("apt", {})
    snapshot = collector.collect()
    apt = snapshot["metrics"].get("updates", {}).get("apt", {})
    send_command_event(
        config,
        command,
        "chunk",
        "running",
        format_apt_upgradeable_output(apt.get("upgradable_count")),
    )
    return {"status": "completed", "message": "APT check refreshed\n", "returncode": 0}


def format_apt_upgradeable_output(upgradable_count: int | None) -> str:
    lines = [
        "",
        "APT upgradeable packages",
        "------------------------",
        f"Count: {upgradable_count if upgradable_count is not None else 'unknown'}",
    ]
    try:
        result = subprocess.run(
            ["apt", "list", "--upgradable"],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (subprocess.SubprocessError, FileNotFoundError) as exc:
        lines.append(f"Failed to list upgradable packages: {exc}")
        return "\n".join(lines) + "\n"

    package_lines = [
        line.strip()
        for line in result.stdout.splitlines()
        if line.strip() and not line.startswith("Listing...")
    ]
    if not package_lines:
        lines.append("No upgradable packages.")
    else:
        lines.extend(package_lines)
    return "\n".join(lines) + "\n"


def run_apt_upgrade(config: AgentConfig, command: dict[str, Any]) -> dict[str, Any]:
    env = os.environ.copy()
    env["DEBIAN_FRONTEND"] = "noninteractive"
    if is_recent_apt_check_available():
        send_command_event(
            config,
            command,
            "chunk",
            "running",
            f"Skipping apt-get update because APT was refreshed less than {APT_UPDATE_FRESH_SECONDS // 60} minutes ago\n",
        )
    else:
        update = run_streamed_command(config, command, privileged_command(["apt-get", "update"]), timeout=600, env=env)
        if update["returncode"] != 0:
            return {"status": "error", "message": "APT update failed\n", "returncode": update["returncode"]}
    upgrade = run_streamed_command(
        config,
        command,
        privileged_command(["apt-get", "upgrade", "-y"]),
        timeout=3600,
        env=env,
    )
    status = "completed" if upgrade["returncode"] == 0 else "error"
    return {"status": status, "message": "APT upgrade completed\n" if status == "completed" else "APT upgrade failed\n", "returncode": upgrade["returncode"]}


def mark_apt_no_updates(collector: SystemMetricsCollector) -> None:
    now = time.time()
    payload = {
        "supported": True,
        "upgradable_count": 0,
        "checked_at": iso_timestamp(now),
    }
    collector._apt_cache_checked_at = now
    collector._apt_cache_count = 0
    collector._state.set("apt", payload)
    LOGGER.info("APT update state cleared after successful upgrade")


def is_recent_apt_check_available() -> bool:
    cached = AgentStateStore().get("apt", {})
    checked_at = cached.get("checked_at") if isinstance(cached, dict) else None
    checked_epoch = parse_iso_timestamp(checked_at) if isinstance(checked_at, str) else 0.0
    return bool(checked_epoch and (time.time() - checked_epoch) < APT_UPDATE_FRESH_SECONDS)


def mark_bootloader_no_pending(collector: SystemMetricsCollector, *, reboot_required: bool = True) -> None:
    now = time.time()
    cached = collector._state.get("bootloader", {})
    payload = dict(cached) if isinstance(cached, dict) else {}
    payload.update(
        {
            "supported": True,
            "status": "reboot_required" if reboot_required else "up_to_date",
            "checked_at": iso_timestamp(now),
            "pending_count": 0,
            "notes": None,
            "pending_releases": [],
        }
    )
    collector._state.set("bootloader", payload)
    LOGGER.info("Bootloader update state cleared after successful upgrade; reboot_required=%s", reboot_required)


def run_set_eeprom_track(config: AgentConfig, command_info: dict[str, Any]) -> dict[str, Any]:
    track = str(command_info.get("track") or "")
    if track not in RPI_EEPROM_TRACKS:
        return {"status": "error", "message": f"Invalid EEPROM release track: {track}\n", "returncode": 2}
    if not is_raspberry_bootloader_supported_model(read_raspberry_model(config)):
        return {
            "status": "unsupported",
            "message": "EEPROM release track is only supported on Raspberry Pi models with an EEPROM bootloader\n",
            "returncode": 1,
        }

    send_command_event(
        config,
        command_info,
        "chunk",
        "running",
        f"Setting {RPI_EEPROM_TRACK_VAR}={track} in {RPI_EEPROM_CONFIG_PATH}\n",
    )
    try:
        write_rpi_eeprom_config_value(
            RPI_EEPROM_TRACK_VAR,
            track,
            remove_aliases=RPI_EEPROM_TRACK_ALIASES,
        )
    except (OSError, PermissionError, ValueError) as exc:
        return {"status": "error", "message": f"Failed to set EEPROM release track: {exc}\n", "returncode": 1}

    status = get_rpi_eeprom_config_status(config)
    message = (
        "EEPROM release track updated\n"
        f"{RPI_EEPROM_TRACK_VAR}={status['track']}\n"
        "Run the bootloader check to refresh pending update information.\n"
    )
    LOGGER.info("EEPROM release track set to %s", status["track"])
    return {"status": "completed", "message": message, "returncode": 0}


def run_set_eeprom_flashrom(config: AgentConfig, command_info: dict[str, Any]) -> dict[str, Any]:
    value = str(command_info.get("use_flashrom") or "")
    if value not in {"0", "1"}:
        return {"status": "error", "message": f"Invalid EEPROM flashrom value: {value}\n", "returncode": 2}
    chip, track = detect_raspberry_chip_and_track(config)
    status = get_rpi_eeprom_config_status(config, chip, track)
    if not status["flashrom_supported"]:
        return {
            "status": "unsupported",
            "message": "EEPROM live flashing is only supported on Raspberry Pi 5 nodes\n",
            "returncode": 1,
        }

    send_command_event(
        config,
        command_info,
        "chunk",
        "running",
        f"Setting {RPI_EEPROM_FLASHROM_VAR}={value} in {RPI_EEPROM_CONFIG_PATH}\n",
    )
    try:
        write_rpi_eeprom_config_value(RPI_EEPROM_FLASHROM_VAR, value)
    except (OSError, PermissionError, ValueError) as exc:
        return {"status": "error", "message": f"Failed to set EEPROM live flashing: {exc}\n", "returncode": 1}

    next_status = get_rpi_eeprom_config_status(config, chip, track)
    label = "enabled" if next_status["flashrom"] == "1" else "disabled"
    message = (
        "EEPROM live flashing updated\n"
        f"{RPI_EEPROM_FLASHROM_VAR}={next_status['flashrom']} ({label})\n"
        "When enabled, Raspberry Pi 5 bootloader upgrades can flash live without an automatic reboot.\n"
    )
    LOGGER.info("EEPROM live flashing set to %s", next_status["flashrom"])
    return {"status": "completed", "message": message, "returncode": 0}


def run_bootloader_upgrade(config: AgentConfig, command_info: dict[str, Any]) -> dict[str, Any]:
    if not is_raspberry_bootloader_supported_model(read_raspberry_model(config)):
        return {
            "status": "unsupported",
            "message": "Bootloader upgrade is only supported on Raspberry Pi models with an EEPROM bootloader\n",
            "returncode": 1,
        }
    executable = shutil.which("rpi-eeprom-update")
    if not executable:
        return {"status": "unsupported", "message": "rpi-eeprom-update not available\n", "returncode": 127}
    sync_result = sync_raspberry_eeprom_firmware(config, command_info)
    if sync_result["returncode"] != 0:
        return {
            "status": "error",
            "message": "Bootloader firmware download/sync failed\n",
            "returncode": sync_result["returncode"],
        }
    result = run_streamed_command(config, command_info, privileged_command([executable, "-a"]), timeout=900)
    status = "completed" if result["returncode"] == 0 else "error"
    return {"status": status, "message": "Bootloader upgrade completed\n" if status == "completed" else "Bootloader upgrade failed\n", "returncode": result["returncode"]}


def sync_raspberry_eeprom_firmware(config: AgentConfig, command_info: dict[str, Any]) -> dict[str, int]:
    chip, track = detect_raspberry_chip_and_track(config)
    if not chip:
        send_command_event(config, command_info, "chunk", "error", "Could not detect Raspberry Pi bootloader chip\n")
        return {"returncode": 1}
    if os.geteuid() != 0:
        send_command_event(
            config,
            command_info,
            "chunk",
            "error",
            "Bootloader firmware sync requires the agent to run as root\n",
        )
        return {"returncode": 1}

    send_command_event(
        config,
        command_info,
        "chunk",
        "running",
        f"Detected Raspberry Pi bootloader chip={chip}, track={track}\n",
    )
    temp_dir = Path(tempfile.mkdtemp(prefix="hostwatch-rpi-eeprom-"))
    tar_path = temp_dir / "rpi-eeprom-master.tar.gz"
    try:
        send_command_event(config, command_info, "chunk", "running", f"Downloading {RPI_EEPROM_TARBALL_URL}\n")
        with request.urlopen(RPI_EEPROM_TARBALL_URL, timeout=60) as response:
            with tar_path.open("wb") as handle:
                shutil.copyfileobj(response, handle)

        send_command_event(config, command_info, "chunk", "running", "Extracting firmware archive\n")
        with tarfile.open(tar_path, "r:gz") as archive:
            archive.extractall(temp_dir)

        root_dir = find_extracted_rpi_eeprom_root(temp_dir)
        firmware_dir = root_dir / f"firmware-{chip}"
        if not firmware_dir.is_dir():
            send_command_event(config, command_info, "chunk", "error", f"Missing firmware directory: {firmware_dir}\n")
            return {"returncode": 1}

        dest_chip_dir = RPI_EEPROM_DEST_ROOT / f"bootloader-{chip}"
        dest_chip_dir.mkdir(parents=True, exist_ok=True)
        for release_track in RPI_EEPROM_TRACKS:
            source_track_dir = firmware_dir / release_track
            if not source_track_dir.is_dir():
                send_command_event(
                    config,
                    command_info,
                    "chunk",
                    "error",
                    f"Missing firmware track in archive: {source_track_dir}\n",
                )
                return {"returncode": 1}
            dest_track_dir = dest_chip_dir / release_track
            send_command_event(
                config,
                command_info,
                "chunk",
                "running",
                f"Syncing {release_track} firmware to {dest_track_dir}\n",
            )
            if dest_track_dir.exists():
                shutil.rmtree(dest_track_dir)
            shutil.copytree(source_track_dir, dest_track_dir)

        notes_source = firmware_dir / "release-notes.md"
        if notes_source.exists():
            shutil.copy2(notes_source, dest_chip_dir / "release-notes.md")
            send_command_event(config, command_info, "chunk", "running", "Updated local release-notes.md\n")
        else:
            send_command_event(config, command_info, "chunk", "running", "Archive has no release-notes.md\n")
    except (OSError, tarfile.TarError, error.URLError, TimeoutError) as exc:
        send_command_event(config, command_info, "chunk", "error", f"Firmware sync failed: {exc}\n")
        return {"returncode": 1}
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

    send_command_event(config, command_info, "chunk", "running", "Firmware files synced successfully\n")
    return {"returncode": 0}


def find_extracted_rpi_eeprom_root(temp_dir: Path) -> Path:
    candidates = [path for path in temp_dir.iterdir() if path.is_dir() and path.name.startswith("rpi-eeprom-")]
    if candidates:
        return candidates[0]
    for path in temp_dir.iterdir():
        if path.is_dir():
            return path
    raise OSError("could not locate extracted rpi-eeprom root directory")


def run_streamed_command(
    config: AgentConfig,
    command_info: dict[str, Any],
    argv: list[str],
    *,
    timeout: int,
    env: dict[str, str] | None = None,
) -> dict[str, int]:
    if argv and argv[0] == "__hostwatch_root_required__":
        send_command_event(
            config,
            command_info,
            "chunk",
            "error",
            f"Cannot run {' '.join(argv[1:])}: root or passwordless sudo required\n",
        )
        return {"returncode": 127}
    send_command_event(config, command_info, "chunk", "running", f"$ {' '.join(argv)}\n")
    try:
        process = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=env,
            bufsize=1,
        )
    except (OSError, FileNotFoundError) as exc:
        send_command_event(config, command_info, "chunk", "error", f"Failed to start command: {exc}\n")
        return {"returncode": 127}

    started = time.monotonic()
    assert process.stdout is not None
    while True:
        line = process.stdout.readline()
        if line:
            send_command_event(config, command_info, "chunk", "running", line)
        if process.poll() is not None:
            remainder = process.stdout.read()
            if remainder:
                send_command_event(config, command_info, "chunk", "running", remainder)
            return {"returncode": process.returncode or 0}
        if time.monotonic() - started > timeout:
            process.kill()
            send_command_event(config, command_info, "chunk", "error", "Command timed out\n")
            return {"returncode": 124}
        time.sleep(0.05)


def privileged_command(argv: list[str]) -> list[str]:
    """Return a command that can perform privileged maintenance actions."""
    if os.geteuid() == 0:
        return argv
    sudo = shutil.which("sudo")
    if sudo:
        return [sudo, "-n", *argv]
    return ["__hostwatch_root_required__", *argv]


def run_power_command(command: list[str], success_message: str) -> dict[str, Any]:
    if command and command[0] == "__hostwatch_root_required__":
        return {
            "status": "error",
            "message": f"{success_message} failed: root or passwordless sudo required\n",
            "returncode": 127,
        }
    try:
        subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        return {"status": "completed", "message": f"{success_message}\n", "returncode": 0}
    except subprocess.CalledProcessError as exc:
        return {
            "status": "error",
            "message": summarize_command_output(exc.stdout, exc.stderr, f"{success_message} failed") + "\n",
            "returncode": exc.returncode,
        }
    except (subprocess.SubprocessError, FileNotFoundError) as exc:
        return {"status": "error", "message": f"{success_message} failed: {exc}\n", "returncode": 127}


def schedule_service_restart(service_name: str, *, delay_seconds: int = 1) -> dict[str, Any]:
    """Schedule a delayed systemd restart so the current process can report completion first."""
    if not re.fullmatch(r"[A-Za-z0-9_.@-]+", service_name):
        return {"status": "error", "message": f"Invalid service name: {service_name}\n", "returncode": 2}
    command = privileged_command(
        [
            "/bin/sh",
            "-c",
            f"sleep {delay_seconds}; exec systemctl restart {service_name}",
        ]
    )
    if command and command[0] == "__hostwatch_root_required__":
        return {
            "status": "error",
            "message": f"Scheduling restart of {service_name} failed: root or passwordless sudo required\n",
            "returncode": 127,
        }
    try:
        subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        return {"status": "completed", "message": f"Restart of {service_name} scheduled\n", "returncode": 0}
    except (OSError, subprocess.SubprocessError, FileNotFoundError) as exc:
        return {"status": "error", "message": f"Scheduling restart of {service_name} failed: {exc}\n", "returncode": 127}


def report_request_failure(kind: str, exc: Exception) -> None:
    """Suppress noisy request errors during intentional shutdown/restart."""
    if SHUTDOWN_EVENT.is_set():
        LOGGER.debug("Ignoring %s failure during shutdown: %s", kind, exc)
        return
    print(f"[hostwatch-agent] {kind} failed: {exc}")


def summarize_command_output(stdout: str | None, stderr: str | None, fallback: str) -> str:
    text = "\n".join(part.strip() for part in (stdout or "", stderr or "") if part.strip()).strip()
    if not text:
        return fallback
    condensed = " | ".join(line.strip() for line in text.splitlines() if line.strip())
    return condensed[:1200]


def create_pairing_code() -> str:
    return f"{int(time.time() * 1000) % 1000000:06d}"


def default_node_name() -> str:
    return os.environ.get("HOSTNAME") or socket.gethostname() or "hostwatch-node"


def stable_node_uid() -> str:
    machine_id_path = Path("/etc/machine-id")
    if machine_id_path.exists():
        try:
            machine_id = machine_id_path.read_text(encoding="utf8").strip()
        except OSError:
            machine_id = ""
        if machine_id:
            return str(uuid.uuid5(uuid.NAMESPACE_DNS, machine_id))
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, default_node_name()))


def read_total_memory() -> int:
    with Path("/proc/meminfo").open("r", encoding="utf8") as handle:
        for line in handle:
            if line.startswith("MemTotal:"):
                return int(line.split()[1]) * 1024
    return 0


def read_cpu_temperature_celsius(config: AgentConfig) -> float | None:
    if config.temperature_source == "none":
        return None
    if config.temperature_source == "path" and config.temperature_path:
        return read_temperature_from_file(Path(config.temperature_path))

    thermal_base = Path("/sys/class/thermal")
    if not thermal_base.exists():
        return None

    preferred_labels = {"cpu", "cpu-thermal", "soc", "package id 0", "tctl", "x86_pkg_temp"}
    candidates: list[float] = []

    for zone in sorted(thermal_base.glob("thermal_zone*")):
        temp_file = zone / "temp"
        if not temp_file.exists():
            continue
        try:
            raw = temp_file.read_text(encoding="utf8").strip()
            value = float(raw)
        except (OSError, ValueError):
            continue
        if value > 1000:
            value = value / 1000.0

        label = ""
        type_file = zone / "type"
        if type_file.exists():
            try:
                label = type_file.read_text(encoding="utf8", errors="ignore").strip().lower()
            except OSError:
                label = ""

        if label in preferred_labels:
            return round(value, 1)
        candidates.append(value)

    if candidates:
        return round(candidates[0], 1)
    return None


def read_temperature_from_file(path: Path) -> float | None:
    if not path.exists():
        return None
    try:
        raw = path.read_text(encoding="utf8", errors="ignore").strip()
        value = float(raw)
    except (OSError, ValueError):
        return None
    if value > 1000:
        value = value / 1000.0
    return round(value, 1)


def read_raspberry_model(config: AgentConfig) -> str | None:
    if config.raspberry_model_override:
        return config.raspberry_model_override
    if config.hardware_profile == "vm":
        return None
    model_path = Path("/proc/device-tree/model")
    if not model_path.exists():
        if config.hardware_profile == "raspberry_pi":
            return "Raspberry Pi"
        return None
    try:
        model = model_path.read_text(encoding="utf8", errors="ignore").replace("\x00", "").strip()
    except OSError:
        return None
    if "raspberry" not in model.lower():
        if config.hardware_profile == "raspberry_pi":
            return "Raspberry Pi"
        return None
    return model


def detect_virtualization(config: AgentConfig) -> str | None:
    if config.hardware_profile == "vm":
        return "virtual machine"
    if config.hardware_profile in {"raspberry_pi", "physical"}:
        return "none"
    detector = shutil.which("systemd-detect-virt")
    if detector:
        result = subprocess.run(
            [detector],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            value = result.stdout.strip()
            return value or "virtualized"
    product_name = Path("/sys/class/dmi/id/product_name")
    if product_name.exists():
        try:
            name = product_name.read_text(encoding="utf8", errors="ignore").strip().lower()
        except OSError:
            name = ""
        if "virtual" in name or "vmware" in name or "kvm" in name or "virtualbox" in name:
            return name
    return "none"


def detect_raspberry_bootloader_status(config: AgentConfig) -> str | None:
    if config.hardware_profile == "vm":
        return None
    command = shutil.which("rpi-eeprom-update")
    if not command:
        return None
    try:
        result = subprocess.run(
            [command],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (subprocess.SubprocessError, FileNotFoundError):
        return None

    output = f"{result.stdout}\n{result.stderr}".lower()
    if "up to date" in output:
        return "up_to_date"
    if "updates pending" in output or "update available" in output:
        return "update_available"
    if result.returncode == 0:
        return "unknown"
    return None


def collect_raspberry_bootloader_status(
    config: AgentConfig, state: AgentStateStore
) -> dict[str, Any]:
    cached = state.get("bootloader", {})
    checked_at = cached.get("checked_at")
    if cached and isinstance(checked_at, str) and not is_bootloader_check_due(checked_at):
        return cached

    now = time.time()
    current_status = detect_raspberry_bootloader_status(config)
    chip, track = detect_raspberry_chip_and_track(config)
    eeprom_config = get_rpi_eeprom_config_status(config, chip, track)
    current_epoch = get_installed_bootloader_epoch()
    notes = ""
    pending_count = 0
    latest_epoch = current_epoch
    latest_version = None

    if chip:
        remote_notes = fetch_rpi_release_notes(chip)
        if remote_notes:
            releases = parse_rpi_release_notes(remote_notes, track)
            pending = [release for release in releases if release["epoch"] > current_epoch]
            pending_count = len(pending)
            if pending:
                latest = pending[0]
                latest_epoch = latest["epoch"]
                latest_version = latest["date"]
                notes = summarize_release_notes(pending)

    if pending_count > 0:
        status = "update_available"
    elif current_status == "up_to_date":
        status = "up_to_date"
    else:
        status = current_status

    payload = {
        "supported": True,
        "status": status,
        "checked_at": iso_timestamp(now),
        "chip": chip,
        "track": track,
        "eeprom_config": eeprom_config,
        "current_epoch": current_epoch,
        "current_version": epoch_to_date(current_epoch),
        "latest_epoch": latest_epoch,
        "version": latest_version,
        "pending_count": pending_count,
        "notes": notes or None,
        "pending_releases": pending if pending_count > 0 else [],
    }
    state.set("bootloader", payload)
    LOGGER.info(
        "Raspberry Pi bootloader check completed: status=%s pending=%s track=%s chip=%s",
        status,
        pending_count,
        track,
        chip,
    )
    return payload


def is_apt_check_due(checked_at: str | None) -> bool:
    scheduled = latest_local_schedule(hour=0, minute=0)
    if scheduled is None:
        return True
    checked_epoch = parse_iso_timestamp(checked_at) if isinstance(checked_at, str) else 0.0
    return checked_epoch < scheduled.timestamp()


def is_bootloader_check_due(checked_at: str | None) -> bool:
    scheduled = latest_local_weekday_schedule(weekday=6, hour=0, minute=0)
    if scheduled is None:
        return True
    checked_epoch = parse_iso_timestamp(checked_at) if isinstance(checked_at, str) else 0.0
    return checked_epoch < scheduled.timestamp()


def latest_local_schedule(*, hour: int, minute: int) -> datetime | None:
    now = datetime.now().astimezone()
    scheduled = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if now < scheduled:
        scheduled = scheduled - timedelta(days=1)
    return scheduled


def latest_local_weekday_schedule(*, weekday: int, hour: int, minute: int) -> datetime | None:
    now = datetime.now().astimezone()
    scheduled = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    days_back = (scheduled.weekday() - weekday) % 7
    scheduled = scheduled - timedelta(days=days_back)
    if now < scheduled:
        scheduled = scheduled - timedelta(days=7)
    return scheduled


def detect_raspberry_chip_and_track(config: AgentConfig) -> tuple[str | None, str]:
    if config.hardware_profile == "vm":
        return None, "latest"

    chip: str | None = None
    track = read_rpi_eeprom_config().get(RPI_EEPROM_TRACK_VAR, "latest")
    command = shutil.which("rpi-eeprom-update")
    if command:
        try:
            result = subprocess.run(
                [command],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (subprocess.SubprocessError, FileNotFoundError):
            result = None
        if result is not None:
            release_line = None
            for line in result.stdout.splitlines():
                stripped = line.strip()
                if stripped.startswith("RELEASE:"):
                    release_line = stripped.split(":", 1)[1].strip()
                    break
            if release_line:
                parts = release_line.split()
                if parts:
                    track = parts[0]
                if "bootloader-" in release_line:
                    try:
                        path = release_line.split("(", 1)[1].split(")", 1)[0]
                        path_parts = path.split("/")
                        for idx, part in enumerate(path_parts):
                            if part.startswith("bootloader-"):
                                chip = part.removeprefix("bootloader-")
                                if idx + 1 < len(path_parts):
                                    track = path_parts[idx + 1]
                                break
                    except (IndexError, ValueError):
                        pass

    model = read_raspberry_model(config)
    if chip is None:
        chip = raspberry_bootloader_chip_from_model(model)

    return chip, track or "latest"


def read_rpi_eeprom_config() -> dict[str, str]:
    """Read active key/value pairs from /etc/default/rpi-eeprom-update."""
    values: dict[str, str] = {}
    try:
        lines = RPI_EEPROM_CONFIG_PATH.read_text(encoding="utf8", errors="ignore").splitlines()
    except OSError:
        return values
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key:
            values[key] = value
    for alias in RPI_EEPROM_TRACK_ALIASES:
        if alias in values and RPI_EEPROM_TRACK_VAR not in values:
            values[RPI_EEPROM_TRACK_VAR] = values[alias]
    return values


def write_rpi_eeprom_config_value(
    key: str,
    value: str,
    *,
    remove_aliases: tuple[str, ...] = (),
) -> None:
    """Set a supported rpi-eeprom default variable without exposing free-form edits."""
    if os.geteuid() != 0:
        raise PermissionError("writing Raspberry Pi EEPROM defaults requires root")
    if key not in {RPI_EEPROM_TRACK_VAR, RPI_EEPROM_FLASHROM_VAR}:
        raise ValueError(f"unsupported EEPROM config key: {key}")

    try:
        original = RPI_EEPROM_CONFIG_PATH.read_text(encoding="utf8", errors="ignore").splitlines()
        stat_result = RPI_EEPROM_CONFIG_PATH.stat()
    except OSError:
        original = []
        stat_result = None

    aliases = set(remove_aliases)
    output: list[str] = []
    replaced = False
    for line in original:
        stripped = line.lstrip()
        uncommented = stripped[1:].lstrip() if stripped.startswith("#") else stripped
        if "=" not in uncommented:
            output.append(line)
            continue
        current_key = uncommented.split("=", 1)[0].strip()
        if current_key in aliases:
            continue
        if current_key == key:
            if not replaced:
                output.append(f"{key}={value}")
                replaced = True
            continue
        output.append(line)
    if not replaced:
        output.append(f"{key}={value}")

    RPI_EEPROM_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=".rpi-eeprom-update.", dir=RPI_EEPROM_CONFIG_PATH.parent)
    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf8") as handle:
            handle.write("\n".join(output).rstrip() + "\n")
        if stat_result is not None:
            os.chmod(temp_path, stat_result.st_mode & 0o777)
            os.chown(temp_path, stat_result.st_uid, stat_result.st_gid)
        else:
            os.chmod(temp_path, 0o644)
        os.replace(temp_path, RPI_EEPROM_CONFIG_PATH)
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise


def get_rpi_eeprom_config_status(config: AgentConfig, chip: str | None = None, track: str | None = None) -> dict[str, Any]:
    """Return current safe EEPROM config settings for metrics and maintenance output."""
    values = read_rpi_eeprom_config()
    model = read_raspberry_model(config)
    detected_chip = chip
    detected_track = track
    if detected_chip is None or detected_track is None:
        detected_chip, detected_track = detect_raspberry_chip_and_track(config)
    flashrom_value = values.get(RPI_EEPROM_FLASHROM_VAR, "0")
    return {
        "track": values.get(RPI_EEPROM_TRACK_VAR, detected_track or "latest"),
        "flashrom": "1" if str(flashrom_value).strip() == "1" else "0",
        "flashrom_supported": detected_chip == "2712" or is_raspberry_pi_5_model(model),
        "path": str(RPI_EEPROM_CONFIG_PATH),
    }


def rpi_eeprom_flashrom_enabled(config: AgentConfig) -> bool:
    status = get_rpi_eeprom_config_status(config)
    return bool(status.get("flashrom_supported") and status.get("flashrom") == "1")


def get_installed_bootloader_epoch() -> int:
    command = shutil.which("rpi-eeprom-update")
    if not command:
        return 0
    try:
        result = subprocess.run(
            [command],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (subprocess.SubprocessError, FileNotFoundError):
        return 0
    for line in result.stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("CURRENT:") and "(" in stripped and ")" in stripped:
            epoch_text = stripped.split("(", 1)[1].split(")", 1)[0].replace(" ", "")
            try:
                return int(epoch_text)
            except ValueError:
                return 0
    return 0


def fetch_rpi_release_notes(chip: str) -> str | None:
    url = RPI_NOTES_URL_TEMPLATE.format(chip=chip)
    try:
        with request.urlopen(url, timeout=15) as response:
            return response.read().decode("utf8", errors="ignore")
    except (error.URLError, TimeoutError, OSError):
        return None


def parse_rpi_release_notes(raw_notes: str, track: str) -> list[dict[str, Any]]:
    releases: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    body_lines: list[str] = []

    def append_current() -> None:
        nonlocal current, body_lines
        if current is None:
            return
        body = "\n".join(line.rstrip() for line in body_lines).strip()
        current["body"] = body
        releases.append(current)
        current = None
        body_lines = []

    for line in raw_notes.splitlines():
        stripped = line.strip()
        if not stripped.startswith("## "):
            if current is not None:
                body_lines.append(line)
            continue
        append_current()
        rest = stripped[3:]
        if ":" not in rest:
            continue
        date_text, message = rest.split(":", 1)
        date_text = date_text.strip()
        message = message.strip()
        tag = None
        if "(latest)" in message:
            tag = "latest"
        elif "(default)" in message:
            tag = "default"
        if tag and tag != track:
            continue
        epoch = parse_release_date(date_text)
        if epoch <= 0:
            continue
        current = {"date": date_text, "message": message, "epoch": epoch, "tag": tag}
    append_current()
    releases.sort(key=lambda item: item["epoch"], reverse=True)
    return releases


def parse_release_date(value: str) -> int:
    try:
        return int(calendar.timegm(time.strptime(f"{value} 00:00:00", "%Y-%m-%d %H:%M:%S")))
    except ValueError:
        return 0


def epoch_to_date(value: int) -> str | None:
    if value <= 0:
        return None
    return time.strftime("%Y-%m-%d", time.gmtime(value))


def summarize_release_notes(releases: list[dict[str, Any]]) -> str:
    items: list[str] = []
    for index, release in enumerate(releases, start=1):
        body = release.get("body")
        if body:
            items.append(f"{index}. {release['date']}: {release['message']}\n{body}")
        else:
            items.append(f"{index}. {release['date']}: {release['message']}")
    return "\n\n".join(items)


def format_bootloader_check_output(bootloader: dict[str, Any]) -> str:
    if not bootloader.get("supported"):
        return "Bootloader check is not supported on this node.\n"

    lines = [
        "Raspberry Pi bootloader check",
        "-----------------------------",
        f"Status: {bootloader.get('status') or 'unknown'}",
        f"Chip: {bootloader.get('chip') or 'unknown'}",
        f"Track: {bootloader.get('track') or 'unknown'}",
        f"Current release: {bootloader.get('current_version') or 'unknown'}",
        f"Latest pending release: {bootloader.get('version') or 'none'}",
        f"Pending releases: {bootloader.get('pending_count', 0)}",
    ]
    eeprom_config = bootloader.get("eeprom_config") or {}
    if eeprom_config:
        lines.extend(
            [
                "",
                "EEPROM config",
                "-------------",
                f"{RPI_EEPROM_TRACK_VAR}: {eeprom_config.get('track') or 'unknown'}",
                f"{RPI_EEPROM_FLASHROM_VAR}: {eeprom_config.get('flashrom') or '0'}",
                f"Live flashing supported: {'yes' if eeprom_config.get('flashrom_supported') else 'no'}",
            ]
        )
    lines.append("")
    pending = bootloader.get("pending_releases") or []
    if not pending:
        lines.append("No pending bootloader releases.")
        return "\n".join(lines) + "\n"

    lines.append("Pending changelog")
    lines.append("-----------------")
    for release in pending:
        lines.append(f"## {release.get('date')} - {release.get('message')}")
        body = release.get("body")
        if body:
            lines.append(body)
        lines.append("")
    return "\n".join(lines)


def configure_agent(config: AgentConfig) -> None:
    print(f"Config file: {DEFAULT_CONFIG_PATH}")
    node_name = prompt_text("Node name", config.node_name)
    ha_url_mode = prompt_choice(
        "Home Assistant URL mode for pairing/webhooks",
        config.ha_url_mode,
        ("local", "external"),
    )
    hardware_profile = prompt_choice(
        "Hardware profile",
        config.hardware_profile,
        ("auto", "physical", "vm", "raspberry_pi"),
    )
    raspberry_override = prompt_text(
        "Raspberry Pi model override (blank for auto/none)",
        config.raspberry_model_override or "",
    ).strip() or None
    temperature_source = prompt_choice(
        "Temperature source",
        config.temperature_source,
        ("auto", "none", "path"),
    )
    temperature_path = config.temperature_path
    if temperature_source == "path":
        temperature_path = prompt_text(
            "Temperature file path",
            config.temperature_path or "/sys/class/thermal/thermal_zone0/temp",
        ).strip() or None
    else:
        temperature_path = None
    primary_interface = prompt_text(
        "Primary network interface for discovery/IP display (auto or interface name)",
        config.primary_interface,
    ).strip() or "auto"
    extra_interfaces = prompt_csv(
        "Additional network interfaces for IP display (comma separated, blank for none)",
        config.extra_interfaces or [],
    )

    next_config = AgentConfig(
        node_name=node_name,
        node_uid=config.node_uid,
        ha_url=config.ha_url,
        ha_url_mode=ha_url_mode,
        heartbeat_webhook_url=config.heartbeat_webhook_url,
        metrics_webhook_url=config.metrics_webhook_url,
        command_result_webhook_url=config.command_result_webhook_url,
        command_poll_webhook_url=config.command_poll_webhook_url,
        node_id=config.node_id,
        node_secret=config.node_secret,
        allowed_ha_name=config.allowed_ha_name,
        hardware_profile=hardware_profile,
        raspberry_model_override=raspberry_override,
        temperature_source=temperature_source,
        temperature_path=temperature_path,
        primary_interface=primary_interface,
        extra_interfaces=extra_interfaces,
    )
    save_config(next_config)
    LOGGER.info("Configuration saved")
    print("Configuration saved.")


def prompt_text(label: str, default: str) -> str:
    answer = input(f"{label} [{default}]: ").strip()
    return answer or default


def prompt_choice(label: str, current: str, choices: tuple[str, ...]) -> str:
    joined = "/".join(choices)
    while True:
        answer = input(f"{label} ({joined}) [{current}]: ").strip().lower()
        if not answer:
            return current
        if answer in choices:
            return answer
        print(f"Invalid choice: {answer}")


def prompt_csv(label: str, current: list[str]) -> list[str]:
    default = ",".join(current)
    answer = input(f"{label} [{default}]: ").strip()
    raw = answer if answer else default
    return [item.strip() for item in raw.split(",") if item.strip()]


def iso_timestamp(timestamp: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(timestamp))


def parse_iso_timestamp(value: str) -> float:
    try:
        return calendar.timegm(time.strptime(value, "%Y-%m-%dT%H:%M:%SZ"))
    except ValueError:
        return 0.0


def collect_configured_ip_addresses(config: AgentConfig) -> dict[str, Any]:
    primary_interface = config.primary_interface or "auto"
    primary_ip = detect_local_ip(primary_interface)
    primary_label = "Primary" if primary_interface == "auto" else primary_interface
    addresses: list[dict[str, str]] = []
    seen_addresses: set[str] = set()
    if primary_ip != "127.0.0.1":
        addresses.append({"interface": primary_label, "address": primary_ip})
        seen_addresses.add(primary_ip)

    for interface in config.extra_interfaces or []:
        address = get_interface_ipv4(interface)
        if not address or address in seen_addresses:
            continue
        item = {"interface": interface, "address": address}
        addresses.append(item)
        seen_addresses.add(address)

    return {"primary": primary_ip, "addresses": addresses}


def detect_local_ip(interface: str = "auto") -> str:
    if interface and interface != "auto":
        address = get_interface_ipv4(interface)
        if address:
            return address
        LOGGER.warning("Configured interface '%s' has no IPv4 address; falling back to auto detection", interface)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            sock.connect(("239.255.255.250", 1900))
            return sock.getsockname()[0]
        except OSError:
            return "127.0.0.1"


def get_interface_ipv4(interface: str) -> str | None:
    if not interface:
        return None
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            packed = struct.pack("256s", interface[:15].encode("utf8"))
            result = fcntl.ioctl(sock.fileno(), 0x8915, packed)
        except OSError:
            return None
    return socket.inet_ntoa(result[20:24])


def device_description_xml(server: PairingServer) -> str:
    return description_xml_for(
        node_name=server.config.node_name,
        device_uuid=server.ssdp_uuid,
        description_port=server.description_port,
        primary_interface=server.config.primary_interface,
    )


def description_xml_for(
    *,
    node_name: str,
    device_uuid: str,
    description_port: int,
    primary_interface: str = "auto",
) -> str:
    return f"""<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <specVersion>
    <major>1</major>
    <minor>0</minor>
  </specVersion>
  <device>
    <deviceType>urn:hostwatch:device:HostWatchNode:1</deviceType>
    <friendlyName>{node_name}</friendlyName>
    <manufacturer>HostWatch</manufacturer>
    <modelName>HostWatch Node</modelName>
    <modelNumber>{AGENT_VERSION}</modelNumber>
    <serialNumber>{device_uuid}</serialNumber>
    <UDN>uuid:{device_uuid}</UDN>
    <presentationURL>https://{detect_local_ip(primary_interface)}:{description_port - 1}/api/hostwatch/pairing/info</presentationURL>
  </device>
</root>
"""


def platform_python_version() -> str:
    return ".".join(str(part) for part in os.sys.version_info[:3])


def main() -> None:
    parser = argparse.ArgumentParser(description="HostWatch agent")
    parser.add_argument("mode", nargs="?", default="run", choices=["run", "pair", "config"])
    parser.add_argument("--port", type=int, default=DEFAULT_PAIRING_PORT)
    args = parser.parse_args()

    config = load_config()
    if args.mode == "config":
        configure_agent(config)
        return
    if args.mode == "pair":
        run_pair(config, args.port)
        return
    run_agent(config)


if __name__ == "__main__":
    main()
