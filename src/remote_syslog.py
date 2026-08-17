"""Bounded, best-effort remote syslog forwarding for stored audit/activity events.

Forwards RFC 5424 messages with JSON payloads over UDP, TCP (RFC 6587
octet-count framing), or TLS (RFC 5425). Delivery is asynchronous via a
bounded in-process queue so request handlers never wait on the network.

Plaintext UDP/TCP require an explicit administrator opt-in because audit
payloads can contain sensitive operational metadata.
"""

from __future__ import annotations

import json
import logging
import queue
import re
import socket
import ssl
import threading
import time
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Any

from .log_constants import (
    LOG_LEVEL_ERROR,
    LOG_LEVEL_INFORMATIONAL,
    LOG_LEVEL_ORDER,
    LOG_LEVEL_VALUES,
    LOG_LEVEL_VERBOSE,
    LOG_LEVEL_WARNING,
)
from .models import (
    ActivityLog,
)

LOGGER = logging.getLogger("api_to_dns")

APP_NAME = "api-to-dns"
DEFAULT_PORT = 514
DEFAULT_TLS_PORT = 6514
DEFAULT_PROTOCOL = "tls"
DEFAULT_FACILITY = "local0"
DEFAULT_MINIMUM_LEVEL = LOG_LEVEL_INFORMATIONAL
DEFAULT_TIMEOUT = 5.0
DEFAULT_QUEUE_SIZE = 1000
MAX_TIMEOUT_SECONDS = 30.0
MAX_QUEUE_SIZE = 5000
DEFAULT_DRAIN_TIMEOUT = 2.0
WARN_INTERVAL_SECONDS = 30.0

SYSLOG_PROTOCOLS = ("tls", "udp", "tcp")
PLAINTEXT_PROTOCOLS = frozenset({"udp", "tcp"})

SYSLOG_FACILITY: dict[str, int] = {
    "kern": 0,
    "user": 1,
    "mail": 2,
    "daemon": 3,
    "auth": 4,
    "syslog": 5,
    "lpr": 6,
    "news": 7,
    "uucp": 8,
    "cron": 9,
    "authpriv": 10,
    "ftp": 11,
    "local0": 16,
    "local1": 17,
    "local2": 18,
    "local3": 19,
    "local4": 20,
    "local5": 21,
    "local6": 22,
    "local7": 23,
}

SYSLOG_SEVERITY: dict[str, int] = {
    LOG_LEVEL_VERBOSE: 7,  # debug
    LOG_LEVEL_INFORMATIONAL: 6,  # info
    LOG_LEVEL_WARNING: 4,  # warning
    LOG_LEVEL_ERROR: 3,  # error
}

_NILVALUE = "-"
_SD_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


@dataclass(frozen=True)
class SyslogConfig:
    """Immutable remote syslog destination configuration."""

    enabled: bool = False
    host: str = ""
    port: int = DEFAULT_TLS_PORT
    protocol: str = DEFAULT_PROTOCOL
    facility: str = DEFAULT_FACILITY
    minimum_level: str = DEFAULT_MINIMUM_LEVEL
    timeout: float = DEFAULT_TIMEOUT
    queue_size: int = DEFAULT_QUEUE_SIZE
    allow_insecure_plaintext: bool = False
    hostname: str = _NILVALUE
    generation: int = 0

    def with_generation(self, generation: int) -> SyslogConfig:
        return replace(self, generation=generation)

    @property
    def uses_plaintext(self) -> bool:
        return self.protocol in PLAINTEXT_PROTOCOLS


@dataclass(frozen=True)
class ActivityLogSnapshot:
    """Serializable snapshot of an ActivityLog row for the forwarder queue."""

    timestamp: datetime | None
    level: str
    category: str | None
    event_type: str
    status: str | None = None
    actor_type: str | None = None
    actor_id: str | None = None
    actor_label: str | None = None
    zone_name: str | None = None
    record_name: str | None = None
    message: str | None = None
    details: Any = None
    request_method: str | None = None
    request_path: str | None = None
    request_status_code: int | None = None
    request_ip: str | None = None
    id: int | None = None

    @classmethod
    def from_row(cls, row: ActivityLog) -> ActivityLogSnapshot:
        details: Any = None
        if row.details_json:
            try:
                details = json.loads(row.details_json)
            except (TypeError, ValueError):
                details = row.details_json
        return cls(
            id=row.id,
            timestamp=row.timestamp,
            level=row.level or LOG_LEVEL_INFORMATIONAL,
            category=row.category,
            event_type=row.event_type or "",
            status=row.status,
            actor_type=row.actor_type,
            actor_id=row.actor_id,
            actor_label=row.actor_label,
            zone_name=row.zone_name,
            record_name=row.record_name,
            message=row.message,
            details=details,
            request_method=row.request_method,
            request_path=row.request_path,
            request_status_code=row.request_status_code,
            request_ip=row.request_ip,
        )

    @property
    def timestamp_iso(self) -> str:
        if self.timestamp is None:
            return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        ts = self.timestamp
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)
        else:
            ts = ts.astimezone(UTC)
        return ts.isoformat(timespec="milliseconds").replace("+00:00", "Z")

    def as_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "timestamp": self.timestamp_iso,
            "level": self.level,
            "event_type": self.event_type,
        }
        optional = {
            "id": self.id,
            "category": self.category,
            "status": self.status,
            "actor_type": self.actor_type,
            "actor_id": self.actor_id,
            "actor_label": self.actor_label,
            "zone_name": self.zone_name,
            "record_name": self.record_name,
            "message": self.message,
            "details": self.details,
            "request_method": self.request_method,
            "request_path": self.request_path,
            "request_status_code": self.request_status_code,
            "request_ip": self.request_ip,
        }
        for key, value in optional.items():
            if value is not None:
                payload[key] = value
        return payload


def sanitize_hostname(value: str | None) -> str:
    cleaned = (value or "").strip()
    if not cleaned:
        return _NILVALUE
    cleaned = cleaned.replace(" ", "_")
    cleaned = re.sub(r"[\r\n\t]+", "", cleaned)
    return cleaned[:255] or _NILVALUE


def sanitize_msg_id(value: str | None) -> str:
    cleaned = (value or "").strip()
    if not cleaned:
        return _NILVALUE
    cleaned = _SD_NAME_RE.sub("_", cleaned)
    return cleaned[:48] or _NILVALUE


def meets_minimum_level(event_level: str, minimum_level: str) -> bool:
    event_rank = LOG_LEVEL_ORDER.get((event_level or "").strip().upper(), LOG_LEVEL_ORDER[LOG_LEVEL_INFORMATIONAL])
    threshold = LOG_LEVEL_ORDER.get((minimum_level or "").strip().upper(), LOG_LEVEL_ORDER[LOG_LEVEL_INFORMATIONAL])
    return event_rank >= threshold


def encode_rfc5424(event: ActivityLogSnapshot, config: SyslogConfig) -> bytes:
    """Encode an audit snapshot as RFC 5424 with a JSON MSG payload."""
    severity = SYSLOG_SEVERITY.get((event.level or "").upper(), SYSLOG_SEVERITY[LOG_LEVEL_INFORMATIONAL])
    facility = SYSLOG_FACILITY.get((config.facility or DEFAULT_FACILITY).lower(), SYSLOG_FACILITY[DEFAULT_FACILITY])
    priority = facility * 8 + severity
    payload = json.dumps(event.as_dict(), ensure_ascii=True, separators=(",", ":"), default=str)
    header = (
        f"<{priority}>1 {event.timestamp_iso} {sanitize_hostname(config.hostname)} "
        f"{APP_NAME} - {sanitize_msg_id(event.event_type)} - "
    )
    # Header is ASCII-safe by construction; payload is ensure_ascii JSON.
    return (header + payload).encode("ascii", errors="replace")


def frame_tcp(message: bytes) -> bytes:
    """RFC 6587 octet-counting framing for TCP syslog."""
    return str(len(message)).encode("ascii") + b" " + message


def validate_syslog_config(
    *,
    enabled: bool,
    host: str,
    port: int | str,
    protocol: str,
    facility: str,
    minimum_level: str,
    timeout: float | str,
    queue_size: int | str,
    allow_insecure_plaintext: bool = False,
    hostname: str | None = None,
) -> SyslogConfig:
    """Validate form/settings values and return an immutable config."""
    cleaned_protocol = (protocol or DEFAULT_PROTOCOL).strip().lower()
    if cleaned_protocol not in SYSLOG_PROTOCOLS:
        raise ValueError("Protocol must be tls, udp, or tcp.")

    cleaned_facility = (facility or DEFAULT_FACILITY).strip().lower()
    if cleaned_facility not in SYSLOG_FACILITY:
        raise ValueError(f"Unsupported syslog facility: {facility}")

    cleaned_level = (minimum_level or DEFAULT_MINIMUM_LEVEL).strip().upper()
    if cleaned_level not in LOG_LEVEL_VALUES:
        raise ValueError(f"Unsupported minimum level: {minimum_level}")

    try:
        cleaned_port = int(port)
    except (TypeError, ValueError) as exc:
        raise ValueError("Port must be an integer between 1 and 65535.") from exc
    if cleaned_port < 1 or cleaned_port > 65535:
        raise ValueError("Port must be an integer between 1 and 65535.")

    try:
        cleaned_timeout = float(timeout)
    except (TypeError, ValueError) as exc:
        raise ValueError("Timeout must be a positive number of seconds.") from exc
    if cleaned_timeout <= 0 or cleaned_timeout > MAX_TIMEOUT_SECONDS:
        raise ValueError(f"Timeout must be between 0 (exclusive) and {int(MAX_TIMEOUT_SECONDS)} seconds.")

    try:
        cleaned_queue = int(queue_size)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Queue size must be an integer between 1 and {MAX_QUEUE_SIZE}.") from exc
    if cleaned_queue < 1 or cleaned_queue > MAX_QUEUE_SIZE:
        raise ValueError(f"Queue size must be an integer between 1 and {MAX_QUEUE_SIZE}.")

    cleaned_host = (host or "").strip()
    if enabled and not cleaned_host:
        raise ValueError("Host is required when remote syslog is enabled.")

    allow_plaintext = bool(allow_insecure_plaintext)
    if enabled and cleaned_protocol in PLAINTEXT_PROTOCOLS and not allow_plaintext:
        raise ValueError(
            "Plaintext UDP/TCP syslog exposes audit metadata on the network. "
            "Prefer TLS, or enable 'Allow insecure plaintext syslog' only if you accept the risk."
        )

    return SyslogConfig(
        enabled=bool(enabled),
        host=cleaned_host,
        port=cleaned_port,
        protocol=cleaned_protocol,
        facility=cleaned_facility,
        minimum_level=cleaned_level,
        timeout=cleaned_timeout,
        queue_size=cleaned_queue,
        allow_insecure_plaintext=allow_plaintext,
        hostname=sanitize_hostname(hostname),
    )


class RemoteSyslogForwarder:
    """In-process syslog queue and worker thread. Not shared across uvicorn workers."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._config = SyslogConfig()
        self._queue: queue.Queue[tuple[int, ActivityLogSnapshot] | None] = queue.Queue(maxsize=self._config.queue_size)
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._udp_sock: socket.socket | None = None
        self._stream_sock: socket.socket | None = None
        self._stream_addr: tuple[str, int, str] | None = None
        self._last_warn_at = 0.0
        self._generation = 0

    def current_config(self) -> SyslogConfig:
        with self._lock:
            return self._config

    def configure(self, config: SyslogConfig) -> None:
        """Apply a new configuration and ensure the worker thread is running when enabled."""
        with self._lock:
            self._generation += 1
            applied = config.with_generation(self._generation)
            old_queue_size = self._config.queue_size
            self._config = applied
            if applied.queue_size != old_queue_size or self._queue.maxsize != applied.queue_size:
                # Preserve pending events when resizing; drop oldest if the new bound is smaller.
                pending: list[tuple[int, ActivityLogSnapshot]] = []
                while True:
                    try:
                        item = self._queue.get_nowait()
                    except queue.Empty:
                        break
                    if item is not None:
                        pending.append(item)
                self._queue = queue.Queue(maxsize=max(1, applied.queue_size))
                for item in pending[-applied.queue_size :]:
                    try:
                        self._queue.put_nowait(item)
                    except queue.Full:
                        break
            self._close_sockets_unlocked()
            if applied.enabled:
                self._ensure_worker_unlocked()
            else:
                # Leave the worker alive briefly so queued items for older generations
                # can be discarded cleanly; sockets are already closed.
                self._ensure_worker_unlocked()

    def start(self, config: SyslogConfig | None = None) -> None:
        if config is not None:
            self.configure(config)
        else:
            with self._lock:
                self._ensure_worker_unlocked()

    def stop(self, *, drain_timeout: float = DEFAULT_DRAIN_TIMEOUT) -> None:
        with self._lock:
            thread = self._thread
            if thread is None:
                self._close_sockets_unlocked()
                return
            self._stop.set()
            try:
                self._queue.put_nowait(None)
            except queue.Full:
                pass
        thread.join(timeout=max(0.0, drain_timeout))
        with self._lock:
            if thread.is_alive():
                LOGGER.warning("remote syslog worker did not stop within %.1fs", drain_timeout)
            else:
                self._thread = None
            self._close_sockets_unlocked()
            self._stop.clear()

    def enqueue(self, event: ActivityLogSnapshot) -> None:
        config = self.current_config()
        if not config.enabled or not meets_minimum_level(event.level, config.minimum_level):
            return
        try:
            self._queue.put_nowait((config.generation, event))
        except queue.Full:
            self._warn_rate_limited("remote syslog queue is full; audit event dropped")

    def _ensure_worker_unlocked(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="remote-syslog-forwarder", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                item = self._queue.get(timeout=0.25)
            except queue.Empty:
                continue
            if item is None:
                if self._stop.is_set():
                    break
                continue
            generation, event = item
            config = self.current_config()
            if generation != config.generation or not config.enabled:
                continue
            try:
                message = encode_rfc5424(event, config)
                self._send(message, config)
            except Exception:
                self._warn_rate_limited(
                    "remote syslog delivery failed for %s",
                    event.event_type,
                    exc_info=True,
                )

    def _send(self, message: bytes, config: SyslogConfig) -> None:
        if config.protocol in {"tcp", "tls"}:
            self._send_stream(message, config)
        else:
            self._send_udp(message, config)

    def _send_udp(self, message: bytes, config: SyslogConfig) -> None:
        with self._lock:
            sock = self._udp_sock
            if sock is None:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(config.timeout)
                self._udp_sock = sock
        sock.sendto(message, (config.host, config.port))

    def _open_stream(self, config: SyslogConfig) -> socket.socket:
        """Open a TCP or TLS stream. Must not be called while holding ``_lock``."""
        addr = (config.host, config.port)
        raw = socket.create_connection(addr, timeout=config.timeout)
        raw.settimeout(config.timeout)
        if config.protocol != "tls":
            return raw
        context = ssl.create_default_context()
        return context.wrap_socket(raw, server_hostname=config.host)

    def _install_stream(self, sock: socket.socket, config: SyslogConfig) -> socket.socket | None:
        """Install ``sock`` if config generation still matches; otherwise close it."""
        target = (config.host, config.port, config.protocol)
        with self._lock:
            current = self._config
            if (
                current.generation != config.generation
                or not current.enabled
                or (current.host, current.port, current.protocol) != target
            ):
                try:
                    sock.close()
                except OSError:
                    pass
                return None
            self._close_stream_unlocked()
            self._stream_sock = sock
            self._stream_addr = target
            return sock

    def _send_stream(self, message: bytes, config: SyslogConfig) -> None:
        framed = frame_tcp(message)
        target = (config.host, config.port, config.protocol)
        with self._lock:
            sock = self._stream_sock if self._stream_addr == target else None
            generation = config.generation
        if sock is None:
            opened = self._open_stream(config)
            sock = self._install_stream(opened, config)
            if sock is None:
                return
        try:
            sock.sendall(framed)
            return
        except OSError:
            with self._lock:
                if self._stream_sock is sock:
                    self._close_stream_unlocked()
                current = self._config
                if current.generation != generation or not current.enabled:
                    return
                if (current.host, current.port, current.protocol) != target:
                    return
                reconnect_config = current
        opened = self._open_stream(reconnect_config)
        sock = self._install_stream(opened, reconnect_config)
        if sock is None:
            return
        sock.sendall(framed)

    def _close_sockets_unlocked(self) -> None:
        self._close_udp_unlocked()
        self._close_stream_unlocked()

    def _close_udp_unlocked(self) -> None:
        if self._udp_sock is not None:
            try:
                self._udp_sock.close()
            except OSError:
                pass
            self._udp_sock = None

    def _close_stream_unlocked(self) -> None:
        if self._stream_sock is not None:
            try:
                self._stream_sock.close()
            except OSError:
                pass
            self._stream_sock = None
            self._stream_addr = None

    def _warn_rate_limited(self, message: str, *args: Any, exc_info: bool = False) -> None:
        now = time.monotonic()
        if now - self._last_warn_at < WARN_INTERVAL_SECONDS:
            return
        self._last_warn_at = now
        LOGGER.warning(message, *args, exc_info=exc_info)


REMOTE_SYSLOG = RemoteSyslogForwarder()

__all__ = [
    "APP_NAME",
    "ActivityLogSnapshot",
    "DEFAULT_FACILITY",
    "DEFAULT_MINIMUM_LEVEL",
    "DEFAULT_PORT",
    "DEFAULT_PROTOCOL",
    "DEFAULT_QUEUE_SIZE",
    "DEFAULT_TIMEOUT",
    "DEFAULT_TLS_PORT",
    "MAX_QUEUE_SIZE",
    "MAX_TIMEOUT_SECONDS",
    "PLAINTEXT_PROTOCOLS",
    "REMOTE_SYSLOG",
    "RemoteSyslogForwarder",
    "SYSLOG_FACILITY",
    "SYSLOG_PROTOCOLS",
    "SYSLOG_SEVERITY",
    "SyslogConfig",
    "encode_rfc5424",
    "frame_tcp",
    "meets_minimum_level",
    "sanitize_hostname",
    "sanitize_msg_id",
    "validate_syslog_config",
]
