"""Hostname, IP, Docker detection, and the configured app DNS name."""

from __future__ import annotations

import os
import socket

from .hostnames import validate_dns_hostname
from .settings_store import get_typed_setting_by_key, set_typed_setting_by_key

SETTING_APP_DNS_NAME = "app_dns_name"
DEFAULT_APP_DNS_NAME_DOCKER = "apitodns.local"
DOCKER_RUNTIME_LABEL = "Detected Docker container runtime."

_host_system_dns_name_cache: str | None = None


def is_running_in_docker() -> bool:
    if os.path.exists("/.dockerenv"):
        return True
    try:
        with open("/proc/1/cgroup", encoding="utf-8") as handle:
            return any("docker" in line or "kubepods" in line or "containerd" in line for line in handle)
    except OSError:
        return False


def _host_system_dns_name() -> str:
    global _host_system_dns_name_cache
    if _host_system_dns_name_cache is not None:
        return _host_system_dns_name_cache
    try:
        hostname = socket.gethostname()
        try:
            resolved = socket.getfqdn(hostname) or hostname
        except OSError:
            resolved = hostname
    except OSError:
        resolved = "unknown"
    _host_system_dns_name_cache = resolved
    return resolved


def detect_system_dns_name() -> str:
    if is_running_in_docker():
        return "Docker Container"
    return _host_system_dns_name()


def default_app_dns_name() -> str:
    if is_running_in_docker():
        return DEFAULT_APP_DNS_NAME_DOCKER
    return _host_system_dns_name()


def get_app_dns_name(db) -> str:
    try:
        value = get_typed_setting_by_key(db, SETTING_APP_DNS_NAME)
    except ValueError:
        value = ""
    stored = "" if value is None else str(value)
    stored = stored.strip()
    if stored:
        return stored
    return default_app_dns_name()


def set_app_dns_name(db, name: str) -> str:
    cleaned = validate_dns_hostname(name)
    set_typed_setting_by_key(db, SETTING_APP_DNS_NAME, cleaned)
    return cleaned


def detect_system_ip_address() -> str:
    if is_running_in_docker():
        return DOCKER_RUNTIME_LABEL
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(0.5)
        sock.connect(("203.0.113.1", 1))
        return sock.getsockname()[0]
    except OSError:
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return "unknown"
    finally:
        sock.close()


def system_identity(db) -> dict[str, str]:
    return {"system_dns_name": get_app_dns_name(db), "system_ip_address": detect_system_ip_address()}
