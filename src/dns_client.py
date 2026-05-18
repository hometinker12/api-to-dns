from typing import Any, Dict, Optional

from .plugins import discover_plugins, get_plugin, provider_options_for_template


def create_dns_client(settings: Dict[str, Optional[str]]) -> Any:
    provider = (settings.get("dns_provider_type") or "azure").strip().lower()
    plugin = get_plugin(provider)
    return plugin.create_client(settings)


def dns_provider_display_name(provider_key: str) -> str:
    plugins = discover_plugins()
    plugin = plugins.get((provider_key or "").strip().lower())
    return plugin.label if plugin else (provider_key or "").strip()


__all__ = [
    "create_dns_client",
    "discover_plugins",
    "dns_provider_display_name",
    "provider_options_for_template",
]
