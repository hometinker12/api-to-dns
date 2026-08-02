import importlib
import pkgutil
from functools import lru_cache

from .base import DnsProviderPlugin, plugin_to_template_dict


@lru_cache(maxsize=1)
def discover_plugins() -> dict[str, DnsProviderPlugin]:
    plugins: dict[str, DnsProviderPlugin] = {}
    for module_info in pkgutil.iter_modules(__path__):
        if module_info.name in {"base", "utils"} or module_info.name.startswith("_"):
            continue
        module = importlib.import_module(f"{__name__}.{module_info.name}")
        plugin = getattr(module, "PLUGIN", None)
        if plugin is None:
            continue
        if not isinstance(plugin, DnsProviderPlugin):
            raise TypeError(f"{module.__name__}.PLUGIN must be a DnsProviderPlugin instance.")
        if plugin.key in plugins:
            raise ValueError(f"Duplicate DNS provider plugin key: {plugin.key}")
        plugins[plugin.key] = plugin
    return dict(sorted(plugins.items()))


def get_plugin(key: str) -> DnsProviderPlugin:
    plugins = discover_plugins()
    try:
        return plugins[key]
    except KeyError as exc:
        available = ", ".join(plugins) or "none"
        raise ValueError(f"Unknown DNS provider type: {key}. Available providers: {available}.") from exc


def provider_options_for_template() -> list[dict]:
    return [plugin_to_template_dict(plugin) for plugin in discover_plugins().values()]
