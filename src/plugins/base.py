from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class PluginField:
    name: str
    label: str
    type: str = "text"
    placeholder: str = ""
    autocomplete: str = ""
    help: str = ""
    default: str = ""
    preserve_on_blank: bool = False


DNS_ZONE_DOMAIN_FIELD = PluginField(
    "dns_zone",
    "DNS zone (domain)",
    placeholder="example.com",
    help="DNS zone managed at the provider (e.g. example.com). Required for record operations.",
)


@dataclass(frozen=True)
class DnsProviderPlugin:
    key: str
    label: str
    heading: str
    help_text: str
    fields: list[PluginField]
    create_client: Callable[[dict[str, str | None]], Any]


def plugin_to_template_dict(plugin: DnsProviderPlugin) -> dict[str, Any]:
    return {
        "key": plugin.key,
        "label": plugin.label,
        "heading": plugin.heading,
        "help_text": plugin.help_text,
        "fields": [
            {
                "name": field.name,
                "label": field.label,
                "type": field.type,
                "placeholder": field.placeholder,
                "autocomplete": field.autocomplete,
                "help": field.help,
                "default": field.default,
                "preserve_on_blank": field.preserve_on_blank,
            }
            for field in plugin.fields
        ],
    }
