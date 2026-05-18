from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional


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


@dataclass(frozen=True)
class DnsProviderPlugin:
    key: str
    label: str
    heading: str
    help_text: str
    fields: List[PluginField]
    create_client: Callable[[Dict[str, Optional[str]]], Any]


def plugin_to_template_dict(plugin: DnsProviderPlugin) -> Dict[str, Any]:
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
