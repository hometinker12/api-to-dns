from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

from ..models import DnsRecordInfo, DnsRecordListResult, DnsRecordRequest


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


class DnsProviderClient(Protocol):
    """Structural contract for clients returned by ``DnsProviderPlugin.create_client``.

    Implementations are duck-typed; they do not need to inherit this Protocol.
    """

    def get_record(
        self,
        *,
        record_name: str,
        record_type: str | None = None,
        dns_server: str | None = None,
        dns_zone: str | None = None,
    ) -> list[DnsRecordInfo]: ...

    def list_records(
        self,
        *,
        name_pattern: str | None = None,
        record_type: str | None = None,
        limit: int = 100,
        dns_server: str | None = None,
        dns_zone: str | None = None,
    ) -> DnsRecordListResult: ...

    def create_or_update_record(
        self,
        payload: DnsRecordRequest,
        dns_server: str | None = None,
        dns_zone: str | None = None,
    ) -> bool: ...


@dataclass(frozen=True)
class DnsProviderPlugin:
    """Provider registration entry.

    Clients created by ``create_client`` must satisfy :class:`DnsProviderClient`:

    - ``get_record(record_name=..., record_type=None, dns_server=None, dns_zone=None)``
      returning ``list[DnsRecordInfo]`` using canonical value formats from
      ``src.dns_record_types`` (MX ``priority exchange``, SRV ``priority weight port target``,
      CAA ``flags tag value``, etc.).
    - ``list_records(name_pattern=None, record_type=None, limit=100, dns_server=None, dns_zone=None)``
      returning ``DnsRecordListResult`` for bounded DNS browser browse and glob searches. ``name_pattern``
      uses case-insensitive relative-name ``*`` and ``?`` matching; providers that cannot enumerate a
      zone should raise a concise ``ValueError``.
    - ``create_or_update_record(payload, dns_server=None, dns_zone=None)`` accepting
      ``DnsRecordRequest`` including synthetic ``DELETE`` (values[0] = RR type).
      SOA must be view-only; apex NS mutations must be rejected by callers.
    """

    key: str
    label: str
    heading: str
    help_text: str
    fields: list[PluginField]
    create_client: Callable[[dict[str, str | None]], DnsProviderClient]


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
