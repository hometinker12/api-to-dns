import json
import time
from typing import Any, Dict, List, Optional

from ..models import DnsRecordInfo, DnsRecordRequest

from .base import DNS_ZONE_DOMAIN_FIELD, DnsProviderPlugin, PluginField
from .utils import dns_relative_name, lookup_record_types_to_query, ps_single_quoted, winrm_rr_type


class MicrosoftWinRmDnsClient:
    """On-premises Microsoft DNS via WinRM and DnsServer PowerShell cmdlets."""

    _WINRM_MAX_ATTEMPTS = 3
    _WINRM_RETRY_DELAY_SEC = 5
    _ACCESS_DENIED_MARKERS = (
        "access is denied",
        "access denied",
        "logon failure",
        "unknown user name or bad password",
        "the user name or password is incorrect",
        "authorization failed",
        "authentication failed",
        "fault code 5",
        "fault_code>5<",
        "permission denied",
        "denied access",
    )

    def __init__(self, username: str, password: str, use_ssl: bool = False):
        if not username or not password:
            raise ValueError("Microsoft DNS (WinRM) requires username and password in settings.")
        self.username = username
        self.password = password
        self.use_ssl = use_ssl

    @classmethod
    def _looks_like_access_denied(cls, text: str) -> bool:
        t = text.lower()
        return any(m in t for m in cls._ACCESS_DENIED_MARKERS)

    def _session(self, server: str):
        try:
            import winrm
        except ImportError as e:
            raise ImportError("pywinrm is required for Microsoft DNS (WinRM). Install pywinrm.") from e

        transport = "ssl" if self.use_ssl else "ntlm"
        kwargs: Dict[str, Any] = {"transport": transport}
        if self.use_ssl:
            kwargs["server_cert_validation"] = "ignore"
        return winrm.Session(server, (self.username, self.password), **kwargs)

    def _run_ps_with_retry(self, server: str, script: str):
        """Run PowerShell on the WinRM target; retry on transient failures (not access denied)."""
        for attempt in range(self._WINRM_MAX_ATTEMPTS):
            try:
                session = self._session(server)
                result = session.run_ps(script)
                stderr = (result.std_err or b"").decode(errors="replace")
                stdout = (result.std_out or b"").decode(errors="replace")
                combined = f"{stderr}\n{stdout}"
                if result.status_code != 0:
                    if self._looks_like_access_denied(combined):
                        raise RuntimeError(
                            f"WinRM/PowerShell failed ({result.status_code}): {stderr or stdout}"
                        )
                    if attempt + 1 < self._WINRM_MAX_ATTEMPTS:
                        time.sleep(self._WINRM_RETRY_DELAY_SEC)
                        continue
                    raise RuntimeError(
                        f"WinRM/PowerShell failed ({result.status_code}): {stderr or stdout}"
                    )
                return result
            except ImportError:
                raise
            except RuntimeError as e:
                if self._looks_like_access_denied(str(e)):
                    raise
                if attempt + 1 < self._WINRM_MAX_ATTEMPTS:
                    time.sleep(self._WINRM_RETRY_DELAY_SEC)
                    continue
                raise
            except Exception as e:
                if self._looks_like_access_denied(str(e)):
                    raise RuntimeError(f"WinRM access denied: {e}") from e
                if attempt + 1 < self._WINRM_MAX_ATTEMPTS:
                    time.sleep(self._WINRM_RETRY_DELAY_SEC)
                    continue
                raise RuntimeError(f"WinRM failed after {self._WINRM_MAX_ATTEMPTS} attempts: {e}") from e

    def create_or_update_record(
        self,
        payload: DnsRecordRequest,
        dns_server: Optional[str] = None,
        dns_zone: Optional[str] = None,
    ) -> bool:
        if not dns_server:
            raise ValueError("DNS server host is required for Microsoft DNS (set Target DNS Server to the DNS/DC WinRM endpoint).")
        zone = (dns_zone or "").strip()
        if not zone:
            raise ValueError("DNS zone (domain) is required in the zone configuration.")

        record_type = payload.record_type.upper()
        ttl = int(payload.ttl or 300)
        name = dns_relative_name(zone, payload.record_name)
        if name == "@":
            name_at = "@"
        else:
            name_at = name

        if record_type == "DELETE":
            inner = payload.values[0].strip().upper()
            ps_rr = winrm_rr_type(inner)
            existed = self._record_exists(dns_server, zone, name_at, ps_rr)
            if not existed:
                return False
            lines: List[str] = [
                "$ErrorActionPreference = 'Stop'",
                f"$ComputerName = {ps_single_quoted(dns_server)}",
                f"$ZoneName = {ps_single_quoted(zone)}",
                f"$Name = {ps_single_quoted(name_at)}",
                "Import-Module DnsServer -ErrorAction Stop",
            ]
            lines.append(
                f"Get-DnsServerResourceRecord -ComputerName $ComputerName -ZoneName $ZoneName "
                f"-Name $Name -RRType {ps_single_quoted(ps_rr)} -ErrorAction SilentlyContinue | "
                "Remove-DnsServerResourceRecord -ComputerName $ComputerName -ZoneName $ZoneName -Force"
            )
            script = "\n".join(lines)
            self._run_ps_with_retry(dns_server, script)
            return True

        existed = self._record_exists(dns_server, zone, name_at, winrm_rr_type(record_type))

        lines: List[str] = [
            "$ErrorActionPreference = 'Stop'",
            f"$ComputerName = {ps_single_quoted(dns_server)}",
            f"$ZoneName = {ps_single_quoted(zone)}",
            f"$Name = {ps_single_quoted(name_at)}",
            f"$TtlSeconds = {ttl}",
            "Import-Module DnsServer -ErrorAction Stop",
        ]

        if record_type == "A":
            lines.append(
                "Get-DnsServerResourceRecord -ComputerName $ComputerName -ZoneName $ZoneName "
                "-Name $Name -RRType A -ErrorAction SilentlyContinue | "
                "Remove-DnsServerResourceRecord -ComputerName $ComputerName -ZoneName $ZoneName -Force"
            )
            for v in payload.values:
                lines.append(
                    "Add-DnsServerResourceRecordA -ComputerName $ComputerName -ZoneName $ZoneName "
                    f"-Name $Name -IPv4Address {ps_single_quoted(v)} "
                    "-TimeToLive (New-TimeSpan -Seconds $TtlSeconds)"
                )
        elif record_type == "AAAA":
            lines.append(
                "Get-DnsServerResourceRecord -ComputerName $ComputerName -ZoneName $ZoneName "
                "-Name $Name -RRType AAAA -ErrorAction SilentlyContinue | "
                "Remove-DnsServerResourceRecord -ComputerName $ComputerName -ZoneName $ZoneName -Force"
            )
            for v in payload.values:
                lines.append(
                    "Add-DnsServerResourceRecordAAAA -ComputerName $ComputerName -ZoneName $ZoneName "
                    f"-Name $Name -IPv6Address {ps_single_quoted(v)} "
                    "-TimeToLive (New-TimeSpan -Seconds $TtlSeconds)"
                )
        elif record_type == "CNAME":
            if len(payload.values) != 1:
                raise ValueError("CNAME requires exactly one value.")
            target = payload.values[0]
            lines.append(
                "Get-DnsServerResourceRecord -ComputerName $ComputerName -ZoneName $ZoneName "
                "-Name $Name -RRType CNAME -ErrorAction SilentlyContinue | "
                "Remove-DnsServerResourceRecord -ComputerName $ComputerName -ZoneName $ZoneName -Force"
            )
            lines.append(
                "Add-DnsServerResourceRecordCName -ComputerName $ComputerName -ZoneName $ZoneName "
                f"-Name $Name -HostNameAlias {ps_single_quoted(target)} "
                "-TimeToLive (New-TimeSpan -Seconds $TtlSeconds)"
            )
        elif record_type == "TXT":
            lines.append(
                f"Get-DnsServerResourceRecord -ComputerName $ComputerName -ZoneName $ZoneName "
                f"-Name $Name -RRType {ps_single_quoted(winrm_rr_type('TXT'))} -ErrorAction SilentlyContinue | "
                "Remove-DnsServerResourceRecord -ComputerName $ComputerName -ZoneName $ZoneName -Force"
            )
            for v in payload.values:
                lines.append(
                    "Add-DnsServerResourceRecordTxt -ComputerName $ComputerName -ZoneName $ZoneName "
                    f"-Name $Name -DescriptiveText {ps_single_quoted(v)} "
                    "-TimeToLive (New-TimeSpan -Seconds $TtlSeconds)"
                )
        else:
            raise ValueError(f"Unsupported record type for Microsoft WinRM: {record_type}")

        script = "\n".join(lines)
        self._run_ps_with_retry(dns_server, script)

        return existed

    def get_record(
        self,
        *,
        record_name: str,
        record_type: Optional[str] = None,
        dns_server: Optional[str] = None,
        dns_zone: Optional[str] = None,
    ) -> List[DnsRecordInfo]:
        if not dns_server:
            raise ValueError("DNS server host is required for Microsoft DNS (set Target DNS Server to the DNS/DC WinRM endpoint).")
        zone = (dns_zone or "").strip()
        if not zone:
            raise ValueError("DNS zone (domain) is required in the zone configuration.")

        name = dns_relative_name(zone, record_name)
        name_at = "@" if name == "@" else name

        types_to_query = lookup_record_types_to_query(record_type)
        results: List[DnsRecordInfo] = []
        for rt in types_to_query:
            info = self._get_record_details(dns_server, zone, name_at, rt)
            if info is not None:
                results.append(info)
        return results

    def _get_record_details(
        self,
        computer: str,
        zone: str,
        name: str,
        api_rr_type: str,
    ) -> Optional[DnsRecordInfo]:
        ps_rr = winrm_rr_type(api_rr_type)
        ps = (
            "Import-Module DnsServer -ErrorAction SilentlyContinue\n"
            f"$records = @(Get-DnsServerResourceRecord -ComputerName {ps_single_quoted(computer)} "
            f"-ZoneName {ps_single_quoted(zone)} -Name {ps_single_quoted(name)} "
            f"-RRType {ps_single_quoted(ps_rr)} -ErrorAction SilentlyContinue)\n"
            "if ($records.Count -eq 0) { exit 0 }\n"
            "$ttl = [int]$records[0].TimeToLive.TotalSeconds\n"
            "$values = @()\n"
            f"switch ('{api_rr_type}') {{\n"
            "  'A' { $values = @($records | ForEach-Object { $_.RecordData.IPv4Address.IPAddressToString }) }\n"
            "  'AAAA' { $values = @($records | ForEach-Object { $_.RecordData.IPv6Address.IPAddressToString }) }\n"
            "  'CNAME' { $values = @([string]$records[0].RecordData.HostNameAlias) }\n"
            "  'TXT' {\n"
            "    foreach ($rec in $records) {\n"
            "      $text = $rec.RecordData.DescriptiveText\n"
            "      if ($text -is [System.Array]) { $values += [string]::Join('', $text) }\n"
            "      else { $values += [string]$text }\n"
            "    }\n"
            "  }\n"
            "}\n"
            "@{ ttl = $ttl; values = @($values) } | ConvertTo-Json -Compress\n"
        )
        result = self._run_ps_with_retry(computer, ps)
        out = (result.std_out or b"").decode(errors="replace").strip()
        if not out:
            return None
        data = json.loads(out)
        values = data.get("values") or []
        if isinstance(values, str):
            values = [values]
        return DnsRecordInfo(
            record_name=name,
            record_type=api_rr_type,
            ttl=int(data["ttl"]),
            values=[str(v) for v in values],
        )

    def _record_exists(self, computer: str, zone: str, name: str, rr_type: str) -> bool:
        ps = (
            "Import-Module DnsServer -ErrorAction SilentlyContinue; "
            f"$r = Get-DnsServerResourceRecord -ComputerName {ps_single_quoted(computer)} "
            f"-ZoneName {ps_single_quoted(zone)} -Name {ps_single_quoted(name)} "
            f"-RRType {ps_single_quoted(rr_type)} -ErrorAction SilentlyContinue; "
            "if ($r) { 'yes' } else { 'no' }"
        )
        result = self._run_ps_with_retry(computer, ps)
        out = (result.std_out or b"").decode(errors="replace").strip().lower()
        return out.startswith("yes")


def create_client(settings: Dict[str, Optional[str]]) -> MicrosoftWinRmDnsClient:
    use_ssl = (settings.get("dns_winrm_ssl") or "").lower() in ("1", "true", "yes", "on")
    return MicrosoftWinRmDnsClient(
        username=settings.get("dns_username") or "",
        password=settings.get("dns_password") or "",
        use_ssl=use_ssl,
    )


PLUGIN = DnsProviderPlugin(
    key="microsoft",
    label="Microsoft DNS (WinRM)",
    heading="Microsoft DNS (WinRM)",
    help_text="Use a DNS server or domain controller that accepts WinRM connections. The account must have rights to manage records in the zone.",
    fields=[
        DNS_ZONE_DOMAIN_FIELD,
        PluginField("dns_server", "Target DNS Server", placeholder="dc01.corp.local or 192.0.2.10"),
        PluginField("dns_username", "Username", autocomplete="off", placeholder="DOMAIN\\dns-admin"),
        PluginField(
            "dns_password",
            "Password",
            type="password",
            autocomplete="new-password",
            preserve_on_blank=True,
        ),
        PluginField("dns_winrm_ssl", "Use HTTPS WinRM (port 5986)", type="checkbox"),
    ],
    create_client=create_client,
)
