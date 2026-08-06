import json
import time
from typing import Any

from ..dns_record_types import (
    MUTABLE_RECORD_TYPES,
    format_caa,
    format_mx,
    format_srv,
    normalize_hostname,
    normalize_record_values,
    parse_caa,
    parse_mx,
    parse_srv,
)
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

    def __init__(
        self,
        username: str,
        password: str,
        use_ssl: bool = False,
        insecure_tls: bool = False,
    ):
        if not username or not password:
            raise ValueError("Microsoft DNS (WinRM) requires username and password in settings.")
        self.username = username
        self.password = password
        self.use_ssl = use_ssl
        self.insecure_tls = bool(insecure_tls)

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
        kwargs: dict[str, Any] = {"transport": transport}
        if self.use_ssl:
            # Validate the WinRM HTTPS certificate unless the zone explicitly opts out.
            kwargs["server_cert_validation"] = "ignore" if self.insecure_tls else "validate"
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
                        raise RuntimeError(f"WinRM/PowerShell failed ({result.status_code}): {stderr or stdout}")
                    if attempt + 1 < self._WINRM_MAX_ATTEMPTS:
                        time.sleep(self._WINRM_RETRY_DELAY_SEC)
                        continue
                    raise RuntimeError(f"WinRM/PowerShell failed ({result.status_code}): {stderr or stdout}")
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
        dns_server: str | None = None,
        dns_zone: str | None = None,
    ) -> bool:
        if not dns_server:
            raise ValueError(
                "DNS server host is required for Microsoft DNS (set Target DNS Server to the DNS/DC WinRM endpoint)."
            )
        zone = (dns_zone or "").strip()
        if not zone:
            raise ValueError("DNS zone (domain) is required in the zone configuration.")

        record_type = payload.record_type.upper()
        ttl = int(payload.ttl or 300)
        name = dns_relative_name(zone, payload.record_name)
        name_at = "@" if name == "@" else name

        if record_type == "DELETE":
            inner = payload.values[0].strip().upper()
            if inner not in MUTABLE_RECORD_TYPES:
                raise ValueError(f"Unsupported record type for Microsoft WinRM: {inner}")
            ps_rr = winrm_rr_type(inner)
            existed = self._record_exists(dns_server, zone, name_at, ps_rr)
            if not existed:
                return False
            lines: list[str] = [
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

        if record_type not in MUTABLE_RECORD_TYPES:
            raise ValueError(f"Unsupported record type for Microsoft WinRM: {record_type}")

        values = normalize_record_values(record_type, list(payload.values))
        existed = self._record_exists(dns_server, zone, name_at, winrm_rr_type(record_type))

        lines: list[str] = [
            "$ErrorActionPreference = 'Stop'",
            f"$ComputerName = {ps_single_quoted(dns_server)}",
            f"$ZoneName = {ps_single_quoted(zone)}",
            f"$Name = {ps_single_quoted(name_at)}",
            f"$TtlSeconds = {ttl}",
            "Import-Module DnsServer -ErrorAction Stop",
        ]
        lines.append(
            f"Get-DnsServerResourceRecord -ComputerName $ComputerName -ZoneName $ZoneName "
            f"-Name $Name -RRType {ps_single_quoted(winrm_rr_type(record_type))} -ErrorAction SilentlyContinue | "
            "Remove-DnsServerResourceRecord -ComputerName $ComputerName -ZoneName $ZoneName -Force"
        )
        lines.extend(self._add_record_lines(record_type, values))

        script = "\n".join(lines)
        self._run_ps_with_retry(dns_server, script)

        return existed

    @staticmethod
    def _add_record_lines(record_type: str, values: list[str]) -> list[str]:
        lines: list[str] = []
        if record_type == "A":
            for v in values:
                lines.append(
                    "Add-DnsServerResourceRecordA -ComputerName $ComputerName -ZoneName $ZoneName "
                    f"-Name $Name -IPv4Address {ps_single_quoted(v)} "
                    "-TimeToLive (New-TimeSpan -Seconds $TtlSeconds)"
                )
        elif record_type == "AAAA":
            for v in values:
                lines.append(
                    "Add-DnsServerResourceRecordAAAA -ComputerName $ComputerName -ZoneName $ZoneName "
                    f"-Name $Name -IPv6Address {ps_single_quoted(v)} "
                    "-TimeToLive (New-TimeSpan -Seconds $TtlSeconds)"
                )
        elif record_type == "CNAME":
            lines.append(
                "Add-DnsServerResourceRecordCName -ComputerName $ComputerName -ZoneName $ZoneName "
                f"-Name $Name -HostNameAlias {ps_single_quoted(values[0])} "
                "-TimeToLive (New-TimeSpan -Seconds $TtlSeconds)"
            )
        elif record_type == "TXT":
            for v in values:
                lines.append(
                    "Add-DnsServerResourceRecordTxt -ComputerName $ComputerName -ZoneName $ZoneName "
                    f"-Name $Name -DescriptiveText {ps_single_quoted(v)} "
                    "-TimeToLive (New-TimeSpan -Seconds $TtlSeconds)"
                )
        elif record_type == "MX":
            for v in values:
                priority, exchange = parse_mx(v)
                lines.append(
                    "Add-DnsServerResourceRecordMX -ComputerName $ComputerName -ZoneName $ZoneName "
                    f"-Name $Name -MailExchange {ps_single_quoted(exchange)} -Preference {priority} "
                    "-TimeToLive (New-TimeSpan -Seconds $TtlSeconds)"
                )
        elif record_type == "NS":
            for v in values:
                lines.append(
                    "Add-DnsServerResourceRecord -ComputerName $ComputerName -ZoneName $ZoneName "
                    f"-Name $Name -NS -NameServer {ps_single_quoted(v)} "
                    "-TimeToLive (New-TimeSpan -Seconds $TtlSeconds)"
                )
        elif record_type == "SRV":
            for v in values:
                priority, weight, port, target = parse_srv(v)
                lines.append(
                    "Add-DnsServerResourceRecord -ComputerName $ComputerName -ZoneName $ZoneName "
                    f"-Name $Name -Srv -DomainName {ps_single_quoted(target)} "
                    f"-Priority {priority} -Weight {weight} -Port {port} "
                    "-TimeToLive (New-TimeSpan -Seconds $TtlSeconds)"
                )
        elif record_type == "CAA":
            for v in values:
                flags, tag, caa_value = parse_caa(v)
                if caa_value.startswith('"') and caa_value.endswith('"') and len(caa_value) >= 2:
                    caa_value = caa_value[1:-1]
                # Windows Server 2022+ supports CAA via Add-DnsServerResourceRecord with -Caa.
                lines.append(
                    "Add-DnsServerResourceRecord -ComputerName $ComputerName -ZoneName $ZoneName "
                    f"-Name $Name -Caa -CaaFlags {flags} -CaaTag {ps_single_quoted(tag)} "
                    f"-CaaValue {ps_single_quoted(caa_value)} "
                    "-TimeToLive (New-TimeSpan -Seconds $TtlSeconds)"
                )
        elif record_type == "PTR":
            for v in values:
                lines.append(
                    "Add-DnsServerResourceRecordPtr -ComputerName $ComputerName -ZoneName $ZoneName "
                    f"-Name $Name -PtrDomainName {ps_single_quoted(v)} "
                    "-TimeToLive (New-TimeSpan -Seconds $TtlSeconds)"
                )
        else:
            raise ValueError(f"Unsupported record type for Microsoft WinRM: {record_type}")
        return lines

    def get_record(
        self,
        *,
        record_name: str,
        record_type: str | None = None,
        dns_server: str | None = None,
        dns_zone: str | None = None,
    ) -> list[DnsRecordInfo]:
        if not dns_server:
            raise ValueError(
                "DNS server host is required for Microsoft DNS (set Target DNS Server to the DNS/DC WinRM endpoint)."
            )
        zone = (dns_zone or "").strip()
        if not zone:
            raise ValueError("DNS zone (domain) is required in the zone configuration.")

        name = dns_relative_name(zone, record_name)
        name_at = "@" if name == "@" else name

        types_to_query = lookup_record_types_to_query(record_type)
        results: list[DnsRecordInfo] = []
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
    ) -> DnsRecordInfo | None:
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
            "  'MX' {\n"
            "    foreach ($rec in $records) {\n"
            "      $values += ('{0} {1}' -f [int]$rec.RecordData.Preference, [string]$rec.RecordData.MailExchange)\n"
            "    }\n"
            "  }\n"
            "  'NS' { $values = @($records | ForEach-Object { [string]$_.RecordData.NameServer }) }\n"
            "  'SRV' {\n"
            "    foreach ($rec in $records) {\n"
            "      $values += ('{0} {1} {2} {3}' -f [int]$rec.RecordData.Priority, "
            "[int]$rec.RecordData.Weight, [int]$rec.RecordData.Port, [string]$rec.RecordData.DomainName)\n"
            "    }\n"
            "  }\n"
            "  'CAA' {\n"
            "    foreach ($rec in $records) {\n"
            "      $values += ('{0} {1} {2}' -f [int]$rec.RecordData.Flags, "
            "[string]$rec.RecordData.Tag, [string]$rec.RecordData.Value)\n"
            "    }\n"
            "  }\n"
            "  'PTR' { $values = @($records | ForEach-Object { [string]$_.RecordData.PtrDomainName }) }\n"
            "  'SOA' {\n"
            "    $soa = $records[0].RecordData\n"
            "    $values = @(('{0} {1} {2} {3} {4} {5} {6}' -f "
            "[string]$soa.PrimaryServer, [string]$soa.ResponsiblePerson, "
            "[uint64]$soa.SerialNumber, [int]$soa.RefreshInterval.TotalSeconds, "
            "[int]$soa.RetryDelay.TotalSeconds, [int]$soa.ExpireLimit.TotalSeconds, "
            "[int]$soa.MinimumTimeToLive.TotalSeconds))\n"
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
        canonical: list[str] = []
        for raw in values:
            text = str(raw).strip()
            if not text:
                continue
            if api_rr_type == "MX":
                priority, exchange = parse_mx(text)
                canonical.append(format_mx(priority, exchange))
            elif api_rr_type == "SRV":
                priority, weight, port, target = parse_srv(text)
                canonical.append(format_srv(priority, weight, port, target))
            elif api_rr_type == "CAA":
                flags, tag, caa_value = parse_caa(text)
                canonical.append(format_caa(flags, tag, caa_value))
            elif api_rr_type in {"CNAME", "NS", "PTR"}:
                canonical.append(normalize_hostname(text))
            else:
                canonical.append(text)
        return DnsRecordInfo(
            record_name=name,
            record_type=api_rr_type,
            ttl=int(data["ttl"]),
            values=canonical,
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


def _truthy_setting(value: str | None) -> bool:
    return (value or "").strip().lower() in ("1", "true", "yes", "on")


def create_client(settings: dict[str, str | None]) -> MicrosoftWinRmDnsClient:
    use_ssl = _truthy_setting(settings.get("dns_winrm_ssl"))
    # Absent dns_winrm_insecure_tls means certificate validation is enabled.
    insecure_tls = _truthy_setting(settings.get("dns_winrm_insecure_tls"))
    return MicrosoftWinRmDnsClient(
        username=settings.get("dns_username") or "",
        password=settings.get("dns_password") or "",
        use_ssl=use_ssl,
        insecure_tls=insecure_tls,
    )


PLUGIN = DnsProviderPlugin(
    key="microsoft",
    label="Microsoft DNS (WinRM)",
    heading="Microsoft DNS (WinRM)",
    help_text=(
        "Use a DNS server or domain controller that accepts WinRM connections. "
        "The account must have rights to manage records in the zone. "
        "HTTPS WinRM validates the server certificate by default."
    ),
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
        PluginField(
            "dns_winrm_insecure_tls",
            "Disable WinRM TLS certificate validation (insecure)",
            type="checkbox",
            help=(
                "WARNING: Disables certificate validation for HTTPS WinRM. "
                "Use only for lab hosts with self-signed certificates. "
                "Leave unchecked in production so the server certificate is verified."
            ),
        ),
    ],
    create_client=create_client,
)
