import base64
import time
from typing import Any, Dict, List, Optional

import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype
import dns.tsig
import dns.update

from .models import DnsRecordRequest


def _ps_single_quoted(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


def _winrm_rr_type(upper_rr: str) -> str:
    """RR type string expected by DnsServer PowerShell cmdlets."""
    u = upper_rr.strip().upper()
    return "Txt" if u == "TXT" else u


def _dns_relative_name(zone_name: str, record_name: str) -> str:
    z = zone_name.strip().rstrip(".")
    r = record_name.strip().rstrip(".")
    if not r or r == "@":
        return "@"
    suffix = "." + z
    if r.lower().endswith(suffix.lower()):
        return r[: -len(suffix)] or "@"
    return r


def _record_existed_before_update(
    server: str,
    zone_name: str,
    relative_name: str,
    rdtype: dns.rdatatype.RdataType,
) -> bool:
    z = zone_name.strip().rstrip(".")
    if relative_name in ("@", ""):
        qname = dns.name.from_text(z)
    else:
        qname = dns.name.from_text(f"{relative_name}.{z}")
    q = dns.message.make_query(qname, rdtype)
    try:
        resp = dns.query.tcp(q, server, timeout=10)
    except Exception:
        return False
    return bool(resp.answer)


class AzureDnsClient:
    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
    ):
        if not tenant_id or not client_id or not client_secret:
            raise ValueError(
                "Azure DNS requires tenant id, client id, and client secret in application settings."
            )
        try:
            from azure.identity import ClientSecretCredential
            from azure.mgmt.dns import DnsManagementClient
            from azure.mgmt.dns.models import RecordSet
            from azure.core.exceptions import ResourceNotFoundError
        except ImportError as e:
            raise ImportError(
                "Azure SDK not installed. Install azure-identity and azure-mgmt-dns: "
                f"{e}"
            ) from e

        self.credential = ClientSecretCredential(tenant_id, client_id, client_secret)
        self.DnsManagementClient = DnsManagementClient
        self.RecordSet = RecordSet
        self.ResourceNotFoundError = ResourceNotFoundError

    def create_or_update_record(
        self,
        payload: DnsRecordRequest,
        dns_server: Optional[str] = None,
        dns_zone: Optional[str] = None,
    ) -> bool:
        if dns_server:
            raise ValueError("Azure DNS ignores per-server host settings; use zone and Azure fields on the request.")

        subscription_id = payload.subscription_id
        if not subscription_id:
            raise ValueError("subscription_id is required for Azure DNS (set a default in settings or send it in the API payload).")
        if not payload.resource_group:
            raise ValueError("resource_group is required for Azure DNS.")
        if not payload.zone_name:
            raise ValueError("zone_name is required for Azure DNS.")

        client = self.DnsManagementClient(self.credential, subscription_id)
        record_set_name = payload.record_name.strip(".") or "@"
        record_type = payload.record_type.upper()

        if record_type == "DELETE":
            inner = payload.values[0].strip().upper()
            existing = self._get_existing_record_set(
                client,
                payload.resource_group,
                payload.zone_name,
                record_set_name,
                inner,
            )
            if existing is None:
                return False
            try:
                client.record_sets.delete(
                    payload.resource_group,
                    payload.zone_name,
                    record_set_name,
                    inner,
                )
            except self.ResourceNotFoundError:
                return False
            return True

        existing = self._get_existing_record_set(
            client,
            payload.resource_group,
            payload.zone_name,
            record_set_name,
            record_type,
        )
        record_set = self._build_record_set(record_type, payload.values, payload.ttl or 300)

        client.record_sets.create_or_update(
            payload.resource_group,
            payload.zone_name,
            record_set_name,
            record_type,
            record_set,
        )

        return existing is not None

    def _get_existing_record_set(
        self,
        client,
        resource_group: str,
        zone_name: str,
        record_name: str,
        record_type: str,
    ):
        try:
            return client.record_sets.get(resource_group, zone_name, record_name, record_type)
        except self.ResourceNotFoundError:
            return None

    def _build_record_set(self, record_type: str, values: List[str], ttl: int):
        if record_type == "A":
            return self.RecordSet(ttl=ttl, a_records=[{"ipv4_address": value} for value in values])
        if record_type == "AAAA":
            return self.RecordSet(ttl=ttl, aaaa_records=[{"ipv6_address": value} for value in values])
        if record_type == "CNAME":
            return self.RecordSet(ttl=ttl, cname_record={"cname": values[0]})
        if record_type == "TXT":
            return self.RecordSet(ttl=ttl, txt_records=[{"value": [value]} for value in values])
        raise ValueError(f"Unsupported record type: {record_type}")


class BindTsigDnsClient:
    """BIND (or any RFC 2136 server with TSIG), including Windows Server DNS with a TSIG key."""

    def __init__(self, tsig_key_name: str, tsig_secret_b64: str, tsig_algorithm: str = "hmac-sha256"):
        if not tsig_key_name or not tsig_secret_b64:
            raise ValueError("BIND DNS requires a TSIG key name and secret (base64) in the credentials fields.")
        try:
            secret = base64.b64decode(tsig_secret_b64.strip())
        except Exception as e:
            raise ValueError("TSIG secret must be valid base64 (as in BIND named.conf).") from e
        keyname = dns.name.from_text(tsig_key_name if tsig_key_name.endswith(".") else f"{tsig_key_name}.")
        algo = dns.name.from_text(tsig_algorithm if tsig_algorithm.endswith(".") else f"{tsig_algorithm}.")
        self._key = dns.tsig.Key(keyname, secret, algorithm=algo)
        self._keyring: Dict[dns.name.Name, dns.tsig.Key] = {keyname: self._key}
        self._keyname = keyname

    def create_or_update_record(
        self,
        payload: DnsRecordRequest,
        dns_server: Optional[str] = None,
        dns_zone: Optional[str] = None,
    ) -> bool:
        if not dns_server:
            raise ValueError("DNS server host is required for BIND (set Target DNS Server in settings).")
        zone_name = (dns_zone or payload.zone_name or "").strip().rstrip(".")
        if not zone_name:
            raise ValueError("Zone name is required for BIND (set Target DNS Zone in settings or zone_name on the request).")

        record_type = payload.record_type.upper()
        ttl = int(payload.ttl or 300)
        relative = _dns_relative_name(zone_name, payload.record_name)
        origin = dns.name.from_text(zone_name)

        if record_type == "DELETE":
            inner = payload.values[0].strip().upper()
            rdtype = dns.rdatatype.from_text(inner)
            existed = _record_existed_before_update(dns_server, zone_name, relative, rdtype)
            if not existed:
                return False
            update = dns.update.Update(origin, keyring=self._keyring, keyname=self._keyname)
            node = relative if relative not in ("@", "") else "@"
            update.delete(node, rdtype)
            response = dns.query.tcp(update, dns_server, timeout=15)
            if response.rcode() != dns.rcode.NOERROR:
                raise RuntimeError(f"DNS UPDATE failed: {dns.rcode.to_text(response.rcode())}")
            return True

        rdtype = dns.rdatatype.from_text(record_type)
        existed = _record_existed_before_update(dns_server, zone_name, relative, rdtype)

        update = dns.update.Update(origin, keyring=self._keyring, keyname=self._keyname)
        node = relative if relative not in ("@", "") else "@"

        # replace() accepts (ttl, rdtype, *text_values) or (ttl, *rdata_objects) — not (ttl, rdtype, *rdata).
        if record_type == "A":
            update.replace(node, ttl, dns.rdatatype.A, *payload.values)
        elif record_type == "AAAA":
            update.replace(node, ttl, dns.rdatatype.AAAA, *payload.values)
        elif record_type == "CNAME":
            if len(payload.values) != 1:
                raise ValueError("CNAME requires exactly one value.")
            update.replace(node, ttl, dns.rdatatype.CNAME, payload.values[0])
        elif record_type == "TXT":
            update.replace(node, ttl, dns.rdatatype.TXT, *payload.values)
        else:
            raise ValueError(f"Unsupported record type for BIND: {record_type}")

        response = dns.query.tcp(update, dns_server, timeout=15)
        if response.rcode() != dns.rcode.NOERROR:
            raise RuntimeError(f"DNS UPDATE failed: {dns.rcode.to_text(response.rcode())}")
        return existed


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
        zone = (dns_zone or payload.zone_name or "").strip()
        if not zone:
            raise ValueError("Zone name is required (set Target DNS Zone in settings or zone_name on the request).")

        record_type = payload.record_type.upper()
        ttl = int(payload.ttl or 300)
        name = _dns_relative_name(zone, payload.record_name)
        if name == "@":
            name_at = "@"
        else:
            name_at = name

        if record_type == "DELETE":
            inner = payload.values[0].strip().upper()
            ps_rr = _winrm_rr_type(inner)
            existed = self._record_exists(dns_server, zone, name_at, ps_rr)
            if not existed:
                return False
            lines: List[str] = [
                "$ErrorActionPreference = 'Stop'",
                f"$ComputerName = {_ps_single_quoted(dns_server)}",
                f"$ZoneName = {_ps_single_quoted(zone)}",
                f"$Name = {_ps_single_quoted(name_at)}",
                "Import-Module DnsServer -ErrorAction Stop",
            ]
            lines.append(
                f"Get-DnsServerResourceRecord -ComputerName $ComputerName -ZoneName $ZoneName "
                f"-Name $Name -RRType {_ps_single_quoted(ps_rr)} -ErrorAction SilentlyContinue | "
                "Remove-DnsServerResourceRecord -ComputerName $ComputerName -ZoneName $ZoneName -Force"
            )
            script = "\n".join(lines)
            self._run_ps_with_retry(dns_server, script)
            return True

        existed = self._record_exists(dns_server, zone, name_at, _winrm_rr_type(record_type))

        lines: List[str] = [
            "$ErrorActionPreference = 'Stop'",
            f"$ComputerName = {_ps_single_quoted(dns_server)}",
            f"$ZoneName = {_ps_single_quoted(zone)}",
            f"$Name = {_ps_single_quoted(name_at)}",
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
                    f"-Name $Name -IPv4Address {_ps_single_quoted(v)} "
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
                    f"-Name $Name -IPv6Address {_ps_single_quoted(v)} "
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
                f"-Name $Name -HostNameAlias {_ps_single_quoted(target)} "
                "-TimeToLive (New-TimeSpan -Seconds $TtlSeconds)"
            )
        elif record_type == "TXT":
            lines.append(
                f"Get-DnsServerResourceRecord -ComputerName $ComputerName -ZoneName $ZoneName "
                f"-Name $Name -RRType {_ps_single_quoted(_winrm_rr_type('TXT'))} -ErrorAction SilentlyContinue | "
                "Remove-DnsServerResourceRecord -ComputerName $ComputerName -ZoneName $ZoneName -Force"
            )
            for v in payload.values:
                lines.append(
                    "Add-DnsServerResourceRecordTxt -ComputerName $ComputerName -ZoneName $ZoneName "
                    f"-Name $Name -DescriptiveText {_ps_single_quoted(v)} "
                    "-TimeToLive (New-TimeSpan -Seconds $TtlSeconds)"
                )
        else:
            raise ValueError(f"Unsupported record type for Microsoft WinRM: {record_type}")

        script = "\n".join(lines)
        self._run_ps_with_retry(dns_server, script)

        return existed

    def _record_exists(self, computer: str, zone: str, name: str, rr_type: str) -> bool:
        ps = (
            "Import-Module DnsServer -ErrorAction SilentlyContinue; "
            f"$r = Get-DnsServerResourceRecord -ComputerName {_ps_single_quoted(computer)} "
            f"-ZoneName {_ps_single_quoted(zone)} -Name {_ps_single_quoted(name)} "
            f"-RRType {_ps_single_quoted(rr_type)} -ErrorAction SilentlyContinue; "
            "if ($r) { 'yes' } else { 'no' }"
        )
        result = self._run_ps_with_retry(computer, ps)
        out = (result.std_out or b"").decode(errors="replace").strip().lower()
        return out.startswith("yes")


def create_dns_client(settings: Dict[str, Optional[str]]) -> Any:
    provider = (settings.get("dns_provider_type") or "azure").strip().lower()
    if provider == "azure":
        return AzureDnsClient(
            tenant_id=settings.get("azure_tenant_id") or "",
            client_id=settings.get("azure_client_id") or "",
            client_secret=settings.get("azure_client_secret") or "",
        )
    if provider == "bind":
        return BindTsigDnsClient(
            tsig_key_name=settings.get("dns_username") or "",
            tsig_secret_b64=settings.get("dns_password") or "",
            tsig_algorithm=settings.get("dns_tsig_algorithm") or "hmac-sha256",
        )
    if provider == "microsoft":
        use_ssl = (settings.get("dns_winrm_ssl") or "").lower() in ("1", "true", "yes", "on")
        return MicrosoftWinRmDnsClient(
            username=settings.get("dns_username") or "",
            password=settings.get("dns_password") or "",
            use_ssl=use_ssl,
        )
    raise ValueError(f"Unknown DNS provider type: {provider}. Use azure, microsoft, or bind.")
