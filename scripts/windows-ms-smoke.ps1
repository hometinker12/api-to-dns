#Requires -Version 7.2
<#
  Start API natively on Windows, then smoke local + optional remote Microsoft zones using
  Invoke-WebRequest / Invoke-RestMethod.

  Env: GITHUB_WORKSPACE, LOCAL_ALLOWED_ZONE, LOCAL_DENIED_ZONE, LOCAL_WINRM_USER,
  LOCAL_WINRM_PASSWORD; optional REMOTE_*, INPUT_QUERY_SERVER.
#>
$ErrorActionPreference = 'Stop'
$workspace = $env:GITHUB_WORKSPACE
Set-Location $workspace

$base = 'http://localhost:8000'
$apiProcess = $null
$apiOut = Join-Path $env:RUNNER_TEMP 'api-to-dns-uvicorn.out.log'
$apiErr = Join-Path $env:RUNNER_TEMP 'api-to-dns-uvicorn.err.log'

function Wait-LoginPage {
  param([int]$MaxAttempts = 60)
  for ($i = 0; $i -lt $MaxAttempts; $i++) {
    try {
      $null = Invoke-WebRequest -Uri "$base/login" -UseBasicParsing -TimeoutSec 5
      return
    }
    catch { Start-Sleep -Seconds 2 }
  }
  throw 'API did not become ready on :8000/login'
}

function Invoke-FormPost {
  param(
    [Parameter(Mandatory)] [string] $Uri,
    $WebSession,
    [Parameter(Mandatory)] [hashtable] $Form,
    # FastAPI form handlers often return 303 See Other (PRG). PS7 treats 0 as "no redirects allowed"
    # and fails with "maximum redirection count has been exceeded" on the first 303.
    [int] $MaximumRedirection = 10
  )
  $pairs = $Form.GetEnumerator() | ForEach-Object {
    '{0}={1}' -f $_.Key, [uri]::EscapeDataString([string]$_.Value)
  }
  $body = $pairs -join '&'
  return Invoke-WebRequest -Uri $Uri -WebSession $WebSession -Method Post -Body $body `
    -ContentType 'application/x-www-form-urlencoded' -UseBasicParsing -MaximumRedirection $MaximumRedirection -SkipHttpErrorCheck
}

function Get-ZoneIdFromApiKeysHtml {
  param([string] $Html, [string] $ZoneFqdn)
  $esc = [regex]::Escape($ZoneFqdn)
  $m = [regex]::Match($Html, "name=`"zone_ids`" value=`"(\d+)`"\s*/>\s*<code>$esc</code>", 'Singleline,IgnoreCase')
  if (-not $m.Success) { throw "Could not find zone id for $ZoneFqdn" }
  return [int]$m.Groups[1].Value
}

function Get-ApiKeyFromCreateHtml {
  param([string] $Html)
  $m = [regex]::Match($Html, 'API key created:\s*(\S+)')
  if (-not $m.Success) { throw 'Could not extract API key from HTML' }
  return $m.Groups[1].Value
}

function Invoke-DnsRecord {
  param(
    [string] $ApiKey,
    [int] $ExpectedStatus,
    [hashtable] $JsonBody
  )
  $json = $JsonBody | ConvertTo-Json -Compress -Depth 6
  $resp = Invoke-WebRequest -Uri "$base/dns-record" -Method Post `
    -Headers @{ 'X-API-Key' = $ApiKey } -Body $json -ContentType 'application/json' `
    -UseBasicParsing -SkipHttpErrorCheck
  if ([int]$resp.StatusCode -ne $ExpectedStatus) {
    throw "dns-record expected HTTP $ExpectedStatus got $($resp.StatusCode): $($resp.Content)"
  }
  return $resp.Content | ConvertFrom-Json
}

function Assert-DnsRecordAction {
  param($Json, [string] $ExpectedAction)
  if ($ExpectedAction -eq 'access_denied') {
    if ($Json.detail.error -ne 'access_denied') { throw "expected access_denied: $($Json | ConvertTo-Json -Compress)" }
  }
  elseif ($Json.action -ne $ExpectedAction) {
    throw "expected action $ExpectedAction got $($Json | ConvertTo-Json -Compress)"
  }
}

function Wait-LocalA {
  param([string] $Fqdn, [string] $ExpectedIp, [string] $DnsServer = '127.0.0.1')
  for ($i = 0; $i -lt 30; $i++) {
    $r = Resolve-DnsName -Name $Fqdn -Type A -DnsOnly -Server $DnsServer -ErrorAction SilentlyContinue |
      Where-Object { $_.IPAddress } | Select-Object -First 1
    if ($null -ne $r -and $r.IPAddress -eq $ExpectedIp) { return }
    Start-Sleep -Seconds 2
  }
  throw "Expected $Fqdn -> $ExpectedIp on $DnsServer"
}

function Wait-LocalAbsent {
  param([string] $Fqdn, [string] $DnsServer = '127.0.0.1')
  for ($i = 0; $i -lt 30; $i++) {
    $r = Resolve-DnsName -Name $Fqdn -Type A -DnsOnly -Server $DnsServer -ErrorAction SilentlyContinue |
      Where-Object { $_.IPAddress } | Select-Object -First 1
    if ($null -eq $r -or [string]::IsNullOrEmpty($r.IPAddress)) { return }
    Start-Sleep -Seconds 2
  }
  throw "Expected $Fqdn absent on $DnsServer"
}

function Wait-RemoteA {
  param([string] $Fqdn, [string] $ExpectedIp, [string] $Server)
  if ([string]::IsNullOrWhiteSpace($Server)) { return }
  for ($i = 0; $i -lt 30; $i++) {
    $r = Resolve-DnsName -Name $Fqdn -Type A -DnsOnly -Server $Server -ErrorAction SilentlyContinue |
      Where-Object { $_.IPAddress } | Select-Object -First 1
    if ($null -ne $r -and $r.IPAddress -eq $ExpectedIp) { return }
    Start-Sleep -Seconds 2
  }
  throw "Expected $Fqdn -> $ExpectedIp via $Server"
}

function Wait-RemoteAbsent {
  param([string] $Fqdn, [string] $Server)
  if ([string]::IsNullOrWhiteSpace($Server)) { return }
  for ($i = 0; $i -lt 30; $i++) {
    $r = Resolve-DnsName -Name $Fqdn -Type A -DnsOnly -Server $Server -ErrorAction SilentlyContinue |
      Where-Object { $_.IPAddress } | Select-Object -First 1
    if ($null -eq $r -or [string]::IsNullOrEmpty($r.IPAddress)) { return }
    Start-Sleep -Seconds 2
  }
  throw "Expected $Fqdn absent at $Server"
}

try {
  $python = (Get-Command python -ErrorAction Stop).Source
  $envFile = Join-Path $workspace '.env'
  $apiArgs = @(
    '-m', 'uvicorn', 'src.app:app',
    '--host', '127.0.0.1',
    '--port', '8000',
    '--env-file', $envFile
  )
  $apiProcess = Start-Process -FilePath $python -ArgumentList $apiArgs -WorkingDirectory $workspace `
    -RedirectStandardOutput $apiOut -RedirectStandardError $apiErr -PassThru
  Write-Host "Started native API process $($apiProcess.Id)."

  Wait-LoginPage

  $null = Invoke-WebRequest -Uri "$base/login" -UseBasicParsing -SessionVariable 'WebSession'
  $login = Invoke-FormPost -Uri "$base/login" -WebSession $WebSession -Form @{
    username = 'admin'
    password = 'your-admin-password'
  }
  if ($login.StatusCode -notin @(200, 303)) {
    throw "Login POST unexpected status $($login.StatusCode)"
  }

  $admin = Invoke-WebRequest -Uri "$base/admin" -WebSession $WebSession -UseBasicParsing
  if ($admin.Content -notmatch 'DNS Admin Dashboard') {
    throw 'Admin page did not contain expected title (session or credentials).'
  }

  $localUser = ".\\$($env:LOCAL_WINRM_USER)"
  $localPass = $env:LOCAL_WINRM_PASSWORD
  $la = $env:LOCAL_ALLOWED_ZONE
  $ld = $env:LOCAL_DENIED_ZONE
  $localDnsServer = '127.0.0.1'

  foreach ($z in @($la, $ld)) {
    $null = Invoke-FormPost -Uri "$base/zones" -WebSession $WebSession -Form @{
      zone_name           = $z
      dns_provider_type   = 'microsoft'
      dns_server          = $localDnsServer
      dns_username        = $localUser
      dns_password        = $localPass
    }
  }

  $keysHtml = (Invoke-WebRequest -Uri "$base/api-keys" -WebSession $WebSession -UseBasicParsing).Content
  $zoneId = Get-ZoneIdFromApiKeysHtml -Html $keysHtml -ZoneFqdn $la

  $createKey = Invoke-FormPost -Uri "$base/api-keys" -WebSession $WebSession -MaximumRedirection 10 -Form @{
    label    = 'ms-local-smoke'
    zone_ids = "$zoneId"
  }
  $msLocalKey = Get-ApiKeyFromCreateHtml -Html $createKey.Content

  $kc = Invoke-RestMethod -Uri "$base/keycheck" -Headers @{ 'X-API-Key' = $msLocalKey }
  if ($kc.status -ne 'success') { throw 'keycheck failed' }

  $www = "www.$la"
  $jCreate = @{ zone_name = $la; record_type = 'A'; record_name = 'www'; ttl = 300; values = @('192.0.2.10') }
  $jUpdate = @{ zone_name = $la; record_type = 'A'; record_name = 'www'; ttl = 300; values = @('192.0.2.20') }
  $jDelete = @{ zone_name = $la; record_type = 'DELETE'; record_name = 'www'; values = @('A') }
  $jDenied = @{ zone_name = $ld; record_type = 'A'; record_name = 'blocked'; ttl = 300; values = @('192.0.2.55') }

  $x = Invoke-DnsRecord -ApiKey $msLocalKey -ExpectedStatus 200 -JsonBody $jCreate
  Assert-DnsRecordAction -Json $x -ExpectedAction 'created'
  Wait-LocalA -Fqdn $www -ExpectedIp '192.0.2.10'

  $x = Invoke-DnsRecord -ApiKey $msLocalKey -ExpectedStatus 200 -JsonBody $jUpdate
  Assert-DnsRecordAction -Json $x -ExpectedAction 'updated'
  Wait-LocalA -Fqdn $www -ExpectedIp '192.0.2.20'

  $x = Invoke-DnsRecord -ApiKey $msLocalKey -ExpectedStatus 200 -JsonBody $jDelete
  Assert-DnsRecordAction -Json $x -ExpectedAction 'deleted'
  Wait-LocalAbsent -Fqdn $www

  $x = Invoke-DnsRecord -ApiKey $msLocalKey -ExpectedStatus 404 -JsonBody $jDelete
  Assert-DnsRecordAction -Json $x -ExpectedAction 'not_found'

  $x = Invoke-DnsRecord -ApiKey $msLocalKey -ExpectedStatus 403 -JsonBody $jDenied
  Assert-DnsRecordAction -Json $x -ExpectedAction 'access_denied'

  if ($env:REMOTE_WINRM_HOST -and $env:REMOTE_WINRM_USER -and $env:REMOTE_WINRM_PASSWORD) {
    Write-Host '=== Remote Microsoft DNS (secrets) ==='
    $remoteDig = $env:INPUT_QUERY_SERVER
    if ([string]::IsNullOrWhiteSpace($remoteDig)) { $remoteDig = $env:REMOTE_QUERY_HOST }

    $ra = $env:REMOTE_ALLOWED_ZONE
    $rd = $env:REMOTE_DENIED_ZONE
    foreach ($z in @($ra, $rd)) {
      $form = @{
        zone_name           = $z
        dns_provider_type   = 'microsoft'
        dns_server          = $env:REMOTE_WINRM_HOST
        dns_username        = $env:REMOTE_WINRM_USER
        dns_password        = $env:REMOTE_WINRM_PASSWORD
      }
      if ($env:REMOTE_WINRM_SSL -in @('true', 'True', '1')) {
        $form['dns_winrm_ssl'] = 'true'
      }
      $null = Invoke-FormPost -Uri "$base/zones" -WebSession $WebSession -Form $form
    }

    $keysHtml2 = (Invoke-WebRequest -Uri "$base/api-keys" -WebSession $WebSession -UseBasicParsing).Content
    $rZoneId = Get-ZoneIdFromApiKeysHtml -Html $keysHtml2 -ZoneFqdn $ra
    $rk = Invoke-FormPost -Uri "$base/api-keys" -WebSession $WebSession -MaximumRedirection 10 -Form @{ label = 'ms-remote-smoke'; zone_ids = "$rZoneId" }
    $msRemoteKey = Get-ApiKeyFromCreateHtml -Html $rk.Content

    $rWww = "www.$ra"
    $rjC = @{ zone_name = $ra; record_type = 'A'; record_name = 'www'; ttl = 300; values = @('192.0.2.10') }
    $rjU = @{ zone_name = $ra; record_type = 'A'; record_name = 'www'; ttl = 300; values = @('192.0.2.20') }
    $rjD = @{ zone_name = $ra; record_type = 'DELETE'; record_name = 'www'; values = @('A') }
    $rjX = @{ zone_name = $rd; record_type = 'A'; record_name = 'blocked'; ttl = 300; values = @('192.0.2.55') }

    $x = Invoke-DnsRecord -ApiKey $msRemoteKey -ExpectedStatus 200 -JsonBody $rjC
    Assert-DnsRecordAction -Json $x -ExpectedAction 'created'
    Wait-RemoteA -Fqdn $rWww -ExpectedIp '192.0.2.10' -Server $remoteDig

    $x = Invoke-DnsRecord -ApiKey $msRemoteKey -ExpectedStatus 200 -JsonBody $rjU
    Assert-DnsRecordAction -Json $x -ExpectedAction 'updated'
    Wait-RemoteA -Fqdn $rWww -ExpectedIp '192.0.2.20' -Server $remoteDig

    $x = Invoke-DnsRecord -ApiKey $msRemoteKey -ExpectedStatus 200 -JsonBody $rjD
    Assert-DnsRecordAction -Json $x -ExpectedAction 'deleted'
    Wait-RemoteAbsent -Fqdn $rWww -Server $remoteDig

    $x = Invoke-DnsRecord -ApiKey $msRemoteKey -ExpectedStatus 404 -JsonBody $rjD
    Assert-DnsRecordAction -Json $x -ExpectedAction 'not_found'

    $x = Invoke-DnsRecord -ApiKey $msRemoteKey -ExpectedStatus 403 -JsonBody $rjX
    Assert-DnsRecordAction -Json $x -ExpectedAction 'access_denied'
  }
  else {
    Write-Host '=== Remote Microsoft DNS skipped (set MICROSOFT_DNS_WINRM_* secrets) ==='
  }

  Write-Host 'Microsoft smoke (native API + PowerShell HTTP) completed successfully.'
}
finally {
  if ($apiProcess -and -not $apiProcess.HasExited) {
    Stop-Process -Id $apiProcess.Id -Force -ErrorAction SilentlyContinue
  }
  foreach ($log in @($apiOut, $apiErr)) {
    if (Test-Path $log) {
      Write-Host "=== $log ==="
      Get-Content $log | Write-Host
    }
  }
}
