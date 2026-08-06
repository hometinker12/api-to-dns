# Build the production image and scan it with Trivy using the same gate as CI:
# High/Critical, ignore-unfixed, os+library, .trivyignore, exit-code 1.
#
# Usage (from repo root):
#   powershell -File scripts/trivy-local-scan.ps1
#
# Prefers a local `trivy` CLI when available; otherwise runs aquasec/trivy via Docker
# against a saved image tar (works on Windows Docker Desktop without docker.sock mounts).

$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $RepoRoot

$ImageTag = "api-to-dns:local-trivy"
$IgnoreFile = Join-Path $RepoRoot ".trivyignore"
$TarPath = Join-Path ([System.IO.Path]::GetTempPath()) ("api-to-dns-trivy-{0}.tar" -f [guid]::NewGuid().ToString("N"))

function Assert-Command([string]$Name) {
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Required command not found: $Name"
    }
}

Assert-Command "docker"

if (-not (Test-Path $IgnoreFile)) {
    throw "Missing .trivyignore at $IgnoreFile"
}

Write-Host "Building $ImageTag ..."
docker build --file Dockerfile --tag $ImageTag .
if ($LASTEXITCODE -ne 0) {
    throw "docker build failed with exit code $LASTEXITCODE"
}

$TrivyArgs = @(
    "image",
    "--format", "table",
    "--exit-code", "1",
    "--ignore-unfixed",
    "--vuln-type", "os,library",
    "--severity", "HIGH,CRITICAL",
    "--ignorefile", $IgnoreFile
)

try {
    if (Get-Command trivy -ErrorAction SilentlyContinue) {
        Write-Host "Scanning $ImageTag with local trivy CLI ..."
        & trivy @TrivyArgs $ImageTag
        $scanExit = $LASTEXITCODE
    }
    else {
        Write-Host "Local trivy CLI not found; scanning via aquasec/trivy Docker image ..."
        docker save --output $TarPath $ImageTag
        if ($LASTEXITCODE -ne 0) {
            throw "docker save failed with exit code $LASTEXITCODE"
        }

        $TarName = Split-Path $TarPath -Leaf
        $TempDir = Split-Path $TarPath -Parent
        docker run --rm `
            --volume "${TempDir}:/tmp/scan:ro" `
            --volume "${IgnoreFile}:/.trivyignore:ro" `
            aquasec/trivy:latest `
            image `
            --input "/tmp/scan/$TarName" `
            --format table `
            --exit-code 1 `
            --ignore-unfixed `
            --vuln-type os,library `
            --severity HIGH,CRITICAL `
            --ignorefile /.trivyignore
        $scanExit = $LASTEXITCODE
    }
}
finally {
    if (Test-Path $TarPath) {
        Remove-Item -Force $TarPath -ErrorAction SilentlyContinue
    }
}

if ($scanExit -ne 0) {
    Write-Error "Trivy found High/Critical vulnerabilities (exit $scanExit). Fix or update .trivyignore before pushing."
    exit $scanExit
}

Write-Host "Trivy local scan passed (no High/Critical findings)."
exit 0
