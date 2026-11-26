<#
.SYNOPSIS
  Collects the release files into -OutDir: HashHarvest.exe, a freshly
  built hashharvest-cli.exe and SHA256SUMS.txt.

.DESCRIPTION
  Run after "wails build" (scripts\check.ps1 does it). With -Tag, it fails
  first unless the tag is "v" followed by the version in
  internal\version\version.go, so a release cannot be mislabeled.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\check.ps1
  powershell -ExecutionPolicy Bypass -File scripts\package-release.ps1 -Tag v1.0.0
#>
param([string]$Tag = "", [string]$OutDir = "dist")
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

$version = [regex]::Match((Get-Content -Raw "internal\version\version.go"), 'const Version = "([^"]+)"').Groups[1].Value
if (-not $version) { throw "no version found in internal\version\version.go" }
if ($Tag -and $Tag -cne "v$version") { throw "tag '$Tag' does not match the code version 'v$version'" }

$gui = "packaging\wails\bin\HashHarvest.exe"
if (-not (Test-Path $gui)) { throw "$gui not found; run 'wails build -trimpath' first" }

New-Item -ItemType Directory -Force $OutDir | Out-Null
Copy-Item $gui $OutDir -Force
$env:CGO_ENABLED = "0"
go build -trimpath -ldflags "-s -w" -o (Join-Path $OutDir "hashharvest-cli.exe") ./cmd/hashharvest-cli
if ($LASTEXITCODE) { throw "building hashharvest-cli failed" }
Remove-Item Env:CGO_ENABLED

# "<sha256>  <name>" with LF line endings, so "sha256sum -c" accepts it.
$lines = foreach ($name in "HashHarvest.exe", "hashharvest-cli.exe") {
  $hash = (Get-FileHash -Algorithm SHA256 (Join-Path $OutDir $name)).Hash.ToLower()
  "$hash  $name"
}
[IO.File]::WriteAllText((Join-Path (Resolve-Path $OutDir) "SHA256SUMS.txt"), (($lines -join "`n") + "`n"))
Write-Host "packaged v$version into $OutDir"
$lines
