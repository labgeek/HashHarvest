<#
.SYNOPSIS
  All checks, run locally and by the Windows job of .github/workflows/ci.yml.

.DESCRIPTION
  Runs, in order: gofmt check, go vet, go test with coverage,
  the race detector (only when a 64-bit C compiler is on PATH),
  cross-compilation of the core for Linux and macOS, and wails build.
  Stops at the first failure.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\check.ps1
#>
param([switch]$SkipBuild)
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

function Step($name, [scriptblock]$run) {
  Write-Host "==> $name"
  & $run
  if ($LASTEXITCODE) { Write-Host "FAILED: $name"; exit $LASTEXITCODE }
}

Step "gofmt -l ." {
  $unformatted = gofmt -l .
  if ($unformatted) { $unformatted; $global:LASTEXITCODE = 1 }
}
Step "go vet ./..." { go vet ./... }
Step "go test -coverprofile=coverage.out ./..." { go test -count=1 "-coverprofile=coverage.out" ./... }
Step "coverage total" { go tool cover "-func=coverage.out" | Select-Object -Last 1 }

$gcc = Get-Command gcc -ErrorAction SilentlyContinue
if (-not ($gcc -and (gcc -dumpmachine) -match "x86_64")) {
  # Fall back to WinLibs installed by: winget install BrechtSanders.WinLibs.POSIX.UCRT
  $winlibs = Get-ChildItem "$env:LOCALAPPDATA\Microsoft\WinGet\Packages\BrechtSanders.WinLibs*\mingw64\bin\gcc.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($winlibs) { $env:PATH = "$($winlibs.DirectoryName);$env:PATH"; $gcc = $winlibs }
}
if ($gcc -and (gcc -dumpmachine) -match "x86_64") {
  $env:CGO_ENABLED = "1"
  Step "go test -race ./..." { go test -race -count=1 ./... }
} else {
  Write-Host "==> go test -race SKIPPED: needs a 64-bit gcc (x86_64-w64-mingw32) on PATH"
}

foreach ($target in "linux/amd64", "linux/arm64", "darwin/amd64", "darwin/arm64") {
  $env:GOOS, $env:GOARCH = $target.Split("/")
  Step "cross-compile internal/... for $target" { go build ./internal/... }
}
Remove-Item Env:GOOS, Env:GOARCH

if (-not $SkipBuild) {
  Step "wails build" { wails build -trimpath }
}
Write-Host "all checks passed"
