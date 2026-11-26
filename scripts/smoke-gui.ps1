<#
.SYNOPSIS
  End-to-end smoke test of the built HashHarvest.exe (Windows only).

.DESCRIPTION
  Copies the exe to a temporary folder (so its hashharvest.db is created
  there), starts it, and drives the real window through Windows UI
  Automation: runs a text-mode scan of tests/corpus, dismisses the native
  "Scan Complete" box, checks the summary, results table and status line,
  opens the Scan History, Watchlist and VirusTotal dialogs, then checks the
  database the app wrote. Exits non-zero on the first failed check.

  Needs an interactive desktop session (it shows the window), so it does
  not run on headless CI agents.

.EXAMPLE
  wails build ; powershell -ExecutionPolicy Bypass -File scripts\smoke-gui.ps1
#>
param(
  [string]$Exe = (Join-Path $PSScriptRoot "..\packaging\wails\bin\HashHarvest.exe"),
  [string]$Corpus = (Join-Path $PSScriptRoot "..\tests\corpus")
)
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes
Add-Type -Namespace W -Name U -MemberDefinition '[DllImport("user32.dll")] public static extern bool PostMessage(System.IntPtr h, uint m, System.IntPtr w, System.IntPtr l);'

$AE = [System.Windows.Automation.AutomationElement]
$TS = [System.Windows.Automation.TreeScope]
$CT = [System.Windows.Automation.ControlType]
$All = [System.Windows.Automation.Condition]::TrueCondition
$failures = 0

function Check($label, $ok, $detail) {
  if ($ok) { Write-Host "PASS  $label" } else { Write-Host "FAIL  $label ($detail)"; $script:failures++ }
}
function Find($root, $type, $name, $timeout = 15) {
  $cond = [System.Windows.Automation.AndCondition]::new(
    [System.Windows.Automation.PropertyCondition]::new($AE::ControlTypeProperty, $type),
    [System.Windows.Automation.PropertyCondition]::new($AE::NameProperty, $name))
  $end = (Get-Date).AddSeconds($timeout)
  do {
    $e = $root.FindFirst($TS::Descendants, $cond)
    if ($e) { return $e }
    Start-Sleep -Milliseconds 300
  } while ((Get-Date) -lt $end)
  throw "UI element not found: $($type.ProgrammaticName) '$name'"
}
function Click($e) { $e.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke() }
function Names($root) { @($root.FindAll($TS::Descendants, $All) | ForEach-Object { $_.Current.Name }) }
function WaitFor($what, [scriptblock]$test, $timeout = 15) {
  $end = (Get-Date).AddSeconds($timeout)
  do { $v = & $test; if ($v) { return $v }; Start-Sleep -Milliseconds 300 } while ((Get-Date) -lt $end)
  throw "timed out waiting for $what"
}

$work = Join-Path ([System.IO.Path]::GetTempPath()) ("hh-smoke-" + [guid]::NewGuid())
New-Item -ItemType Directory $work | Out-Null
Copy-Item $Exe $work
$Corpus = (Resolve-Path $Corpus).Path
$proc = Start-Process -FilePath (Join-Path $work "HashHarvest.exe") -PassThru
try {
  WaitFor "main window" { $proc.Refresh(); $proc.MainWindowHandle -ne 0 } 30 | Out-Null
  $win = $AE::FromHandle($proc.MainWindowHandle)
  Check "window title" ($win.Current.Name -eq "HashHarvest v0.8.0 (labgeek)") $win.Current.Name
  Check "database created next to the exe" (Test-Path (Join-Path $work "hashharvest.db")) $work

  # --- scan ---------------------------------------------------------------
  (Find $win $CT::Edit "Input Directory").GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern).SetValue($Corpus)
  Click (Find $win $CT::Button "Start Scan")
  $byPid = [System.Windows.Automation.PropertyCondition]::new($AE::ProcessIdProperty, $proc.Id)
  $box = WaitFor "Scan Complete box" {
    @($AE::RootElement.FindAll($TS::Children, $byPid)) + @($win.FindAll($TS::Children, $All)) |
      Where-Object { $_.Current.Name -eq "Scan Complete" } | Select-Object -First 1
  } 30
  Check "Scan Complete message" ((Names $box) -contains "Scan complete. Use Export CSV or Export JSON to save results.") ((Names $box) -join " | ")
  # The box's OK button exposes no Invoke pattern; send IDOK like a key press would.
  [void][W.U]::PostMessage([System.IntPtr]$box.Current.NativeWindowHandle, 0x111, [System.IntPtr]1, [System.IntPtr]::Zero)
  Start-Sleep -Milliseconds 700

  $names = Names $win
  # A label can appear twice (the element and its text); its value follows the last one.
  $summary = @("Files Scanned", "Hashes Found", "Skipped Files" | ForEach-Object { $names[[array]::LastIndexOf($names, $_) + 1] }) -join ","
  Check "summary counts" ($summary -eq "2,3,0") $summary
  Check "status line" ($names -contains ("Scan complete " + [char]0x2014 + " saved to database.")) "status missing"
  $hashes = @($names | Where-Object { $_ -match '^[0-9a-f]{32,128}$' } | Sort-Object -Unique)
  $expected = @("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
                "5d41402abc4b2a76b9719d911017c592", "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d")
  Check "result rows" (($hashes -join ",") -eq ($expected -join ",")) ($hashes -join ",")
  Check "exports enabled" (Find $win $CT::Button "Export CSV").Current.IsEnabled "disabled"

  # --- dialogs ------------------------------------------------------------
  Click (Find $win $CT::Button "Scan History")
  WaitFor "history row" { (Names $win) -contains $Corpus } | Out-Null
  Check "scan history lists the scan" $true ""
  Click (Find $win $CT::Button "Close")

  Click (Find $win $CT::Button "Watchlist")
  Check "watchlist manager opens" ([bool](Find $win $CT::Button "Import from Text")) ""
  Click (Find $win $CT::Button "Close")

  Click (Find $win $CT::Button "VirusTotal")
  Check "VirusTotal dialog offers the 3 hashes" ([bool](Find $win $CT::Button "Look Up 3 Hashes")) ""
  Click (Find $win $CT::Button "Close")
} finally {
  Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
  $proc.WaitForExit(10000) | Out-Null
}

# --- what the app stored ------------------------------------------------------
$env:HASHHARVEST_SMOKE_DB = Join-Path $work "hashharvest.db"
Push-Location (Join-Path $PSScriptRoot "..")
$out = go test -count=1 -run TestSmokeDatabase ./internal/db/ | Out-String
# Judge by the test result: on Windows go can exit non-zero when it cannot delete
# its temporary test binary.
Check "stored scan, rows and schema version" ($out -match '(?m)^ok\s') $out
Pop-Location
Remove-Item Env:HASHHARVEST_SMOKE_DB
Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue

if ($failures) { Write-Host "$failures check(s) failed"; exit 1 }
Write-Host "smoke test passed"
