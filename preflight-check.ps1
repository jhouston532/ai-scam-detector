<#
.SYNOPSIS
    Pre-flight check + batch runner for scam_agent.py.

.DESCRIPTION
    Reads a text file of websites (one URL per line), verifies the whole
    pipeline is healthy (input file, Python tool, Python runtime + deps,
    Ollama reachable, model present), then runs scam_agent.py against each
    URL and prints a pass/fail summary.

    By default the Python tool is run INSIDE WSL (python3), since that's where
    Ollama and the scam-detection env live. Use -WindowsPython to run a
    Windows-native `python` instead.

.PARAMETER InputFile
    Path to a text file with one website per line. Blank lines and lines
    starting with '#' are ignored.

.EXAMPLE
    .\Invoke-ScamScan.ps1 sites.txt

.EXAMPLE
    .\Invoke-ScamScan.ps1 sites.txt -OutDir results -Model qwen2.5-coder:14b

.EXAMPLE
    .\Invoke-ScamScan.ps1 sites.txt -DryRun          # skip Ollama, signals only

.EXAMPLE
    .\Invoke-ScamScan.ps1 sites.txt -Panel "qwen2.5-coder:14b,qwen2.5:14b,gemma2:9b"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)]
    [string]$InputFile,

    [string]$Model      = "qwen2.5-coder:14b",
    [string]$OutDir     = "results",
    [string]$ScriptPath = (Join-Path $PSScriptRoot "scam_agent.py"),
    [string]$OllamaUrl  = "http://localhost:11434",
    [string]$Panel,
    [switch]$DryRun,
    [switch]$WindowsPython
)

# Native commands (wsl, python, scam_agent.py) legitimately write progress and
# version text to stderr, so their stderr must NOT be treated as fatal. Keep the
# default 'Continue' and judge native commands by their OUTPUT / exit code; the
# one cmdlet we want to catch (Invoke-RestMethod) gets an explicit -ErrorAction.
$ErrorActionPreference = "Continue"
$PSNativeCommandUseErrorActionPreference = $false   # no-op on Windows PowerShell 5.1

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

function Write-Step  ($m) { Write-Host "  [ .. ] $m" -ForegroundColor Gray }
function Write-Ok    ($m) { Write-Host "  [ OK ] $m" -ForegroundColor Green }
function Write-Fail  ($m) { Write-Host "  [FAIL] $m" -ForegroundColor Red }
function Write-Warn  ($m) { Write-Host "  [WARN] $m" -ForegroundColor Yellow }
function Write-Head  ($m) { Write-Host "`n$m" -ForegroundColor Cyan }

$script:PreflightFailed = $false
function Fail ($m) { Write-Fail $m; $script:PreflightFailed = $true }

# Run python (in WSL or on Windows) with the given argument array.
function Invoke-Python {
    param([string[]]$PyArgs)
    if ($WindowsPython) { & python @PyArgs }
    else                { & wsl python3 @PyArgs }
}

# Convert a Windows path to a WSL path (/mnt/c/...) unless running Windows python.
function Resolve-ForRuntime {
    param([string]$WinPath)
    if ($WindowsPython) { return $WinPath }
    return (wsl wslpath -a "$WinPath").Trim()
}

# --------------------------------------------------------------------------- #
# Pre-flight
# --------------------------------------------------------------------------- #

Write-Head "PRE-FLIGHT"
$runtimeLabel = if ($WindowsPython) { "Windows python" } else { "WSL python3" }
Write-Host "  runtime: $runtimeLabel" -ForegroundColor DarkGray

# 1. Input file
Write-Step "input file: $InputFile"
if (-not (Test-Path -LiteralPath $InputFile -PathType Leaf)) {
    Fail "input file not found: $InputFile"
} else {
    Write-Ok "input file found"
}

# 2. Tool script
Write-Step "tool script: $ScriptPath"
if (-not (Test-Path -LiteralPath $ScriptPath -PathType Leaf)) {
    Fail "scam_agent.py not found at $ScriptPath  (pass -ScriptPath to override)"
} else {
    Write-Ok "scam_agent.py found"
}

# 3. Python runtime
Write-Step "python runtime ($runtimeLabel)"
try {
    $pyVer = (Invoke-Python @("--version") 2>&1 | Out-String).Trim()
} catch {
    $pyVer = ""
}
if ($pyVer -match 'Python \d') {
    Write-Ok $pyVer
} else {
    Fail "could not run python. Is WSL installed / python3 on PATH?"
}

# 4. Python deps
if (-not $script:PreflightFailed) {
    Write-Step "python deps (requests, bs4)"
    Invoke-Python @("-c", "import requests, bs4") 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Ok "requests + beautifulsoup4 importable"
    } else {
        Fail "missing deps. Run:  pip install -r requirements.txt"
    }
}

# 5 & 6. Ollama + model  (skipped in dry-run)
if ($DryRun) {
    Write-Warn "dry-run: skipping Ollama and model checks"
} else {
    Write-Step "Ollama reachable at $OllamaUrl"
    $tags = $null
    try {
        $resp = Invoke-RestMethod -Uri "$OllamaUrl/api/tags" -TimeoutSec 5 -ErrorAction Stop
        $tags = @($resp.models.name)
        Write-Ok "Ollama up ($($tags.Count) model(s) installed)"
    } catch {
        Fail "cannot reach Ollama. Start it with 'ollama serve' (in WSL). ($_)"
    }

    if ($tags) {
        $needed = if ($Panel) { $Panel.Split(",") | ForEach-Object { $_.Trim() } }
                  else        { @($Model) }
        foreach ($m in $needed) {
            Write-Step "model present: $m"
            if ($tags -contains $m) {
                Write-Ok "$m installed"
            } else {
                Fail "model '$m' not installed. Run:  ollama pull $m"
            }
        }
    }
}

if ($script:PreflightFailed) {
    Write-Host "`nPre-flight failed. Fix the items above and re-run.`n" -ForegroundColor Red
    exit 1
}
Write-Host "`nPre-flight passed.`n" -ForegroundColor Green

# --------------------------------------------------------------------------- #
# Load URLs
# --------------------------------------------------------------------------- #

$urls = Get-Content -LiteralPath $InputFile |
        ForEach-Object { $_.Trim() } |
        Where-Object   { $_ -and -not $_.StartsWith("#") }

if (-not $urls) {
    Write-Host "No URLs found in $InputFile (all blank or commented)." -ForegroundColor Red
    exit 1
}

# Prepare output dir and resolve paths for the chosen runtime
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$scriptRt = Resolve-ForRuntime (Resolve-Path -LiteralPath $ScriptPath).Path
$outRt    = Resolve-ForRuntime (Resolve-Path -LiteralPath $OutDir).Path

# --------------------------------------------------------------------------- #
# Run
# --------------------------------------------------------------------------- #

Write-Head ("RUNNING {0} site(s)" -f $urls.Count)
$sw       = [System.Diagnostics.Stopwatch]::StartNew()
$ok       = 0
$failed   = @()
$i        = 0

foreach ($url in $urls) {
    $i++
    Write-Host ("`n[{0}/{1}] {2}" -f $i, $urls.Count, $url) -ForegroundColor White

    $pyArgs = @($scriptRt, $url, "--outdir", $outRt)
    if ($DryRun) { $pyArgs += "--dry-run" }
    elseif ($Panel) { $pyArgs += @("--panel", $Panel) }
    else { $pyArgs += @("--model", $Model) }

    try {
        Invoke-Python $pyArgs
        if ($LASTEXITCODE -eq 0) { $ok++ }
        else { $failed += $url; Write-Fail "exit code $LASTEXITCODE" }
    } catch {
        $failed += $url
        Write-Fail "error: $_"
    }
}

$sw.Stop()

# --------------------------------------------------------------------------- #
# Summary
# --------------------------------------------------------------------------- #

Write-Head "SUMMARY"
Write-Host ("  scanned : {0}" -f $urls.Count)
Write-Host ("  ok      : {0}" -f $ok) -ForegroundColor Green
$failColor = "Green"; if ($failed.Count) { $failColor = "Red" }
Write-Host ("  failed  : {0}" -f $failed.Count) -ForegroundColor $failColor
foreach ($f in $failed) { Write-Host "            - $f" -ForegroundColor Red }
Write-Host ("  elapsed : {0:mm\:ss}" -f $sw.Elapsed)
Write-Host ("  output  : {0}" -f (Resolve-Path -LiteralPath $OutDir).Path)
Write-Host ""

exit ([int]([bool]$failed.Count))