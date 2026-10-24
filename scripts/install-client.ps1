# CrossWire client installer for the machine that runs the agent (Windows).
#
#   powershell -ExecutionPolicy Bypass -File install-client.ps1
#   powershell -ExecutionPolicy Bypass -File install-client.ps1 -InstallDir D:\tools\crosswire
#
# Copies the client somewhere stable, wires it into DeepSeek Harness, and
# prints the config block for anything else.

param(
    [string]$InstallDir = "$env:LOCALAPPDATA\crosswire",
    [string]$Python = "",
    [switch]$NoDsh
)

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

function Find-Python {
    param([string]$Hint)
    if ($Hint -and (Test-Path $Hint)) { return $Hint }
    foreach ($name in @("python", "python3")) {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue
        if ($cmd -and $cmd.Source -notmatch "WindowsApps") { return $cmd.Source }
    }
    foreach ($guess in @(
        "$env:LOCALAPPDATA\Programs\Python\Python313\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe",
        "C:\Python313\python.exe",
        "C:\Python312\python.exe")) {
        if (Test-Path $guess) { return $guess }
    }
    throw "Python 3.9+ not found. Install it from python.org, or pass -Python <path>."
}

$py = Find-Python -Hint $Python
Write-Host "python     : $py"
$ver = & $py -c "import sys; print('%d.%d' % sys.version_info[:2])"
Write-Host "version    : $ver"
if ([version]$ver -lt [version]"3.9") { throw "CrossWire needs Python 3.9 or newer, found $ver" }

Write-Host "installing : $InstallDir"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
foreach ($item in @("crosswire", "agent", "cw.py", "docs", "examples")) {
    $src = Join-Path $here $item
    if (Test-Path $src) {
        Copy-Item -Recurse -Force $src (Join-Path $InstallDir $item)
    }
}

# drop stale bytecode from a previous version
Get-ChildItem -Recurse -Path (Join-Path $InstallDir "crosswire") -Filter "__pycache__" -ErrorAction SilentlyContinue |
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

$launcher = Join-Path $InstallDir "cw.py"
Write-Host "launcher   : $launcher"

& $py $launcher init
Write-Host ""
Write-Host "self check:"
& $py $launcher doctor

if (-not $NoDsh) {
    Write-Host ""
    Write-Host "registering with DeepSeek Harness ..."
    & $py $launcher dsh-install --python $py
}

Write-Host ""
Write-Host "done. the MCP server command is:"
Write-Host "  `"$py`" `"$launcher`" serve"
