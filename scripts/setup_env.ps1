# =============================================================================
# scripts/setup_env.ps1
# Recreates the `Agent3` virtual environment and installs requirements.txt.
#
# Run from the project root (the folder containing this repo's README.md):
#     powershell -ExecutionPolicy Bypass -File .\scripts\setup_env.ps1
#
# Why this script exists:
#   * The machine has an NVIDIA PyIndex pip configuration
#     (%USERPROFILE%\pip\pip.ini and %PROGRAMDATA%\pip\pip.ini) whose
#     `extra-index-url = https://pypi.ngc.nvidia.com` does not resolve here.
#     pip queries it on every install and floods the output with DNS retries.
#     We neutralize it for our installs by pointing the extra index at PyPI.
#     This changes NOTHING globally - it only affects this PowerShell process.
# =============================================================================

[CmdletBinding()]
param(
    [string]$EnvName = "Agent3",
    [switch]$Recreate
)

$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $projectRoot

Write-Host "Project root : $projectRoot"
Write-Host "Environment  : $EnvName"

$pythonExe = Join-Path $projectRoot "$EnvName\Scripts\python.exe"
$requirements = Join-Path $projectRoot "requirements.txt"

if ($Recreate -and (Test-Path $pythonExe)) {
    Write-Host "Removing existing environment (-Recreate)..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force (Join-Path $projectRoot $EnvName)
}

if (-not (Test-Path $pythonExe)) {
    Write-Host "Creating virtual environment..." -ForegroundColor Cyan
    python -m venv $EnvName
} else {
    Write-Host "Environment already exists (pass -Recreate to rebuild)." -ForegroundColor DarkGray
}

# Neutralize the unreachable NVIDIA extra index for this process only.
$env:PIP_EXTRA_INDEX_URL = "https://pypi.org/simple"

Write-Host "Upgrading pip..." -ForegroundColor Cyan
& $pythonExe -m pip install --upgrade pip --quiet --retries 2 --timeout 30

Write-Host "Installing requirements.txt..." -ForegroundColor Cyan
& $pythonExe -m pip install -r $requirements --retries 2 --timeout 60

Write-Host ""
Write-Host "Environment ready." -ForegroundColor Green
Write-Host "Activate it with:" -ForegroundColor Green
Write-Host "    .\$EnvName\Scripts\Activate.ps1"
Write-Host "Or call it directly (no activation needed):"
Write-Host "    .\$EnvName\Scripts\python.exe -m pytest"
