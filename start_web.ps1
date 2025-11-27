# Start the zkSNARK Authentication Web Application
# Usage: 
#   Normal mode: pwsh start_web.ps1
#   With real TPM: pwsh start_web.ps1 -Admin

param(
    [switch]$Admin
)

# Store current directory before elevation
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Check if admin is needed but not running as admin
if ($Admin -and -NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "============================================================" -ForegroundColor Yellow
    Write-Host "  Requesting Administrator privileges for Real TPM" -ForegroundColor Yellow
    Write-Host "============================================================" -ForegroundColor Yellow
    Write-Host ""
    
    $arguments = "-ExecutionPolicy Bypass -Command `"Set-Location '$scriptDir'; & '$PSCommandPath' -Admin`""
    Start-Process powershell -Verb RunAs -ArgumentList $arguments
    exit
}

# Ensure we're in the correct directory (important for admin mode)
if ($scriptDir) {
    Set-Location $scriptDir
    Write-Host "Working directory: $scriptDir" -ForegroundColor Gray
    Write-Host ""
}

$tpmMode = if ($Admin) { "Real TPM Mode (Admin)" } else { "Software Mode" }

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "    zkSNARK Authentication System - $tpmMode" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# Check if Python is available
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: Python not found. Please install Python 3.8+" -ForegroundColor Red
    pause
    exit 1
}

# Check if Node is available
if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: Node.js not found. Please install Node.js 16+" -ForegroundColor Red
    pause
    exit 1
}

# Check if zkSNARK artifacts exist
if (-not (Test-Path "static\auth.wasm")) {
    Write-Host "WARNING: zkSNARK artifacts not found in static/" -ForegroundColor Yellow
    if (Test-Path ".\scripts\copy_artifacts.ps1") {
        Write-Host "Running artifact copy script..." -ForegroundColor Yellow
        & ".\scripts\copy_artifacts.ps1"
    } else {
        Write-Host "Note: Run setup_snark.ps1 first to generate artifacts" -ForegroundColor Yellow
    }
}

Write-Host "Starting Backend API Server..." -ForegroundColor Green
$backend = Start-Process powershell -ArgumentList "-NoExit", "-Command", "python api_server.py" -PassThru
Write-Host "Backend PID: $($backend.Id)" -ForegroundColor Gray
Write-Host "Backend URL: http://localhost:8000" -ForegroundColor Gray
Write-Host "API Docs: http://localhost:8000/docs" -ForegroundColor Gray
Write-Host ""

Start-Sleep -Seconds 2

Write-Host "Starting Frontend Dev Server..." -ForegroundColor Green

# Get the frontend directory path
$frontendPath = Join-Path (Get-Location) "frontend"

# Check if node_modules exists
if (-not (Test-Path "$frontendPath\node_modules")) {
    Write-Host "Installing frontend dependencies..." -ForegroundColor Yellow
    Push-Location $frontendPath
    npm install
    Pop-Location
}

$frontend = Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$frontendPath'; npm run dev" -PassThru
Write-Host "Frontend PID: $($frontend.Id)" -ForegroundColor Gray
Write-Host "Frontend URL: http://localhost:5173" -ForegroundColor Gray
Write-Host ""

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Both servers are starting up..." -ForegroundColor Green
Write-Host ""
Write-Host "Open your browser to: http://localhost:5173" -ForegroundColor Cyan
Write-Host ""
Write-Host "Press Ctrl+C to stop both servers" -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Cyan

# Wait for user interrupt
try {
    while ($true) {
        Start-Sleep -Seconds 1
    }
}
finally {
    Write-Host ""
    Write-Host "Shutting down servers..." -ForegroundColor Yellow
    Stop-Process -Id $backend.Id -Force -ErrorAction SilentlyContinue
    Stop-Process -Id $frontend.Id -Force -ErrorAction SilentlyContinue
    Write-Host "Servers stopped." -ForegroundColor Green
}

