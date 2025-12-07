# Build script for Lab 3 P2P Messaging System

Write-Host "Building Lab 3 P2P Encrypted Messaging System..." -ForegroundColor Cyan
Write-Host ""

# Check if virtual environment is activated
if (-not $env:VIRTUAL_ENV) {
    Write-Host "Warning: Virtual environment not activated" -ForegroundColor Yellow
    Write-Host "Run: .\Scripts\Activate.ps1" -ForegroundColor Yellow
    Write-Host ""
}

# Step 1: Build C++ encryption module
Write-Host "[1/3] Building C++ encryption module..." -ForegroundColor Green

$buildDir = "..\lab2\build"
if (-not (Test-Path $buildDir)) {
    Write-Host "Error: Build directory not found at $buildDir" -ForegroundColor Red
    Write-Host "Please run CMake configuration first:" -ForegroundColor Red
    Write-Host "  cd ..\lab2" -ForegroundColor Yellow
    Write-Host "  cmake -S . -B build" -ForegroundColor Yellow
    exit 1
}

Push-Location $buildDir
try {
    cmake --build . --config Release --target crypto_module
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Error: Build failed!" -ForegroundColor Red
        exit 1
    }
} finally {
    Pop-Location
}

Write-Host "  crypto_module built successfully" -ForegroundColor Green
Write-Host ""

# Step 2: Check for crypto_module.pyd
Write-Host "[2/3] Verifying crypto_module..." -ForegroundColor Green

$moduleFiles = @(
    "..\lab2\build\Release\crypto_module.cp312-win_amd64.pyd",
    "..\lab2\build\Release\crypto_module.pyd",
    "..\lab2\build\Debug\crypto_module.cp312-win_amd64.pyd",
    "..\lab2\build\Debug\crypto_module.pyd"
)

$moduleFound = $false
foreach ($moduleFile in $moduleFiles) {
    if (Test-Path $moduleFile) {
        Write-Host "  Found $(Split-Path -Leaf $moduleFile)" -ForegroundColor Green
        $moduleFound = $true
        break
    }
}

if (-not $moduleFound) {
    Write-Host "  crypto_module not found!" -ForegroundColor Red
    Write-Host "  Searched for:" -ForegroundColor Yellow
    foreach ($file in $moduleFiles) {
        Write-Host "    - $file" -ForegroundColor Yellow
    }
    exit 1
}
Write-Host ""

# Step 3: Install Python dependencies
Write-Host "[3/3] Installing Python dependencies..." -ForegroundColor Green

pip install cryptography --quiet
if ($LASTEXITCODE -ne 0) {
    Write-Host "  Failed to install dependencies" -ForegroundColor Red
    exit 1
}

Write-Host "  Python dependencies installed" -ForegroundColor Green
Write-Host ""

# Success
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Build completed successfully!" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "Quick Start:" -ForegroundColor Yellow
Write-Host "  1. Start keyserver:  python keyserver.py" -ForegroundColor White
Write-Host "  2. Start client:     python client.py Alice 9001" -ForegroundColor White
Write-Host "  3. In another terminal: python client.py Bob 9002" -ForegroundColor White
Write-Host ""
