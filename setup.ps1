# OSINT-ThreatLink Module 1 - Automated Setup Script
# Run with: .\setup.ps1

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "OSINT-ThreatLink Module 1 Setup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check Python
Write-Host "[*] Checking Python installation..." -ForegroundColor Yellow
try {
    $pythonVersion = python --version 2>&1
    Write-Host "    $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "    [ERROR] Python not found!" -ForegroundColor Red
    Write-Host "    Download from: https://www.python.org/downloads/" -ForegroundColor Yellow
    exit 1
}

# Check if virtual environment exists
Write-Host ""
Write-Host "[*] Checking virtual environment..." -ForegroundColor Yellow
if (Test-Path "osint-env") {
    Write-Host "    Virtual environment already exists" -ForegroundColor Green
    $createVenv = Read-Host "    Recreate it? (y/n)"
    if ($createVenv -eq "y") {
        Remove-Item -Recurse -Force "osint-env"
        python -m venv osint-env
        Write-Host "    Virtual environment recreated" -ForegroundColor Green
    }
} else {
    Write-Host "    Creating virtual environment..." -ForegroundColor Yellow
    python -m venv osint-env
    Write-Host "    Virtual environment created" -ForegroundColor Green
}

# Activate virtual environment
Write-Host ""
Write-Host "[*] Activating virtual environment..." -ForegroundColor Yellow
& ".\osint-env\Scripts\Activate.ps1"

# Upgrade pip
Write-Host ""
Write-Host "[*] Upgrading pip..." -ForegroundColor Yellow
python -m pip install --upgrade pip --quiet

# Install requirements
Write-Host ""
Write-Host "[*] Installing Python packages..." -ForegroundColor Yellow
if (Test-Path "requirements.txt") {
    pip install -r requirements.txt
    Write-Host "    All Python packages installed" -ForegroundColor Green
} else {
    Write-Host "    [WARNING] requirements.txt not found" -ForegroundColor Red
    Write-Host "    Installing packages manually..." -ForegroundColor Yellow
    
    pip install sherlock-project holehe httpx[cli] requests beautifulsoup4 lxml dnspython python-whois colorama
    Write-Host "    Packages installed" -ForegroundColor Green
}

# Check Subfinder
Write-Host ""
Write-Host "[*] Checking Subfinder..." -ForegroundColor Yellow
try {
    subfinderVersion = subfinder -version 2>&1
    Write-Host "    Subfinder installed" -ForegroundColor Green
} catch {
    Write-Host "    [WARNING] Subfinder not found" -ForegroundColor Red
    Write-Host ""
    Write-Host "    To install Subfinder:" -ForegroundColor Yellow
    Write-Host "    1. Download from: https://github.com/projectdiscovery/subfinder/releases" -ForegroundColor Yellow
    Write-Host "    2. Extract subfinder.exe to C:\osint-tools\" -ForegroundColor Yellow
    Write-Host "    3. Add C:\osint-tools\ to your PATH" -ForegroundColor Yellow
    Write-Host ""
    
    $installSubfinder = Read-Host "    Open Subfinder releases page? (y/n)"
    if ($installSubfinder -eq "y") {
        Start-Process "https://github.com/projectdiscovery/subfinder/releases"
    }
}

# Create directory structure
Write-Host ""
Write-Host "[*] Creating directory structure..." -ForegroundColor Yellow
$directories = @("output", "data", "logs", "output/sherlock")
foreach ($dir in $directories) {
    if (!(Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir | Out-Null
        Write-Host "    Created: $dir" -ForegroundColor Green
    }
}

# Verify installation
Write-Host ""
Write-Host "[*] Verifying installation..." -ForegroundColor Yellow
Write-Host ""

# Test imports
$modules = @(
    "dns.resolver",
    "whois",
    "httpx",
    "bs4",
    "requests",
    "lxml"
)

$allGood = $true
foreach ($module in $modules) {
    try {
        python -c "import $module" 2>$null
        Write-Host "    [OK] $module" -ForegroundColor Green
    } catch {
        Write-Host "    [FAIL] $module" -ForegroundColor Red
        $allGood = $false
    }
}

# Test CLI tools
Write-Host ""
$tools = @{
    "sherlock" = "sherlock --version"
    "holehe" = "holehe --help"
}

foreach ($tool in $tools.Keys) {
    try {
        Invoke-Expression $tools[$tool] 2>$null | Out-Null
        Write-Host "    [OK] $tool" -ForegroundColor Green
    } catch {
        Write-Host "    [FAIL] $tool" -ForegroundColor Red
        $allGood = $false
    }
}

# Summary
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Setup Complete!" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

if ($allGood) {
    Write-Host "[SUCCESS] All dependencies installed!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Yellow
    Write-Host "  1. Test installation: python test_orchestrator.py" -ForegroundColor White
    Write-Host "  2. Run quick start: python quick_start.py" -ForegroundColor White
    Write-Host "  3. Scan a domain: python orchestrator.py example.com" -ForegroundColor White
} else {
    Write-Host "[WARNING] Some dependencies failed to install" -ForegroundColor Yellow
    Write-Host "Review the errors above and install missing packages" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")