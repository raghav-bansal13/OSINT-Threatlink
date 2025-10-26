# OSINT-ThreatLink Module 1 - Troubleshooting Guide

## 🚨 Common Issues & Solutions

---

## Installation Issues

### ❌ "Python not recognized"

**Cause:** Python not installed or not in PATH

**Solution:**
```powershell
# Check if Python is installed
python --version

# If not found, download from:
# https://www.python.org/downloads/

# During installation, CHECK "Add Python to PATH"
```

---

### ❌ "pip: command not found"

**Cause:** pip not installed or Python installation incomplete

**Solution:**
```powershell
# Reinstall pip
python -m ensurepip --upgrade

# Or download get-pip.py
curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
python get-pip.py
```

---

### ❌ "Cannot activate virtual environment"

**Error:**
```
.\osint-env\Scripts\Activate.ps1 : cannot be loaded because running scripts is disabled
```

**Cause:** PowerShell execution policy restriction

**Solution:**
```powershell
# Option 1: Temporarily allow scripts (recommended)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process

# Then activate
.\osint-env\Scripts\Activate.ps1

# Option 2: Use Command Prompt instead
osint-env\Scripts\activate.bat
```

---

### ❌ "ModuleNotFoundError: No module named 'X'"

**Cause:** Package not installed in virtual environment

**Solution:**
```powershell
# Ensure virtual environment is active
.\osint-env\Scripts\Activate.ps1

# Install missing package
pip install <package-name>

# Or reinstall all requirements
pip install -r requirements.txt
```

---

## Tool-Specific Issues

### ❌ "Subfinder not found"

**Cause:** Subfinder not installed or not in PATH

**Solution 1: Download Binary (Easiest)**
```powershell
# 1. Download from GitHub
# https://github.com/projectdiscovery/subfinder/releases

# 2. Extract to: C:\osint-tools\

# 3. Add to PATH temporarily
$env:Path += ";C:\osint-tools"

# 4. Test
subfinder -version

# 5. Add permanently via:
# System Properties > Environment Variables > Path > New > C:\osint-tools
```

**Solution 2: Install via Go**
```powershell
# Install Go first from: https://golang.org/dl/

# Then install subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Add Go bin to PATH
$env:Path += ";$env:USERPROFILE\go\bin"
```

---

### ❌ "Sherlock not found"

**Cause:** Sherlock not installed properly

**Solution:**
```powershell
# Activate virtual environment
.\osint-env\Scripts\Activate.ps1

# Uninstall and reinstall
pip uninstall sherlock-project -y
pip install sherlock-project

# Test
sherlock --version
```

---

### ❌ "Holehe: command not found"

**Solution:**
```powershell
# Ensure holehe is installed
pip install holehe

# If still not working, run as module
python -m holehe test@example.com
```

---

## Runtime Errors

### ❌ "TimeoutError" during scan

**Cause:** Tool taking too long or network issues

**Solution 1: Increase Timeouts**

Edit `config.py`:
```python
SUBFINDER_CONFIG = {
    "timeout": 600  # Increase from 300 to 600 seconds
}

HOLEHE_CONFIG = {
    "timeout": 180  # Increase from 120 to 180 seconds
}
```

**Solution 2: Skip Slow Tools**

Edit `orchestrator.py` in the `run_all()` method:
```python
# Comment out slow operations
# self.run_holehe(email)  # Skip if too slow
# self.run_sherlock(username)  # Skip if too slow
```

---

### ❌ "No subdomains found"

**Cause:** Target has few subdomains OR subfinder rate limited

**Solution:**
```powershell
# Test subfinder manually
subfinder -d example.com -o test.txt

# Check if test.txt has results
cat test.txt

# If empty, try different target
subfinder -d github.com -o test.txt
```

**Alternative:** Use DNS brute force as backup:
```python
# The orchestrator will fall back to common subdomains
# Check COMMON_SUBDOMAINS list in config.py
```

---

### ❌ "ConnectionError" or "SSLError"

**Cause:** Network connectivity or SSL certificate issues

**Solution:**
```powershell
# Test network connectivity
ping 8.8.8.8

# Test specific domain
curl https://example.com

# If behind proxy, set environment variables
$env:HTTP_PROXY = "http://proxy:port"
$env:HTTPS_PROXY = "https://proxy:port"
```

---

### ❌ "PermissionError: [WinError 5] Access denied"

**Cause:** Insufficient permissions to create files/directories

**Solution:**
```powershell
# Run as Administrator OR

# Change project location to user directory
cd C:\Users\YourUsername\Documents\osint-threatlink

# Give full permissions to project folder
icacls . /grant Users:F /T
```

---

### ❌ "UnicodeDecodeError"

**Cause:** Tool output contains special characters

**Solution:**

Edit `orchestrator.py`, add encoding parameter:
```python
# Change this:
result = subprocess.run(cmd, capture_output=True, text=True)

# To this:
result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='ignore')
```

---

## Performance Issues

### ⏱️ Scan takes too long (>5 minutes)

**Optimization 1: Reduce Scope**

Edit `orchestrator.py`:
```python
# Line ~295 in run_all()
all_domains = [self.target] + subdomains[:10]  # Reduce from 20 to 10

# Line ~303 - Limit emails
for email in self.results["emails"][:2]:  # Reduce from 3 to 2

# Line ~309 - Limit usernames
for username in potential_usernames[:2]:  # Reduce from 3 to 2
```

**Optimization 2: Skip Heavy Tools**

Comment out in `run_all()`:
```python
def run_all(self):
    # ... existing code ...
    
    # subdomains = self.run_subfinder()  # Skip if too slow
    dns_data = self.run_dns_lookup()
    whois_data = self.run_whois()
    
    # Only probe main domain, skip subdomains
    asyncio.run(self.run_httpx_probes([self.target]))
    
    # Skip these entirely for quick scans
    # self.run_holehe(email)
    # self.run_sherlock(username)
```

---

### 💾 High Memory Usage

**Cause:** Large number of subdomains/endpoints

**Solution:**

Process in batches:
```python
# In run_httpx_probes, add batch processing
BATCH_SIZE = 20
for i in range(0, len(urls), BATCH_SIZE):
    batch = urls[i:i+BATCH_SIZE]
    batch_results = await asyncio.gather(*[self.probe_endpoint_async(client, url) for url in batch])
    valid_results.extend([r for r in batch_results if r])
```

---

## Output Issues

### ❌ "No JSON file created"

**Cause:** Error during save_results()

**Solution:**

Check logs:
```powershell
# View last 20 lines of log
Get-Content logs\orchestrator.log -Tail 20

# Check if data directory exists
Test-Path data\

# Create manually if needed
mkdir data
```

---

### ❌ "Cannot read JSON file"

**Cause:** Malformed JSON or incomplete scan

**Solution:**
```powershell
# Validate JSON
python -m json.tool data\osint_results_*.json

# If invalid, check logs for errors during scan
cat logs\orchestrator.log | Select-String "error"
```

---

## Windows-Specific Issues

### ❌ "Path too long" error

**Cause:** Windows MAX_PATH limitation (260 characters)

**Solution 1: Enable Long Paths**
```powershell
# Run as Administrator
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "LongPathsEnabled" -Value 1 -PropertyType DWORD -Force

# Restart required
```

**Solution 2: Use shorter project path**
```powershell
# Move project to root
cd C:\
mkdir osint
cd osint
# Continue from here
```

---

### ❌ "Antivirus blocking tools"

**Cause:** Security software flagging OSINT tools as suspicious

**Solution:**
```powershell
# Add project folder to exclusions
# Windows Security > Virus & threat protection > Exclusions > Add folder

# Or temporarily disable real-time protection (NOT recommended)
```

---

## Data/API Issues

### ❌ "Rate limit exceeded"

**Cause:** Too many requests to third-party services

**Solution:**
```powershell
# Wait 10-15 minutes before retrying

# Use VPN to change IP (if ethical and allowed)

# Reduce request frequency in config.py
```

---

### ❌ "No WHOIS data returned"

**Cause:** WHOIS server blocking requests or domain recently registered

**Solution:**

Test manually:
```powershell
# Windows
nslookup example.com

# Or use online tool
# https://who.is/
```

---

## Integration Issues

### ❌ "Import error: cannot import name 'OSINTOrchestrator'"

**Cause:** Circular import or syntax error

**Solution:**
```powershell
# Check for syntax errors
python -m py_compile orchestrator.py

# If error shown, fix the line number indicated
```

---

### ❌ "Config module not found"

**Cause:** Running from wrong directory

**Solution:**
```powershell
# Always run from project root
cd C:\path\to\osint-threatlink

# Verify files are present
ls config.py
ls orchestrator.py

# Then run
python orchestrator.py example.com
```

---

## Testing Issues

### ❌ Test suite fails with "4/4 tests failed"

**Cause:** Missing dependencies or wrong directory

**Solution:**
```powershell
# 1. Activate virtual environment
.\osint-env\Scripts\Activate.ps1

# 2. Verify you're in project root
pwd  # Should show osint-threatlink directory

# 3. Reinstall dependencies
pip install -r requirements.txt

# 4. Run tests again
python test_orchestrator.py
```

---

## Debug Mode

### Enable Verbose Logging

Edit `config.py`:
```python
VERBOSE = True  # Print everything to console
ENABLE_LOGGING = True  # Save to log file
```

### View Real-Time Logs

```powershell
# In one terminal, run scan
python orchestrator.py example.com

# In another terminal, tail logs
Get-Content logs\orchestrator.log -Wait -Tail 50
```

### Manual Tool Testing

Test each tool individually:
```powershell
# Activate environment
.\osint-env\Scripts\Activate.ps1

# Test Subfinder
subfinder -d example.com -silent

# Test Sherlock
sherlock test_user

# Test Holehe  
holehe test@example.com

# Test httpx (Python)
python -c "import httpx; print(httpx.get('https://example.com').status_code)"

# Test WHOIS
python -c "import whois; print(whois.whois('example.com'))"
```

---

## Still Having Issues?

### Checklist Before Asking for Help

- [ ] Virtual environment activated
- [ ] All dependencies installed (`pip list`)
- [ ] Running from project root directory
- [ ] Config.py exists and is correct
- [ ] Logs checked for specific errors
- [ ] Individual tools tested manually
- [ ] Windows execution policy allows scripts
- [ ] Antivirus not blocking tools
- [ ] Network connectivity working

### Collect Debug Information

```powershell
# Create debug report
python --version > debug_report.txt
pip list >> debug_report.txt
echo "---" >> debug_report.txt
Get-Content logs\orchestrator.log -Tail 50 >> debug_report.txt

# Share debug_report.txt when seeking help
```

---

## Quick Fixes Summary

| Issue | Quick Fix |
|-------|-----------|
| Subfinder not found | Add `C:\osint-tools` to PATH |
| Python not found | Install from python.org, check "Add to PATH" |
| Can't activate venv | Run `Set-ExecutionPolicy RemoteSigned -Scope Process` |
| Timeout errors | Increase timeouts in config.py |
| No results | Try different target domain |
| Slow scan | Reduce scope in orchestrator.py |
| Import errors | Reinstall: `pip install -r requirements.txt` |
| Permission errors | Run from user directory or as admin |

---

## Emergency Reset

If everything breaks:
```powershell
# 1. Delete virtual environment
Remove-Item -Recurse -Force osint-env

# 2. Recreate environment
python -m venv osint-env
.\osint-env\Scripts\Activate.ps1

# 3. Reinstall everything
pip install -r requirements.txt

# 4. Test
python test_orchestrator.py
```

---

**✅ Most issues are resolved by:**
1. Activating virtual environment
2. Reinstalling requirements
3. Running from correct directory
4. Checking logs for specific errors

**📝 When in doubt, check `logs\orchestrator.log` first!