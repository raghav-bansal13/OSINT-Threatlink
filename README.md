# OSINT-ThreatLink Module 1: OSINT Orchestrator

## 📋 Overview

Module 1 automates the reconnaissance phase of cybersecurity assessment by orchestrating multiple OSINT tools to map an organization's digital footprint.

## 🎯 Features

- **Subdomain Discovery**: Automatically finds all subdomains using subfinder
- **DNS Intelligence**: Extracts A, MX, NS, and TXT records
- **WHOIS Lookup**: Gathers domain registration information
- **Web Probing**: Asynchronously probes endpoints and detects technologies
- **Email Intelligence**: Checks email registrations and breach exposure
- **Social Media OSINT**: Hunts for social media profiles
- **Automated Correlation**: Links discovered assets (emails, usernames, domains)

## 📁 Project Structure

```
osint-threatlink/
├── config.py                  # Configuration settings
├── orchestrator.py            # Main orchestration engine
├── test_orchestrator.py       # Test suite
├── requirements.txt           # Python dependencies
├── output/                    # Raw tool outputs
│   ├── subfinder_results.txt
│   ├── holehe_results.txt
│   └── sherlock/
├── data/                      # Processed JSON results
│   └── osint_results_*.json
└── logs/                      # Execution logs
    └── orchestrator.log
```

## 🔧 Installation

### Prerequisites

- Python 3.9+
- Git
- Windows PowerShell / Command Prompt

### Step 1: Clone/Setup Project

```powershell
# Create project directory
mkdir osint-threatlink
cd osint-threatlink

# Create virtual environment
python -m venv osint-env
.\osint-env\Scripts\Activate.ps1
```

### Step 2: Install Python Dependencies

```powershell
pip install -r requirements.txt
```

### Step 3: Install Subfinder (Binary)

**Option A: Direct Download (Recommended)**
1. Go to: https://github.com/projectdiscovery/subfinder/releases
2. Download: `subfinder_*_windows_amd64.zip`
3. Extract `subfinder.exe` to `C:\osint-tools\`
4. Add to PATH:

```powershell
# Temporary (current session)
$env:Path += ";C:\osint-tools"

# Permanent (add via System Properties > Environment Variables)
# Add C:\osint-tools to System PATH
```

**Option B: Via Go**
```powershell
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

### Step 4: Verify Installation

```powershell
python test_orchestrator.py
```

Expected output:
```
✅ All Python modules imported successfully
✅ All CLI tools available
✅ Configuration OK
✅ Orchestrator OK
Results: 4/4 tests passed
```

## 🚀 Usage

### Basic Usage

```powershell
python orchestrator.py <target_domain>
```

### Examples

```powershell
# Scan a single domain
python orchestrator.py example.com

# Scan a company domain
python orchestrator.py tesla.com

# Scan with verbose output
python orchestrator.py github.com
```

### Output

The orchestrator will:
1. Create timestamped output files in `output/`
2. Save structured JSON results in `data/`
3. Log execution details to `logs/orchestrator.log`

**Sample Output:**
```
============================================================
Starting OSINT reconnaissance on: example.com
============================================================
[INFO] Running subfinder on example.com...
[INFO] Found 15 subdomains via subfinder
[INFO] Performing DNS lookups for example.com...
[INFO] Found 2 A records
[INFO] Found 3 MX records
[INFO] Fetching WHOIS data for example.com...
[INFO] WHOIS data retrieved successfully
[INFO] Probing 16 endpoints with httpx...
[INFO] Probed https://example.com: 200 - Example Domain
[INFO] Successfully probed 14/16 endpoints
[INFO] Running holehe on admin@example.com...
[INFO] Found 8 registrations for admin@example.com
============================================================
OSINT reconnaissance completed in 127.45 seconds
============================================================

============================================================
OSINT SUMMARY FOR: example.com
============================================================
Subdomains Found: 15
Emails Found: 2
Social Profiles: 7
Web Endpoints Probed: 14
DNS Records: 8
============================================================
```

## 📊 Output Data Structure

### JSON Output Format

```json
{
  "target": "example.com",
  "timestamp": "20250126_143022",
  "subdomains": [
    "www.example.com",
    "mail.example.com",
    "dev.example.com"
  ],
  "emails": [
    "admin@example.com",
    "contact@example.com"
  ],
  "social_profiles": [
    "https://twitter.com/example",
    "https://github.com/example"
  ],
  "web_endpoints": [
    {
      "url": "https://example.com",
      "status_code": 200,
      "title": "Example Domain",
      "server": "nginx",
      "content_length": 1256,
      "technologies": ["React", "jQuery"],
      "headers": {...}
    }
  ],
  "whois_data": {
    "domain_name": "EXAMPLE.COM",
    "registrar": "MarkMonitor Inc.",
    "creation_date": "1995-08-14",
    "expiration_date": "2025-08-13",
    "name_servers": ["a.iana-servers.net"],
    "emails": ["admin@example.com"]
  },
  "dns_records": {
    "A": ["93.184.216.34"],
    "MX": ["mail.example.com"],
    "NS": ["a.iana-servers.net", "b.iana-servers.net"],
    "TXT": ["v=spf1 -all"]
  }
}
```

## ⚙️ Configuration

Edit `config.py` to customize:

### Timeouts
```python
SUBFINDER_CONFIG = {
    "timeout": 300  # 5 minutes
}

SHERLOCK_CONFIG = {
    "timeout": 60  # 1 minute
}
```

### Output Paths
```python
OUTPUT_DIR = BASE_DIR / "output"
DATA_DIR = BASE_DIR / "data"
LOGS_DIR = BASE_DIR / "logs"
```

### Verbosity
```python
VERBOSE = True  # Print detailed logs to console
ENABLE_LOGGING = True  # Save logs to file
```

## 🔍 Tool-by-Tool Breakdown

| Tool | Purpose | Input | Output | Speed |
|------|---------|-------|--------|-------|
| **Subfinder** | Subdomain enumeration | Domain | List of subdomains | Fast (30-60s) |
| **DNS Python** | DNS record lookup | Domain | A, MX, NS, TXT records | Very Fast (5-10s) |
| **WHOIS** | Domain registration info | Domain | Registrar, dates, emails | Fast (5-10s) |
| **httpx** | Web probing & tech detection | URLs | Status, title, tech stack | Medium (async) |
| **Holehe** | Email registration check | Email | Sites where registered | Slow (60-120s) |
| **Sherlock** | Social media username search | Username | Social profiles | Medium (30-60s) |

## 🐛 Troubleshooting

### Problem: "Subfinder not found"

**Solution:**
```powershell
# Check if subfinder is in PATH
subfinder -version

# If not found, add to PATH
$env:Path += ";C:\path\to\subfinder"
```

### Problem: "Sherlock not found"

**Solution:**
```powershell
pip install sherlock-project
# Test
sherlock --version
```

### Problem: "Holehe not found"

**Solution:**
```powershell
pip install holehe
# Test
holehe --help
```

### Problem: "TimeoutError"

**Solution:** Increase timeouts in `config.py`:
```python
SUBFINDER_CONFIG = {
    "timeout": 600  # Increase to 10 minutes
}
```

### Problem: "No subdomains found"

**Possible Reasons:**
- Target domain has very few subdomains
- Subfinder API rate limits reached
- Network connectivity issues

**Solution:** Try manually:
```powershell
subfinder -d example.com -o test.txt
```

### Problem: "httpx errors"

**Solution:** Check if domains are reachable:
```powershell
# Test with Python
python -c "import httpx; print(httpx.get('https://example.com').status_code)"
```

## 📈 Performance Tips

### Speed Optimization

1. **Limit Endpoint Probing:**
```python
# In orchestrator.py, line ~300
all_domains = [self.target] + subdomains[:10]  # Reduce from 20 to 10
```

2. **Skip Slow Tools:**
```python
# Comment out in run_all() method
# self.run_holehe(email)  # Skip holehe (slow)
# self.run_sherlock(username)  # Skip sherlock (medium)
```

3. **Use Parallel Processing:**
The httpx probes already use async. Other tools run sequentially by design.

### Memory Optimization

For large-scale scans:
```python
# Process results in batches
BATCH_SIZE = 50
for i in range(0, len(subdomains), BATCH_SIZE):
    batch = subdomains[i:i+BATCH_SIZE]
    asyncio.run(self.run_httpx_probes(batch))
```

## 🔐 Security Considerations

### Ethical Use

⚠️ **IMPORTANT**: Only scan domains you own or have explicit permission to test.

- Aggressive scanning may violate Terms of Service
- Some tools query third-party APIs (rate limits apply)
- Web probing generates HTTP traffic (may be logged)

### Rate Limiting

Built-in protections:
- Subfinder: Uses passive DNS (no direct scanning)
- httpx: Limited to 10 concurrent connections
- Sherlock: Timeout per site prevents flooding

### Anonymity

This tool does NOT provide anonymity:
- Your IP address is exposed in HTTP requests
- DNS queries are logged by resolvers
- WHOIS lookups may be logged

For sensitive assessments, use through a VPN or proxy.

## 🎯 What's Next?

### Module 2: Data Parser & Correlator (Day 3)
- Parse raw tool outputs
- Extract entities (IPs, emails, domains)
- Build graph structure (nodes & edges)
- Correlate relationships

### Module 3: ML Risk Scoring Engine (Day 4-5)
- Heuristic baseline scoring
- Integrate phishing URL classifier
- Risk scoring for all assets

### Module 4: Visualization Dashboard (Day 6)
- Flask backend API
- Interactive network graph (vis.js)
- Color-coded risk visualization

## 📝 Testing Checklist

Before moving to Module 2:

- [ ] All tools install successfully
- [ ] Test suite passes (4/4 tests)
- [ ] Can scan example.com without errors
- [ ] JSON output file created in `data/`
- [ ] All 6 tools execute (check logs)
- [ ] Subdomains discovered (if target has any)
- [ ] Web endpoints probed successfully

## 🤝 Contributing

When moving to Module 2, preserve this structure:
- Keep `orchestrator.py` unchanged
- Module 2 will CONSUME the JSON output
- Module 3 will ADD risk scores to the data
- Module 4 will VISUALIZE the final results

## 📚 Resources

- [Subfinder GitHub](https://github.com/projectdiscovery/subfinder)
- [Sherlock Documentation](https://github.com/sherlock-project/sherlock)
- [Holehe GitHub](https://github.com/megadose/holehe)
- [httpx Documentation](https://www.python-httpx.org/)
- [OSINT Framework](https://osintframework.com/)

## 📄 License

This project is for educational and authorized security testing only.

---

**🎉 Module 1 Complete! Ready for Module 2: Data Parser & Correlator**# OSINT-Threatlink
