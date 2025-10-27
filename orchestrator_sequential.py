"""
OSINT-ThreatLink Module 1: OSINT Orchestrator
Automates the execution of multiple OSINT tools and collects raw output
"""

import subprocess
import sys
import json
import time
import asyncio
from pathlib import Path
from datetime import datetime

import dns.resolver
import whois
import httpx
from bs4 import BeautifulSoup

import config

class OSINTOrchestrator:
    """Main orchestrator class that runs all OSINT tools"""
    
    def __init__(self, target_domain):
        self.target = target_domain
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.results = {
            "target": target_domain,
            "timestamp": self.timestamp,
            "subdomains": [],
            "emails": [],
            "social_profiles": [],
            "web_endpoints": [],
            "whois_data": {},
            "dns_records": []
        }
        
        if config.ENABLE_LOGGING:
            self._setup_logging()
    
        self._clear_old_outputs()
    
    def _setup_logging(self):
        """Setup logging configuration"""
        import logging
        logging.basicConfig(
            filename=config.LOG_FILE,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    def _log(self, message, level="info"):
        """Log message to console and file"""
        if config.VERBOSE:
            print(f"[{level.upper()}] {message}")
        if config.ENABLE_LOGGING:
            getattr(self.logger, level)(message)

    def _clear_old_outputs(self):
        try:
            # Clear subfinder output
            subfinder_output = config.SUBFINDER_CONFIG["output_file"]
            if subfinder_output.exists():
                subfinder_output.unlink()
                self._log("Cleared old subfinder output")
            
            # Note: holehe and sherlock now use target-specific names,
            # so they won't conflict between runs
            
        except Exception as e:
            self._log(f"Error clearing outputs: {str(e)}", "warning")
    
    # ============================================
    # TOOL 1: SUBFINDER - Subdomain Enumeration
    # ============================================
    def run_subfinder(self):
        """Execute subfinder to discover subdomains"""
        self._log(f"Running subfinder on {self.target}...")
        
        try:
            output_file = config.OUTPUT_DIR / f"subfinder_{self.target}_{self.timestamp}.txt"
            
            cmd = [
                "subfinder",
                "-d", self.target,
                "-o", str(output_file),
                "-silent" if config.SUBFINDER_CONFIG["silent"] else ""
            ]
            
            # Remove empty strings from cmd
            cmd = [c for c in cmd if c]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=config.SUBFINDER_CONFIG["timeout"]
            )
            
            # Read results
            if output_file.exists():
                with open(output_file, 'r') as f:
                    subdomains = [line.strip() for line in f if line.strip()]
                    self.results["subdomains"] = subdomains
                    self._log(f"Found {len(subdomains)} subdomains via subfinder")
                    return subdomains
            else:
                self._log("Subfinder output file not found", "warning")
                return []
                
        except subprocess.TimeoutExpired:
            self._log("Subfinder timed out", "error")
            return []
        except FileNotFoundError:
            self._log("Subfinder not found. Install it or ensure it's in PATH", "error")
            return []
        except Exception as e:
            self._log(f"Subfinder error: {str(e)}", "error")
            return []
    
    # ============================================
    # TOOL 2: DNS PYTHON - DNS Records
    # ============================================
    def run_dns_lookup(self):
        """Perform DNS lookups for A, MX, NS records"""
        self._log(f"Performing DNS lookups for {self.target}...")
        
        dns_data = {
            "A": [],
            "MX": [],
            "NS": [],
            "TXT": []
        }
        
        resolver = dns.resolver.Resolver()
        resolver.timeout = config.DNS_CONFIG["timeout"]
        resolver.nameservers = config.DNS_CONFIG["nameservers"]
        
        record_types = ['A', 'MX', 'NS', 'TXT']
        
        for record_type in record_types:
            try:
                answers = resolver.resolve(self.target, record_type)
                for rdata in answers:
                    dns_data[record_type].append(str(rdata))
                
                self._log(f"Found {len(answers)} {record_type} records")
            except dns.exception.DNSException as e:
                self._log(f"No {record_type} records found: {str(e)}", "warning")
            except Exception as e:
                self._log(f"DNS lookup error for {record_type}: {str(e)}", "error")
        
        self.results["dns_records"] = dns_data
        return dns_data
    
    # ============================================
    # TOOL 3: WHOIS - Domain Information
    # ============================================
    def run_whois(self):
        """Fetch WHOIS information for the domain"""
        self._log(f"Fetching WHOIS data for {self.target}...")
        
        try:
            w = whois.whois(self.target)
            
            whois_data = {
                "domain_name": w.domain_name if hasattr(w, 'domain_name') else None,
                "registrar": w.registrar if hasattr(w, 'registrar') else None,
                "creation_date": str(w.creation_date) if hasattr(w, 'creation_date') else None,
                "expiration_date": str(w.expiration_date) if hasattr(w, 'expiration_date') else None,
                "name_servers": w.name_servers if hasattr(w, 'name_servers') else [],
                "emails": w.emails if hasattr(w, 'emails') else []
            }
            
            self.results["whois_data"] = whois_data
            
            # Extract emails from WHOIS
            if whois_data.get("emails"):
                self.results["emails"].extend(whois_data["emails"])
            
            self._log("WHOIS data retrieved successfully")
            return whois_data
            
        except Exception as e:
            self._log(f"WHOIS lookup error: {str(e)}", "error")
            return {}
    
    # ============================================
    # TOOL 4: HOLEHE - Email Registration Check
    # ============================================
    def run_holehe(self, email):
        """Check if email is registered on various sites using holehe"""
        self._log(f"Running holehe on {email}...")
        
        try:
            output_file = config.OUTPUT_DIR / f"holehe_{self.target}_{self.timestamp}.txt"
            
            cmd = [
                "holehe",
                email,
                "--only-used"  # Only show sites where email is registered
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=config.HOLEHE_CONFIG["timeout"]
            )
            
            # Parse output
            registrations = []
            if result.stdout:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if '[+]' in line or 'used' in line.lower():
                        registrations.append(line.strip())
            
            self._log(f"Found {len(registrations)} registrations for {email}")
            
            # Save to file
            with open(output_file, 'a') as f:
                f.write(f"\n=== {email} - {self.timestamp} ===\n")
                f.write(result.stdout)
            
            return registrations
            
        except subprocess.TimeoutExpired:
            self._log("Holehe timed out", "error")
            return []
        except FileNotFoundError:
            self._log("Holehe not found. Install it with: pip install holehe", "error")
            return []
        except Exception as e:
            self._log(f"Holehe error: {str(e)}", "error")
            return []
    
    # ============================================
    # TOOL 5: SHERLOCK - Username Search
    # ============================================
    def run_sherlock(self, username):
        """Search for username across social media platforms"""
        self._log(f"Running sherlock on username: {username}...")
        
        try:
            output_dir = config.OUTPUT_DIR / "sherlock" / f"{self.target}_{self.timestamp}"
            output_dir.mkdir(exist_ok=True)
            
            cmd = [
                "sherlock",
                username,
                "--timeout", str(config.SHERLOCK_CONFIG["timeout"]),
                "--folderoutput", str(output_dir),
                "--print-found"
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=config.SHERLOCK_CONFIG["timeout"] + 30
            )
            
            # Parse found profiles
            profiles = []
            if result.stdout:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if 'http' in line.lower():
                        profiles.append(line.strip())
            
            self._log(f"Found {len(profiles)} social profiles for {username}")
            return profiles
            
        except subprocess.TimeoutExpired:
            self._log("Sherlock timed out", "error")
            return []
        except FileNotFoundError:
            self._log("Sherlock not found. Install it with: pip install sherlock-project", "error")
            return []
        except Exception as e:
            self._log(f"Sherlock error: {str(e)}", "error")
            return []
    
    # ============================================
    # TOOL 6: HTTPX - Web Endpoint Probing
    # ============================================
    async def probe_endpoint_async(self, client, url):
        """Async probe a single endpoint with httpx"""
        
        if not url.startswith('http'):
            url = f"https://{url}"
        
        try:
            response = await client.get(
                url,
                timeout=config.HTTPX_CONFIG["timeout"],
                follow_redirects=config.HTTPX_CONFIG["follow_redirects"]
            )
            
            # Extract title
            soup = BeautifulSoup(response.text, 'lxml')
            title = soup.title.string if soup.title else "No title"
            
            # Detect basic technologies
            technologies = []
            html_lower = response.text.lower()
            
            if 'wordpress' in html_lower:
                technologies.append('WordPress')
            if 'react' in html_lower:
                technologies.append('React')
            if 'jquery' in html_lower:
                technologies.append('jQuery')
            if 'angular' in html_lower:
                technologies.append('Angular')
            
            endpoint_data = {
                "url": url,
                "status_code": response.status_code,
                "title": title.strip() if title else "",
                "server": response.headers.get('Server', 'Unknown'),
                "content_length": len(response.text),
                "technologies": technologies,
                "headers": dict(response.headers)
            }
            
            self._log(f"Probed {url}: {response.status_code} - {title}")
            return endpoint_data
            
        except httpx.TimeoutException:
            self._log(f"Timeout probing {url}", "warning")
            return None
        except Exception as e:
            self._log(f"Error probing {url}: {str(e)}", "warning")
            return None
    
    async def run_httpx_probes(self, urls):
        """Probe multiple URLs concurrently with httpx"""
        self._log(f"Probing {len(urls)} endpoints with httpx...")
        
        async with httpx.AsyncClient() as client:
            tasks = [self.probe_endpoint_async(client, url) for url in urls]
            results = await asyncio.gather(*tasks)
        
        # Filter out None results
        valid_results = [r for r in results if r is not None]
        self.results["web_endpoints"] = valid_results
        
        self._log(f"Successfully probed {len(valid_results)}/{len(urls)} endpoints")
        return valid_results
    
    # ============================================
    # MAIN ORCHESTRATION
    # ============================================
    def run_all(self):
        """Execute all OSINT tools in sequence"""
        self._log("="*60)
        self._log(f"Starting OSINT reconnaissance on: {self.target}")
        self._log("="*60)
        
        start_time = time.time()
        
        # Step 1: Subdomain enumeration
        subdomains = self.run_subfinder()
        
        # Step 2: DNS lookups
        dns_data = self.run_dns_lookup()
        
        # Step 3: WHOIS lookup
        whois_data = self.run_whois()
        
        # Step 4: Web endpoint probing (async)
        if subdomains:
            # Probe discovered subdomains + main domain
            all_domains = [self.target] + subdomains[:20]  # Limit to 20 for speed
            asyncio.run(self.run_httpx_probes(all_domains))
        
        # Step 5: Email checks (if emails found in WHOIS)
        if self.results.get("emails"):
            for email in self.results["emails"][:3]:  # Limit to 3 emails
                self.run_holehe(email)
        
        # Step 6: Username search (extract from emails/subdomains)
        potential_usernames = self._extract_usernames()
        if potential_usernames:
            for username in potential_usernames[:3]:  # Limit to 3 usernames
                profiles = self.run_sherlock(username)
                self.results["social_profiles"].extend(profiles)
        
        elapsed = time.time() - start_time
        self._log("="*60)
        self._log(f"OSINT reconnaissance completed in {elapsed:.2f} seconds")
        self._log("="*60)
        
        # Save final results
        self.save_results()
        
        return self.results
    
    def _extract_usernames(self):
        """Extract potential usernames from emails and subdomains"""
        usernames = set()
        
        # From emails
        for email in self.results.get("emails", []):
            if '@' in email:
                username = email.split('@')[0]
                usernames.add(username)
        
        # From subdomains (admin, dev, etc.)
        for subdomain in self.results.get("subdomains", [])[:10]:
            parts = subdomain.replace(self.target, '').split('.')
            for part in parts:
                if part and len(part) > 3 and part not in ['www', 'mail', 'ftp']:
                    usernames.add(part)
        
        return list(usernames)[:5]  # Return max 5 usernames
    
    def save_results(self):
        """Save all results to JSON file"""
        output_file = config.DATA_DIR / f"osint_results_{self.target}_{self.timestamp}.json"
        
        try:
            with open(output_file, 'w') as f:
                json.dump(self.results, f, indent=2, default=str)
            
            self._log(f"Results saved to: {output_file}")
        except Exception as e:
            self._log(f"Error saving results: {str(e)}", "error")
    
    def print_summary(self):
        """Print a summary of findings"""
        print("\n" + "="*60)
        print(f"OSINT SUMMARY FOR: {self.target}")
        print("="*60)
        print(f"Subdomains Found: {len(self.results.get('subdomains', []))}")
        print(f"Emails Found: {len(self.results.get('emails', []))}")
        print(f"Social Profiles: {len(self.results.get('social_profiles', []))}")
        print(f"Web Endpoints Probed: {len(self.results.get('web_endpoints', []))}")
        print(f"DNS Records: {sum(len(v) for v in self.results.get('dns_records', {}).values())}")
        print("="*60)


def main():
    """Main entry point"""
    if len(sys.argv) < 2:
        print("Usage: python orchestrator.py <target_domain>")
        print("Example: python orchestrator.py example.com")
        sys.exit(1)
    
    target = sys.argv[1]
    
    # Create orchestrator
    orchestrator = OSINTOrchestrator(target)
    
    # Run all tools
    results = orchestrator.run_all()
    
    # Print summary
    orchestrator.print_summary()


if __name__ == "__main__":
    main()