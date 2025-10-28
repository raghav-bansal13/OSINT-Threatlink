import subprocess
import sys
import json
import time
import asyncio
from pathlib import Path
from datetime import datetime
import logging

from concurrent.futures import ThreadPoolExecutor, as_completed

import dns.resolver
import whois
import httpx
from bs4 import BeautifulSoup

import config

class OSINTOrchestrator:
    
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
        logging.basicConfig(
            filename=config.LOG_FILE,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    def _log(self, message, level="info"):
        if config.VERBOSE:
            print(f"[{level.upper()}] {message}")
        if config.ENABLE_LOGGING:
            getattr(self.logger, level)(message)
    
    def _clear_old_outputs(self):
        try:
            subfinder_output = config.SUBFINDER_CONFIG["output_file"]
            if subfinder_output.exists():
                subfinder_output.unlink()
                self._log("Cleared old subfinder output")
        except Exception as e:
            self._log(f"Error clearing outputs: {str(e)}", "warning")
    
    def run_subfinder(self):
        self._log(f"[PARALLEL] Running subfinder on {self.target}...")
        
        try:
            output_file = config.OUTPUT_DIR / f"subfinder_{self.target}_{self.timestamp}.txt"
            
            cmd = [
                "subfinder",
                "-d", self.target,
                "-o", str(output_file),
                "-silent" if config.SUBFINDER_CONFIG["silent"] else ""
            ]
            
            cmd = [c for c in cmd if c]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=config.SUBFINDER_CONFIG["timeout"]
            )
            
            if output_file.exists():
                with open(output_file, 'r') as f:
                    subdomains = [line.strip() for line in f if line.strip()]
                    self._log(f"[SUBFINDER] Found {len(subdomains)} subdomains")
                    return ("subdomains", subdomains)
            else:
                return ("subdomains", [])
                
        except subprocess.TimeoutExpired:
            self._log("[SUBFINDER] Timed out", "error")
            return ("subdomains", [])
        except FileNotFoundError:
            self._log("[SUBFINDER] Not found in PATH", "error")
            return ("subdomains", [])
        except Exception as e:
            self._log(f"[SUBFINDER] Error: {str(e)}", "error")
            return ("subdomains", [])
    
    def run_dns_lookup(self):
        self._log(f"[PARALLEL] Performing DNS lookups for {self.target}...")
        
        dns_data = {"A": [], "MX": [], "NS": [], "TXT": []}
        
        resolver = dns.resolver.Resolver()
        resolver.timeout = config.DNS_CONFIG["timeout"]
        resolver.nameservers = config.DNS_CONFIG["nameservers"]
        
        record_types = ['A', 'MX', 'NS', 'TXT']
        
        for record_type in record_types:
            try:
                answers = resolver.resolve(self.target, record_type)
                for rdata in answers:
                    dns_data[record_type].append(str(rdata))
            except Exception:
                pass
        
        total_records = sum(len(v) for v in dns_data.values())
        self._log(f"[DNS] Found {total_records} total records")
        return ("dns_records", dns_data)
    
    def run_whois(self):
        self._log(f"[PARALLEL] Fetching WHOIS data for {self.target}...")
        
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
            
            emails = whois_data.get("emails", [])
            if emails:
                self._log(f"[WHOIS] Found {len(emails)} emails")
            
            return ("whois", {"whois_data": whois_data, "emails": emails if emails else []})
            
        except Exception as e:
            self._log(f"[WHOIS] Error: {str(e)}", "error")
            return ("whois", {"whois_data": {}, "emails": []})
    
    def run_holehe(self, email):
        self._log(f"[PARALLEL] Running holehe on {email}...")
        
        try:
            output_file = config.OUTPUT_DIR / f"holehe_{self.target}_{self.timestamp}.txt"
            
            cmd = ["holehe", email, "--only-used"]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=config.HOLEHE_CONFIG["timeout"]
            )
            
            registrations = []
            if result.stdout:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if '[+]' in line or 'used' in line.lower():
                        registrations.append(line.strip())
            
            self._log(f"[HOLEHE] Found {len(registrations)} registrations for {email}")
            
            with open(output_file, 'a') as f:
                f.write(f"\n=== {email} - {self.timestamp} ===\n")
                f.write(result.stdout)
            
            return ("holehe", registrations)
            
        except Exception as e:
            self._log(f"[HOLEHE] Error: {str(e)}", "error")
            return ("holehe", [])
    
    def run_sherlock(self, username):
        self._log(f"[PARALLEL] Running sherlock on username: {username}...")
        
        try:
            output_dir = config.OUTPUT_DIR / "sherlock" / f"{self.target}_{self.timestamp}"
            output_dir.mkdir(exist_ok=True, parents=True)
            
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
            
            profiles = []
            if result.stdout:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if 'http' in line.lower():
                        profiles.append(line.strip())
            
            self._log(f"[SHERLOCK] Found {len(profiles)} profiles for {username}")
            return ("sherlock", profiles)
            
        except Exception as e:
            self._log(f"[SHERLOCK] Error: {str(e)}", "error")
            return ("sherlock", [])
    
    async def probe_endpoint_async(self, client, url):
        
        if not url.startswith('http'):
            url = f"https://{url}"
        
        try:
            response = await client.get(
                url,
                timeout=config.HTTPX_CONFIG["timeout"],
                follow_redirects=config.HTTPX_CONFIG["follow_redirects"]
            )
            
            soup = BeautifulSoup(response.text, 'lxml')
            title = soup.title.string if soup.title else "No title"
            
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
            
            return endpoint_data
            
        except Exception:
            return None
    
    async def run_httpx_probes(self, urls):
        self._log(f"[PARALLEL] Probing {len(urls)} endpoints with httpx...")
        
        async with httpx.AsyncClient() as client:
            tasks = [self.probe_endpoint_async(client, url) for url in urls]
            results = await asyncio.gather(*tasks)
        
        valid_results = [r for r in results if r is not None]
        self._log(f"[HTTPX] Successfully probed {len(valid_results)}/{len(urls)} endpoints")
        return ("web_endpoints", valid_results)
    
    def run_all_parallel(self):
        self._log("="*60)
        self._log(f"Starting PARALLEL OSINT reconnaissance on: {self.target}")
        self._log("="*60)
        
        start_time = time.time()
        
        self._log("\n[PHASE 1] Running independent tools in parallel...")
        
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {
                executor.submit(self.run_subfinder): "subfinder",
                executor.submit(self.run_dns_lookup): "dns",
                executor.submit(self.run_whois): "whois"
            }
            
            for future in as_completed(futures):
                tool_name = futures[future]
                try:
                    result_type, result_data = future.result()
                    
                    if result_type == "subdomains":
                        self.results["subdomains"] = result_data
                    elif result_type == "dns_records":
                        self.results["dns_records"] = result_data
                    elif result_type == "whois":
                        self.results["whois_data"] = result_data["whois_data"]
                        if result_data["emails"]:
                            self.results["emails"].extend(result_data["emails"])
                    
                    self._log(f"✓ {tool_name} completed")
                except Exception as e:
                    self._log(f"✗ {tool_name} failed: {str(e)}", "error")
        
        phase1_time = time.time() - start_time
        self._log(f"\n[PHASE 1] Completed in {phase1_time:.2f}s")
        
        self._log("\n[PHASE 2] Running dependent tools in parallel...")
        phase2_start = time.time()
        
        if self.results.get("subdomains"):
            all_domains = [self.target] + self.results["subdomains"][:20]
            web_result_type, web_results = asyncio.run(self.run_httpx_probes(all_domains))
            self.results["web_endpoints"] = web_results
        
        self._log("\n[PHASE 3] Running OSINT on discovered entities...")
        phase3_start = time.time()
        
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = []
            
            for email in self.results.get("emails", [])[:3]:
                futures.append(executor.submit(self.run_holehe, email))
            
            potential_usernames = self._extract_usernames()
            for username in potential_usernames[:3]:
                futures.append(executor.submit(self.run_sherlock, username))
            
            for future in as_completed(futures):
                try:
                    result_type, result_data = future.result()
                    if result_type == "sherlock":
                        self.results["social_profiles"].extend(result_data)
                except Exception as e:
                    self._log(f"✗ Task failed: {str(e)}", "error")
        
        phase3_time = time.time() - phase3_start
        
        elapsed = time.time() - start_time
        self._log("\n" + "="*60)
        self._log(f"PARALLEL OSINT completed in {elapsed:.2f} seconds")
        self._log(f"  Phase 1 (Independent): {phase1_time:.2f}s")
        self._log(f"  Phase 2 (Web probing): {time.time() - phase2_start - phase3_time:.2f}s")
        self._log(f"  Phase 3 (Email/Username): {phase3_time:.2f}s")
        self._log("="*60)
        
        self.save_results()
        
        return self.results
    
    def _extract_usernames(self):
        usernames = set()
        
        for email in self.results.get("emails", []):
            if '@' in email:
                username = email.split('@')[0]
                usernames.add(username)
        
        for subdomain in self.results.get("subdomains", [])[:10]:
            parts = subdomain.replace(self.target, '').split('.')
            for part in parts:
                if part and len(part) > 3 and part not in ['www', 'mail', 'ftp']:
                    usernames.add(part)
        
        return list(usernames)[:5]
    
    def save_results(self):
        output_file = config.DATA_DIR / f"osint_results_{self.target}_{self.timestamp}.json"
        
        try:
            with open(output_file, 'w') as f:
                json.dump(self.results, f, indent=2, default=str)
            
            self._log(f"Results saved to: {output_file}")
        except Exception as e:
            self._log(f"Error saving results: {str(e)}", "error")
    
    def print_summary(self):
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
    if len(sys.argv) < 2:
        print("Usage: python orchestrator.py <target_domain>")
        print("Example: python orchestrator.py example.com")
        sys.exit(1)
    
    target = sys.argv[1]
    
    orchestrator = OSINTOrchestrator(target)
    
    results = orchestrator.run_all_parallel()
    
    orchestrator.print_summary()


if __name__ == "__main__":
    main()