"""
Quick Start Script for OSINT-ThreatLink Module 1
Simplified interface for testing and demonstration
"""

import sys
import os
from pathlib import Path

def print_banner():
    """Print tool banner"""
    banner = """
    ╔═══════════════════════════════════════════════════════╗
    ║                                                       ║
    ║           OSINT-THREATLINK - MODULE 1                 ║
    ║        AI-Powered Threat Surface Analyzer             ║
    ║                                                       ║
    ╚═══════════════════════════════════════════════════════╝
    """
    print(banner)


def check_setup():
    """Quick setup verification"""
    print("\n[*] Checking setup...")
    
    issues = []
    
    # Check config
    if not Path("config.py").exists():
        issues.append("❌ config.py not found")
    else:
        print("✅ config.py found")
    
    # Check orchestrator
    if not Path("orchestrator.py").exists():
        issues.append("❌ orchestrator.py not found")
    else:
        print("✅ orchestrator.py found")
    
    # Check Python modules
    try:
        import dns.resolver
        import whois
        import httpx
        from bs4 import BeautifulSoup
        print("✅ All Python modules available")
    except ImportError as e:
        issues.append(f"❌ Missing Python module: {e.name}")
    
    if issues:
        print("\n⚠️  Setup Issues Found:")
        for issue in issues:
            print(f"   {issue}")
        print("\nRun: pip install -r requirements.txt")
        return False
    
    print("✅ Setup verified!\n")
    return True


def run_scan(target):
    """Run the orchestrator scan"""
    try:
        from orchestrator import OSINTOrchestrator
        
        print(f"\n{'='*60}")
        print(f"Starting scan on: {target}")
        print(f"{'='*60}\n")
        
        # Create and run orchestrator
        orch = OSINTOrchestrator(target)
        results = orch.run_all_parallel()
        
        # Print summary
        print("\n")
        orch.print_summary()
        
        # Show output location
        print(f"\n📁 Results saved to: data/osint_results_{target}_{orch.timestamp}.json")
        print(f"📁 Raw outputs in: output/")
        print(f"📁 Logs in: logs/orchestrator.log")
        
        return results
        
    except Exception as e:
        print(f"\n❌ Error during scan: {str(e)}")
        import traceback
        traceback.print_exc()
        return None


def show_menu():
    """Interactive menu"""
    print("\n" + "="*60)
    print("OSINT-ThreatLink Quick Start Menu")
    print("="*60)
    print("\n1. Run full scan on a domain")
    print("2. Run test scan (example.com)")
    print("3. View last scan results")
    print("4. Run setup verification")
    print("5. Exit")
    print("\n" + "="*60)
    
    choice = input("\nEnter choice (1-5): ").strip()
    return choice


def view_last_results():
    """Display last scan results"""
    import json
    from pathlib import Path
    
    data_dir = Path("data")
    if not data_dir.exists():
        print("\n❌ No scans found. Run a scan first.")
        return
    
    # Find most recent JSON file
    json_files = sorted(data_dir.glob("osint_results_*.json"), key=os.path.getmtime, reverse=True)
    
    if not json_files:
        print("\n❌ No scan results found.")
        return
    
    latest = json_files[0]
    print(f"\n📄 Loading: {latest.name}")
    
    try:
        with open(latest, 'r') as f:
            data = json.load(f)
        
        print("\n" + "="*60)
        print(f"SCAN RESULTS: {data['target']}")
        print(f"Timestamp: {data['timestamp']}")
        print("="*60)
        
        print(f"\n📊 Summary:")
        print(f"   Subdomains: {len(data.get('subdomains', []))}")
        print(f"   Emails: {len(data.get('emails', []))}")
        print(f"   Social Profiles: {len(data.get('social_profiles', []))}")
        print(f"   Web Endpoints: {len(data.get('web_endpoints', []))}")
        print(f"   DNS Records: {sum(len(v) for v in data.get('dns_records', {}).values())}")
        
        # Show sample subdomains
        if data.get('subdomains'):
            print(f"\n🌐 Sample Subdomains (showing first 5):")
            for subdomain in data['subdomains'][:5]:
                print(f"   • {subdomain}")
            if len(data['subdomains']) > 5:
                print(f"   ... and {len(data['subdomains']) - 5} more")
        
        # Show sample endpoints
        if data.get('web_endpoints'):
            print(f"\n🔍 Sample Web Endpoints:")
            for endpoint in data['web_endpoints'][:3]:
                print(f"   • {endpoint['url']}")
                print(f"     Status: {endpoint['status_code']} | Title: {endpoint['title']}")
                if endpoint.get('technologies'):
                    print(f"     Tech: {', '.join(endpoint['technologies'])}")
        
        print("\n" + "="*60)
        
    except Exception as e:
        print(f"\n❌ Error reading results: {str(e)}")


def main():
    """Main interactive function"""
    print_banner()
    
    # Check if running with command line argument
    if len(sys.argv) > 1:
        target = sys.argv[1]
        
        if not check_setup():
            sys.exit(1)
        
        run_scan(target)
        sys.exit(0)
    
    # Interactive mode
    while True:
        choice = show_menu()
        
        if choice == '1':
            target = input("\nEnter target domain (e.g., example.com): ").strip()
            if not target:
                print("❌ Invalid domain")
                continue
            
            if not check_setup():
                continue
            
            run_scan(target)
            input("\nPress Enter to continue...")
        
        elif choice == '2':
            print("\n[*] Running test scan on example.com...")
            
            if not check_setup():
                continue
            
            run_scan("example.com")
            input("\nPress Enter to continue...")
        
        elif choice == '3':
            view_last_results()
            input("\nPress Enter to continue...")
        
        elif choice == '4':
            check_setup()
            input("\nPress Enter to continue...")
        
        elif choice == '5':
            print("\n👋 Goodbye!")
            break
        
        else:
            print("\n❌ Invalid choice. Please enter 1-5.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Interrupted by user. Goodbye!")
        sys.exit(0)