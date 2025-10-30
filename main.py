#!/usr/bin/env python3
"""
OSINT-ThreatLink: Main Integration Script
Seamlessly connects Module 1 (Orchestrator) and Module 2 (Parser & Correlator)

Usage:
    python main.py <target_domain>
    python main.py example.com
    python main.py tesla.com --skip-module1  # Use existing data
"""

import sys
import json
import logging
from pathlib import Path
from datetime import datetime
import argparse

# Import modules
try:
    import config
    from orchestrator import OSINTOrchestrator
    from parser_correlator import DataCorrelator
except ImportError as e:
    print(f"❌ Import Error: {e}")
    print("Make sure orchestrator.py, parser_correlator.py, and config.py are in the same directory")
    sys.exit(1)

# Setup logging
logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.INFO
)
logger = logging.getLogger("main")


class OSINTThreatLink:
    """Main orchestration class that runs Module 1 and Module 2 in sequence."""
    
    def __init__(self, target_domain: str, skip_module1: bool = False):
        self.target = target_domain
        self.skip_module1 = skip_module1
        self.module1_output_file = None
        self.module2_output_file = None
        self.execution_start = datetime.now()
        
    def run_module1(self) -> dict:
        """Execute Module 1: OSINT Orchestrator"""
        logger.info("=" * 70)
        logger.info("🚀 MODULE 1: OSINT Orchestrator - Starting...")
        logger.info("=" * 70)
        
        try:
            orchestrator = OSINTOrchestrator(self.target)
            results = orchestrator.run_all_parallel()
            
            # Find the output file that was just created
            timestamp = orchestrator.timestamp
            expected_file = config.DATA_DIR / f"osint_results_{self.target}_{timestamp}.json"
            
            if expected_file.exists():
                self.module1_output_file = expected_file
                logger.info("✅ Module 1 completed successfully")
                logger.info(f"📄 Output saved: {expected_file}")
                return results
            else:
                raise FileNotFoundError(f"Expected output file not found: {expected_file}")
                
        except Exception as e:
            logger.error(f"❌ Module 1 failed: {str(e)}")
            raise
    
    def load_existing_module1_data(self) -> dict:
        """Load the most recent Module 1 output for the target domain"""
        logger.info("🔍 Searching for existing Module 1 data...")
        
        # Find all matching files
        pattern = f"osint_results_{self.target}_*.json"
        matching_files = sorted(config.DATA_DIR.glob(pattern), reverse=True)
        
        if not matching_files:
            raise FileNotFoundError(
                f"No existing Module 1 data found for {self.target}\n"
                f"Run without --skip-module1 to generate new data"
            )
        
        # Use the most recent file
        self.module1_output_file = matching_files[0]
        logger.info(f"📄 Loading: {self.module1_output_file}")
        
        with open(self.module1_output_file, 'r') as f:
            results = json.load(f)
        
        logger.info("✅ Module 1 data loaded successfully")
        return results
    
    def run_module2(self, osint_results: dict) -> None:
        """Execute Module 2: Parser & Correlator"""
        logger.info("\n" + "=" * 70)
        logger.info("🧠 MODULE 2: Data Parser & Correlator - Starting...")
        logger.info("=" * 70)
        
        try:
            # Validate input data
            if not osint_results.get("target"):
                raise ValueError("Invalid Module 1 output: missing 'target' field")
            
            # Initialize correlator
            correlator = DataCorrelator(osint_results)
            
            # Parse all data
            correlator.parse_all()
            
            # Run correlation algorithms
            correlator.correlate_all()
            
            # Save the intelligence graph
            self.module2_output_file = correlator.save_graph()
            
            # Print summary
            correlator.print_summary()
            
            logger.info("✅ Module 2 completed successfully")
            logger.info(f"📄 Intelligence Graph saved: {self.module2_output_file}")
            
        except Exception as e:
            logger.error(f"❌ Module 2 failed: {str(e)}")
            raise
    
    def print_final_summary(self):
        """Print execution summary"""
        execution_time = (datetime.now() - self.execution_start).total_seconds()
        
        print("\n" + "=" * 70)
        print("🎉 OSINT-THREATLINK EXECUTION COMPLETE")
        print("=" * 70)
        print(f"Target Domain      : {self.target}")
        print(f"Execution Time     : {execution_time:.2f} seconds")
        print(f"Module 1 Output    : {self.module1_output_file}")
        print(f"Module 2 Output    : {self.module2_output_file}")
        print("=" * 70)
        print("\n📊 Next Steps:")
        print("  1. Review the intelligence graph JSON file")
        print("  2. Run Module 3 for ML risk scoring")
        print("  3. Visualize in Module 4 dashboard")
        print()
    
    def run(self):
        """Main execution flow"""
        try:
            # Step 1: Get Module 1 data
            if self.skip_module1:
                osint_results = self.load_existing_module1_data()
            else:
                osint_results = self.run_module1()
            
            # Step 2: Run Module 2
            self.run_module2(osint_results)
            
            # Step 3: Print summary
            self.print_final_summary()
            
            return True
            
        except KeyboardInterrupt:
            logger.warning("\n⚠️  Execution interrupted by user")
            return False
        except Exception as e:
            logger.error(f"\n❌ Fatal error: {str(e)}")
            logger.exception("Full traceback:")
            return False


def validate_environment():
    """Check if all dependencies are available"""
    issues = []
    
    # Check Python version
    if sys.version_info < (3, 9):
        issues.append(f"Python 3.9+ required (current: {sys.version_info.major}.{sys.version_info.minor})")
    
    # Check required directories
    for directory in [config.OUTPUT_DIR, config.DATA_DIR, config.LOGS_DIR]:
        if not directory.exists():
            try:
                directory.mkdir(parents=True, exist_ok=True)
                logger.info(f"✅ Created directory: {directory}")
            except Exception as e:
                issues.append(f"Cannot create directory {directory}: {e}")
    
    # Check required Python packages
    required_packages = {
        'dns.resolver': 'dnspython',
        'whois': 'python-whois', 
        'httpx': 'httpx',
        'bs4': 'beautifulsoup4',
        'lxml': 'lxml'
    }
    
    for module_name, package in required_packages.items():
        try:
            if '.' in module_name:
                # Handle submodules like dns.resolver
                parts = module_name.split('.')
                mod = __import__(parts[0])
                for part in parts[1:]:
                    mod = getattr(mod, part)
            else:
                __import__(module_name)
        except (ImportError, AttributeError):
            issues.append(f"Package missing: {package} (install: pip install {package})")
    
    # Check CLI tools (optional - don't fail if missing)
    cli_tools = ['subfinder', 'holehe', 'sherlock']
    missing_tools = []
    for tool in cli_tools:
        try:
            import subprocess
            result = subprocess.run(
                [tool, '--version'], 
                capture_output=True, 
                timeout=5,
                text=True
            )
        except FileNotFoundError:
            missing_tools.append(tool)
        except subprocess.TimeoutExpired:
            pass  # Tool exists but timed out, that's ok
        except Exception:
            missing_tools.append(tool)
    
    if missing_tools:
        issues.append(f"CLI tools missing (optional): {', '.join(missing_tools)}")
    
    return issues


def main():
    parser = argparse.ArgumentParser(
        description="OSINT-ThreatLink: Automated Threat Surface Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py example.com                    # Full scan
  python main.py tesla.com --skip-module1       # Use existing data
  python main.py github.com --validate-only     # Check environment only
        """
    )
    
    parser.add_argument(
        'target',
        nargs='?',
        help='Target domain to analyze (e.g., example.com)'
    )
    
    parser.add_argument(
        '--skip-module1',
        action='store_true',
        help='Skip Module 1 and use existing OSINT data'
    )
    
    parser.add_argument(
        '--validate-only',
        action='store_true',
        help='Only validate environment and exit'
    )
    
    args = parser.parse_args()
    
    # Print banner
    print("""
╔═══════════════════════════════════════════════════════════════════╗
║                    OSINT-THREATLINK v1.0                          ║
║         AI-Powered Proactive Threat Surface Analyzer              ║
╚═══════════════════════════════════════════════════════════════════╝
    """)
    
    # Validate environment
    print("🔍 Validating environment...")
    issues = validate_environment()
    
    if issues:
        print("\n⚠️  Environment Issues Detected:")
        for issue in issues:
            print(f"  ❌ {issue}")
        print("\nPlease fix these issues before running.")
        sys.exit(1)
    else:
        print("✅ Environment validation passed\n")
    
    if args.validate_only:
        print("Validation complete. Exiting.")
        sys.exit(0)
    
    # Require target domain
    if not args.target:
        parser.print_help()
        print("\n❌ Error: target domain is required")
        sys.exit(1)
    
    # Validate domain format (basic)
    target = args.target.lower().strip()
    if not target or '/' in target or ' ' in target:
        print(f"❌ Error: Invalid domain format: {args.target}")
        sys.exit(1)
    
    # Run the pipeline
    pipeline = OSINTThreatLink(target, skip_module1=args.skip_module1)
    success = pipeline.run()
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()