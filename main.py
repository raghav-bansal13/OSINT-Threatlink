#!/usr/bin/env python3
"""
OSINT-ThreatLink: Complete Pipeline
Integrates Module 1 (Orchestrator) and Module 2 (Parser & Correlator)
"""

import sys
import argparse
from pathlib import Path

# Import our modules
from orchestrator import OSINTOrchestrator
from parser_correlator import DataCorrelator
import config


def print_banner():
    """Print application banner"""
    banner = """
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║        OSINT-ThreatLink: AI-Powered Threat Surface        ║
║               Proactive Analyzer v2.0                     ║
║                                                           ║
║        Module 1: OSINT Orchestrator                       ║
║        Module 2: Intelligence Graph Builder               ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
    """
    print(banner)


def run_full_pipeline(target_domain: str, skip_modules: list = None):
    """Run complete OSINT-ThreatLink pipeline"""
    
    skip_modules = skip_modules or []
    
    print_banner()
    print(f"\n🎯 Target: {target_domain}")
    print(f"📅 Started: {Path.ctime(Path.cwd())}\n")
    
    # ============================================
    # PHASE 1: OSINT Data Collection
    # ============================================
    if 'module1' not in skip_modules:
        print("\n" + "="*70)
        print("PHASE 1: OSINT Data Collection (Module 1)")
        print("="*70)
        
        orchestrator = OSINTOrchestrator(target_domain)
        osint_results = orchestrator.run_all_parallel()
        orchestrator.print_summary()
        
    else:
        print("\n⚠ Skipping Module 1 - Loading existing results...")
        # Load latest results
        results_files = sorted(config.DATA_DIR.glob(f"osint_results_{target_domain}_*.json"))
        if not results_files:
            print("❌ No existing results found! Run without --skip-module1")
            sys.exit(1)
        
        import json
        with open(results_files[-1], 'r') as f:
            osint_results = json.load(f)
        print(f"✓ Loaded: {results_files[-1].name}")
    
    # ============================================
    # PHASE 2: Data Parsing & Correlation
    # ============================================
    if 'module2' not in skip_modules:
        print("\n" + "="*70)
        print("PHASE 2: Intelligence Fusion (Module 2)")
        print("="*70)
        
        correlator = DataCorrelator(osint_results)
        correlator.parse_all()
        correlator.correlate_all()
        
        # Save the intelligence graph
        graph_file = correlator.save_graph()
        correlator.print_summary()
        
        print("\n✅ Intelligence graph ready for Module 3 (Risk Scoring)")
        print(f"📊 Graph file: {graph_file}")
    
    # ============================================
    # FINAL SUMMARY
    # ============================================
    print("\n" + "="*70)
    print("PIPELINE EXECUTION COMPLETE")
    print("="*70)
    print(f"✓ Target: {target_domain}")
    print(f"✓ OSINT data collected and correlated")
    print(f"✓ Intelligence graph generated")
    print(f"\n📁 Output Directory: {config.DATA_DIR}")
    print("\n🚀 Next Steps:")
    print("  1. Run Module 3 for ML-based risk scoring")
    print("  2. Visualize with Module 4 dashboard")
    print("="*70)


def export_graph_formats(target_domain: str):
    """Export intelligence graph in multiple formats"""
    import json
    
    # Find latest graph file
    graph_files = sorted(config.DATA_DIR.glob(f"intelligence_graph_{target_domain}_*.json"))
    if not graph_files:
        print("❌ No intelligence graph found! Run main pipeline first.")
        return
    
    graph_file = graph_files[-1]
    print(f"\n📊 Exporting graph from: {graph_file.name}\n")
    
    with open(graph_file, 'r') as f:
        graph_data = json.load(f)
    
    # Export as CSV (for spreadsheet analysis)
    print("1. Exporting entities to CSV...")
    entities_csv = config.DATA_DIR / f"entities_{target_domain}.csv"
    with open(entities_csv, 'w') as f:
        f.write("ID,Type,Value,Source,Timestamp\n")
        for entity in graph_data["entities"]:
            f.write(f"{entity['id']},{entity['type']},{entity['value']},{entity['source']},{entity['timestamp']}\n")
    print(f"   ✓ {entities_csv}")
    
    # Export relationships to CSV
    print("2. Exporting relationships to CSV...")
    relations_csv = config.DATA_DIR / f"relationships_{target_domain}.csv"
    with open(relations_csv, 'w') as f:
        f.write("ID,Source,Target,Type,Confidence\n")
        for rel in graph_data["relationships"]:
            f.write(f"{rel['id']},{rel['source_id']},{rel['target_id']},{rel['relationship_type']},{rel['confidence']}\n")
    print(f"   ✓ {relations_csv}")
    
    # Export as Cytoscape.js format (for visualization)
    print("3. Exporting to Cytoscape.js format...")
    cytoscape_data = {
        "elements": {
            "nodes": [
                {
                    "data": {
                        "id": e["id"],
                        "label": e["value"],
                        "type": e["type"],
                        "source": e["source"]
                    }
                } for e in graph_data["entities"]
            ],
            "edges": [
                {
                    "data": {
                        "id": r["id"],
                        "source": r["source_id"],
                        "target": r["target_id"],
                        "label": r["relationship_type"],
                        "confidence": r["confidence"]
                    }
                } for r in graph_data["relationships"]
            ]
        }
    }
    
    cytoscape_file = config.DATA_DIR / f"cytoscape_{target_domain}.json"
    with open(cytoscape_file, 'w') as f:
        json.dump(cytoscape_data, f, indent=2)
    print(f"   ✓ {cytoscape_file}")
    
    # Export as vis.js format (for interactive network graphs)
    print("4. Exporting to vis.js format...")
    visjs_data = {
        "nodes": [
            {
                "id": e["id"],
                "label": e["value"][:30],  # Truncate long labels
                "group": e["type"],
                "title": f"{e['type']}: {e['value']}",
                "value": len([r for r in graph_data["relationships"] 
                             if r["source_id"] == e["id"] or r["target_id"] == e["id"]])
            } for e in graph_data["entities"]
        ],
        "edges": [
            {
                "from": r["source_id"],
                "to": r["target_id"],
                "label": r["relationship_type"],
                "title": f"{r['relationship_type']} (confidence: {r['confidence']})",
                "width": int(r["confidence"] * 3)
            } for r in graph_data["relationships"]
        ]
    }
    
    visjs_file = config.DATA_DIR / f"visjs_{target_domain}.json"
    with open(visjs_file, 'w') as f:
        json.dump(visjs_data, f, indent=2)
    print(f"   ✓ {visjs_file}")
    
    print("\n✅ Export complete! Files ready for visualization.")


def analyze_graph(target_domain: str):
    """Run advanced analysis on the intelligence graph"""
    import json
    
    # Find latest graph file
    graph_files = sorted(config.DATA_DIR.glob(f"intelligence_graph_{target_domain}_*.json"))
    if not graph_files:
        print("❌ No intelligence graph found! Run main pipeline first.")
        return
    
    graph_file = graph_files[-1]
    with open(graph_file, 'r') as f:
        graph_data = json.load(f)
    
    print("\n" + "="*70)
    print("ADVANCED GRAPH ANALYSIS")
    print("="*70)
    
    # Analysis 1: Most connected entities
    print("\n📊 Top 10 Most Connected Entities:")
    entity_connections = {}
    for entity in graph_data["entities"]:
        entity_id = entity["id"]
        connections = len([r for r in graph_data["relationships"] 
                          if r["source_id"] == entity_id or r["target_id"] == entity_id])
        entity_connections[entity_id] = (entity["value"], entity["type"], connections)
    
    sorted_entities = sorted(entity_connections.items(), key=lambda x: x[1][2], reverse=True)
    for i, (entity_id, (value, entity_type, count)) in enumerate(sorted_entities[:10], 1):
        print(f"  {i:2d}. {value:40s} ({entity_type:15s}) - {count} connections")
    
    # Analysis 2: Entity type distribution
    print("\n📈 Entity Distribution:")
    entity_types = {}
    for entity in graph_data["entities"]:
        entity_types[entity["type"]] = entity_types.get(entity["type"], 0) + 1
    
    for entity_type, count in sorted(entity_types.items(), key=lambda x: x[1], reverse=True):
        bar = "█" * (count // 2)
        print(f"  {entity_type:20s}: {bar} {count}")
    
    # Analysis 3: Relationship patterns
    print("\n🔗 Relationship Patterns:")
    rel_types = {}
    for rel in graph_data["relationships"]:
        rel_types[rel["relationship_type"]] = rel_types.get(rel["relationship_type"], 0) + 1
    
    for rel_type, count in sorted(rel_types.items(), key=lambda x: x[1], reverse=True):
        print(f"  • {rel_type:30s}: {count}")
    
    # Analysis 4: Risk indicators
    print("\n⚠️  Risk Indicators:")
    risk_count = 0
    for entity in graph_data["entities"]:
        if entity.get("metadata", {}).get("risk_keywords"):
            risk_count += 1
            if risk_count <= 5:  # Show first 5
                keywords = entity["metadata"]["risk_keywords"]
                print(f"  • {entity['value']:40s} - {', '.join(keywords)}")
    
    if risk_count > 5:
        print(f"  ... and {risk_count - 5} more")
    
    # Analysis 5: Email exposure
    print("\n📧 Email Exposure Analysis:")
    emails = [e for e in graph_data["entities"] if e["type"] == "email"]
    print(f"  • Total emails discovered: {len(emails)}")
    
    email_domains = {}
    for email in emails:
        domain = email["value"].split('@')[1] if '@' in email["value"] else "unknown"
        email_domains[domain] = email_domains.get(domain, 0) + 1
    
    print("  • Email domains:")
    for domain, count in sorted(email_domains.items(), key=lambda x: x[1], reverse=True):
        print(f"    - {domain:30s}: {count} email(s)")
    
    # Analysis 6: Social media footprint
    print("\n🌐 Social Media Footprint:")
    social_profiles = [e for e in graph_data["entities"] if e["type"] == "social_profile"]
    print(f"  • Total profiles found: {len(social_profiles)}")
    
    platforms = {}
    for profile in social_profiles:
        platform = profile.get("metadata", {}).get("platform", "Unknown")
        platforms[platform] = platforms.get(platform, 0) + 1
    
    for platform, count in sorted(platforms.items(), key=lambda x: x[1], reverse=True):
        print(f"    - {platform:20s}: {count} profile(s)")
    
    print("\n" + "="*70)


def main():
    """Main entry point with CLI"""
    parser = argparse.ArgumentParser(
        description='OSINT-ThreatLink: Complete Threat Surface Analysis Pipeline',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run complete pipeline
  python main.py example.com
  
  # Skip Module 1 (use existing OSINT data)
  python main.py example.com --skip-module1
  
  # Export graph in multiple formats
  python main.py example.com --export
  
  # Run advanced analysis
  python main.py example.com --analyze
  
  # Run only specific phases
  python main.py example.com --module1-only
  python main.py example.com --module2-only
        """
    )
    
    parser.add_argument('target', help='Target domain (e.g., example.com)')
    parser.add_argument('--skip-module1', action='store_true', 
                       help='Skip Module 1 and use existing OSINT results')
    parser.add_argument('--skip-module2', action='store_true',
                       help='Skip Module 2 (only collect OSINT data)')
    parser.add_argument('--module1-only', action='store_true',
                       help='Run only Module 1')
    parser.add_argument('--module2-only', action='store_true',
                       help='Run only Module 2 (requires existing data)')
    parser.add_argument('--export', action='store_true',
                       help='Export graph in multiple formats (CSV, Cytoscape, vis.js)')
    parser.add_argument('--analyze', action='store_true',
                       help='Run advanced graph analysis')
    
    args = parser.parse_args()
    
    # Handle special modes
    if args.export:
        export_graph_formats(args.target)
        return
    
    if args.analyze:
        analyze_graph(args.target)
        return
    
    # Determine which modules to skip
    skip_modules = []
    
    if args.skip_module1 or args.module2_only:
        skip_modules.append('module1')
    
    if args.skip_module2 or args.module1_only:
        skip_modules.append('module2')
    
    # Run pipeline
    run_full_pipeline(args.target, skip_modules)


if __name__ == "__main__":
    main()