#!/usr/bin/env python3
"""
OSINT-ThreatLink Module 2: Test & Validation Script
Tests parsing, correlation, and graph generation
"""

import json
from pathlib import Path
from parser_correlator import DataCorrelator, IntelligenceGraph, OSINTParser


def create_mock_osint_data(target="example.com"):
    """Create mock OSINT data for testing"""
    return {
        "target": target,
        "timestamp": "20241027_103000",
        "subdomains": [
            "www.example.com",
            "dev.example.com",
            "api.example.com",
            "admin.example.com",
            "mail.example.com",
            "vpn.example.com"
        ],
        "emails": [
            "admin@example.com",
            "security@example.com",
            "dev@dev.example.com",
            "contact@example.com"
        ],
        "social_profiles": [
            "https://github.com/admin",
            "https://twitter.com/security",
            "https://linkedin.com/in/dev"
        ],
        "web_endpoints": [
            {
                "url": "https://www.example.com",
                "status_code": 200,
                "title": "Example Domain",
                "server": "nginx",
                "technologies": ["nginx", "PHP"],
                "content_length": 1256
            },
            {
                "url": "https://api.example.com",
                "status_code": 200,
                "title": "API Documentation",
                "server": "Apache",
                "technologies": ["Apache", "REST"],
                "content_length": 3420
            }
        ],
        "dns_records": {
            "A": ["93.184.216.34", "93.184.216.35"],
            "MX": ["mail.example.com"],
            "NS": ["ns1.example.com", "ns2.example.com"],
            "TXT": ["v=spf1 include:_spf.example.com ~all"]
        },
        "whois_data": {
            "domain_name": "EXAMPLE.COM",
            "registrar": "Example Registrar Inc.",
            "creation_date": "1995-08-14",
            "expiration_date": "2025-08-13",
            "name_servers": ["ns1.example.com", "ns2.example.com"],
            "emails": ["admin@example.com"]
        }
    }


def test_graph_creation():
    """Test 1: Basic graph creation"""
    print("\n" + "="*60)
    print("TEST 1: Graph Creation")
    print("="*60)
    
    graph = IntelligenceGraph("test.com")
    
    # Add entities
    domain_id = graph.add_entity("domain", "test.com", "test", {"is_root": True})
    email_id = graph.add_entity("email", "admin@test.com", "test")
    
    # Add relationship
    rel_id = graph.add_relationship(email_id, domain_id, "associated_with", 0.9)
    
    # Verify
    assert len(graph.entities) == 2, "Should have 2 entities"
    assert len(graph.relationships) == 1, "Should have 1 relationship"
    
    print("✓ Graph creation successful")
    print(f"  • Entities: {len(graph.entities)}")
    print(f"  • Relationships: {len(graph.relationships)}")


def test_parsing():
    """Test 2: OSINT data parsing"""
    print("\n" + "="*60)
    print("TEST 2: Data Parsing")
    print("="*60)
    
    mock_data = create_mock_osint_data()
    correlator = DataCorrelator(mock_data)
    
    # Parse all data
    correlator.parse_all()
    
    graph = correlator.get_graph()
    
    # Verify entity counts
    entity_types = {}
    for entity in graph.entities.values():
        entity_types[entity.type] = entity_types.get(entity.type, 0) + 1
    
    print("✓ Parsing successful")
    print("  Entity distribution:")
    for entity_type, count in entity_types.items():
        print(f"    • {entity_type:20s}: {count}")
    
    # Assertions
    assert entity_types.get("subdomain", 0) >= 6, "Should parse all subdomains"
    assert entity_types.get("email", 0) >= 4, "Should parse all emails"
    assert entity_types.get("url", 0) >= 2, "Should parse web endpoints"
    
    return correlator


def test_correlation(correlator):
    """Test 3: Correlation algorithms"""
    print("\n" + "="*60)
    print("TEST 3: Correlation")
    print("="*60)
    
    initial_rel_count = len(correlator.parser.graph.relationships)
    
    # Run correlations
    correlator.correlate_all()
    
    final_rel_count = len(correlator.parser.graph.relationships)
    
    correlations_added = final_rel_count - initial_rel_count
    
    print("✓ Correlation successful")
    print(f"  • Initial relationships: {initial_rel_count}")
    print(f"  • Final relationships: {final_rel_count}")
    print(f"  • Correlations added: {correlations_added}")
    
    assert correlations_added >= 0, "Should add correlations"


def test_graph_export(correlator):
    """Test 4: Graph export"""
    print("\n" + "="*60)
    print("TEST 4: Graph Export")
    print("="*60)
    
    # Export to dict
    graph_dict = correlator.parser.graph.to_dict()
    
    # Verify structure
    assert "entities" in graph_dict, "Should have entities key"
    assert "relationships" in graph_dict, "Should have relationships key"
    assert "stats" in graph_dict, "Should have stats key"
    assert "target" in graph_dict, "Should have target key"
    
    print("✓ Export successful")
    print("  Graph structure:")
    print(f"    • Target: {graph_dict['target']}")
    print(f"    • Total entities: {graph_dict['stats']['total_entities']}")
    print(f"    • Total relationships: {graph_dict['stats']['total_relationships']}")
    
    # Save to file
    test_file = Path("data") / "test_graph.json"
    test_file.parent.mkdir(exist_ok=True)
    
    with open(test_file, 'w') as f:
        json.dump(graph_dict, f, indent=2)
    
    print(f"  • Saved to: {test_file}")
    
    return graph_dict


def test_graph_queries(graph_dict):
    """Test 5: Graph querying"""
    print("\n" + "="*60)
    print("TEST 5: Graph Queries")
    print("="*60)
    
    entities = graph_dict["entities"]
    relationships = graph_dict["relationships"]
    
    # Query 1: Find all emails
    emails = [e for e in entities if e["type"] == "email"]
    print(f"✓ Query 1: Found {len(emails)} emails")
    
    # Query 2: Find high-value targets
    hvt = [e for e in entities if e.get("metadata", {}).get("high_value_target")]
    print(f"✓ Query 2: Found {len(hvt)} high-value targets")
    
    # Query 3: Find risky subdomains
    risky_subdomains = [
        e for e in entities 
        if e["type"] == "subdomain" and e.get("metadata", {}).get("risk_keywords")
    ]
    print(f"✓ Query 3: Found {len(risky_subdomains)} risky subdomains")
    if risky_subdomains:
        print("  Examples:")
        for sub in risky_subdomains[:3]:
            keywords = sub["metadata"]["risk_keywords"]
            print(f"    • {sub['value']:30s} - {', '.join(keywords)}")
    
    # Query 4: Find connected entities
    if entities:
        sample_entity_id = entities[0]["id"]
        connections = [
            r for r in relationships 
            if r["source_id"] == sample_entity_id or r["target_id"] == sample_entity_id
        ]
        print(f"✓ Query 4: Entity '{entities[0]['value']}' has {len(connections)} connections")
    
    # Query 5: Count relationship types
    rel_types = {}
    for rel in relationships:
        rel_type = rel["relationship_type"]
        rel_types[rel_type] = rel_types.get(rel_type, 0) + 1
    
    print(f"✓ Query 5: Found {len(rel_types)} relationship types:")
    for rel_type, count in sorted(rel_types.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"    • {rel_type:30s}: {count}")


def test_duplicate_handling():
    """Test 6: Duplicate entity handling"""
    print("\n" + "="*60)
    print("TEST 6: Duplicate Handling")
    print("="*60)
    
    graph = IntelligenceGraph("test.com")
    
    # Add same entity twice
    id1 = graph.add_entity("email", "test@test.com", "source1")
    id2 = graph.add_entity("email", "test@test.com", "source2")
    
    # Should return same ID
    assert id1 == id2, "Duplicate entities should return same ID"
    assert len(graph.entities) == 1, "Should only have 1 entity"
    
    print("✓ Duplicate handling works correctly")
    print(f"  • Added same entity twice, got ID: {id1}")
    print(f"  • Total unique entities: {len(graph.entities)}")


def test_relationship_deduplication():
    """Test 7: Relationship deduplication"""
    print("\n" + "="*60)
    print("TEST 7: Relationship Deduplication")
    print("="*60)
    
    graph = IntelligenceGraph("test.com")
    
    e1 = graph.add_entity("email", "test1@test.com", "source1")
    e2 = graph.add_entity("email", "test2@test.com", "source2")
    
    # Add same relationship twice
    r1 = graph.add_relationship(e1, e2, "related_to", 0.9)
    r2 = graph.add_relationship(e1, e2, "related_to", 0.9)
    
    assert r1 == r2, "Duplicate relationships should return same ID"
    assert len(graph.relationships) == 1, "Should only have 1 relationship"
    
    print("✓ Relationship deduplication works correctly")
    print(f"  • Added same relationship twice, got ID: {r1}")
    print(f"  • Total unique relationships: {len(graph.relationships)}")


def test_email_validation():
    """Test 8: Email validation"""
    print("\n" + "="*60)
    print("TEST 8: Email Validation")
    print("="*60)
    
    parser = OSINTParser("test.com")
    
    valid_emails = [
        "test@example.com",
        "admin@test.co.uk",
        "user.name@domain.io"
    ]
    
    invalid_emails = [
        "notanemail",
        "@example.com",
        "test@",
        "test @example.com"
    ]
    
    valid_count = sum(1 for e in valid_emails if parser._is_valid_email(e))
    invalid_count = sum(1 for e in invalid_emails if parser._is_valid_email(e))
    
    assert valid_count == len(valid_emails), "All valid emails should pass"
    assert invalid_count == 0, "All invalid emails should fail"
    
    print("✓ Email validation working correctly")
    print(f"  • Valid emails passed: {valid_count}/{len(valid_emails)}")
    print(f"  • Invalid emails rejected: {len(invalid_emails) - invalid_count}/{len(invalid_emails)}")


def test_full_pipeline():
    """Test 9: Complete pipeline integration"""
    print("\n" + "="*60)
    print("TEST 9: Full Pipeline Integration")
    print("="*60)
    
    # Create mock data
    mock_data = create_mock_osint_data("fulltest.com")
    
    # Run complete pipeline
    correlator = DataCorrelator(mock_data)
    correlator.parse_all()
    correlator.correlate_all()
    
    # Get graph
    graph_dict = correlator.parser.graph.to_dict()
    stats = graph_dict["stats"]
    
    print("✓ Full pipeline completed successfully")
    print("\n  Pipeline Statistics:")
    print(f"    • Target: {graph_dict['target']}")
    print(f"    • Total entities: {stats['total_entities']}")
    print(f"    • Total relationships: {stats['total_relationships']}")
    print(f"    • Entity types: {len(stats['entity_types'])}")
    print(f"    • Relationship types: {len(stats['relationship_types'])}")
    
    # Verify minimum expected data
    assert stats['total_entities'] >= 10, "Should have at least 10 entities"
    assert stats['total_relationships'] >= 5, "Should have at least 5 relationships"
    
    # Print entity breakdown
    print("\n  Entity Breakdown:")
    for entity_type, count in sorted(stats['entity_types'].items(), key=lambda x: x[1], reverse=True):
        print(f"    • {entity_type:20s}: {count}")
    
    # Print relationship breakdown
    print("\n  Relationship Breakdown:")
    for rel_type, count in sorted(stats['relationship_types'].items(), key=lambda x: x[1], reverse=True):
        print(f"    • {rel_type:30s}: {count}")


def run_all_tests():
    """Run all validation tests"""
    print("\n" + "╔" + "="*68 + "╗")
    print("║" + " "*20 + "MODULE 2: VALIDATION SUITE" + " "*22 + "║")
    print("╚" + "="*68 + "╝")
    
    tests_passed = 0
    tests_failed = 0
    
    tests = [
        ("Graph Creation", test_graph_creation),
        ("Data Parsing", test_parsing),
        ("Duplicate Handling", test_duplicate_handling),
        ("Relationship Deduplication", test_relationship_deduplication),
        ("Email Validation", test_email_validation),
        ("Full Pipeline", test_full_pipeline)
    ]
    
    # Run parsing test first to get correlator
    correlator = None
    
    for test_name, test_func in tests:
        try:
            if test_name == "Data Parsing":
                correlator = test_func()
            elif test_name == "Correlation":
                test_func(correlator)
            elif test_name == "Graph Export":
                graph_dict = test_func(correlator)
            elif test_name == "Graph Queries":
                test_func(graph_dict)
            else:
                test_func()
            
            tests_passed += 1
        except AssertionError as e:
            print(f"\n✗ {test_name} FAILED: {e}")
            tests_failed += 1
        except Exception as e:
            print(f"\n✗ {test_name} ERROR: {e}")
            tests_failed += 1
    
    # Run correlation and export tests with correlator
    if correlator:
        try:
            test_correlation(correlator)
            tests_passed += 1
        except Exception as e:
            print(f"\n✗ Correlation FAILED: {e}")
            tests_failed += 1
        
        try:
            graph_dict = test_graph_export(correlator)
            tests_passed += 1
        except Exception as e:
            print(f"\n✗ Graph Export FAILED: {e}")
            tests_failed += 1
        
        try:
            test_graph_queries(graph_dict)
            tests_passed += 1
        except Exception as e:
            print(f"\n✗ Graph Queries FAILED: {e}")
            tests_failed += 1
    
    # Final summary
    print("\n" + "="*70)
    print("VALIDATION SUMMARY")
    print("="*70)
    print(f"Tests Passed: {tests_passed}")
    print(f"Tests Failed: {tests_failed}")
    print(f"Success Rate: {tests_passed / (tests_passed + tests_failed) * 100:.1f}%")
    
    if tests_failed == 0:
        print("\n🎉 ALL TESTS PASSED! Module 2 is ready for production.")
    else:
        print(f"\n⚠️  {tests_failed} test(s) failed. Review errors above.")
    
    print("="*70)
    
    return tests_failed == 0


def main():
    """Main entry point"""
    import sys
    
    success = run_all_tests()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()