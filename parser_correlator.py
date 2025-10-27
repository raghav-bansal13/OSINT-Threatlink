"""
OSINT-ThreatLink Module 2: Data Parser & Correlator
Transforms raw OSINT outputs into unified graph structure with intelligent relationships
"""

import json
import re
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Set, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict

import config


@dataclass
class Entity:
    """Base entity class for all discovered assets"""
    id: str
    type: str  # domain, subdomain, email, username, ip, url
    value: str
    source: str  # Which tool discovered it
    timestamp: str
    metadata: Dict = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}
    
    def to_dict(self):
        return asdict(self)


@dataclass
class Relationship:
    """Relationship between two entities"""
    id: str
    source_id: str
    target_id: str
    relationship_type: str  # subdomain_of, email_from, registered_on, profile_of, etc.
    confidence: float  # 0.0 to 1.0
    metadata: Dict = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}
    
    def to_dict(self):
        return asdict(self)


class IntelligenceGraph:
    """Graph structure to store entities and their relationships"""
    
    def __init__(self, target_domain: str):
        self.target = target_domain
        self.entities: Dict[str, Entity] = {}
        self.relationships: Dict[str, Relationship] = {}
        self.entity_counter = 0
        self.relationship_counter = 0
    
    def add_entity(self, entity_type: str, value: str, source: str, metadata: Dict = None) -> str:
        """Add entity to graph, return entity ID"""
        # Generate unique ID
        entity_id = f"{entity_type}_{self.entity_counter}"
        self.entity_counter += 1
        
        # Check for duplicates
        for existing_id, existing_entity in self.entities.items():
            if existing_entity.value == value and existing_entity.type == entity_type:
                # Update metadata if new source provides more info
                if metadata:
                    existing_entity.metadata.update(metadata)
                return existing_id
        
        # Create new entity
        entity = Entity(
            id=entity_id,
            type=entity_type,
            value=value,
            source=source,
            timestamp=datetime.now().isoformat(),
            metadata=metadata or {}
        )
        
        self.entities[entity_id] = entity
        return entity_id
    
    def add_relationship(self, source_id: str, target_id: str, 
                        rel_type: str, confidence: float = 1.0, 
                        metadata: Dict = None) -> str:
        """Add relationship between entities"""
        rel_id = f"rel_{self.relationship_counter}"
        self.relationship_counter += 1
        
        # Check if relationship already exists
        for existing_rel in self.relationships.values():
            if (existing_rel.source_id == source_id and 
                existing_rel.target_id == target_id and 
                existing_rel.relationship_type == rel_type):
                return existing_rel.id
        
        relationship = Relationship(
            id=rel_id,
            source_id=source_id,
            target_id=target_id,
            relationship_type=rel_type,
            confidence=confidence,
            metadata=metadata or {}
        )
        
        self.relationships[rel_id] = relationship
        return rel_id
    
    def get_entity_by_value(self, value: str, entity_type: str = None):
        """Find entity by value and optionally type"""
        for entity in self.entities.values():
            if entity.value == value:
                if entity_type is None or entity.type == entity_type:
                    return entity
        return None
    
    def get_connected_entities(self, entity_id: str) -> List[Entity]:
        """Get all entities connected to given entity"""
        connected = []
        for rel in self.relationships.values():
            if rel.source_id == entity_id:
                connected.append(self.entities[rel.target_id])
            elif rel.target_id == entity_id:
                connected.append(self.entities[rel.source_id])
        return connected
    
    def to_dict(self):
        """Export graph as dictionary"""
        return {
            "target": self.target,
            "entities": [e.to_dict() for e in self.entities.values()],
            "relationships": [r.to_dict() for r in self.relationships.values()],
            "stats": {
                "total_entities": len(self.entities),
                "total_relationships": len(self.relationships),
                "entity_types": self._count_entity_types(),
                "relationship_types": self._count_relationship_types()
            }
        }
    
    def _count_entity_types(self):
        """Count entities by type"""
        counts = defaultdict(int)
        for entity in self.entities.values():
            counts[entity.type] += 1
        return dict(counts)
    
    def _count_relationship_types(self):
        """Count relationships by type"""
        counts = defaultdict(int)
        for rel in self.relationships.values():
            counts[rel.relationship_type] += 1
        return dict(counts)


class OSINTParser:
    """Parse raw OSINT tool outputs into structured data"""
    
    def __init__(self, target_domain: str):
        self.target = target_domain
        self.graph = IntelligenceGraph(target_domain)
        
        # Add root domain as primary entity
        self.root_domain_id = self.graph.add_entity(
            entity_type="domain",
            value=target_domain,
            source="user_input",
            metadata={"is_root": True}
        )
    
    # ============================================
    # PARSING METHODS FOR EACH TOOL
    # ============================================
    
    def parse_subdomains(self, subdomains: List[str]):
        """Parse subfinder results"""
        print(f"[PARSER] Processing {len(subdomains)} subdomains...")
        
        for subdomain in subdomains:
            if not subdomain or subdomain == self.target:
                continue
            
            # Add subdomain entity
            subdomain_id = self.graph.add_entity(
                entity_type="subdomain",
                value=subdomain,
                source="subfinder",
                metadata={
                    "parent_domain": self.target,
                    "risk_keywords": self._check_risk_keywords(subdomain)
                }
            )
            
            # Create relationship to root domain
            self.graph.add_relationship(
                source_id=subdomain_id,
                target_id=self.root_domain_id,
                rel_type="subdomain_of",
                confidence=1.0
            )
    
    def parse_dns_records(self, dns_data: Dict):
        """Parse DNS lookup results"""
        print(f"[PARSER] Processing DNS records...")
        
        for record_type, records in dns_data.items():
            for record in records:
                # Determine entity type
                if record_type == 'A':
                    entity_type = 'ip_address'
                elif record_type == 'MX':
                    entity_type = 'mail_server'
                elif record_type == 'NS':
                    entity_type = 'nameserver'
                elif record_type == 'TXT':
                    entity_type = 'txt_record'
                else:
                    entity_type = 'dns_record'
                
                # Add DNS record entity
                dns_id = self.graph.add_entity(
                    entity_type=entity_type,
                    value=record,
                    source="dns_lookup",
                    metadata={"record_type": record_type}
                )
                
                # Link to root domain
                self.graph.add_relationship(
                    source_id=dns_id,
                    target_id=self.root_domain_id,
                    rel_type=f"dns_{record_type.lower()}_for",
                    confidence=1.0
                )
    
    def parse_whois(self, whois_data: Dict, emails: List[str]):
        """Parse WHOIS data"""
        print(f"[PARSER] Processing WHOIS data...")
        
        # Add WHOIS metadata to root domain
        if whois_data:
            root_entity = self.graph.entities[self.root_domain_id]
            root_entity.metadata.update({
                "registrar": whois_data.get("registrar"),
                "creation_date": whois_data.get("creation_date"),
                "expiration_date": whois_data.get("expiration_date")
            })
        
        # Parse emails from WHOIS
        for email in emails:
            if email and self._is_valid_email(email):
                email_id = self.graph.add_entity(
                    entity_type="email",
                    value=email,
                    source="whois",
                    metadata={"domain": email.split('@')[1] if '@' in email else ""}
                )
                
                # Link email to domain
                self.graph.add_relationship(
                    source_id=email_id,
                    target_id=self.root_domain_id,
                    rel_type="registered_to",
                    confidence=0.9
                )
    
    def parse_web_endpoints(self, endpoints: List[Dict]):
        """Parse httpx probe results"""
        print(f"[PARSER] Processing {len(endpoints)} web endpoints...")
        
        for endpoint in endpoints:
            url = endpoint.get("url", "")
            status_code = endpoint.get("status_code")
            
            if not url or status_code != 200:
                continue
            
            # Add URL entity
            url_id = self.graph.add_entity(
                entity_type="url",
                value=url,
                source="httpx",
                metadata={
                    "status_code": status_code,
                    "title": endpoint.get("title", ""),
                    "server": endpoint.get("server", ""),
                    "technologies": endpoint.get("technologies", []),
                    "content_length": endpoint.get("content_length", 0)
                }
            )
            
            # Extract domain from URL
            domain = self._extract_domain_from_url(url)
            domain_entity = self.graph.get_entity_by_value(domain)
            
            if domain_entity:
                # Link URL to its domain/subdomain
                self.graph.add_relationship(
                    source_id=url_id,
                    target_id=domain_entity.id,
                    rel_type="hosted_on",
                    confidence=1.0
                )
    
    def parse_emails(self, emails: List[str], source: str = "theharvester"):
        """Parse discovered emails"""
        print(f"[PARSER] Processing {len(emails)} emails from {source}...")
        
        for email in emails:
            if not self._is_valid_email(email):
                continue
            
            email_id = self.graph.add_entity(
                entity_type="email",
                value=email,
                source=source,
                metadata={"domain": email.split('@')[1] if '@' in email else ""}
            )
            
            # Link email to root domain
            self.graph.add_relationship(
                source_id=email_id,
                target_id=self.root_domain_id,
                rel_type="associated_with",
                confidence=0.8
            )
            
            # Extract potential username from email
            username = email.split('@')[0]
            username_id = self.graph.add_entity(
                entity_type="username",
                value=username,
                source=f"{source}_derived",
                metadata={"derived_from": "email"}
            )
            
            # Link username to email
            self.graph.add_relationship(
                source_id=username_id,
                target_id=email_id,
                rel_type="username_of",
                confidence=0.9
            )
    
    def parse_social_profiles(self, profiles: List[str]):
        """Parse Sherlock social media results"""
        print(f"[PARSER] Processing {len(profiles)} social profiles...")
        
        for profile_url in profiles:
            if not profile_url.startswith('http'):
                continue
            
            # Extract platform name
            platform = self._extract_platform_name(profile_url)
            
            # Extract username from URL
            username = self._extract_username_from_url(profile_url)
            
            # Add profile entity
            profile_id = self.graph.add_entity(
                entity_type="social_profile",
                value=profile_url,
                source="sherlock",
                metadata={
                    "platform": platform,
                    "username": username
                }
            )
            
            # Try to link to existing username entity
            username_entity = self.graph.get_entity_by_value(username, "username")
            if username_entity:
                self.graph.add_relationship(
                    source_id=profile_id,
                    target_id=username_entity.id,
                    rel_type="profile_of",
                    confidence=0.95
                )
    
    # ============================================
    # CORRELATION METHODS
    # ============================================
    
    def correlate_emails_and_subdomains(self):
        """Find connections between emails and subdomains"""
        print("[CORRELATOR] Finding email-subdomain connections...")
        
        correlations = 0
        
        for email_entity in self.graph.entities.values():
            if email_entity.type != "email":
                continue
            
            email_domain = email_entity.value.split('@')[1] if '@' in email_entity.value else ""
            
            # Check if email domain matches any subdomain
            for subdomain_entity in self.graph.entities.values():
                if subdomain_entity.type != "subdomain":
                    continue
                
                if email_domain in subdomain_entity.value or subdomain_entity.value in email_domain:
                    # Create correlation
                    self.graph.add_relationship(
                        source_id=email_entity.id,
                        target_id=subdomain_entity.id,
                        rel_type="email_from_subdomain",
                        confidence=0.8,
                        metadata={"correlation_type": "domain_match"}
                    )
                    correlations += 1
        
        print(f"[CORRELATOR] Found {correlations} email-subdomain correlations")
    
    def correlate_usernames_across_sources(self):
        """Link same usernames from different sources"""
        print("[CORRELATOR] Correlating usernames across sources...")
        
        # Group usernames by value
        username_groups = defaultdict(list)
        for entity in self.graph.entities.values():
            if entity.type == "username":
                username_groups[entity.value].append(entity.id)
        
        # Create correlations for duplicates
        correlations = 0
        for username, entity_ids in username_groups.items():
            if len(entity_ids) > 1:
                # Link all instances of same username
                for i, id1 in enumerate(entity_ids):
                    for id2 in entity_ids[i+1:]:
                        self.graph.add_relationship(
                            source_id=id1,
                            target_id=id2,
                            rel_type="same_username",
                            confidence=1.0
                        )
                        correlations += 1
        
        print(f"[CORRELATOR] Found {correlations} username correlations")
    
    def identify_high_value_targets(self):
        """Identify entities with high connectivity (likely important)"""
        print("[CORRELATOR] Identifying high-value targets...")
        
        # Count connections for each entity
        connection_counts = defaultdict(int)
        for rel in self.graph.relationships.values():
            connection_counts[rel.source_id] += 1
            connection_counts[rel.target_id] += 1
        
        # Mark high-value entities
        high_value_count = 0
        for entity_id, count in connection_counts.items():
            if count >= 3:  # Threshold for "high-value"
                entity = self.graph.entities[entity_id]
                entity.metadata["high_value_target"] = True
                entity.metadata["connection_count"] = count
                high_value_count += 1
        
        print(f"[CORRELATOR] Identified {high_value_count} high-value targets")
    
    # ============================================
    # UTILITY METHODS
    # ============================================
    
    def _is_valid_email(self, email: str) -> bool:
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    def _extract_domain_from_url(self, url: str) -> str:
        """Extract domain from URL"""
        pattern = r'https?://([^/]+)'
        match = re.search(pattern, url)
        return match.group(1) if match else url
    
    def _extract_platform_name(self, url: str) -> str:
        """Extract social media platform name from URL"""
        url_lower = url.lower()
        platforms = {
            'twitter': 'Twitter',
            'github': 'GitHub',
            'linkedin': 'LinkedIn',
            'facebook': 'Facebook',
            'instagram': 'Instagram',
            'reddit': 'Reddit',
            'youtube': 'YouTube',
            'tiktok': 'TikTok'
        }
        
        for key, name in platforms.items():
            if key in url_lower:
                return name
        
        return "Unknown"
    
    def _extract_username_from_url(self, url: str) -> str:
        """Extract username from social media URL"""
        parts = url.rstrip('/').split('/')
        return parts[-1] if parts else "unknown"
    
    def _check_risk_keywords(self, subdomain: str) -> List[str]:
        """Check if subdomain contains risk keywords"""
        risk_keywords = []
        subdomain_lower = subdomain.lower()
        
        for risk_level, keywords in config.RISK_KEYWORDS.get('subdomains', {}).items():
            for keyword in keywords:
                if keyword in subdomain_lower:
                    risk_keywords.append(f"{keyword}_{risk_level}")
        
        return risk_keywords


class DataCorrelator:
    """Main orchestration class for Module 2"""
    
    def __init__(self, osint_results: Dict):
        self.raw_data = osint_results
        self.target = osint_results.get("target")
        self.parser = OSINTParser(self.target)
    
    def parse_all(self):
        """Parse all OSINT results into graph structure"""
        print("\n" + "="*60)
        print("MODULE 2: Data Parser & Correlator")
        print("="*60)
        
        # Parse each data type
        if self.raw_data.get("subdomains"):
            self.parser.parse_subdomains(self.raw_data["subdomains"])
        
        if self.raw_data.get("dns_records"):
            self.parser.parse_dns_records(self.raw_data["dns_records"])
        
        if self.raw_data.get("whois_data") or self.raw_data.get("emails"):
            self.parser.parse_whois(
                self.raw_data.get("whois_data", {}),
                self.raw_data.get("emails", [])
            )
        
        if self.raw_data.get("web_endpoints"):
            self.parser.parse_web_endpoints(self.raw_data["web_endpoints"])
        
        if self.raw_data.get("emails"):
            self.parser.parse_emails(self.raw_data["emails"])
        
        if self.raw_data.get("social_profiles"):
            self.parser.parse_social_profiles(self.raw_data["social_profiles"])
        
        print("\n[PARSING COMPLETE]")
        print(f"  • Entities: {len(self.parser.graph.entities)}")
        print(f"  • Relationships: {len(self.parser.graph.relationships)}")
    
    def correlate_all(self):
        """Run all correlation algorithms"""
        print("\n" + "-"*60)
        print("Running Correlation Algorithms...")
        print("-"*60)
        
        self.parser.correlate_emails_and_subdomains()
        self.parser.correlate_usernames_across_sources()
        self.parser.identify_high_value_targets()
        
        print("\n[CORRELATION COMPLETE]")
        print(f"  • Total Relationships: {len(self.parser.graph.relationships)}")
    
    def get_graph(self) -> IntelligenceGraph:
        """Return the intelligence graph"""
        return self.parser.graph
    
    def save_graph(self, output_file: Path = None):
        """Save graph to JSON file"""
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = config.DATA_DIR / f"intelligence_graph_{self.target}_{timestamp}.json"
        
        graph_data = self.parser.graph.to_dict()
        
        with open(output_file, 'w') as f:
            json.dump(graph_data, f, indent=2)
        
        print(f"\n[GRAPH SAVED] {output_file}")
        return output_file
    
    def print_summary(self):
        """Print detailed summary of the graph"""
        graph_data = self.parser.graph.to_dict()
        stats = graph_data["stats"]
        
        print("\n" + "="*60)
        print(f"INTELLIGENCE GRAPH SUMMARY: {self.target}")
        print("="*60)
        
        print("\nEntity Distribution:")
        for entity_type, count in stats["entity_types"].items():
            print(f"  • {entity_type:20s}: {count}")
        
        print("\nRelationship Distribution:")
        for rel_type, count in stats["relationship_types"].items():
            print(f"  • {rel_type:25s}: {count}")
        
        # Find high-value targets
        high_value = [e for e in self.parser.graph.entities.values() 
                     if e.metadata.get("high_value_target")]
        
        if high_value:
            print(f"\nHigh-Value Targets ({len(high_value)}):")
            for entity in high_value[:5]:
                connections = entity.metadata.get("connection_count", 0)
                print(f"  • {entity.value:40s} ({entity.type}) - {connections} connections")
        
        print("="*60)


def main():
    """Standalone test for Module 2"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python parser_correlator.py <osint_results.json>")
        sys.exit(1)
    
    # Load OSINT results from Module 1
    results_file = Path(sys.argv[1])
    with open(results_file, 'r') as f:
        osint_results = json.load(f)
    
    # Create correlator
    correlator = DataCorrelator(osint_results)
    
    # Parse and correlate
    correlator.parse_all()
    correlator.correlate_all()
    
    # Save and print
    correlator.save_graph()
    correlator.print_summary()


if __name__ == "__main__":
    main()