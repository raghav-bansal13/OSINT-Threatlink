#!/usr/bin/env python3
"""
OSINT-ThreatLink Module 2: Data Parser & Correlator (Improved)
Transforms raw OSINT outputs into unified graph structure with intelligent relationships.

Improvements over original:
- dataclass default_factory for metadata
- UUID-based IDs (short)
- logging instead of prints
- type hints and docstrings
- safer duplicate detection with normalized values
- argparse CLI and safer JSON save
"""

from __future__ import annotations

import json
import re
import uuid
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict, field
from collections import defaultdict

import config  # expects same config used earlier (DATA_DIR, RISK_KEYWORDS)

# -----------------------
# Logging configuration
# -----------------------
logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    level=logging.INFO
)
logger = logging.getLogger("module2")

# -----------------------
# Utilities
# -----------------------
def _short_id(prefix: str = "", length: int = 8) -> str:
    """Generate a short hex id with optional prefix."""
    return f"{prefix}{uuid.uuid4().hex[:length]}"

def _now_iso() -> str:
    return datetime.utcnow().isoformat()

def _normalize_value(value: str) -> str:
    """Normalize a value for duplicate detection (basic)."""
    return value.strip().lower()

# -----------------------
# Data models
# -----------------------
@dataclass
class Entity:
    """Base entity class for all discovered assets."""
    id: str
    type: str  # domain, subdomain, email, username, ip, url, etc.
    value: str
    source: str  # Which tool discovered it
    timestamp: str = field(default_factory=_now_iso)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.id:
            self.id = _short_id(f"{self.type}_")
        if not isinstance(self.metadata, dict):
            raise TypeError("metadata must be a dict")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Relationship:
    """Relationship between two entities."""
    id: str
    source_id: str
    target_id: str
    relationship_type: str  # subdomain_of, email_from, profile_of, etc.
    confidence: float = 1.0  # 0.0 to 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.id:
            self.id = _short_id("rel_")
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError("confidence must be between 0.0 and 1.0")
        if not isinstance(self.metadata, dict):
            raise TypeError("metadata must be a dict")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

# -----------------------
# Graph container
# -----------------------
class IntelligenceGraph:
    """Graph structure to store entities and relationships."""

    def __init__(self, target_domain: str):
        self.target = target_domain
        self.entities: Dict[str, Entity] = {}
        self.relationships: Dict[str, Relationship] = {}
        # Indexes to help quick lookup
        self._value_index: Dict[str, str] = {}  # normalized value -> entity_id

    # ---------- Entities ----------
    def add_entity(self, entity_type: str, value: str, source: str, metadata: Optional[Dict[str, Any]] = None) -> str:
        """
        Add an entity if not duplicate, else update metadata and return existing ID.
        Returns entity id.
        """
        if not value:
            raise ValueError("value must be non-empty")

        norm = _normalize_value(value)
        key = f"{entity_type}:{norm}"

        # If exists, update metadata
        existing_id = self._value_index.get(key)
        if existing_id:
            existing_entity = self.entities[existing_id]
            if metadata:
                existing_entity.metadata.update(metadata)
            # keep earliest timestamp (or leave as-is)
            return existing_id

        # create new entity
        eid = _short_id(f"{entity_type}_")
        entity = Entity(
            id=eid,
            type=entity_type,
            value=value,
            source=source,
            timestamp=_now_iso(),
            metadata=metadata or {}
        )
        self.entities[eid] = entity
        self._value_index[key] = eid
        return eid

    # ---------- Relationships ----------
    def add_relationship(self, source_id: str, target_id: str, rel_type: str, confidence: float = 1.0, metadata: Optional[Dict[str, Any]] = None) -> str:
        """
        Add a relationship if not already present (based on source,target,type).
        Returns relationship id.
        """
        # Basic validation
        if source_id not in self.entities or target_id not in self.entities:
            raise KeyError("Both source_id and target_id must exist as entities")

        # detect duplicate relationship
        for rid, rel in self.relationships.items():
            if rel.source_id == source_id and rel.target_id == target_id and rel.relationship_type == rel_type:
                # optionally merge metadata
                if metadata:
                    rel.metadata.update(metadata)
                return rid

        rid = _short_id("rel_")
        relationship = Relationship(
            id=rid,
            source_id=source_id,
            target_id=target_id,
            relationship_type=rel_type,
            confidence=confidence,
            metadata=metadata or {}
        )
        self.relationships[rid] = relationship
        return rid

    # ---------- Lookup / Utilities ----------
    def get_entity_by_value(self, value: str, entity_type: Optional[str] = None) -> Optional[Entity]:
        """Find entity by raw value and optional type. Returns Entity or None."""
        if value is None:
            return None
        norm = _normalize_value(value)
        if entity_type:
            key = f"{entity_type}:{norm}"
            eid = self._value_index.get(key)
            return self.entities.get(eid) if eid else None
        # try to find any type
        # faster to try direct hits from index
        for k, eid in self._value_index.items():
            # stored format type:normvalue
            _, stored_norm = k.split(":", 1)
            if stored_norm == norm:
                return self.entities.get(eid)
        return None

    def get_connected_entities(self, entity_id: str) -> List[Entity]:
        """Get all entities connected to given entity."""
        connected = []
        for rel in self.relationships.values():
            if rel.source_id == entity_id:
                connected.append(self.entities[rel.target_id])
            elif rel.target_id == entity_id:
                connected.append(self.entities[rel.source_id])
        return connected

    def to_dict(self) -> Dict[str, Any]:
        """Export graph as dictionary."""
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

    def _count_entity_types(self) -> Dict[str, int]:
        counts = defaultdict(int)
        for entity in self.entities.values():
            counts[entity.type] += 1
        return dict(counts)

    def _count_relationship_types(self) -> Dict[str, int]:
        counts = defaultdict(int)
        for rel in self.relationships.values():
            counts[rel.relationship_type] += 1
        return dict(counts)

# -----------------------
# Parser & Correlator
# -----------------------
class OSINTParser:
    """Parse raw OSINT tool outputs into structured data."""

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

    # ---------------------
    # PARSING METHODS
    # ---------------------
    def parse_subdomains(self, subdomains: List[str]) -> None:
        """Parse subfinder results (subdomain list)."""
        logger.info("[PARSER] Processing %d subdomains...", len(subdomains or []))
        for subdomain in subdomains or []:
            if not subdomain:
                continue
            if _normalize_value(subdomain) == _normalize_value(self.target):
                continue

            subdomain_id = self.graph.add_entity(
                entity_type="subdomain",
                value=subdomain,
                source="subfinder",
                metadata={
                    "parent_domain": self.target,
                    "risk_keywords": self._check_risk_keywords(subdomain)
                }
            )
            self.graph.add_relationship(
                source_id=subdomain_id,
                target_id=self.root_domain_id,
                rel_type="subdomain_of",
                confidence=1.0
            )

    def parse_dns_records(self, dns_data: Dict[str, List[str]]) -> None:
        """Parse DNS lookup results (dict of record_type -> list of records)."""
        logger.info("[PARSER] Processing DNS records...")
        for record_type, records in (dns_data or {}).items():
            for record in records or []:
                if not record:
                    continue
                # map to entity type
                entity_type = {
                    "A": "ip_address",
                    "MX": "mail_server",
                    "NS": "nameserver",
                    "TXT": "txt_record"
                }.get(record_type, "dns_record")

                dns_id = self.graph.add_entity(
                    entity_type=entity_type,
                    value=record,
                    source="dns_lookup",
                    metadata={"record_type": record_type}
                )

                self.graph.add_relationship(
                    source_id=dns_id,
                    target_id=self.root_domain_id,
                    rel_type=f"dns_{record_type.lower()}_for",
                    confidence=1.0
                )

    def parse_whois(self, whois_data: Dict[str, Any], emails: List[str]) -> None:
        """Parse WHOIS data and add emails found in whois."""
        logger.info("[PARSER] Processing WHOIS data...")
        if whois_data:
            root_entity = self.graph.entities[self.root_domain_id]
            # only set keys if present
            for key in ("registrar", "creation_date", "expiration_date"):
                if whois_data.get(key):
                    root_entity.metadata[key] = whois_data.get(key)

        for email in emails or []:
            if email and self._is_valid_email(email):
                email_id = self.graph.add_entity(
                    entity_type="email",
                    value=email,
                    source="whois",
                    metadata={"domain": email.split('@')[1] if '@' in email else ""}
                )
                self.graph.add_relationship(
                    source_id=email_id,
                    target_id=self.root_domain_id,
                    rel_type="registered_to",
                    confidence=0.9
                )

    def parse_web_endpoints(self, endpoints: List[Dict[str, Any]]) -> None:
        """Parse httpx-like probe results and add only healthy endpoints."""
        logger.info("[PARSER] Processing %d web endpoints...", len(endpoints or []))
        for endpoint in endpoints or []:
            url = endpoint.get("url", "") if isinstance(endpoint, dict) else ""
            status_code = endpoint.get("status_code") if isinstance(endpoint, dict) else None

            if not url or status_code != 200:
                continue

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

            domain = self._extract_domain_from_url(url)
            domain_entity = self.graph.get_entity_by_value(domain)
            if domain_entity:
                self.graph.add_relationship(
                    source_id=url_id,
                    target_id=domain_entity.id,
                    rel_type="hosted_on",
                    confidence=1.0
                )

    def parse_emails(self, emails: List[str], source: str = "theharvester") -> None:
        """Parse discovered emails and derive username entities."""
        logger.info("[PARSER] Processing %d emails from %s...", len(emails or []), source)
        for email in emails or []:
            if not self._is_valid_email(email):
                continue
            email_id = self.graph.add_entity(
                entity_type="email",
                value=email,
                source=source,
                metadata={"domain": email.split('@')[1] if '@' in email else ""}
            )
            self.graph.add_relationship(
                source_id=email_id,
                target_id=self.root_domain_id,
                rel_type="associated_with",
                confidence=0.8
            )
            username = email.split('@')[0]
            username_id = self.graph.add_entity(
                entity_type="username",
                value=username,
                source=f"{source}_derived",
                metadata={"derived_from": "email"}
            )
            self.graph.add_relationship(
                source_id=username_id,
                target_id=email_id,
                rel_type="username_of",
                confidence=0.9
            )

    def parse_social_profiles(self, profiles: List[str]) -> None:
        """Parse Sherlock-like social profile URLs."""
        logger.info("[PARSER] Processing %d social profiles...", len(profiles or []))
        for profile_url in profiles or []:
            if not isinstance(profile_url, str) or not profile_url.startswith("http"):
                continue
            platform = self._extract_platform_name(profile_url)
            username = self._extract_username_from_url(profile_url)

            profile_id = self.graph.add_entity(
                entity_type="social_profile",
                value=profile_url,
                source="sherlock",
                metadata={"platform": platform, "username": username}
            )

            username_entity = self.graph.get_entity_by_value(username, "username")
            if username_entity:
                self.graph.add_relationship(
                    source_id=profile_id,
                    target_id=username_entity.id,
                    rel_type="profile_of",
                    confidence=0.95
                )

    # ---------------------
    # CORRELATION METHODS
    # ---------------------
    def correlate_emails_and_subdomains(self) -> None:
        """Find connections between emails and subdomains via domain matching."""
        logger.info("[CORRELATOR] Finding email-subdomain connections...")
        correlations = 0
        # collect lists first to avoid runtime-dict-change surprises
        entities = list(self.graph.entities.values())
        subdomains = [e for e in entities if e.type == "subdomain"]
        emails = [e for e in entities if e.type == "email"]

        for email_entity in emails:
            email_domain = email_entity.value.split('@')[1] if '@' in email_entity.value else ""
            for subdomain_entity in subdomains:
                if email_domain and (email_domain in subdomain_entity.value or subdomain_entity.value in email_domain):
                    self.graph.add_relationship(
                        source_id=email_entity.id,
                        target_id=subdomain_entity.id,
                        rel_type="email_from_subdomain",
                        confidence=0.8,
                        metadata={"correlation_type": "domain_match"}
                    )
                    correlations += 1
        logger.info("[CORRELATOR] Found %d email-subdomain correlations", correlations)

    def correlate_usernames_across_sources(self) -> None:
        """Link same usernames found in different places."""
        logger.info("[CORRELATOR] Correlating usernames across sources...")
        username_groups: Dict[str, List[str]] = defaultdict(list)
        for entity in self.graph.entities.values():
            if entity.type == "username":
                username_groups[_normalize_value(entity.value)].append(entity.id)

        correlations = 0
        for username, ids in username_groups.items():
            if len(ids) > 1:
                for i, id1 in enumerate(ids):
                    for id2 in ids[i + 1 :]:
                        self.graph.add_relationship(
                            source_id=id1,
                            target_id=id2,
                            rel_type="same_username",
                            confidence=1.0
                        )
                        correlations += 1
        logger.info("[CORRELATOR] Found %d username correlations", correlations)

    def identify_high_value_targets(self, threshold: int = 3) -> None:
        """Mark entities with connection_count >= threshold as high-value."""
        logger.info("[CORRELATOR] Identifying high-value targets...")
        connection_counts: Dict[str, int] = defaultdict(int)
        for rel in self.graph.relationships.values():
            connection_counts[rel.source_id] += 1
            connection_counts[rel.target_id] += 1

        high_value_count = 0
        for entity_id, count in connection_counts.items():
            if count >= threshold:
                entity = self.graph.entities[entity_id]
                entity.metadata["high_value_target"] = True
                entity.metadata["connection_count"] = count
                high_value_count += 1
        logger.info("[CORRELATOR] Identified %d high-value targets", high_value_count)

    # ---------------------
    # Utility methods
    # ---------------------
    @staticmethod
    def _is_valid_email(email: str) -> bool:
        """Simple regex email validation."""
        if not isinstance(email, str):
            return False
        pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        return bool(re.match(pattern, email))

    @staticmethod
    def _extract_domain_from_url(url: str) -> str:
        """Return domain portion from URL."""
        match = re.search(r"https?://([^/]+)", url)
        return match.group(1) if match else url

    @staticmethod
    def _extract_platform_name(url: str) -> str:
        url_lower = url.lower()
        platforms = {
            "twitter": "Twitter",
            "github": "GitHub",
            "linkedin": "LinkedIn",
            "facebook": "Facebook",
            "instagram": "Instagram",
            "reddit": "Reddit",
            "youtube": "YouTube",
            "tiktok": "TikTok",
        }
        for key, name in platforms.items():
            if key in url_lower:
                return name
        return "Unknown"

    @staticmethod
    def _extract_username_from_url(url: str) -> str:
        parts = url.rstrip("/").split("/")
        return parts[-1] if parts else "unknown"

    @staticmethod
    def _check_risk_keywords(subdomain: str) -> List[str]:
        """Check subdomain for configured risk keywords."""
        risk_keywords = []
        try:
            subdomain_lower = subdomain.lower()
        except Exception:
            return risk_keywords
        for risk_level, keywords in config.RISK_KEYWORDS.get("subdomains", {}).items():
            for keyword in keywords:
                if keyword in subdomain_lower:
                    risk_keywords.append(f"{keyword}_{risk_level}")
        return risk_keywords

# -----------------------
# Orchestration
# -----------------------
class DataCorrelator:
    """Main orchestration class for Module 2."""

    def __init__(self, osint_results: Dict[str, Any]):
        if not osint_results:
            raise ValueError("osint_results must be provided")
        self.raw_data = osint_results
        self.target = osint_results.get("target")
        if not self.target:
            raise ValueError("target domain must be provided in osint_results")
        self.parser = OSINTParser(self.target)

    def parse_all(self) -> None:
        logger.info("=" * 60)
        logger.info("MODULE 2: Data Parser & Correlator")
        logger.info("=" * 60)

        if self.raw_data.get("subdomains"):
            self.parser.parse_subdomains(self.raw_data["subdomains"])

        if self.raw_data.get("dns_records"):
            self.parser.parse_dns_records(self.raw_data["dns_records"])

        if self.raw_data.get("whois_data") or self.raw_data.get("emails"):
            self.parser.parse_whois(self.raw_data.get("whois_data", {}), self.raw_data.get("emails", []))

        if self.raw_data.get("web_endpoints"):
            self.parser.parse_web_endpoints(self.raw_data["web_endpoints"])

        if self.raw_data.get("emails"):
            self.parser.parse_emails(self.raw_data["emails"])

        if self.raw_data.get("social_profiles"):
            self.parser.parse_social_profiles(self.raw_data["social_profiles"])

        logger.info("[PARSING COMPLETE]")
        logger.info("  • Entities: %d", len(self.parser.graph.entities))
        logger.info("  • Relationships: %d", len(self.parser.graph.relationships))

    def correlate_all(self) -> None:
        logger.info("-" * 60)
        logger.info("Running Correlation Algorithms...")
        logger.info("-" * 60)
        self.parser.correlate_emails_and_subdomains()
        self.parser.correlate_usernames_across_sources()
        self.parser.identify_high_value_targets()
        logger.info("[CORRELATION COMPLETE]")
        logger.info("  • Total Relationships: %d", len(self.parser.graph.relationships))

    def get_graph(self) -> IntelligenceGraph:
        return self.parser.graph

    def save_graph(self, output_file: Optional[Path] = None) -> Path:
        """Save graph to JSON file. If output_file not provided, creates one under config.DATA_DIR."""
        graph = self.parser.graph.to_dict()
        if output_file is None:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename = f"intelligence_graph_{self.target}_{timestamp}.json"
            output_file = Path(config.DATA_DIR) / filename

        # ensure directory exists
        output_file.parent.mkdir(parents=True, exist_ok=True)

        # write atomically (temp -> rename)
        tmp_path = output_file.with_suffix(output_file.suffix + ".tmp")
        with tmp_path.open("w", encoding="utf-8") as f:
            json.dump(graph, f, indent=2)
        tmp_path.replace(output_file)

        logger.info("[GRAPH SAVED] %s", output_file)
        return output_file

    def print_summary(self) -> None:
        """Print a terminal summary (keeps original behavior)."""
        graph_data = self.parser.graph.to_dict()
        stats = graph_data["stats"]

        logger.info("=" * 60)
        logger.info("INTELLIGENCE GRAPH SUMMARY: %s", self.target)
        logger.info("=" * 60)

        logger.info("Entity Distribution:")
        for entity_type, count in stats["entity_types"].items():
            logger.info("  • %-20s: %d", entity_type, count)

        logger.info("Relationship Distribution:")
        for rel_type, count in stats["relationship_types"].items():
            logger.info("  • %-25s: %d", rel_type, count)

        high_value = [e for e in self.parser.graph.entities.values() if e.metadata.get("high_value_target")]
        if high_value:
            logger.info("High-Value Targets (%d):", len(high_value))
            for entity in high_value[:5]:
                connections = entity.metadata.get("connection_count", 0)
                logger.info("  • %-40s (%s) - %d connections", entity.value, entity.type, connections)
        logger.info("=" * 60)

# -----------------------
# CLI entrypoint
# -----------------------
def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Module 2: OSINT Parser & Correlator")
    parser.add_argument("input", help="Path to osint_results.json (output from Module 1)")
    parser.add_argument("--out", "-o", help="Output path for intelligence graph JSON (optional)")
    args = parser.parse_args()

    results_file = Path(args.input)
    if not results_file.exists():
        logger.error("Input file not found: %s", results_file)
        raise SystemExit(1)

    with results_file.open("r", encoding="utf-8") as f:
        osint_results = json.load(f)

    correlator = DataCorrelator(osint_results)
    correlator.parse_all()
    correlator.correlate_all()

    out_path = Path(args.out) if args.out else None
    saved = correlator.save_graph(out_path)
    correlator.print_summary()
    logger.info("Done. Saved: %s", saved)


if __name__ == "__main__":
    main()
