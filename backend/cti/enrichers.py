"""
CTI enrichers for SENTRIX LIVE++.
Enriches security events with threat intelligence data.
"""
import logging
import json
from typing import Dict, List, Any, Optional
import ipaddress
import re

from backend.core.db import get_elasticsearch_client
from backend.core.config import settings

logger = logging.getLogger(__name__)

class CTIEnricher:
    """Enriches security events with threat intelligence data."""
    
    def __init__(self):
        """Initialize the CTI enricher."""
        self.es_client = get_elasticsearch_client()
    
    def enrich_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich a security event with CTI data."""
        try:
            # Extract potential indicators
            indicators = self._extract_indicators(event)
            
            # Look up indicators in CTI data
            cti_data = self._lookup_indicators(indicators)
            
            # Add CTI data to event
            if cti_data:
                event["cti_enrichment"] = cti_data
            
            return event
        
        except Exception as e:
            logger.error(f"Error enriching event: {str(e)}")
            return event
    
    def _extract_indicators(self, event: Dict[str, Any]) -> Dict[str, List[str]]:
        """Extract potential indicators from an event."""
        indicators = {
            "ip": [],
            "domain": [],
            "hash": [],
            "url": []
        }
        
        # Extract IPs
        if "source_ip" in event and event["source_ip"]:
            indicators["ip"].append(event["source_ip"])
        if "destination_ip" in event and event["destination_ip"]:
            indicators["ip"].append(event["destination_ip"])
        
        # Extract domains
        if "dns_query" in event:
            indicators["domain"].append(event["dns_query"])
        if "host" in event:
            indicators["domain"].append(event["host"])
        
        # Extract hashes
        if "file_hash" in event:
            indicators["hash"].append(event["file_hash"])
        if "md5" in event:
            indicators["hash"].append(event["md5"])
        if "sha1" in event:
            indicators["hash"].append(event["sha1"])
        if "sha256" in event:
            indicators["hash"].append(event["sha256"])
        
        # Extract URLs
        if "url" in event:
            indicators["url"].append(event["url"])
        if "request_url" in event:
            indicators["url"].append(event["request_url"])
        
        # Deduplicate
        for ioc_type in indicators:
            indicators[ioc_type] = list(set(indicators[ioc_type]))
        
        return indicators
    
    def _lookup_indicators(self, indicators: Dict[str, List[str]]) -> List[Dict[str, Any]]:
        """Look up indicators in CTI data."""
        results = []
        
        # Build query
        should_clauses = []
        
        # IP indicators
        for ip in indicators["ip"]:
            should_clauses.append({
                "match_phrase": {
                    "pattern": ip
                }
            })
        
        # Domain indicators
        for domain in indicators["domain"]:
            should_clauses.append({
                "match_phrase": {
                    "pattern": domain
                }
            })
        
        # Hash indicators
        for hash_value in indicators["hash"]:
            should_clauses.append({
                "match_phrase": {
                    "pattern": hash_value
                }
            })
        
        # URL indicators
        for url in indicators["url"]:
            should_clauses.append({
                "match_phrase": {
                    "pattern": url
                }
            })
        
        if not should_clauses:
            return results
        
        # Execute query
        query = {
            "query": {
                "bool": {
                    "should": should_clauses,
                    "minimum_should_match": 1
                }
            },
            "size": 10
        }
        
        try:
            response = self.es_client.search(
                index=f"{settings.elasticsearch.INDEX_PREFIX}cti",
                body=query
            )
            
            hits = response.get("hits", {}).get("hits", [])
            
            for hit in hits:
                source = hit.get("_source", {})
                
                # Extract relevant fields
                cti_item = {
                    "id": source.get("id", ""),
                    "type": source.get("type", ""),
                    "name": source.get("name", ""),
                    "description": source.get("description", ""),
                    "pattern": source.get("pattern", ""),
                    "source_name": source.get("source_name", ""),
                    "confidence": 0.8,  # Default confidence
                    "severity": "medium"  # Default severity
                }
                
                # Add MITRE ATT&CK specific fields
                if "kill_chain_phases" in source:
                    phases = source["kill_chain_phases"]
                    if phases and isinstance(phases, list):
                        cti_item["kill_chain_phases"] = phases
                
                # Add external references
                if "external_references" in source:
                    refs = source["external_references"]
                    if refs and isinstance(refs, list):
                        cti_item["external_references"] = refs
                
                results.append(cti_item)
            
            return results
        
        except Exception as e:
            logger.error(f"Error looking up indicators: {str(e)}")
            return []

# Singleton instance
cti_enricher = CTIEnricher()

def get_cti_enricher():
    """Get the CTI enricher instance."""
    return cti_enricher