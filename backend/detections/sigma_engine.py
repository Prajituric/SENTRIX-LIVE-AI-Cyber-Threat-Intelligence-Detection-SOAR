"""
Sigma rule detection engine for SENTRIX LIVE++.
Converts Sigma rules to Elasticsearch queries and executes them against indexed events.
"""
import os
import logging
import yaml
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta

from backend.core.config import settings
from backend.core.db import get_elasticsearch_client

logger = logging.getLogger(__name__)

class SigmaEngine:
    """Engine for loading, converting, and executing Sigma rules against Elasticsearch."""
    
    def __init__(self, rules_directory: str = None):
        self.es_client = get_elasticsearch_client()
        self.rules_directory = rules_directory or os.path.join(os.getcwd(), "rules", "sigma")
        self.rules = {}
        self.load_rules()
    
    def load_rules(self) -> None:
        """Load Sigma rules from the rules directory."""
        if not os.path.exists(self.rules_directory):
            logger.warning(f"Sigma rules directory not found: {self.rules_directory}")
            return
        
        for root, _, files in os.walk(self.rules_directory):
            for file in files:
                if file.endswith(('.yml', '.yaml')):
                    try:
                        rule_path = os.path.join(root, file)
                        with open(rule_path, 'r') as f:
                            rule = yaml.safe_load(f)
                            
                        if not all(k in rule for k in ['id', 'title', 'detection']):
                            logger.warning(f"Skipping invalid Sigma rule: {rule_path}")
                            continue
                        
                        es_query = self._convert_rule_to_es_query(rule)
                        if es_query:
                            self.rules[rule['id']] = {
                                'rule': rule,
                                'es_query': es_query,
                                'path': rule_path
                            }
                            logger.info(f"Loaded Sigma rule: {rule['id']} - {rule['title']}")
                    except Exception as e:
                        logger.error(f"Error loading Sigma rule {file}: {str(e)}")
        
        logger.info(f"Loaded {len(self.rules)} Sigma rules")
    
    def _convert_rule_to_es_query(self, rule: Dict) -> Optional[Dict]:
        """Convert a Sigma rule to an Elasticsearch query."""
        try:
            detection = rule.get('detection', {})
            
            if 'selection' in detection and 'condition' in detection:
                condition = detection['condition']
                
                if condition == 'selection':
                    return self._build_query_from_selection(detection['selection'])
                
                elif ' and ' in condition:
                    parts = condition.split(' and ')
                    must_clauses = []
                    for part in parts:
                        part = part.strip()
                        if part in detection:
                            must_clauses.append(self._build_query_from_selection(detection[part]))
                    
                    return {"bool": {"must": must_clauses}}
                
                elif ' or ' in condition:
                    parts = condition.split(' or ')
                    should_clauses = []
                    for part in parts:
                        part = part.strip()
                        if part in detection:
                            should_clauses.append(self._build_query_from_selection(detection[part]))
                    
                    return {"bool": {"should": should_clauses, "minimum_should_match": 1}}
                
                elif ' and not ' in condition:
                    parts = condition.split(' and not ')
                    if len(parts) == 2 and parts[0].strip() in detection and parts[1].strip() in detection:
                        return {
                            "bool": {
                                "must": self._build_query_from_selection(detection[parts[0].strip()]),
                                "must_not": self._build_query_from_selection(detection[parts[1].strip()])
                            }
                        }
            
            logger.warning(f"Complex Sigma rule condition not fully supported: {rule['id']}")
            return self._build_fallback_query(rule)
            
        except Exception as e:
            logger.error(f"Error converting Sigma rule {rule.get('id', 'unknown')}: {str(e)}")
            return None
    
    def _build_query_from_selection(self, selection: Dict) -> Dict:
        """Build an Elasticsearch query from a Sigma rule selection."""
        must_clauses = []
        
        for field, value in selection.items():
            if isinstance(value, list):
                should_clauses = []
                for v in value:
                    should_clauses.append(self._build_field_query(field, v))
                
                must_clauses.append({
                    "bool": {
                        "should": should_clauses,
                        "minimum_should_match": 1
                    }
                })
            else:
                must_clauses.append(self._build_field_query(field, value))
        
        return {"bool": {"must": must_clauses}}
    
    def _build_field_query(self, field: str, value: Any) -> Dict:
        """Build an Elasticsearch query for a single field."""
        if isinstance(value, str) and ('*' in value or '?' in value):
            return {"wildcard": {field: value}}
        
        return {"match": {field: value}}
    
    def _build_fallback_query(self, rule: Dict) -> Dict:
        """Build a simplified fallback query for complex rules."""
        keywords = []
        if 'title' in rule:
            keywords.extend(rule['title'].lower().split())
        if 'description' in rule:
            keywords.extend(rule['description'].lower().split())
        
        common_words = ['the', 'and', 'or', 'in', 'on', 'at', 'to', 'for', 'with', 'by', 'from']
        keywords = [k for k in keywords if len(k) > 3 and k not in common_words]
        
        return {
            "multi_match": {
                "query": " ".join(keywords),
                "fields": ["*"],
                "type": "best_fields"
            }
        }
    
    def run_detection(self, time_range: int = 15) -> List[Dict]:
        """Run all loaded Sigma rules against Elasticsearch."""
        alerts = []
        
        now = datetime.utcnow()
        start_time = now - timedelta(minutes=time_range)
        
        time_filter = {
            "range": {
                "@timestamp": {
                    "gte": start_time.isoformat(),
                    "lte": now.isoformat()
                }
            }
        }
        
        for rule_id, rule_data in self.rules.items():
            try:
                rule = rule_data['rule']
                es_query = rule_data['es_query']
                
                query = {
                    "bool": {
                        "must": [
                            es_query,
                            time_filter
                        ]
                    }
                }
                
                log_type = rule.get('logsource', {}).get('product', 'generic')
                if log_type == 'windows':
                    index_pattern = f"{settings.elasticsearch.INDEX_PREFIX}windows-*"
                elif log_type == 'linux':
                    index_pattern = f"{settings.elasticsearch.INDEX_PREFIX}linux-*"
                elif log_type == 'network':
                    index_pattern = f"{settings.elasticsearch.INDEX_PREFIX}network-*"
                else:
                    index_pattern = f"{settings.elasticsearch.INDEX_PREFIX}*"
                
                response = self.es_client.search(
                    index=index_pattern,
                    body={"query": query, "size": 100}
                )
                
                hits = response.get('hits', {}).get('hits', [])
                if hits:
                    for hit in hits:
                        source = hit.get('_source', {})
                        
                        alert = {
                            "rule_id": rule_id,
                            "rule_name": rule.get('title', 'Unknown'),
                            "severity": rule.get('level', 'medium'),
                            "description": rule.get('description', ''),
                            "event_id": hit.get('_id'),
                            "timestamp": source.get('@timestamp', now.isoformat()),
                            "source_ip": source.get('source.ip', source.get('src_ip', '')),
                            "destination_ip": source.get('destination.ip', source.get('dest_ip', '')),
                            "source_user": source.get('source.user', source.get('user', '')),
                            "event_data": source,
                            "detection_time": now.isoformat(),
                            "mitre_attack": rule.get('tags', []),
                            "false_positive": rule.get('falsepositives', []),
                            "references": rule.get('references', [])
                        }
                        
                        alerts.append(alert)
                        
                        self.es_client.index(
                            index=f"{settings.elasticsearch.INDEX_PREFIX}alerts",
                            body=alert
                        )
                        
                        logger.info(f"Alert generated: {rule.get('title')} - {source.get('source.ip', '')}")
            
            except Exception as e:
                logger.error(f"Error running Sigma rule {rule_id}: {str(e)}")
        
        return alerts
    
    def run_rule(self, rule_id: str, time_range: int = 15) -> List[Dict]:
        """Run a specific Sigma rule against Elasticsearch."""
        if rule_id not in self.rules:
            logger.warning(f"Sigma rule not found: {rule_id}")
            return []
        
        now = datetime.utcnow()
        start_time = now - timedelta(minutes=time_range)
        
        time_filter = {
            "range": {
                "@timestamp": {
                    "gte": start_time.isoformat(),
                    "lte": now.isoformat()
                }
            }
        }
        
        rule_data = self.rules[rule_id]
        rule = rule_data['rule']
        es_query = rule_data['es_query']
        
        query = {
            "bool": {
                "must": [
                    es_query,
                    time_filter
                ]
            }
        }
        
        log_type = rule.get('logsource', {}).get('product', 'generic')
        if log_type == 'windows':
            index_pattern = f"{settings.elasticsearch.INDEX_PREFIX}windows-*"
        elif log_type == 'linux':
            index_pattern = f"{settings.elasticsearch.INDEX_PREFIX}linux-*"
        elif log_type == 'network':
            index_pattern = f"{settings.elasticsearch.INDEX_PREFIX}network-*"
        else:
            index_pattern = f"{settings.elasticsearch.INDEX_PREFIX}*"
        
        alerts = []
        try:
            response = self.es_client.search(
                index=index_pattern,
                body={"query": query, "size": 100}
            )
            
            hits = response.get('hits', {}).get('hits', [])
            if hits:
                for hit in hits:
                    source = hit.get('_source', {})
                    
                    alert = {
                        "rule_id": rule_id,
                        "rule_name": rule.get('title', 'Unknown'),
                        "severity": rule.get('level', 'medium'),
                        "description": rule.get('description', ''),
                        "event_id": hit.get('_id'),
                        "timestamp": source.get('@timestamp', now.isoformat()),
                        "source_ip": source.get('source.ip', source.get('src_ip', '')),
                        "destination_ip": source.get('destination.ip', source.get('dest_ip', '')),
                        "source_user": source.get('source.user', source.get('user', '')),
                        "event_data": source,
                        "detection_time": now.isoformat(),
                        "mitre_attack": rule.get('tags', []),
                        "false_positive": rule.get('falsepositives', []),
                        "references": rule.get('references', [])
                    }
                    
                    alerts.append(alert)
                    
                    self.es_client.index(
                        index=f"{settings.elasticsearch.INDEX_PREFIX}alerts",
                        body=alert
                    )
                    
                    logger.info(f"Alert generated: {rule.get('title')} - {source.get('source.ip', '')}")
        
        except Exception as e:
            logger.error(f"Error running Sigma rule {rule_id}: {str(e)}")
        
        return alerts

# Singleton instance
sigma_engine = SigmaEngine()

def get_sigma_engine() -> SigmaEngine:
    """Get the Sigma engine instance."""
    return sigma_engine