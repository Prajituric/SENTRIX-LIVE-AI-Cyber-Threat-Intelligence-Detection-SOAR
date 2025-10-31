"""
Simplified SOAR Integration Module for SENTRIX LIVE++
"""

import logging
from typing import Dict, Any, List, Optional

from elasticsearch import Elasticsearch
from redis import Redis

logger = logging.getLogger(__name__)

class SOARIntegration:
    """Simplified integration of SOAR capabilities with other system components."""
    
    def __init__(
        self,
        es_client: Elasticsearch,
        redis_client: Redis,
        index_prefix: str = "sentrix"
    ):
        """Initialize the SOAR integration.
        
        Args:
            es_client: Elasticsearch client
            redis_client: Redis client
            index_prefix: Prefix for Elasticsearch indices
        """
        self.es = es_client
        self.redis = redis_client
        self.index_prefix = index_prefix
        self.alert_index = f"{index_prefix}-alerts"
        self.template_index = f"{index_prefix}-playbook-templates"
        self.execution_index = f"{index_prefix}-playbook-executions"
    
    def process_alert(self, alert: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Process an alert and trigger appropriate playbooks.
        
        Args:
            alert: Alert data
            
        Returns:
            List of triggered playbook executions
        """
        logger.info(f"Processing alert: {alert.get('id', 'unknown')}")
        
        # Find matching playbook templates
        matching_templates = self._find_matching_templates(alert)
        
        # Execute matching playbooks
        executions = []
        for template in matching_templates:
            try:
                # In a real implementation, this would call the PlaybookEngine
                # For now, just log that we would execute the playbook
                logger.info(f"Would execute playbook {template['id']} for alert {alert.get('id', 'unknown')}")
                
                executions.append({
                    "template_id": template["id"],
                    "template_name": template["name"],
                    "execution_id": "simulated-execution-id"
                })
            except Exception as e:
                logger.error(f"Error executing playbook {template['id']}: {str(e)}")
        
        return executions
    
    def _find_matching_templates(self, alert: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find playbook templates that match the alert.
        
        Args:
            alert: Alert data
            
        Returns:
            List of matching playbook templates
        """
        try:
            # Simple query for templates that match the alert type and severity
            query = {
                "bool": {
                    "must": [
                        {"term": {"trigger.type": "alert"}}
                    ],
                    "should": [],
                    "minimum_should_match": 1
                }
            }
            
            # Add alert type condition if available
            if "type" in alert:
                query["bool"]["should"].append({
                    "term": {"trigger.conditions.alert_type": alert["type"]}
                })
            
            # Add severity condition if available
            if "severity" in alert:
                query["bool"]["should"].append({
                    "term": {"trigger.conditions.severity": alert["severity"]}
                })
            
            # Search for matching templates
            result = self.es.search(
                index=self.template_index,
                body={"query": query},
                size=10
            )
            
            return [hit["_source"] for hit in result["hits"]["hits"]]
        except Exception as e:
            logger.error(f"Error finding matching templates: {str(e)}")
            return []
    
    def get_active_playbooks(self) -> List[Dict[str, Any]]:
        """Get all active playbook executions.
        
        Returns:
            List of active playbook executions
        """
        try:
            query = {
                "bool": {
                    "must": [
                        {"terms": {"status": ["running", "pending"]}}
                    ]
                }
            }
            
            result = self.es.search(
                index=self.execution_index,
                body={
                    "query": query,
                    "sort": [{"created_at": {"order": "desc"}}]
                },
                size=100
            )
            
            return [hit["_source"] for hit in result["hits"]["hits"]]
        except Exception as e:
            logger.error(f"Error getting active playbooks: {str(e)}")
            return []