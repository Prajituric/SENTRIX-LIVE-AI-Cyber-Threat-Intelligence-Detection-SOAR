"""
LLM Explainer Module for security event explanation with guardrails.
"""

import json
import logging
from typing import Dict, List, Any, Optional
from enum import Enum

from pydantic import BaseModel, Field

from .guardrails import SecurityLLMGuardrails, StructuredOutputGuardrails, MITRE_ATTACK_SCHEMA

logger = logging.getLogger(__name__)

class ExplanationFormat(str, Enum):
    """Formats for security event explanations."""
    MITRE_ATTACK = "mitre_attack"
    IOC = "ioc"
    GENERAL = "general"
    REMEDIATION = "remediation"

class SecurityEventExplainer:
    """Explains security events using LLM with RAG over CTI data."""
    
    def __init__(self, llm_client, cti_retriever=None, guardrails_config=None):
        """Initialize the explainer with LLM client and optional components."""
        self.llm_client = llm_client
        self.cti_retriever = cti_retriever
        self.security_guardrails = SecurityLLMGuardrails(config=guardrails_config)
        self.mitre_validator = StructuredOutputGuardrails(MITRE_ATTACK_SCHEMA)
        self._load_prompt_templates()
    
    def _load_prompt_templates(self):
        """Load prompt templates for different explanation types."""
        self.templates = {
            ExplanationFormat.MITRE_ATTACK: """
                Analyze the following security event and provide a MITRE ATT&CK mapping:
                EVENT: {event_data}
                CONTEXT: {cti_context}
                Format your response as JSON with tactics, techniques, confidence, and explanation.
            """,
            ExplanationFormat.GENERAL: """
                Explain the following security event in clear, concise language:
                EVENT: {event_data}
                CONTEXT: {cti_context}
                Format your response as JSON with title, description, severity, and confidence.
            """
        }
    
    async def explain(self, event_data: Dict[str, Any], format_type: ExplanationFormat = ExplanationFormat.GENERAL, 
                     user_id: str = "system") -> Dict[str, Any]:
        """Generate an explanation for a security event."""
        # Convert event data to string representation
        event_str = json.dumps(event_data, indent=2)
        
        # Retrieve relevant CTI context if retriever is available
        cti_context = ""
        if self.cti_retriever:
            cti_docs = await self.cti_retriever.retrieve(
                query=self._generate_cti_query(event_data),
                limit=3
            )
            cti_context = "\n\n".join([doc.content for doc in cti_docs])
        
        # Fill in the prompt template
        prompt_template = self.templates.get(format_type, self.templates[ExplanationFormat.GENERAL])
        prompt = prompt_template.format(
            event_data=event_str,
            cti_context=cti_context or "No additional context available."
        )
        
        # Apply security guardrails to the prompt
        sanitized_prompt = self.security_guardrails.validate_input(prompt)
        
        # Call LLM with sanitized prompt
        llm_response = await self.llm_client.generate(sanitized_prompt)
        
        # Apply security guardrails to the response
        sanitized_response = self.security_guardrails.validate_output(llm_response)
        
        # Parse JSON response
        try:
            # Extract JSON from response
            json_str = self._extract_json(sanitized_response)
            parsed = json.loads(json_str)
            
            # Validate against schema if MITRE format
            if format_type == ExplanationFormat.MITRE_ATTACK:
                return self.mitre_validator.validate(parsed)
            return parsed
            
        except Exception as e:
            logger.error(f"Error parsing LLM response: {e}")
            raise
    
    def _generate_cti_query(self, event_data: Dict[str, Any]) -> str:
        """Generate a query for CTI retrieval based on event data."""
        query_parts = []
        
        # Extract key fields for query
        for field in ["alert_name", "source_ip", "destination_ip", "malware", "cve_id"]:
            if field in event_data:
                query_parts.append(str(event_data[field]))
                
        return " ".join(query_parts) or json.dumps(event_data)[:200]
    
    def _extract_json(self, text: str) -> str:
        """Extract JSON from text that might contain additional content."""
        import re
        json_match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text)
        if json_match:
            return json_match.group(1)
        
        json_match = re.search(r"(\{[\s\S]*\})", text)
        if json_match:
            return json_match.group(1)
        
        return text