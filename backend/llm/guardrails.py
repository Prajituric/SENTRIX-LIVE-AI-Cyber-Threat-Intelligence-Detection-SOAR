"""
LLM Guardrails Module

This module implements security guardrails for LLM interactions in the SENTRIX LIVE++ platform.
It provides mechanisms to prevent prompt injection, scrub PII, enforce rate limits,
validate outputs, and ensure LLM actions are safe and auditable.
"""

import re
import json
import logging
from enum import Enum
from typing import Dict, List, Optional, Any, Union, Set
from pydantic import BaseModel, Field, validator

logger = logging.getLogger(__name__)

class GuardrailViolation(Exception):
    """Exception raised when a guardrail is violated."""
    def __init__(self, message: str, guardrail_type: str):
        self.message = message
        self.guardrail_type = guardrail_type
        super().__init__(f"{guardrail_type}: {message}")


class GuardrailType(str, Enum):
    """Types of guardrails that can be enforced."""
    PROMPT_INJECTION = "prompt_injection"
    SENSITIVE_DATA = "sensitive_data"
    HARMFUL_INSTRUCTIONS = "harmful_instructions"
    IRRELEVANT_CONTENT = "irrelevant_content"
    STRUCTURED_OUTPUT = "structured_output"
    RATE_LIMIT = "rate_limit"


class GuardrailConfig(BaseModel):
    """Configuration for LLM guardrails."""
    
    # Sensitive data patterns to redact (regex patterns)
    sensitive_data_patterns: Dict[str, str] = Field(default_factory=lambda: {
        "ip_address": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "credit_card": r"\b(?:\d{4}[- ]?){3}\d{4}\b",
        "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
        "api_key": r"\b(?:api[_-]?key|token|secret)[_-]?[0-9a-zA-Z]{16,}\b",
    })
    
    # Patterns that might indicate prompt injection attempts
    prompt_injection_patterns: List[str] = Field(default_factory=lambda: [
        r"ignore previous instructions",
        r"disregard (?:all|previous) instructions",
        r"forget (?:all|your|previous) instructions",
        r"ignore (?:all|your) training",
        r"you are now",
        r"now you are",
        r"you're no longer",
        r"you are no longer",
    ])
    
    # Patterns for harmful instructions that should be blocked
    harmful_instruction_patterns: List[str] = Field(default_factory=lambda: [
        r"execute\s+(?:command|cmd|script|code)",
        r"run\s+(?:command|cmd|script|code)",
        r"delete\s+(?:all|files|data|database)",
        r"drop\s+(?:table|database)",
        r"format\s+(?:disk|drive|system)",
        r"(?:exploit|hack|attack)\s+(?:system|server|network)",
    ])
    
    # Allowed security topics to ensure relevance
    allowed_security_topics: Set[str] = Field(default_factory=lambda: {
        "malware", "phishing", "ransomware", "vulnerability", "exploit", 
        "threat", "attack", "security", "incident", "breach", "detection",
        "alert", "warning", "suspicious", "compromise", "unauthorized",
        "authentication", "access", "firewall", "network", "traffic",
        "anomaly", "scan", "reconnaissance", "lateral movement", "exfiltration",
        "command and control", "c2", "persistence", "privilege escalation",
        "defense evasion", "credential", "discovery", "collection", "impact",
        "mitre", "att&ck", "cve", "cwe", "ioc", "indicator", "signature",
        "rule", "policy", "compliance", "audit", "log", "event", "monitor",
        "response", "remediation", "mitigation", "containment", "eradication",
        "recovery", "forensics", "analysis", "investigation", "hunting",
        "intelligence", "cti", "threat intelligence", "attribution", "actor",
        "campaign", "apt", "advanced persistent threat", "zero day", "0day",
        "patch", "update", "configuration", "hardening", "baseline", "control",
        "safeguard", "protection", "prevention", "detection", "response",
        "soar", "siem", "edr", "xdr", "ndr", "ids", "ips", "waf", "dlp",
    })
    
    # Maximum tokens per minute for rate limiting
    rate_limit_tokens_per_minute: int = 10000
    
    # Maximum consecutive LLM calls from same user/session
    rate_limit_consecutive_calls: int = 20
    
    # Timeout between consecutive calls (seconds)
    rate_limit_timeout_seconds: int = 1
    
    # Whether to audit all LLM interactions
    audit_all_interactions: bool = True
    
    # Whether to enforce structured output validation
    enforce_structured_output: bool = True
    
    # Default redaction text for sensitive data
    redaction_text: str = "[REDACTED]"


class SecurityLLMGuardrails:
    """
    Implements security guardrails for LLM interactions.
    
    This class provides methods to:
    1. Detect and prevent prompt injection attempts
    2. Redact sensitive data from inputs and outputs
    3. Block harmful instructions
    4. Ensure content relevance to security topics
    5. Enforce rate limits
    6. Audit LLM interactions
    """
    
    def __init__(self, config: Optional[GuardrailConfig] = None):
        """Initialize with optional custom configuration."""
        self.config = config or GuardrailConfig()
        self._compile_regex_patterns()
        
    def _compile_regex_patterns(self):
        """Compile regex patterns for efficiency."""
        # Compile sensitive data patterns
        self.sensitive_patterns = {
            name: re.compile(pattern, re.IGNORECASE) 
            for name, pattern in self.config.sensitive_data_patterns.items()
        }
        
        # Compile prompt injection patterns
        self.injection_pattern = re.compile(
            "|".join(f"({p})" for p in self.config.prompt_injection_patterns), 
            re.IGNORECASE
        )
        
        # Compile harmful instruction patterns
        self.harmful_pattern = re.compile(
            "|".join(f"({p})" for p in self.config.harmful_instruction_patterns), 
            re.IGNORECASE
        )
    
    def validate_input(self, text: str) -> str:
        """
        Validate and sanitize LLM input.
        
        Args:
            text: The input text to validate
            
        Returns:
            Sanitized text
            
        Raises:
            GuardrailViolation: If input violates guardrails
        """
        # Check for prompt injection attempts
        self._check_prompt_injection(text)
        
        # Check for harmful instructions
        self._check_harmful_instructions(text)
        
        # Check for relevance to security topics
        self._check_relevance(text)
        
        # Redact sensitive data
        sanitized_text = self._redact_sensitive_data(text)
        
        return sanitized_text
    
    def validate_output(self, text: str) -> str:
        """
        Validate and sanitize LLM output.
        
        Args:
            text: The output text to validate
            
        Returns:
            Sanitized text
        """
        # Redact sensitive data from output
        sanitized_text = self._redact_sensitive_data(text)
        
        return sanitized_text
    
    def _check_prompt_injection(self, text: str):
        """Check for prompt injection attempts."""
        if self.injection_pattern.search(text):
            matches = [m.group(0) for m in self.injection_pattern.finditer(text)]
            raise GuardrailViolation(
                f"Potential prompt injection detected: {matches}",
                GuardrailType.PROMPT_INJECTION
            )
    
    def _check_harmful_instructions(self, text: str):
        """Check for harmful instructions."""
        if self.harmful_pattern.search(text):
            matches = [m.group(0) for m in self.harmful_pattern.finditer(text)]
            raise GuardrailViolation(
                f"Harmful instructions detected: {matches}",
                GuardrailType.HARMFUL_INSTRUCTIONS
            )
    
    def _check_relevance(self, text: str):
        """Check if content is relevant to security topics."""
        # Simple check: at least one security-related term should be present
        text_lower = text.lower()
        if not any(topic in text_lower for topic in self.config.allowed_security_topics):
            raise GuardrailViolation(
                "Content does not appear to be related to security topics",
                GuardrailType.IRRELEVANT_CONTENT
            )
    
    def _redact_sensitive_data(self, text: str) -> str:
        """Redact sensitive data from text."""
        redacted = text
        for name, pattern in self.sensitive_patterns.items():
            redacted = pattern.sub(self.config.redaction_text, redacted)
        return redacted
    
    def audit_interaction(self, 
                         user_id: str, 
                         input_text: str, 
                         output_text: str, 
                         metadata: Optional[Dict[str, Any]] = None):
        """
        Audit an LLM interaction.
        
        Args:
            user_id: ID of the user making the request
            input_text: The input prompt
            output_text: The LLM response
            metadata: Additional metadata about the interaction
        """
        if not self.config.audit_all_interactions:
            return
            
        # In a real implementation, this would write to a secure audit log
        # For now, we'll just log it
        audit_entry = {
            "user_id": user_id,
            "input_length": len(input_text),
            "output_length": len(output_text),
            "timestamp": "TIMESTAMP",  # Would use actual timestamp
            "metadata": metadata or {},
        }
        
        logger.info(f"LLM Interaction Audit: {json.dumps(audit_entry)}")


class StructuredOutputGuardrails:
    """
    Enforces structured output validation for LLM responses.
    
    This ensures that LLM outputs conform to expected schemas,
    particularly important for security-related structured data.
    """
    
    def __init__(self, schema: Dict[str, Any]):
        """
        Initialize with a JSON schema.
        
        Args:
            schema: JSON schema that outputs should conform to
        """
        self.schema = schema
    
    def validate(self, output: Union[str, Dict[str, Any]]) -> Dict[str, Any]:
        """
        Validate that output conforms to the expected schema.
        
        Args:
            output: LLM output (string or parsed JSON)
            
        Returns:
            Validated and parsed output
            
        Raises:
            GuardrailViolation: If output doesn't conform to schema
        """
        # Parse output if it's a string
        if isinstance(output, str):
            try:
                parsed_output = json.loads(output)
            except json.JSONDecodeError:
                raise GuardrailViolation(
                    "Output is not valid JSON",
                    GuardrailType.STRUCTURED_OUTPUT
                )
        else:
            parsed_output = output
            
        # Validate against schema
        # In a real implementation, this would use jsonschema or similar
        # For simplicity, we'll just check required fields
        if "required" in self.schema:
            missing_fields = [
                field for field in self.schema["required"]
                if field not in parsed_output
            ]
            if missing_fields:
                raise GuardrailViolation(
                    f"Output missing required fields: {missing_fields}",
                    GuardrailType.STRUCTURED_OUTPUT
                )
                
        return parsed_output


# Example schemas for structured outputs

MITRE_ATTACK_SCHEMA = {
    "type": "object",
    "required": ["tactics", "techniques", "confidence", "explanation"],
    "properties": {
        "tactics": {
            "type": "array",
            "items": {"type": "string"},
            "description": "MITRE ATT&CK tactics identified"
        },
        "techniques": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["id", "name", "confidence"],
                "properties": {
                    "id": {"type": "string"},
                    "name": {"type": "string"},
                    "confidence": {"type": "number", "minimum": 0, "maximum": 1}
                }
            },
            "description": "MITRE ATT&CK techniques identified"
        },
        "confidence": {
            "type": "number",
            "minimum": 0,
            "maximum": 1,
            "description": "Overall confidence in the assessment"
        },
        "explanation": {
            "type": "string",
            "description": "Human-readable explanation of the assessment"
        }
    }
}

IOC_SCHEMA = {
    "type": "object",
    "required": ["iocs", "confidence", "context"],
    "properties": {
        "iocs": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["type", "value", "confidence"],
                "properties": {
                    "type": {
                        "type": "string",
                        "enum": ["ip", "domain", "url", "file_hash", "email"]
                    },
                    "value": {"type": "string"},
                    "confidence": {"type": "number", "minimum": 0, "maximum": 1}
                }
            }
        },
        "confidence": {
            "type": "number",
            "minimum": 0,
            "maximum": 1
        },
        "context": {
            "type": "string"
        }
    }
}


class GuardrailConfig(BaseModel):
    """Configuration for guardrails."""
    enabled_guardrails: List[GuardrailType] = Field(
        default_factory=lambda: list(GuardrailType),
        description="List of enabled guardrails"
    )
    max_tokens: int = Field(
        default=2000,
        description="Maximum number of tokens allowed in response"
    )
    sensitive_patterns: List[str] = Field(
        default_factory=lambda: [
            r'\b(?:\d[ -]*?){13,16}\b',  # Credit card numbers
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email addresses
            r'\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',  # IP addresses
            r'\b[A-Za-z0-9]{32}\b',  # MD5 hashes
            r'\b[A-Za-z0-9]{40}\b',  # SHA-1 hashes
            r'\b[A-Za-z0-9]{64}\b',  # SHA-256 hashes
        ],
        description="Regex patterns for sensitive data detection"
    )
    harmful_instructions_patterns: List[str] = Field(
        default_factory=lambda: [
            r'\b(?:delete|remove|drop)\s+(?:all|database|table|collection|index)\b',
            r'\b(?:format|wipe)\s+(?:disk|drive|volume|partition)\b',
            r'\b(?:shutdown|reboot)\s+(?:system|server|host|computer)\b',
            r'\b(?:exploit|hack|attack|compromise)\b',
        ],
        description="Regex patterns for harmful instructions detection"
    )
    prompt_injection_patterns: List[str] = Field(
        default_factory=lambda: [
            r'\bignore previous instructions\b',
            r'\bdisregard (?:your|earlier|prior) instructions\b',
            r'\bforget (?:your|earlier|prior) instructions\b',
        ],
        description="Regex patterns for prompt injection detection"
    )
    allowed_security_topics: List[str] = Field(
        default_factory=lambda: [
            "malware", "phishing", "ransomware", "vulnerability", "exploit",
            "threat", "attack", "incident", "detection", "response",
            "mitigation", "remediation", "security", "breach", "compromise",
            "alert", "warning", "indicator", "signature", "rule",
            "MITRE", "ATT&CK", "CVE", "CWE", "IOC", "TTP", "STIX", "TAXII",
            "network", "endpoint", "host", "server", "client", "user", "account",
            "authentication", "authorization", "access", "permission", "privilege",
            "encryption", "decryption", "hash", "signature", "certificate",
            "firewall", "IDS", "IPS", "SIEM", "SOC", "SOAR", "EDR", "XDR", "NDR",
        ],
        description="List of allowed security topics"
    )


class SecurityLLMGuardrails:
    """
    Implements guardrails for LLM interactions in security context.
    
    This class provides methods to:
    1. Sanitize inputs to LLMs to prevent prompt injection
    2. Validate outputs from LLMs to ensure they don't contain sensitive data
    3. Ensure outputs are relevant to security operations
    4. Prevent harmful instructions in outputs
    """
    
    def __init__(self, config: Optional[GuardrailConfig] = None):
        """Initialize guardrails with optional custom configuration."""
        self.config = config or GuardrailConfig()
    
    def validate_input(self, prompt: str) -> str:
        """
        Validate and sanitize input prompt before sending to LLM.
        
        Args:
            prompt: The input prompt to validate
            
        Returns:
            Sanitized prompt
            
        Raises:
            GuardrailViolation: If prompt contains injection attempts
        """
        if GuardrailType.PROMPT_INJECTION in self.config.enabled_guardrails:
            for pattern in self.config.prompt_injection_patterns:
                if re.search(pattern, prompt, re.IGNORECASE):
                    raise GuardrailViolation(f"Prompt injection detected: {pattern}")
        
        # Add security context reminder to help prevent hallucinations
        security_context = (
            "\nRemember to focus only on security-related information and avoid "
            "including any sensitive data in your response. Base your analysis "
            "only on the provided information and your security knowledge."
        )
        
        return prompt + security_context
    
    def validate_output(self, output: str) -> str:
        """
        Validate LLM output to ensure it complies with security guardrails.
        
        Args:
            output: The LLM-generated output to validate
            
        Returns:
            Validated output (may be modified if needed)
            
        Raises:
            GuardrailViolation: If output violates any enabled guardrails
        """
        # Check for sensitive data
        if GuardrailType.SENSITIVE_DATA in self.config.enabled_guardrails:
            for pattern in self.config.sensitive_patterns:
                matches = re.findall(pattern, output, re.IGNORECASE)
                if matches:
                    # Redact sensitive information
                    redacted_output = output
                    for match in matches:
                        redacted_output = redacted_output.replace(match, "[REDACTED]")
                    output = redacted_output
        
        # Check for harmful instructions
        if GuardrailType.HARMFUL_INSTRUCTIONS in self.config.enabled_guardrails:
            for pattern in self.config.harmful_instructions_patterns:
                if re.search(pattern, output, re.IGNORECASE):
                    raise GuardrailViolation(f"Harmful instruction detected in output: {pattern}")
        
        # Check for relevance to security topics
        if GuardrailType.IRRELEVANT_CONTENT in self.config.enabled_guardrails:
            # Simple heuristic: check if output contains security-related terms
            security_terms_found = any(
                term.lower() in output.lower() 
                for term in self.config.allowed_security_topics
            )
            
            if not security_terms_found and len(output) > 50:  # Ignore short responses
                raise GuardrailViolation("Output does not appear to be security-related")
        
        return output
    
    def apply_guardrails(self, prompt: str, model_fn) -> str:
        """
        Apply guardrails to both input and output of LLM interaction.
        
        Args:
            prompt: The input prompt
            model_fn: Function that takes a prompt and returns LLM response
            
        Returns:
            Validated LLM response
        """
        sanitized_prompt = self.validate_input(prompt)
        raw_output = model_fn(sanitized_prompt)
        validated_output = self.validate_output(raw_output)
        return validated_output


class StructuredOutputGuardrails(SecurityLLMGuardrails):
    """
    Extended guardrails for ensuring LLM outputs conform to expected structured formats.
    Useful for ensuring MITRE ATT&CK mappings, IOCs, and other structured data are valid.
    """
    
    def __init__(self, config: Optional[GuardrailConfig] = None, schema: Optional[Dict] = None):
        """
        Initialize with optional schema for validating structured outputs.
        
        Args:
            config: GuardrailConfig for base security guardrails
            schema: JSON schema for validating structured outputs
        """
        super().__init__(config)
        self.schema = schema
    
    def validate_structured_output(self, output: str) -> Dict:
        """
        Validate that LLM output conforms to expected JSON schema.
        
        Args:
            output: String output from LLM that should contain JSON
            
        Returns:
            Parsed and validated JSON object
            
        Raises:
            GuardrailViolation: If output is not valid JSON or doesn't match schema
        """
        # First apply standard security guardrails
        validated_output = self.validate_output(output)
        
        # Extract JSON from the output
        try:
            # Try to find JSON-like content in the output
            json_match = re.search(r'```json\s*([\s\S]*?)\s*```|({[\s\S]*})', validated_output)
            if json_match:
                json_str = json_match.group(1) or json_match.group(2)
                parsed_json = json.loads(json_str)
            else:
                # Try to parse the entire output as JSON
                parsed_json = json.loads(validated_output)
        except (json.JSONDecodeError, TypeError):
            raise GuardrailViolation("Output is not valid JSON")
        
        # If schema is provided, validate against it
        if self.schema:
            # Simple schema validation (in production, use a proper JSON schema validator)
            for key, value_type in self.schema.items():
                if key not in parsed_json:
                    raise GuardrailViolation(f"Required field '{key}' missing from output")
                
                if not isinstance(parsed_json[key], value_type):
                    raise GuardrailViolation(
                        f"Field '{key}' has wrong type. Expected {value_type.__name__}, "
                        f"got {type(parsed_json[key]).__name__}"
                    )
        
        return parsed_json


# Example MITRE ATT&CK schema for structured output validation
MITRE_ATTACK_SCHEMA = {
    "tactics": list,
    "techniques": list,
    "mitigations": list
}

# Example IOC schema for structured output validation
IOC_SCHEMA = {
    "ips": list,
    "domains": list,
    "hashes": list,
    "urls": list
}