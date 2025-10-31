"""
Stream parsers for security logs in SENTRIX LIVE++.
These parsers handle different log formats and convert them to standardized alert format.
"""

import json
import re
from datetime import datetime
from typing import Dict, Any, List, Optional, Union, Callable
from abc import ABC, abstractmethod

class BaseStreamParser(ABC):
    """Base class for all stream parsers."""
    
    @abstractmethod
    def parse(self, log_data: str) -> Optional[Dict[str, Any]]:
        """Parse log data and return standardized alert format or None if not applicable."""
        pass

class SyslogParser(BaseStreamParser):
    """Parser for syslog format logs."""
    
    def __init__(self):
        # Basic syslog pattern
        self.pattern = re.compile(
            r'<(?P<priority>\d+)>(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+'
            r'(?P<hostname>[\w\-\.]+)\s+(?P<application>[\w\-]+)(?:\[(?P<pid>\d+)\])?:\s+'
            r'(?P<message>.*)'
        )
    
    def parse(self, log_data: str) -> Optional[Dict[str, Any]]:
        match = self.pattern.match(log_data)
        if not match:
            return None
            
        data = match.groupdict()
        
        # Convert to standardized format
        return {
            "timestamp": datetime.now().isoformat(),  # In production, parse from log
            "source": data.get("hostname", "unknown"),
            "source_type": "syslog",
            "severity": self._map_priority_to_severity(data.get("priority")),
            "alert_name": f"{data.get('application', 'syslog')} alert",
            "message": data.get("message", ""),
            "raw_log": log_data
        }
    
    def _map_priority_to_severity(self, priority: Optional[str]) -> str:
        """Map syslog priority to severity level."""
        if not priority:
            return "medium"
            
        try:
            priority_int = int(priority)
            # Extract severity from priority (lower 3 bits)
            severity = priority_int & 0x7
            
            # Map to text severity
            severity_map = {
                0: "critical",  # Emergency
                1: "critical",  # Alert
                2: "critical",  # Critical
                3: "high",      # Error
                4: "medium",    # Warning
                5: "low",       # Notice
                6: "low",       # Informational
                7: "low"        # Debug
            }
            
            return severity_map.get(severity, "medium")
        except ValueError:
            return "medium"

class JSONLogParser(BaseStreamParser):
    """Parser for JSON format logs."""
    
    def parse(self, log_data: str) -> Optional[Dict[str, Any]]:
        try:
            data = json.loads(log_data)
            
            # Check if this is a security-related log
            if not self._is_security_log(data):
                return None
                
            # Map to standardized format
            return {
                "timestamp": data.get("timestamp", datetime.now().isoformat()),
                "source": data.get("source", data.get("host", "unknown")),
                "source_type": "json",
                "severity": data.get("severity", data.get("level", "medium")),
                "alert_name": data.get("alert_name", data.get("title", "Security Alert")),
                "message": data.get("message", data.get("description", "")),
                "raw_log": log_data,
                "metadata": {k: v for k, v in data.items() if k not in 
                            ["timestamp", "source", "host", "severity", "level", 
                             "alert_name", "title", "message", "description"]}
            }
        except json.JSONDecodeError:
            return None
    
    def _is_security_log(self, data: Dict[str, Any]) -> bool:
        """Determine if the JSON log is security-related."""
        # Check for common security-related fields
        security_keywords = [
            "security", "alert", "threat", "attack", "malware", "virus",
            "intrusion", "breach", "vulnerability", "exploit", "suspicious"
        ]
        
        # Check in values
        for value in data.values():
            if isinstance(value, str):
                for keyword in security_keywords:
                    if keyword in value.lower():
                        return True
        
        # Check in keys
        for key in data.keys():
            for keyword in security_keywords:
                if keyword in key.lower():
                    return True
        
        return False

class CEFParser(BaseStreamParser):
    """Parser for Common Event Format (CEF) logs."""
    
    def __init__(self):
        # Basic CEF pattern
        self.pattern = re.compile(
            r'CEF:(?P<version>\d+)\|(?P<device_vendor>[^|]*)\|(?P<device_product>[^|]*)\|'
            r'(?P<device_version>[^|]*)\|(?P<signature_id>[^|]*)\|(?P<name>[^|]*)\|'
            r'(?P<severity>[^|]*)\|(?P<extension>.*)'
        )
        
    def parse(self, log_data: str) -> Optional[Dict[str, Any]]:
        match = self.pattern.match(log_data)
        if not match:
            return None
            
        data = match.groupdict()
        extensions = self._parse_extensions(data.get("extension", ""))
        
        # Map severity
        severity = self._map_severity(data.get("severity", ""))
        
        # Convert to standardized format
        return {
            "timestamp": extensions.get("rt", datetime.now().isoformat()),
            "source": extensions.get("src", extensions.get("dvc", "unknown")),
            "source_type": "cef",
            "severity": severity,
            "alert_name": data.get("name", "CEF Alert"),
            "message": extensions.get("msg", data.get("name", "")),
            "raw_log": log_data,
            "metadata": {
                "device_vendor": data.get("device_vendor"),
                "device_product": data.get("device_product"),
                "signature_id": data.get("signature_id"),
                **extensions
            }
        }
    
    def _parse_extensions(self, extension_str: str) -> Dict[str, str]:
        """Parse CEF extensions into key-value pairs."""
        extensions = {}
        
        # Simple key=value parsing (doesn't handle all CEF complexities)
        parts = extension_str.split(" ")
        for part in parts:
            if "=" in part:
                key, value = part.split("=", 1)
                extensions[key] = value
                
        return extensions
    
    def _map_severity(self, severity: str) -> str:
        """Map CEF severity (0-10) to standardized severity."""
        try:
            severity_int = int(severity)
            if severity_int >= 9:
                return "critical"
            elif severity_int >= 7:
                return "high"
            elif severity_int >= 4:
                return "medium"
            else:
                return "low"
        except ValueError:
            return "medium"

class StreamParserManager:
    """Manager class that handles multiple parsers and selects the appropriate one."""
    
    def __init__(self):
        self.parsers = [
            SyslogParser(),
            JSONLogParser(),
            CEFParser()
        ]
        
    def parse(self, log_data: str) -> Optional[Dict[str, Any]]:
        """Try all parsers until one succeeds."""
        for parser in self.parsers:
            result = parser.parse(log_data)
            if result:
                return result
                
        return None
    
    def register_parser(self, parser: BaseStreamParser) -> None:
        """Register a new parser."""
        self.parsers.append(parser)