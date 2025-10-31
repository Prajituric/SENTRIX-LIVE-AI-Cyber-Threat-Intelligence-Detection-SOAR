"""
Simple Playbook Templates for SENTRIX LIVE++
Provides basic pre-defined security playbook templates.
"""

import uuid
from typing import Dict, Any, List

from .models import ActionType


def get_default_templates() -> List[Dict[str, Any]]:
    """Return a list of default playbook templates."""
    return [
        get_malware_response_template(),
        get_phishing_response_template()
    ]


def get_malware_response_template() -> Dict[str, Any]:
    """Template for responding to malware detection."""
    template_id = str(uuid.uuid4())
    
    # Define action IDs
    notify_action_id = f"{template_id}-notify"
    isolate_action_id = f"{template_id}-isolate"
    scan_action_id = f"{template_id}-scan"
    
    return {
        "id": template_id,
        "name": "Malware Response Playbook",
        "description": "Automated response to malware detection alerts",
        "author": "SENTRIX",
        "version": "1.0",
        "tags": ["malware", "incident-response", "containment"],
        "trigger": {
            "type": "alert",
            "conditions": {
                "alert_type": "malware",
                "severity": ["high", "critical"]
            }
        },
        "actions": {
            notify_action_id: {
                "id": notify_action_id,
                "name": "Notify Security Team",
                "description": "Send notification to security team about malware detection",
                "type": ActionType.NOTIFY,
                "parameters": {
                    "type": "email",
                    "recipients": ["security@example.com"],
                    "subject": "ALERT: Malware Detected - {{event.hostname}}",
                    "message": "Malware has been detected on {{event.hostname}} ({{event.ip}}). \nDetails: {{event.malware_name}} \nSeverity: {{event.severity}}"
                },
                "requires_approval": False,
                "next_actions": [isolate_action_id]
            },
            isolate_action_id: {
                "id": isolate_action_id,
                "name": "Isolate Infected Host",
                "description": "Isolate the infected host from the network",
                "type": ActionType.CONTAIN,
                "parameters": {
                    "type": "isolate_host",
                    "target": "{{event.hostname}}"
                },
                "requires_approval": True,
                "next_actions": [scan_action_id]
            },
            scan_action_id: {
                "id": scan_action_id,
                "name": "Perform Deep Scan",
                "description": "Run a deep scan on the infected host",
                "type": ActionType.SCAN,
                "parameters": {
                    "type": "malware",
                    "target": "{{event.hostname}}"
                },
                "requires_approval": False,
                "next_actions": []
            }
        },
        "start_action_id": notify_action_id
    }


def get_phishing_response_template() -> Dict[str, Any]:
    """Template for responding to phishing incidents."""
    template_id = str(uuid.uuid4())
    
    # Define action IDs
    notify_action_id = f"{template_id}-notify"
    block_action_id = f"{template_id}-block"
    scan_action_id = f"{template_id}-scan"
    
    return {
        "id": template_id,
        "name": "Phishing Response Playbook",
        "description": "Automated response to phishing incidents",
        "author": "SENTRIX",
        "version": "1.0",
        "tags": ["phishing", "email", "blocking"],
        "trigger": {
            "type": "alert",
            "conditions": {
                "alert_type": "phishing",
                "severity": ["medium", "high", "critical"]
            }
        },
        "actions": {
            notify_action_id: {
                "id": notify_action_id,
                "name": "Notify Security Team",
                "description": "Send notification to security team about phishing attempt",
                "type": ActionType.NOTIFY,
                "parameters": {
                    "type": "email",
                    "recipients": ["security@example.com"],
                    "subject": "ALERT: Phishing Email Detected - {{event.recipient}}",
                    "message": "Phishing email detected sent to {{event.recipient}}. \nSender: {{event.sender}} \nSubject: {{event.email_subject}} \nAttachments: {{event.attachments}} \nTimestamp: {{event.timestamp}}"
                },
                "requires_approval": False,
                "next_actions": [block_action_id]
            },
            block_action_id: {
                "id": block_action_id,
                "name": "Block IOCs",
                "description": "Block sender and malicious URLs",
                "type": ActionType.BLOCK,
                "parameters": {
                    "type": "multi",
                    "targets": [
                        {"type": "email", "value": "{{event.sender}}"},
                        {"type": "url", "value": "{{event.urls}}"}
                    ],
                    "duration": "7d"
                },
                "requires_approval": True,
                "next_actions": [scan_action_id]
            },
            scan_action_id: {
                "id": scan_action_id,
                "name": "Scan for Similar Emails",
                "description": "Scan email system for similar phishing attempts",
                "type": ActionType.SCAN,
                "parameters": {
                    "type": "email",
                    "target": "mail_system",
                    "iocs": [
                        "{{event.sender}}",
                        "{{event.email_subject}}",
                        "{{event.urls}}"
                    ]
                },
                "requires_approval": False,
                "next_actions": []
            }
        },
        "start_action_id": notify_action_id
    }