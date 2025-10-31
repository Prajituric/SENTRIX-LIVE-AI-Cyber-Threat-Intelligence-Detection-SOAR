"""
Syslog parser for the SENTRIX LIVE++ platform.
Parses syslog messages, focusing on authentication events.
"""
import re
import uuid
from datetime import datetime
from typing import Dict, Any, Optional, List, Tuple


def parse_syslog_event(raw_event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Parse a syslog event into a normalized format.
    
    Args:
        raw_event: The raw syslog event
        
    Returns:
        A normalized event dictionary
    """
    # Create base event structure
    event = {
        'id': str(uuid.uuid4()),
        'timestamp': raw_event.get('timestamp', datetime.utcnow().isoformat()),
        'event_type': 'syslog',
        'source': 'syslog',
        'raw_data': raw_event
    }
    
    # Extract message content
    message = raw_event.get('message', '')
    
    # Determine the message type and parse accordingly
    if 'sshd' in message:
        return _parse_ssh_event(event, message, raw_event)
    elif 'sudo' in message:
        return _parse_sudo_event(event, message, raw_event)
    elif 'authentication' in message.lower() or 'auth' in message.lower():
        return _parse_auth_event(event, message, raw_event)
    else:
        return _parse_generic_syslog(event, message, raw_event)


def _parse_ssh_event(event: Dict[str, Any], message: str, raw_event: Dict[str, Any]) -> Dict[str, Any]:
    """Parse an SSH-related syslog event."""
    event['event_type'] = 'syslog.ssh'
    
    # Extract common SSH event information
    host = raw_event.get('host', '')
    program = raw_event.get('program', '')
    
    event.update({
        'host': host,
        'program': program
    })
    
    # Check for successful login
    if 'Accepted' in message:
        event.update({
            'action': 'login',
            'status': 'success'
        })
        
        # Extract user and source IP
        user_match = re.search(r'Accepted (?:password|publickey) for (\S+)', message)
        ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', message)
        port_match = re.search(r'port (\d+)', message)
        
        if user_match:
            event['user'] = user_match.group(1)
        if ip_match:
            event['source_ip'] = ip_match.group(1)
            event['source_geo'] = _get_geo_info(ip_match.group(1))
        if port_match:
            event['source_port'] = int(port_match.group(1))
    
    # Check for failed login
    elif 'Failed' in message:
        event.update({
            'action': 'login',
            'status': 'failure'
        })
        
        # Extract user and source IP
        user_match = re.search(r'Failed (?:password|publickey) for (?:invalid user )?(\S+)', message)
        ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', message)
        port_match = re.search(r'port (\d+)', message)
        
        if user_match:
            event['user'] = user_match.group(1)
        if ip_match:
            event['source_ip'] = ip_match.group(1)
            event['source_geo'] = _get_geo_info(ip_match.group(1))
        if port_match:
            event['source_port'] = int(port_match.group(1))
    
    # Check for invalid user
    elif 'Invalid user' in message:
        event.update({
            'action': 'login',
            'status': 'failure',
            'reason': 'invalid_user'
        })
        
        # Extract user and source IP
        user_match = re.search(r'Invalid user (\S+)', message)
        ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', message)
        port_match = re.search(r'port (\d+)', message)
        
        if user_match:
            event['user'] = user_match.group(1)
        if ip_match:
            event['source_ip'] = ip_match.group(1)
            event['source_geo'] = _get_geo_info(ip_match.group(1))
        if port_match:
            event['source_port'] = int(port_match.group(1))
    
    # Check for connection closed
    elif 'Connection closed' in message:
        event.update({
            'action': 'logout',
            'status': 'success'
        })
        
        # Extract user and source IP if available
        user_match = re.search(r'for user (\S+)', message)
        ip_match = re.search(r'by (\d+\.\d+\.\d+\.\d+)', message)
        
        if user_match:
            event['user'] = user_match.group(1)
        if ip_match:
            event['source_ip'] = ip_match.group(1)
            event['source_geo'] = _get_geo_info(ip_match.group(1))
    
    # Other SSH events
    else:
        event.update({
            'action': 'other',
            'message': message
        })
    
    return event


def _parse_sudo_event(event: Dict[str, Any], message: str, raw_event: Dict[str, Any]) -> Dict[str, Any]:
    """Parse a sudo-related syslog event."""
    event['event_type'] = 'syslog.sudo'
    
    # Extract common sudo event information
    host = raw_event.get('host', '')
    program = raw_event.get('program', '')
    
    event.update({
        'host': host,
        'program': program
    })
    
    # Check for successful sudo
    if 'COMMAND=' in message:
        event.update({
            'action': 'sudo',
            'status': 'success'
        })
        
        # Extract user and command
        user_match = re.search(r'sudo: (\S+) : ', message)
        command_match = re.search(r'COMMAND=(.+)$', message)
        
        if user_match:
            event['user'] = user_match.group(1)
        if command_match:
            event['command'] = command_match.group(1).strip()
    
    # Check for failed sudo
    elif 'authentication failure' in message:
        event.update({
            'action': 'sudo',
            'status': 'failure'
        })
        
        # Extract user
        user_match = re.search(r'user=(\S+)', message)
        
        if user_match:
            event['user'] = user_match.group(1)
    
    # Other sudo events
    else:
        event.update({
            'action': 'other',
            'message': message
        })
    
    return event


def _parse_auth_event(event: Dict[str, Any], message: str, raw_event: Dict[str, Any]) -> Dict[str, Any]:
    """Parse an authentication-related syslog event."""
    event['event_type'] = 'syslog.auth'
    
    # Extract common auth event information
    host = raw_event.get('host', '')
    program = raw_event.get('program', '')
    
    event.update({
        'host': host,
        'program': program
    })
    
    # Check for successful authentication
    if 'session opened' in message:
        event.update({
            'action': 'login',
            'status': 'success'
        })
        
        # Extract user
        user_match = re.search(r'for user (\S+)', message)
        
        if user_match:
            event['user'] = user_match.group(1)
    
    # Check for session closed
    elif 'session closed' in message:
        event.update({
            'action': 'logout',
            'status': 'success'
        })
        
        # Extract user
        user_match = re.search(r'for user (\S+)', message)
        
        if user_match:
            event['user'] = user_match.group(1)
    
    # Check for authentication failure
    elif 'authentication failure' in message:
        event.update({
            'action': 'login',
            'status': 'failure'
        })
        
        # Extract user
        user_match = re.search(r'user=(\S+)', message)
        
        if user_match:
            event['user'] = user_match.group(1)
    
    # Other auth events
    else:
        event.update({
            'action': 'other',
            'message': message
        })
    
    return event


def _parse_generic_syslog(event: Dict[str, Any], message: str, raw_event: Dict[str, Any]) -> Dict[str, Any]:
    """Parse a generic syslog event."""
    # Extract common syslog information
    host = raw_event.get('host', '')
    program = raw_event.get('program', '')
    
    event.update({
        'host': host,
        'program': program,
        'message': message
    })
    
    return event


def _get_geo_info(ip: str) -> Dict[str, Any]:
    """
    Get geolocation information for an IP address.
    This is a placeholder - in a real implementation, this would use a GeoIP database.
    """
    # Placeholder - in a real implementation, this would use a GeoIP database
    return {
        'country_code': 'XX',
        'country_name': 'Unknown',
        'city_name': 'Unknown',
        'location': {
            'lat': 0.0,
            'lon': 0.0
        }
    }