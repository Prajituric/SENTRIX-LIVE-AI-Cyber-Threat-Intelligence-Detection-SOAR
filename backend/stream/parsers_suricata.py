"""
Suricata event parser for the SENTRIX LIVE++ platform.
"""
import json
import uuid
from datetime import datetime
from typing import Dict, Any, Optional


def parse_suricata_event(raw_event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Parse a Suricata event into a normalized format.
    
    Args:
        raw_event: The raw Suricata event
        
    Returns:
        A normalized event dictionary
    """
    event_type = raw_event.get('event_type', 'unknown')
    
    # Create base event structure
    event = {
        'id': str(uuid.uuid4()),
        'timestamp': raw_event.get('timestamp', datetime.utcnow().isoformat()),
        'event_type': f"suricata.{event_type}",
        'source': 'suricata',
        'raw_data': raw_event
    }
    
    # Handle different event types
    if event_type == 'alert':
        return _parse_alert_event(event, raw_event)
    elif event_type == 'flow':
        return _parse_flow_event(event, raw_event)
    elif event_type == 'dns':
        return _parse_dns_event(event, raw_event)
    elif event_type == 'http':
        return _parse_http_event(event, raw_event)
    elif event_type == 'tls':
        return _parse_tls_event(event, raw_event)
    else:
        # Generic parsing for other event types
        return _parse_generic_event(event, raw_event)


def _parse_alert_event(event: Dict[str, Any], raw_event: Dict[str, Any]) -> Dict[str, Any]:
    """Parse a Suricata alert event."""
    alert = raw_event.get('alert', {})
    src_ip = _get_src_ip(raw_event)
    dest_ip = _get_dest_ip(raw_event)
    
    event.update({
        'title': alert.get('signature', 'Unknown Alert'),
        'description': alert.get('signature', ''),
        'severity': _map_severity(alert.get('severity', 0)),
        'category': alert.get('category', ''),
        'signature_id': alert.get('signature_id', 0),
        'source_ip': src_ip,
        'destination_ip': dest_ip,
        'source_port': raw_event.get('src_port'),
        'destination_port': raw_event.get('dest_port'),
        'protocol': raw_event.get('proto', '').upper(),
        'action': alert.get('action', '')
    })
    
    # Add geo information if available
    if src_ip:
        event['source_geo'] = _get_geo_info(src_ip)
    if dest_ip:
        event['destination_geo'] = _get_geo_info(dest_ip)
    
    return event


def _parse_flow_event(event: Dict[str, Any], raw_event: Dict[str, Any]) -> Dict[str, Any]:
    """Parse a Suricata flow event."""
    flow = raw_event.get('flow', {})
    src_ip = _get_src_ip(raw_event)
    dest_ip = _get_dest_ip(raw_event)
    
    event.update({
        'source_ip': src_ip,
        'destination_ip': dest_ip,
        'source_port': raw_event.get('src_port'),
        'destination_port': raw_event.get('dest_port'),
        'protocol': raw_event.get('proto', '').upper(),
        'bytes_toserver': flow.get('bytes_toserver', 0),
        'bytes_toclient': flow.get('bytes_toclient', 0),
        'pkts_toserver': flow.get('pkts_toserver', 0),
        'pkts_toclient': flow.get('pkts_toclient', 0),
        'start': flow.get('start', ''),
        'end': flow.get('end', '')
    })
    
    # Add geo information if available
    if src_ip:
        event['source_geo'] = _get_geo_info(src_ip)
    if dest_ip:
        event['destination_geo'] = _get_geo_info(dest_ip)
    
    return event


def _parse_dns_event(event: Dict[str, Any], raw_event: Dict[str, Any]) -> Dict[str, Any]:
    """Parse a Suricata DNS event."""
    dns = raw_event.get('dns', {})
    src_ip = _get_src_ip(raw_event)
    dest_ip = _get_dest_ip(raw_event)
    
    event.update({
        'source_ip': src_ip,
        'destination_ip': dest_ip,
        'source_port': raw_event.get('src_port'),
        'destination_port': raw_event.get('dest_port'),
        'protocol': raw_event.get('proto', '').upper(),
        'dns_type': dns.get('type', ''),
        'dns_rrname': dns.get('rrname', ''),
        'dns_rrtype': dns.get('rrtype', ''),
        'dns_rcode': dns.get('rcode', ''),
        'dns_answers': dns.get('answers', [])
    })
    
    # Add geo information if available
    if src_ip:
        event['source_geo'] = _get_geo_info(src_ip)
    if dest_ip:
        event['destination_geo'] = _get_geo_info(dest_ip)
    
    return event


def _parse_http_event(event: Dict[str, Any], raw_event: Dict[str, Any]) -> Dict[str, Any]:
    """Parse a Suricata HTTP event."""
    http = raw_event.get('http', {})
    src_ip = _get_src_ip(raw_event)
    dest_ip = _get_dest_ip(raw_event)
    
    event.update({
        'source_ip': src_ip,
        'destination_ip': dest_ip,
        'source_port': raw_event.get('src_port'),
        'destination_port': raw_event.get('dest_port'),
        'protocol': raw_event.get('proto', '').upper(),
        'http_method': http.get('http_method', ''),
        'http_uri': http.get('url', ''),
        'http_host': http.get('hostname', ''),
        'http_user_agent': http.get('http_user_agent', ''),
        'http_content_type': http.get('http_content_type', ''),
        'http_status': http.get('status', 0),
        'http_length': http.get('length', 0)
    })
    
    # Add geo information if available
    if src_ip:
        event['source_geo'] = _get_geo_info(src_ip)
    if dest_ip:
        event['destination_geo'] = _get_geo_info(dest_ip)
    
    return event


def _parse_tls_event(event: Dict[str, Any], raw_event: Dict[str, Any]) -> Dict[str, Any]:
    """Parse a Suricata TLS event."""
    tls = raw_event.get('tls', {})
    src_ip = _get_src_ip(raw_event)
    dest_ip = _get_dest_ip(raw_event)
    
    event.update({
        'source_ip': src_ip,
        'destination_ip': dest_ip,
        'source_port': raw_event.get('src_port'),
        'destination_port': raw_event.get('dest_port'),
        'protocol': raw_event.get('proto', '').upper(),
        'tls_version': tls.get('version', ''),
        'tls_subject': tls.get('subject', ''),
        'tls_issuerdn': tls.get('issuerdn', ''),
        'tls_serial': tls.get('serial', ''),
        'tls_fingerprint': tls.get('fingerprint', ''),
        'tls_sni': tls.get('sni', '')
    })
    
    # Add geo information if available
    if src_ip:
        event['source_geo'] = _get_geo_info(src_ip)
    if dest_ip:
        event['destination_geo'] = _get_geo_info(dest_ip)
    
    return event


def _parse_generic_event(event: Dict[str, Any], raw_event: Dict[str, Any]) -> Dict[str, Any]:
    """Parse a generic Suricata event."""
    src_ip = _get_src_ip(raw_event)
    dest_ip = _get_dest_ip(raw_event)
    
    event.update({
        'source_ip': src_ip,
        'destination_ip': dest_ip,
        'source_port': raw_event.get('src_port'),
        'destination_port': raw_event.get('dest_port'),
        'protocol': raw_event.get('proto', '').upper()
    })
    
    # Add geo information if available
    if src_ip:
        event['source_geo'] = _get_geo_info(src_ip)
    if dest_ip:
        event['destination_geo'] = _get_geo_info(dest_ip)
    
    return event


def _get_src_ip(raw_event: Dict[str, Any]) -> Optional[str]:
    """Get the source IP address from a Suricata event."""
    return raw_event.get('src_ip')


def _get_dest_ip(raw_event: Dict[str, Any]) -> Optional[str]:
    """Get the destination IP address from a Suricata event."""
    return raw_event.get('dest_ip')


def _map_severity(severity: int) -> str:
    """Map Suricata severity level to a string."""
    if severity == 1:
        return 'high'
    elif severity == 2:
        return 'medium'
    elif severity == 3:
        return 'low'
    else:
        return 'info'


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