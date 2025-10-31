"""
Zeek event parser for the SENTRIX LIVE++ platform.
"""
import uuid
from datetime import datetime
from typing import Dict, Any, Optional


def parse_zeek_event(raw_event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Parse a Zeek event into a normalized format.
    
    Args:
        raw_event: The raw Zeek event
        
    Returns:
        A normalized event dictionary
    """
    # Determine the log type from the raw event
    log_type = raw_event.get('_path', 'unknown')
    
    # Create base event structure
    event = {
        'id': str(uuid.uuid4()),
        'timestamp': raw_event.get('ts', datetime.utcnow().isoformat()),
        'event_type': f"zeek.{log_type}",
        'source': 'zeek',
        'raw_data': raw_event
    }
    
    # Handle different log types
    if log_type == 'conn':
        return _parse_conn_log(event, raw_event)
    elif log_type == 'dns':
        return _parse_dns_log(event, raw_event)
    elif log_type == 'http':
        return _parse_http_log(event, raw_event)
    elif log_type == 'ssl' or log_type == 'x509':
        return _parse_ssl_log(event, raw_event)
    elif log_type == 'files':
        return _parse_files_log(event, raw_event)
    elif log_type == 'notice':
        return _parse_notice_log(event, raw_event)
    else:
        # Generic parsing for other log types
        return _parse_generic_log(event, raw_event)


def _parse_conn_log(event: Dict[str, Any], raw_event: Dict[str, Any]) -> Dict[str, Any]:
    """Parse a Zeek connection log."""
    event.update({
        'source_ip': raw_event.get('id.orig_h'),
        'destination_ip': raw_event.get('id.resp_h'),
        'source_port': raw_event.get('id.orig_p'),
        'destination_port': raw_event.get('id.resp_p'),
        'protocol': raw_event.get('proto', '').upper(),
        'service': raw_event.get('service'),
        'duration': raw_event.get('duration'),
        'orig_bytes': raw_event.get('orig_bytes'),
        'resp_bytes': raw_event.get('resp_bytes'),
        'conn_state': raw_event.get('conn_state'),
        'local_orig': raw_event.get('local_orig'),
        'local_resp': raw_event.get('local_resp'),
        'missed_bytes': raw_event.get('missed_bytes'),
        'history': raw_event.get('history'),
        'orig_pkts': raw_event.get('orig_pkts'),
        'orig_ip_bytes': raw_event.get('orig_ip_bytes'),
        'resp_pkts': raw_event.get('resp_pkts'),
        'resp_ip_bytes': raw_event.get('resp_ip_bytes')
    })
    
    # Add geo information if available
    src_ip = raw_event.get('id.orig_h')
    dest_ip = raw_event.get('id.resp_h')
    if src_ip:
        event['source_geo'] = _get_geo_info(src_ip)
    if dest_ip:
        event['destination_geo'] = _get_geo_info(dest_ip)
    
    return event


def _parse_dns_log(event: Dict[str, Any], raw_event: Dict[str, Any]) -> Dict[str, Any]:
    """Parse a Zeek DNS log."""
    event.update({
        'source_ip': raw_event.get('id.orig_h'),
        'destination_ip': raw_event.get('id.resp_h'),
        'source_port': raw_event.get('id.orig_p'),
        'destination_port': raw_event.get('id.resp_p'),
        'protocol': 'UDP',  # DNS typically uses UDP
        'query': raw_event.get('query'),
        'qtype': raw_event.get('qtype'),
        'qtype_name': raw_event.get('qtype_name'),
        'rcode': raw_event.get('rcode'),
        'rcode_name': raw_event.get('rcode_name'),
        'answers': raw_event.get('answers'),
        'ttls': raw_event.get('TTLs'),
        'rejected': raw_event.get('rejected')
    })
    
    # Add geo information if available
    src_ip = raw_event.get('id.orig_h')
    dest_ip = raw_event.get('id.resp_h')
    if src_ip:
        event['source_geo'] = _get_geo_info(src_ip)
    if dest_ip:
        event['destination_geo'] = _get_geo_info(dest_ip)
    
    return event


def _parse_http_log(event: Dict[str, Any], raw_event: Dict[str, Any]) -> Dict[str, Any]:
    """Parse a Zeek HTTP log."""
    event.update({
        'source_ip': raw_event.get('id.orig_h'),
        'destination_ip': raw_event.get('id.resp_h'),
        'source_port': raw_event.get('id.orig_p'),
        'destination_port': raw_event.get('id.resp_p'),
        'protocol': 'TCP',  # HTTP uses TCP
        'method': raw_event.get('method'),
        'host': raw_event.get('host'),
        'uri': raw_event.get('uri'),
        'referrer': raw_event.get('referrer'),
        'user_agent': raw_event.get('user_agent'),
        'status_code': raw_event.get('status_code'),
        'status_msg': raw_event.get('status_msg'),
        'request_body_len': raw_event.get('request_body_len'),
        'response_body_len': raw_event.get('response_body_len'),
        'content_type': raw_event.get('resp_mime_types', [None])[0]
    })
    
    # Add geo information if available
    src_ip = raw_event.get('id.orig_h')
    dest_ip = raw_event.get('id.resp_h')
    if src_ip:
        event['source_geo'] = _get_geo_info(src_ip)
    if dest_ip:
        event['destination_geo'] = _get_geo_info(dest_ip)
    
    return event


def _parse_ssl_log(event: Dict[str, Any], raw_event: Dict[str, Any]) -> Dict[str, Any]:
    """Parse a Zeek SSL/TLS log."""
    event.update({
        'source_ip': raw_event.get('id.orig_h'),
        'destination_ip': raw_event.get('id.resp_h'),
        'source_port': raw_event.get('id.orig_p'),
        'destination_port': raw_event.get('id.resp_p'),
        'protocol': 'TCP',  # SSL/TLS uses TCP
        'version': raw_event.get('version'),
        'cipher': raw_event.get('cipher'),
        'curve': raw_event.get('curve'),
        'server_name': raw_event.get('server_name'),
        'subject': raw_event.get('subject'),
        'issuer': raw_event.get('issuer'),
        'validation_status': raw_event.get('validation_status'),
        'established': raw_event.get('established')
    })
    
    # Add geo information if available
    src_ip = raw_event.get('id.orig_h')
    dest_ip = raw_event.get('id.resp_h')
    if src_ip:
        event['source_geo'] = _get_geo_info(src_ip)
    if dest_ip:
        event['destination_geo'] = _get_geo_info(dest_ip)
    
    return event


def _parse_files_log(event: Dict[str, Any], raw_event: Dict[str, Any]) -> Dict[str, Any]:
    """Parse a Zeek files log."""
    event.update({
        'source': raw_event.get('source'),
        'file_id': raw_event.get('fuid'),
        'tx_hosts': raw_event.get('tx_hosts'),
        'rx_hosts': raw_event.get('rx_hosts'),
        'conn_uids': raw_event.get('conn_uids'),
        'filename': raw_event.get('filename'),
        'mime_type': raw_event.get('mime_type'),
        'md5': raw_event.get('md5'),
        'sha1': raw_event.get('sha1'),
        'sha256': raw_event.get('sha256'),
        'extracted': raw_event.get('extracted'),
        'extracted_cutoff': raw_event.get('extracted_cutoff'),
        'seen_bytes': raw_event.get('seen_bytes'),
        'total_bytes': raw_event.get('total_bytes'),
        'missing_bytes': raw_event.get('missing_bytes'),
        'overflow_bytes': raw_event.get('overflow_bytes'),
        'is_orig': raw_event.get('is_orig')
    })
    
    # Add geo information if available for tx_hosts and rx_hosts
    tx_hosts = raw_event.get('tx_hosts', [])
    rx_hosts = raw_event.get('rx_hosts', [])
    
    if tx_hosts and isinstance(tx_hosts, list) and tx_hosts[0]:
        event['tx_geo'] = _get_geo_info(tx_hosts[0])
    
    if rx_hosts and isinstance(rx_hosts, list) and rx_hosts[0]:
        event['rx_geo'] = _get_geo_info(rx_hosts[0])
    
    return event


def _parse_notice_log(event: Dict[str, Any], raw_event: Dict[str, Any]) -> Dict[str, Any]:
    """Parse a Zeek notice log."""
    event.update({
        'source_ip': raw_event.get('src'),
        'destination_ip': raw_event.get('dst'),
        'source_port': raw_event.get('p'),
        'note': raw_event.get('note'),
        'msg': raw_event.get('msg'),
        'sub': raw_event.get('sub'),
        'conn_id': raw_event.get('conn_id'),
        'suppress_for': raw_event.get('suppress_for'),
        'dropped': raw_event.get('dropped'),
        'remote_location': raw_event.get('remote_location')
    })
    
    # Add severity based on notice type
    note = raw_event.get('note', '')
    if 'Scan' in note or 'Bruteforce' in note:
        event['severity'] = 'medium'
    elif 'Attack' in note or 'Exploit' in note:
        event['severity'] = 'high'
    else:
        event['severity'] = 'low'
    
    # Add geo information if available
    src_ip = raw_event.get('src')
    dest_ip = raw_event.get('dst')
    if src_ip:
        event['source_geo'] = _get_geo_info(src_ip)
    if dest_ip:
        event['destination_geo'] = _get_geo_info(dest_ip)
    
    return event


def _parse_generic_log(event: Dict[str, Any], raw_event: Dict[str, Any]) -> Dict[str, Any]:
    """Parse a generic Zeek log."""
    # Extract common fields if they exist
    if 'id.orig_h' in raw_event:
        event['source_ip'] = raw_event.get('id.orig_h')
    if 'id.resp_h' in raw_event:
        event['destination_ip'] = raw_event.get('id.resp_h')
    if 'id.orig_p' in raw_event:
        event['source_port'] = raw_event.get('id.orig_p')
    if 'id.resp_p' in raw_event:
        event['destination_port'] = raw_event.get('id.resp_p')
    if 'proto' in raw_event:
        event['protocol'] = raw_event.get('proto', '').upper()
    
    # Add geo information if available
    src_ip = raw_event.get('id.orig_h')
    dest_ip = raw_event.get('id.resp_h')
    if src_ip:
        event['source_geo'] = _get_geo_info(src_ip)
    if dest_ip:
        event['destination_geo'] = _get_geo_info(dest_ip)
    
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