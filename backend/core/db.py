"""
Database connection module for the SENTRIX LIVE++ platform.
Provides connections to PostgreSQL and Elasticsearch.
"""
from elasticsearch import Elasticsearch
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from backend.core.config import settings

# PostgreSQL connection
engine = create_engine(settings.db.connection_string)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Elasticsearch connection
es_client = Elasticsearch(
    hosts=settings.es.hosts,
    http_auth=settings.es.auth,
    verify_certs=False
)

# Elasticsearch index names
ALERT_INDEX = "sentrix-alerts"
EVENT_INDEX = "sentrix-events"
CTI_INDEX = "sentrix-cti"
AUDIT_INDEX = "sentrix-audit"

# Elasticsearch index mappings
ALERT_MAPPING = {
    "mappings": {
        "properties": {
            "id": {"type": "keyword"},
            "title": {"type": "text"},
            "description": {"type": "text"},
            "severity": {"type": "keyword"},
            "status": {"type": "keyword"},
            "created_at": {"type": "date"},
            "updated_at": {"type": "date"},
            "source_ip": {"type": "ip"},
            "destination_ip": {"type": "ip"},
            "source_user": {"type": "keyword"},
            "source_host": {"type": "keyword"},
            "destination_host": {"type": "keyword"},
            "tactic": {"type": "keyword"},
            "technique": {"type": "keyword"},
            "rule_id": {"type": "keyword"},
            "rule_name": {"type": "keyword"},
            "raw_data": {"type": "object", "enabled": False},
            "explanation": {"type": "text"},
            "remediation": {"type": "text"},
            "confidence": {"type": "float"}
        }
    }
}

EVENT_MAPPING = {
    "mappings": {
        "properties": {
            "id": {"type": "keyword"},
            "timestamp": {"type": "date"},
            "event_type": {"type": "keyword"},
            "source_ip": {"type": "ip"},
            "destination_ip": {"type": "ip"},
            "source_port": {"type": "integer"},
            "destination_port": {"type": "integer"},
            "protocol": {"type": "keyword"},
            "user": {"type": "keyword"},
            "host": {"type": "keyword"},
            "process": {"type": "keyword"},
            "command": {"type": "text"},
            "status": {"type": "keyword"},
            "geo": {
                "properties": {
                    "country_code": {"type": "keyword"},
                    "country_name": {"type": "keyword"},
                    "city_name": {"type": "keyword"},
                    "location": {"type": "geo_point"}
                }
            },
            "raw_data": {"type": "object", "enabled": False}
        }
    }
}

CTI_MAPPING = {
    "mappings": {
        "properties": {
            "id": {"type": "keyword"},
            "type": {"type": "keyword"},
            "value": {"type": "keyword"},
            "title": {"type": "text"},
            "description": {"type": "text"},
            "source": {"type": "keyword"},
            "confidence": {"type": "float"},
            "created_at": {"type": "date"},
            "updated_at": {"type": "date"},
            "tags": {"type": "keyword"},
            "mitre_tactic": {"type": "keyword"},
            "mitre_technique": {"type": "keyword"},
            "related_iocs": {"type": "keyword"}
        }
    }
}

AUDIT_MAPPING = {
    "mappings": {
        "properties": {
            "id": {"type": "keyword"},
            "timestamp": {"type": "date"},
            "user_id": {"type": "keyword"},
            "user_email": {"type": "keyword"},
            "action": {"type": "keyword"},
            "resource_type": {"type": "keyword"},
            "resource_id": {"type": "keyword"},
            "details": {"type": "object"},
            "ip_address": {"type": "ip"},
            "user_agent": {"type": "text"}
        }
    }
}


def get_db():
    """Get a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_elasticsearch():
    """Initialize Elasticsearch indices."""
    # Create indices if they don't exist
    if not es_client.indices.exists(index=ALERT_INDEX):
        es_client.indices.create(index=ALERT_INDEX, body=ALERT_MAPPING)
    
    if not es_client.indices.exists(index=EVENT_INDEX):
        es_client.indices.create(index=EVENT_INDEX, body=EVENT_MAPPING)
    
    if not es_client.indices.exists(index=CTI_INDEX):
        es_client.indices.create(index=CTI_INDEX, body=CTI_MAPPING)
    
    if not es_client.indices.exists(index=AUDIT_INDEX):
        es_client.indices.create(index=AUDIT_INDEX, body=AUDIT_MAPPING)


def init_db():
    """Initialize the database."""
    # Create PostgreSQL tables
    Base.metadata.create_all(bind=engine)
    
    # Initialize Elasticsearch indices
    init_elasticsearch()