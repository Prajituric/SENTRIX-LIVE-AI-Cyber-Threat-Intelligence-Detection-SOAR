"""
Alerts API routes for the SENTRIX LIVE++ platform.
Provides endpoints for retrieving and managing security alerts.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
import json

from ...core.auth import get_current_user
from ...core.db import get_elasticsearch_client
from ...llm.explainer import SecurityEventExplainer, ExplanationFormat

router = APIRouter(prefix="/alerts", tags=["alerts"])

@router.get("/")
async def get_alerts(
    since: Optional[str] = Query(None, description="Timestamp to filter alerts from"),
    severity: Optional[str] = Query(None, description="Filter by severity level"),
    limit: int = Query(100, description="Maximum number of alerts to return"),
    current_user = Depends(get_current_user),
    es_client = Depends(get_elasticsearch_client)
):
    """
    Get security alerts with optional filtering.
    """
    # Build Elasticsearch query
    query = {"bool": {"must": [{"match_all": {}}]}}
    
    if since:
        query["bool"]["must"].append({"range": {"timestamp": {"gte": since}}})
    
    if severity:
        query["bool"]["must"].append({"match": {"severity": severity}})
    
    # Execute query
    try:
        result = await es_client.search(
            index="security-alerts",
            query=query,
            size=limit,
            sort=[{"timestamp": {"order": "desc"}}]
        )
        
        alerts = [hit["_source"] for hit in result["hits"]["hits"]]
        return {"alerts": alerts, "total": result["hits"]["total"]["value"]}
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving alerts: {str(e)}")

@router.get("/stream")
async def stream_alerts(
    current_user = Depends(get_current_user),
    es_client = Depends(get_elasticsearch_client)
):
    """
    Stream real-time security alerts using Server-Sent Events (SSE).
    """
    async def event_generator():
        # In a real implementation, this would use a message queue or ES scroll API
        # For demo purposes, we'll just yield some sample alerts
        yield "data: " + json.dumps({"type": "connection", "status": "connected"}) + "\n\n"
        
        # In production, this would be an infinite loop with proper error handling
        # that subscribes to a message queue or other real-time data source
        
    return StreamingResponse(event_generator(), media_type="text/event-stream")

@router.get("/{alert_id}")
async def get_alert_details(
    alert_id: str,
    explain: bool = Query(False, description="Include LLM explanation"),
    format: str = Query("general", description="Explanation format (general, mitre_attack, ioc, remediation)"),
    current_user = Depends(get_current_user),
    es_client = Depends(get_elasticsearch_client)
):
    """
    Get detailed information about a specific alert.
    Optionally includes LLM-generated explanation.
    """
    try:
        # Get alert from Elasticsearch
        result = await es_client.get(index="security-alerts", id=alert_id)
        alert = result["_source"]
        
        # If explanation requested, generate it
        if explain:
            # In a real implementation, this would use the actual LLM client
            # For now, we'll return a placeholder
            explanation_format = ExplanationFormat(format)
            explanation = {
                "title": f"Explanation of {alert.get('alert_name', 'Security Alert')}",
                "description": "This is a placeholder for the LLM-generated explanation.",
                "severity": alert.get("severity", "medium"),
                "confidence": 0.85
            }
            
            alert["explanation"] = explanation
        
        return alert
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving alert: {str(e)}")

@router.post("/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: str,
    current_user = Depends(get_current_user),
    es_client = Depends(get_elasticsearch_client)
):
    """
    Acknowledge an alert to mark it as being handled.
    """
    try:
        # Update alert in Elasticsearch
        await es_client.update(
            index="security-alerts",
            id=alert_id,
            body={
                "doc": {
                    "status": "acknowledged",
                    "acknowledged_by": current_user.username,
                    "acknowledged_at": "now"  # In production, use actual timestamp
                }
            }
        )
        
        return {"status": "success", "message": f"Alert {alert_id} acknowledged"}
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error acknowledging alert: {str(e)}")