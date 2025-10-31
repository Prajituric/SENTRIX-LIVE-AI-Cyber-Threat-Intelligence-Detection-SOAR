"""
SOAR API Routes for SENTRIX LIVE++
Provides endpoints for managing security playbooks and actions.
"""

from typing import Dict, List, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Body, Query, Path
from fastapi.responses import JSONResponse

from ...core.auth import get_current_user
from ...core.db import get_elasticsearch_client
from ...models.user import User
from ...soar.models import Playbook, PlaybookAction, PlaybookStatus
from ...soar.engine import playbook_engine

router = APIRouter(prefix="/api/soar", tags=["soar"])


@router.get("/playbooks/templates", response_model=List[Dict[str, Any]])
async def get_playbook_templates(
    current_user: User = Depends(get_current_user)
):
    """Get all available playbook templates."""
    es = get_elasticsearch_client()
    
    try:
        results = es.search(
            index="sentrix-playbooks-templates",
            body={
                "query": {"match_all": {}},
                "size": 100
            }
        )
        
        templates = []
        for hit in results["hits"]["hits"]:
            template = hit["_source"]
            template["id"] = hit["_id"]
            templates.append(template)
        
        return templates
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch playbook templates: {str(e)}")


@router.post("/playbooks/templates", status_code=201)
async def create_playbook_template(
    template: Dict[str, Any] = Body(...),
    current_user: User = Depends(get_current_user)
):
    """Create a new playbook template."""
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Only administrators can create playbook templates")
    
    es = get_elasticsearch_client()
    
    try:
        # Add metadata
        template["created_by"] = current_user.username
        template["created_at"] = template.get("created_at") or {"$date": {"$numberLong": str(int(datetime.now().timestamp() * 1000))}}
        
        # Validate template structure
        required_fields = ["name", "description", "trigger", "actions", "start_action_id"]
        for field in required_fields:
            if field not in template:
                raise HTTPException(status_code=400, detail=f"Missing required field: {field}")
        
        # Ensure all referenced actions exist
        for action_id in template.get("actions", {}):
            if action_id == template["start_action_id"]:
                continue
                
            found = False
            for action in template["actions"].values():
                if action_id in action.get("next_actions", []):
                    found = True
                    break
            
            if not found:
                raise HTTPException(
                    status_code=400, 
                    detail=f"Action {action_id} is not referenced by any other action"
                )
        
        # Store in Elasticsearch
        result = es.index(
            index="sentrix-playbooks-templates",
            body=template
        )
        
        return {"id": result["_id"], "message": "Playbook template created successfully"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create playbook template: {str(e)}")


@router.get("/playbooks/executions", response_model=List[Dict[str, Any]])
async def get_playbook_executions(
    status: Optional[str] = Query(None),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(get_current_user)
):
    """Get all playbook executions with optional filtering."""
    es = get_elasticsearch_client()
    
    try:
        query = {"match_all": {}}
        if status:
            query = {"match": {"status": status}}
        
        results = es.search(
            index="sentrix-playbooks-executions",
            body={
                "query": query,
                "size": limit,
                "from": offset,
                "sort": [{"created_at": {"order": "desc"}}]
            }
        )
        
        executions = []
        for hit in results["hits"]["hits"]:
            execution = hit["_source"]
            execution["id"] = hit["_id"]
            executions.append(execution)
        
        return executions
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch playbook executions: {str(e)}")


@router.get("/playbooks/executions/{playbook_id}", response_model=Dict[str, Any])
async def get_playbook_execution(
    playbook_id: str = Path(...),
    current_user: User = Depends(get_current_user)
):
    """Get a specific playbook execution by ID."""
    es = get_elasticsearch_client()
    
    try:
        result = es.get(index="sentrix-playbooks-executions", id=playbook_id)
        execution = result["_source"]
        execution["id"] = result["_id"]
        return execution
    except Exception as e:
        raise HTTPException(status_code=404, detail=f"Playbook execution not found: {str(e)}")


@router.post("/playbooks/execute", status_code=202)
async def execute_playbook(
    data: Dict[str, Any] = Body(...),
    current_user: User = Depends(get_current_user)
):
    """Execute a playbook based on a template for a specific alert."""
    template_id = data.get("template_id")
    alert_id = data.get("alert_id")
    event_data = data.get("event_data", {})
    
    if not template_id or not alert_id:
        raise HTTPException(status_code=400, detail="template_id and alert_id are required")
    
    try:
        # Create a new playbook instance from the template
        playbook = await playbook_engine.create_playbook_from_template(
            template_id=template_id,
            alert_id=alert_id,
            event_data=event_data
        )
        
        # Start execution asynchronously
        # We don't await here to return a response immediately
        playbook_engine.execute_playbook(playbook.id)
        
        return {"id": playbook.id, "message": "Playbook execution started"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to execute playbook: {str(e)}")


@router.post("/playbooks/executions/{playbook_id}/actions/{action_id}/approve", status_code=202)
async def approve_action(
    playbook_id: str = Path(...),
    action_id: str = Path(...),
    current_user: User = Depends(get_current_user)
):
    """Approve a waiting action in a playbook."""
    try:
        await playbook_engine.approve_action(
            playbook_id=playbook_id,
            action_id=action_id,
            approver=current_user.username
        )
        
        return {"message": "Action approved successfully"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to approve action: {str(e)}")


@router.post("/playbooks/executions/{playbook_id}/cancel", status_code=202)
async def cancel_playbook(
    playbook_id: str = Path(...),
    current_user: User = Depends(get_current_user)
):
    """Cancel a running playbook execution."""
    es = get_elasticsearch_client()
    
    try:
        # Update playbook status to cancelled
        es.update(
            index="sentrix-playbooks-executions",
            id=playbook_id,
            body={
                "doc": {
                    "status": PlaybookStatus.CANCELLED,
                    "execution_log": [
                        {
                            "timestamp": datetime.now().isoformat(),
                            "level": "INFO",
                            "message": f"Playbook cancelled by {current_user.username}"
                        }
                    ]
                }
            }
        )
        
        return {"message": "Playbook cancelled successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to cancel playbook: {str(e)}")