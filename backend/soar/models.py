"""
SOAR Models for SENTRIX LIVE++
Defines the data models for security playbooks and actions.
"""

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class PlaybookStatus(str, Enum):
    """Status of a playbook execution."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    WAITING_APPROVAL = "waiting_approval"
    CANCELLED = "cancelled"


class ActionStatus(str, Enum):
    """Status of an action within a playbook."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    WAITING_APPROVAL = "waiting_approval"
    SKIPPED = "skipped"


class ActionType(str, Enum):
    """Types of actions that can be performed in a playbook."""
    NOTIFY = "notify"
    ENRICH = "enrich"
    CONTAIN = "contain"
    BLOCK = "block"
    SCAN = "scan"
    CUSTOM = "custom"
    CONDITION = "condition"
    WAIT = "wait"
    LLM = "llm"


class PlaybookAction(BaseModel):
    """Definition of an action within a playbook."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str
    type: ActionType
    parameters: Dict[str, Any] = {}
    requires_approval: bool = False
    timeout_seconds: int = 300
    retry_count: int = 0
    next_actions: List[str] = []
    condition: Optional[str] = None
    status: ActionStatus = ActionStatus.PENDING
    result: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


class Playbook(BaseModel):
    """Definition of a security playbook."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str
    author: str
    version: str = "1.0"
    tags: List[str] = []
    trigger: Dict[str, Any]
    actions: Dict[str, PlaybookAction]
    start_action_id: str
    status: PlaybookStatus = PlaybookStatus.PENDING
    alert_id: Optional[str] = None
    event_data: Dict[str, Any] = {}
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    execution_log: List[Dict[str, Any]] = []