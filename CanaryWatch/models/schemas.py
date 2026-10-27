from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class DecoyCreate(BaseModel):
    name: str
    decoy_type: str
    deployment_location: str

class DecoyResponse(BaseModel):
    id: str
    name: str
    decoy_type: str
    token_value: str
    deployment_location: str
    is_active: bool
    hits_count: int
    created_at: datetime
    class Config:
        from_attributes = True

class EventTriggerRequest(BaseModel):
    token_value: Optional[str] = None
    attacker_ip: str = "185.220.101.42"
    user_agent: str = "Mozilla/5.0 (Kali Linux) python-requests/2.31.0"
    request_path: str = "/trap/aws-credentials"
    payload_captured: str = "Attempted unauthorized SecretAccessKey enumeration"

class TelemetryEventResponse(BaseModel):
    id: str
    decoy_id: str
    attacker_ip: str
    geo_location: str
    asn_org: str
    user_agent: str
    request_path: str
    payload_captured: str
    severity: str
    evidence_sha256: str
    timestamp: datetime
    class Config:
        from_attributes = True

class IncidentResponse(BaseModel):
    id: str
    title: str
    attacker_ip: str
    status: str
    containment_action: str
    risk_score: int
    event_id: str
    created_at: datetime
    class Config:
        from_attributes = True
