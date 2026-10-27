from fastapi import APIRouter, Request, Depends
from sqlalchemy.orm import Session
from core.database import get_db, DecoyModel
from models.schemas import EventTriggerRequest, DecoyCreate
from services.decoy_service import create_honeytoken
from services.event_engine import process_deception_alert

router = APIRouter()
@router.post("/honeytoken-webhook")
async def trigger_honeytoken(payload: EventTriggerRequest, db: Session = Depends(get_db)):
    decoy = db.query(DecoyModel).filter(DecoyModel.token_value == payload.token_value).first()
    if not decoy:
        decoy = create_honeytoken(db, DecoyCreate(name="Default Vault", decoy_type="AWS_KEY", deployment_location="/etc/env"))
    event, incident = process_deception_alert(db, payload, decoy)
    return {"alert": "TRAP_SPRUNG", "event_id": event.id, "incident_id": incident.id}
