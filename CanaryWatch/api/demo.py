from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from core.database import get_db
from services.demo_service import trigger_demo_scenario

router = APIRouter()
@router.post("/simulate-attack")
def simulate(db: Session = Depends(get_db)):
    (event, incident), decoy = trigger_demo_scenario(db)
    return {"status": "SUCCESS", "event_id": event.id, "incident_id": incident.id}
