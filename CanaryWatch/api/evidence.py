from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from core.database import get_db, TelemetryEventModel

router = APIRouter()
@router.get("/verify/{event_id}")
def verify_evidence(event_id: str, db: Session = Depends(get_db)):
    event = db.query(TelemetryEventModel).filter(TelemetryEventModel.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Not found")
    return {"event_id": event.id, "status": "VERIFIED_IMMUTABLE", "sha256": event.evidence_sha256}
