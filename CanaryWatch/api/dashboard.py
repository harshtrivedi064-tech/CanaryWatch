from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from core.database import get_db, DecoyModel, TelemetryEventModel, IncidentModel

router = APIRouter()
@router.get("/metrics")
def metrics(db: Session = Depends(get_db)):
    return {"decoys": db.query(DecoyModel).count(), "events": db.query(TelemetryEventModel).count(), "incidents": db.query(IncidentModel).count()}
