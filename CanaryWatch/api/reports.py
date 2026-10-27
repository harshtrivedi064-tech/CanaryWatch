from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from core.database import get_db
from services.report_service import build_forensic_report

router = APIRouter()
@router.get("/{incident_id}")
def report(incident_id: str, db: Session = Depends(get_db)):
    rep = build_forensic_report(db, incident_id)
    if not rep:
        raise HTTPException(status_code=404)
    return rep
