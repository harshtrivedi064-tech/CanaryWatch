from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import List
from core.database import get_db, TelemetryEventModel
from models.schemas import TelemetryEventResponse

router = APIRouter()
@router.get("/", response_model=List[TelemetryEventResponse])
def get_all_events(db: Session = Depends(get_db)):
    return db.query(TelemetryEventModel).all()
