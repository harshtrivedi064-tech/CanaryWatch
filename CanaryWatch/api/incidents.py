from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import List
from core.database import get_db, IncidentModel
from models.schemas import IncidentResponse

router = APIRouter()
@router.get("/", response_model=List[IncidentResponse])
def get_all_incidents(db: Session = Depends(get_db)):
    return db.query(IncidentModel).all()
