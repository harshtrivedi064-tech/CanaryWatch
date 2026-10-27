from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import List
from core.database import get_db, DecoyModel
from models.schemas import DecoyCreate, DecoyResponse
from services.decoy_service import create_honeytoken

router = APIRouter()
@router.get("/", response_model=List[DecoyResponse])
def list_decoys(db: Session = Depends(get_db)):
    return db.query(DecoyModel).all()

@router.post("/", response_model=DecoyResponse)
def deploy_decoy(payload: DecoyCreate, db: Session = Depends(get_db)):
    return create_honeytoken(db, payload)
