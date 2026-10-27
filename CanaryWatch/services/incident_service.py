from sqlalchemy.orm import Session
from core.database import IncidentModel

def update_incident_status(db: Session, incident_id: str, new_status: str):
    inc = db.query(IncidentModel).filter(IncidentModel.id == incident_id).first()
    if inc:
        inc.status = new_status
        db.commit()
        db.refresh(inc)
    return inc
