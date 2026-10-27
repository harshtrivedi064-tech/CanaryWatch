from sqlalchemy.orm import Session
from core.database import IncidentModel, TelemetryEventModel

def build_forensic_report(db: Session, incident_id: str):
    incident = db.query(IncidentModel).filter(IncidentModel.id == incident_id).first()
    if not incident:
        return None
    event = db.query(TelemetryEventModel).filter(TelemetryEventModel.id == incident.event_id).first()
    return {
        "incident_id": incident.id, "title": incident.title, "status": incident.status,
        "risk_score": incident.risk_score, "containment_action": incident.containment_action,
        "attacker_ip": incident.attacker_ip,
        "forensic_evidence": {
            "event_id": event.id if event else None,
            "sha256_signature": event.evidence_sha256 if event else None,
            "geo_location": event.geo_location if event else None,
            "timestamp_utc": str(event.timestamp) if event else None
        }
    }
