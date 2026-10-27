import uuid
from datetime import datetime
from sqlalchemy.orm import Session
from core.database import DecoyModel, TelemetryEventModel, IncidentModel
from core.security import generate_evidence_hash
from services.ip_engine import enrich_ip_telemetry
from models.schemas import EventTriggerRequest

def process_deception_alert(db: Session, trigger: EventTriggerRequest, decoy: DecoyModel):
    ip_meta = enrich_ip_telemetry(trigger.attacker_ip)
    event_id = f"evt-{uuid.uuid4().hex[:10]}"
    now = datetime.utcnow()

    raw_forensic_record = {
        "event_id": event_id, "decoy_id": decoy.id, "token_value": decoy.token_value,
        "attacker_ip": trigger.attacker_ip, "user_agent": trigger.user_agent,
        "request_path": trigger.request_path, "payload": trigger.payload_captured, "timestamp": now.isoformat()
    }
    evidence_hash = generate_evidence_hash(raw_forensic_record)

    event = TelemetryEventModel(
        id=event_id, decoy_id=decoy.id, attacker_ip=trigger.attacker_ip,
        geo_location=ip_meta["geo"], asn_org=ip_meta["asn"], user_agent=trigger.user_agent,
        request_path=trigger.request_path, payload_captured=trigger.payload_captured,
        severity="CRITICAL", evidence_sha256=evidence_hash, timestamp=now
    )
    decoy.hits_count += 1

    incident = IncidentModel(
        id=f"inc-{uuid.uuid4().hex[:8]}", title=f"Honeytoken Triggered: {decoy.name}",
        attacker_ip=trigger.attacker_ip, status="CONTAINED",
        containment_action="WAF_NULL_ROUTE_IP + IAM_QUARANTINE_SESSION",
        risk_score=ip_meta["threat_score"], event_id=event_id, created_at=now
    )

    db.add(event)
    db.add(incident)
    db.commit()
    db.refresh(event)
    return event, incident
