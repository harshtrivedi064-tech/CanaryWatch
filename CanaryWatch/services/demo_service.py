from sqlalchemy.orm import Session
from core.database import DecoyModel
from models.schemas import DecoyCreate, EventTriggerRequest
from services.decoy_service import create_honeytoken
from services.event_engine import process_deception_alert

def trigger_demo_scenario(db: Session):
    decoy = db.query(DecoyModel).first()
    if not decoy:
        decoy = create_honeytoken(db, DecoyCreate(name="Production AWS IAM Root Canary", decoy_type="AWS_KEY", deployment_location="GitHub CI/CD Runner"))

    simulated_trigger = EventTriggerRequest(
        token_value=decoy.token_value, attacker_ip="185.220.101.42",
        user_agent="aws-cli/2.15.30", request_path="sts:GetCallerIdentity",
        payload_captured="Unauthorized AWS CLI reconnaissance using leaked Canary key"
    )
    return process_deception_alert(db, simulated_trigger, decoy), decoy
