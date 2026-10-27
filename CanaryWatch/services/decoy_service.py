import uuid, secrets
from sqlalchemy.orm import Session
from core.database import DecoyModel
from models.schemas import DecoyCreate

def create_honeytoken(db: Session, payload: DecoyCreate) -> DecoyModel:
    prefix_map = {"AWS_KEY": "AKIA-CANARY-", "DB_CRED": "postgres://canary_admin:", "API_TOKEN": "cw_live_"}
    prefix = prefix_map.get(payload.decoy_type.upper(), "CW-TOKEN-")
    token_val = f"{prefix}{secrets.token_hex(8).upper()}"

    new_decoy = DecoyModel(
        id=f"decoy-{uuid.uuid4().hex[:8]}",
        name=payload.name,
        decoy_type=payload.decoy_type.upper(),
        token_value=token_val,
        deployment_location=payload.deployment_location
    )
    db.add(new_decoy)
    db.commit()
    db.refresh(new_decoy)
    return new_decoy
