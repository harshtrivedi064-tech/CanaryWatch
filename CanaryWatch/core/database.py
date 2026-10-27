from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, ForeignKey, Text
from sqlalchemy.orm import declarative_base, sessionmaker
from core.config import settings

engine = create_engine(settings.DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class DecoyModel(Base):
    __tablename__ = "decoys"
    id = Column(String, primary_key=True, index=True)
    name = Column(String, nullable=False)
    decoy_type = Column(String, nullable=False)
    token_value = Column(String, unique=True, index=True)
    deployment_location = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    hits_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)

class TelemetryEventModel(Base):
    __tablename__ = "telemetry_events"
    id = Column(String, primary_key=True, index=True)
    decoy_id = Column(String, ForeignKey("decoys.id"))
    attacker_ip = Column(String, index=True)
    geo_location = Column(String)
    asn_org = Column(String)
    user_agent = Column(String)
    request_path = Column(String)
    payload_captured = Column(Text)
    severity = Column(String, default="HIGH")
    evidence_sha256 = Column(String, unique=True)
    timestamp = Column(DateTime, default=datetime.utcnow)

class IncidentModel(Base):
    __tablename__ = "incidents"
    id = Column(String, primary_key=True, index=True)
    title = Column(String, nullable=False)
    attacker_ip = Column(String, index=True)
    status = Column(String, default="OPEN")
    containment_action = Column(String, default="AUTO_BLOCK_IP_AND_REVOKE_TOKEN")
    risk_score = Column(Integer, default=90)
    event_id = Column(String, ForeignKey("telemetry_events.id"))
    created_at = Column(DateTime, default=datetime.utcnow)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
