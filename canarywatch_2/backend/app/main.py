import asyncio, os
import ipaddress
from datetime import datetime, timezone
from threading import Lock
from fastapi import FastAPI, Depends, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import select, func
from .db import Base, engine, get_db, SessionLocal
from .models import Honeytoken, Incident, SecurityEvent, AuditEvent, IpBlock
from .schemas import HoneytokenCreate
from .services import create_token, trigger_token, serialize, uid, audit

Base.metadata.create_all(bind=engine)
app = FastAPI(title="CanaryWatch API", version="0.1.0",
              description="Local deception-security demo. External provider integrations are not enabled.")
origins = os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",")
origins.extend(["http://localhost:5173", "http://127.0.0.1:5173"])
origins = list(dict.fromkeys(origin.strip() for origin in origins if origin.strip()))
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=False,
                   allow_methods=["GET", "POST", "OPTIONS"], allow_headers=["*"])
clients = set()
demo_seed_lock = Lock()
ip_attempt_lock = Lock()
IP_BLOCK_THRESHOLD = 4
demo_seeds = [
    ("Payroll API canary", "API credential", "Demo finance", "critical"),
    ("Repository config decoy", "Config file", "Demo repository", "high"),
    ("Cloud archive decoy", "Cloud object", "Demo storage", "medium"),
    ("Customer DB canary", "Database record", "Demo database", "high"),
]

def seed_demo(db: Session):
    created = 0
    for name, kind, environment, severity in demo_seeds:
        existing = db.query(Honeytoken).filter_by(name=name, environment=environment).first()
        if existing is None:
            create_token(db, name, kind, environment, severity)
            created += 1
    return created

def record_failed_trigger(db: Session, ip_address: str):
    newly_blocked = False
    with ip_attempt_lock:
        entry = db.get(IpBlock, ip_address)
        if entry is None:
            entry = IpBlock(ip_address=ip_address, failed_attempts=0, blocked=False)
            db.add(entry)
        if not entry.blocked:
            entry.failed_attempts += 1
            entry.updated_at = datetime.now(timezone.utc)
            if entry.failed_attempts >= IP_BLOCK_THRESHOLD:
                entry.blocked = True
                entry.blocked_at = entry.updated_at
                newly_blocked = True
        db.commit()
        if newly_blocked:
            audit(db, "IP_BLOCKED", ip_address, f"{IP_BLOCK_THRESHOLD} failed simulated trigger attempts")
        return entry

async def broadcast(payload):
    dead = []
    for ws in list(clients):
        try:
            await ws.send_json(payload)
        except Exception:
            dead.append(ws)
    for ws in dead:
        clients.discard(ws)

@app.get("/api/v1/health")
def health():
    return {"status": "ok", "service": "CanaryWatch API", "mode": "local-demo"}

@app.get("/api/v1/dashboard/summary")
def summary(db: Session = Depends(get_db)):
    tokens = db.scalars(select(Honeytoken)).all()
    incidents = db.scalars(select(Incident)).all()
    events = db.scalars(select(SecurityEvent)).all()
    latencies = [e.latency_ms for e in events if e.latency_ms is not None]
    return {
        "active_honeytokens": sum(t.status == "active" for t in tokens),
        "triggered_decoys": sum(t.status == "triggered" for t in tokens),
        "open_incidents": sum(i.status == "open" for i in incidents),
        "total_events": len(events),
        "median_latency_ms": sorted(latencies)[len(latencies)//2] if latencies else None,
        "mode": "controlled local demo"
    }

@app.get("/api/v1/honeytokens")
def list_tokens(db: Session = Depends(get_db)):
    return [serialize(x) for x in db.scalars(select(Honeytoken).order_by(Honeytoken.created_at.desc())).all()]

@app.post("/api/v1/honeytokens")
def new_token(payload: HoneytokenCreate, db: Session = Depends(get_db)):
    token, demo_secret = create_token(db, payload.name, payload.kind, payload.environment, payload.severity)
    result = serialize(token)
    result["demo_secret_once"] = demo_secret
    return result

@app.post("/api/v1/demo/scenario")
async def run_demo_scenario(db: Session = Depends(get_db)):
    scenario_id = uid("scenario")
    triggered_incidents = []
    for index, (name, kind, environment, severity) in enumerate(demo_seeds, start=1):
        token, _ = create_token(
            db, f"{name} · {scenario_id}", kind, environment, severity
        )
        result, error = trigger_token(db, token.id)
        if error is not None:
            raise HTTPException(500, f"Could not trigger demo scenario canary {index}: {error}")
        payload = {
            "type": "incident.created",
            "incident": serialize(result["incident"]),
            "event": serialize(result["event"]),
            "token_id": token.id,
        }
        await broadcast(payload)
        triggered_incidents.append(payload["incident"])
    return {
        "scenario_id": scenario_id,
        "triggered_count": len(triggered_incidents),
        "incidents": triggered_incidents,
        "message": "Synthetic four-canary scenario completed",
    }

@app.post("/api/v1/demo/trigger/{token_id}")
async def demo_trigger(token_id: str, request: Request, db: Session = Depends(get_db)):
    ip_address = request.client.host if request.client else "unknown"
    ip_block = db.get(IpBlock, ip_address)
    if ip_block is not None and ip_block.blocked:
        raise HTTPException(403, f"Trigger access blocked for this IP after {IP_BLOCK_THRESHOLD} failed attempts")
    result, error = trigger_token(db, token_id)
    if error == "not_found":
        entry = record_failed_trigger(db, ip_address)
        if entry.blocked:
            raise HTTPException(403, f"Trigger access blocked for this IP after {IP_BLOCK_THRESHOLD} failed attempts")
        raise HTTPException(404, "Honeytoken not found")
    if error == "not_active":
        entry = record_failed_trigger(db, ip_address)
        if entry.blocked:
            raise HTTPException(403, f"Trigger access blocked for this IP after {IP_BLOCK_THRESHOLD} failed attempts")
        raise HTTPException(409, "Honeytoken is not active; rotate it to create a replacement")
    payload = {"type": "incident.created", "incident": serialize(result["incident"]),
               "event": serialize(result["event"]), "token_id": token_id}
    await broadcast(payload)
    return {"message": "Controlled demo trigger processed", **payload, "measured_latency_ms": result["latency_ms"]}

@app.post("/api/v1/honeytokens/{token_id}/rotate")
def rotate(token_id: str, db: Session = Depends(get_db)):
    token = db.get(Honeytoken, token_id)
    if not token:
        raise HTTPException(404, "Honeytoken not found")
    token.status = "revoked"
    db.commit()
    replacement, secret = create_token(db, f"{token.name} (replacement)", token.kind,
                                       token.environment, token.severity, rotation_of=token.id)
    audit(db, "HONEYTOKEN_ROTATED", token.id, f"replacement={replacement.id}")
    result = serialize(replacement)
    result["demo_secret_once"] = secret
    result["replaces"] = token.id
    return result

@app.post("/api/v1/honeytokens/{token_id}/revoke")
def revoke(token_id: str, db: Session = Depends(get_db)):
    token = db.get(Honeytoken, token_id)
    if not token:
        raise HTTPException(404, "Honeytoken not found")
    token.status = "revoked"
    db.commit()
    audit(db, "HONEYTOKEN_REVOKED", token.id, "Local demo revocation")
    return serialize(token)

@app.get("/api/v1/incidents")
def incidents(db: Session = Depends(get_db)):
    return [serialize(x) for x in db.scalars(select(Incident).order_by(Incident.created_at.desc())).all()]

@app.get("/api/v1/incidents/{incident_id}")
def incident_detail(incident_id: str, db: Session = Depends(get_db)):
    x = db.get(Incident, incident_id)
    if not x:
        raise HTTPException(404, "Incident not found")
    return serialize(x)

@app.post("/api/v1/incidents/{incident_id}/acknowledge")
def acknowledge(incident_id: str, db: Session = Depends(get_db)):
    x = db.get(Incident, incident_id)
    if not x:
        raise HTTPException(404, "Incident not found")
    x.status = "acknowledged"; db.commit(); audit(db, "INCIDENT_ACKNOWLEDGED", x.id)
    return serialize(x)

@app.post("/api/v1/incidents/{incident_id}/resolve")
def resolve(incident_id: str, db: Session = Depends(get_db)):
    x = db.get(Incident, incident_id)
    if not x:
        raise HTTPException(404, "Incident not found")
    x.status = "resolved"; db.commit(); audit(db, "INCIDENT_RESOLVED", x.id)
    return serialize(x)

@app.get("/api/v1/events")
def events(db: Session = Depends(get_db)):
    return [serialize(x) for x in db.scalars(select(SecurityEvent).order_by(SecurityEvent.created_at.desc())).all()]

@app.get("/api/v1/analytics/latency")
def latency(db: Session = Depends(get_db)):
    values = [x.latency_ms for x in db.scalars(select(SecurityEvent)).all() if x.latency_ms is not None]
    ordered = sorted(values)
    def percentile(p):
        return ordered[min(int((len(ordered)-1)*p), len(ordered)-1)] if ordered else None
    return {"sample_count": len(ordered), "min_ms": min(ordered) if ordered else None,
            "median_ms": percentile(.5), "p95_ms": percentile(.95),
            "max_ms": max(ordered) if ordered else None,
            "note": "Backend processing measurement for local demo events; not network-wide detection latency."}

@app.get("/api/v1/integrations")
def integrations():
    return [
        {"name": "Repository canary files", "status": "simulated", "enabled": True},
        {"name": "Cloud storage", "status": "integration interface only", "enabled": False},
        {"name": "Endpoint files", "status": "simulated", "enabled": True},
        {"name": "Database records", "status": "simulated", "enabled": True}
    ]

@app.get("/api/v1/audit")
def audit_events(db: Session = Depends(get_db)):
    return [serialize(x) for x in db.scalars(select(AuditEvent).order_by(AuditEvent.created_at.desc())).all()]

@app.get("/api/v1/ip-blocks")
def ip_blocks(db: Session = Depends(get_db)):
    return [serialize(x) for x in db.scalars(
        select(IpBlock).order_by(IpBlock.blocked.desc(), IpBlock.updated_at.desc())
    ).all()]

@app.post("/api/v1/ip-blocks/{ip_address}/unblock")
def unblock_ip(ip_address: str, db: Session = Depends(get_db)):
    try:
        normalized_ip = str(ipaddress.ip_address(ip_address))
    except ValueError as exc:
        raise HTTPException(422, "A valid IPv4 or IPv6 address is required") from exc
    with ip_attempt_lock:
        entry = db.get(IpBlock, normalized_ip)
        if entry is None:
            raise HTTPException(404, "IP address is not in the protection list")
        entry.failed_attempts = 0
        entry.blocked = False
        entry.blocked_at = None
        entry.updated_at = datetime.now(timezone.utc)
        db.commit()
        audit(db, "IP_UNBLOCKED", normalized_ip, "Manually unblocked in local demo")
    return serialize(entry)

@app.post("/api/v1/demo/ip-protection/simulate")
def simulate_ip_block(request: Request, db: Session = Depends(get_db)):
    ip_address = request.client.host if request.client else "unknown"
    for _ in range(IP_BLOCK_THRESHOLD):
        record_failed_trigger(db, ip_address)
    entry = db.get(IpBlock, ip_address)
    return {
        "ip_address": ip_address,
        "failed_attempts": entry.failed_attempts,
        "threshold": IP_BLOCK_THRESHOLD,
        "blocked": bool(entry.blocked),
        "message": "Simulated failed trigger attempts; only this demo's trigger endpoint is blocked."
    }

@app.post("/api/v1/demo/reset")
def reset_demo(db: Session = Depends(get_db)):
    with demo_seed_lock:
        db.query(SecurityEvent).delete()
        db.query(Incident).delete()
        db.query(Honeytoken).delete()
        db.query(IpBlock).delete()
        db.commit()
        created = seed_demo(db)
        audit(db, "DEMO_RESET", None, "Synthetic demo records reset to baseline")
    return {"status": "reset", "message": "Synthetic demo records reset to baseline", "created": created}

@app.post("/api/v1/demo/start")
def start_demo(db: Session = Depends(get_db)):
    with demo_seed_lock:
        created = seed_demo(db)
    return {"status": "initialized" if created else "already_initialized", "created": created}

@app.websocket("/api/v1/ws/alerts")
async def websocket_alerts(ws: WebSocket):
    await ws.accept()
    clients.add(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        clients.discard(ws)
