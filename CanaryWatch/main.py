from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from core.config import settings
from core.database import engine, Base
from core.security import require_google_session
from api import auth, decoys, decoy_portal, events, incidents, evidence, dashboard, demo, reports

Base.metadata.create_all(bind=engine)

app = FastAPI(title=settings.PROJECT_NAME, version=settings.VERSION, description="CanaryWatch Deception Mesh")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(dashboard.router, prefix="/api/dashboard", tags=["SOC Dashboard"], dependencies=[Depends(require_google_session)])
app.include_router(decoys.router, prefix="/api/decoys", tags=["Honeytokens & Decoys"], dependencies=[Depends(require_google_session)])
app.include_router(decoy_portal.router, prefix="/trap", tags=["Deception Trap Endpoints"])
app.include_router(events.router, prefix="/api/events", tags=["Telemetry Events"], dependencies=[Depends(require_google_session)])
app.include_router(incidents.router, prefix="/api/incidents", tags=["Incidents & Containment"], dependencies=[Depends(require_google_session)])
app.include_router(evidence.router, prefix="/api/evidence", tags=["Cryptographic Forensics"], dependencies=[Depends(require_google_session)])
app.include_router(reports.router, prefix="/api/reports", tags=["Forensic Reports"], dependencies=[Depends(require_google_session)])
app.include_router(demo.router, prefix="/api/demo", tags=["Breach Simulation Runner"], dependencies=[Depends(require_google_session)])

@app.get("/")
async def root():
    return {"system": settings.PROJECT_NAME, "status": "ONLINE", "deception_mesh": "ACTIVE"}
