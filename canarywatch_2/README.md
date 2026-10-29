# CanaryWatch — Trap, Don't Track

A hackathon-ready deception-security prototype. It demonstrates synthetic honeytokens, a real FastAPI trigger pipeline, incident creation, measured latency, WebSocket alerts, token rotation/revocation, a React dashboard, and benchmark scripts.

> **Safety / scope:** This project defaults to a local simulation using synthetic data. Provider adapters are demonstrations, not real AWS/GitHub/cloud integrations. Do not place decoys in systems you do not own or administer. Latency and accuracy claims must be based on measured tests.

## Requirements
- Python 3.11+
- Node.js 20+
- npm

## Run on Windows PowerShell

### 1. Backend
```powershell
cd backend
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
uvicorn app.main:app --reload
```
API docs: http://127.0.0.1:8000/docs

### 2. Frontend (new terminal)
```powershell
cd frontend
npm install
Copy-Item .env.example .env
npm run dev
```
Open the Vite URL printed in the terminal (usually http://localhost:5173).

## Run on macOS/Linux
Backend:
```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload
```
Frontend:
```bash
cd frontend
npm install
cp .env.example .env
npm run dev
```

## Demo flow
1. Start the backend and frontend using the commands above, then open the Vite URL.
2. The dashboard automatically prepares four synthetic demo honeytokens on first run.
3. Click **Run 4-event scenario** for a judge-ready walkthrough: it creates four fresh synthetic canaries, triggers them, and opens the incident queue.
4. Alternatively, click **Create honeytoken** to create a single synthetic decoy; its demo value is shown once.
5. Observe the incident, measured processing latency, and WebSocket notification. Polling continues as a fallback if the live connection drops.
6. Use the dashboard time-range selector to scope event and incident metrics, and enable alert sound or mark live alerts read from the top bar.
7. Search and filter incidents by severity or status, then export the matching incident queue as CSV if needed.
8. Open **Threat Analytics** to show the recorded sample count, minimum, median, 95th percentile, maximum and incident latency chart. These are measured backend processing times, not end-to-end network or breach-detection guarantees.
9. Acknowledge or resolve the incident, and rotate or revoke honeytokens from the inventory.
10. Open **IP Protection**, simulate four failed trigger attempts, observe the block for the browser's client IP, then manually unblock it.
11. Use **Reset synthetic demo** and confirm the prompt to clear custom demo data and restore the four baseline honeytokens.

IP protection is a reversible, local-demo rule: it counts failed simulated trigger attempts from the direct client IP and rejects further calls to the demo trigger endpoint at four failures. The simulation button creates safe local demo attempts; it does not send traffic to another system or block the computer/network. Resetting the demo also clears the IP attempt records.

The backend permits both `localhost:5173` and `127.0.0.1:5173` for local browser testing. Keep the demo bound to a trusted local network; authentication is not implemented.

## API
- `GET /api/v1/health`
- `GET /api/v1/dashboard/summary`
- `GET /api/v1/honeytokens`
- `POST /api/v1/honeytokens`
- `POST /api/v1/demo/trigger/{token_id}`
- `POST /api/v1/honeytokens/{token_id}/rotate`
- `POST /api/v1/honeytokens/{token_id}/revoke`
- `GET /api/v1/incidents`
- `POST /api/v1/incidents/{incident_id}/acknowledge`
- `POST /api/v1/incidents/{incident_id}/resolve`
- `GET /api/v1/events`
- `GET /api/v1/analytics/latency`
- `GET /api/v1/integrations`
- `POST /api/v1/demo/reset`
- `POST /api/v1/demo/scenario`
- `GET /api/v1/ip-blocks`
- `POST /api/v1/ip-blocks/{ip_address}/unblock`
- `POST /api/v1/demo/ip-protection/simulate`
- `GET /api/v1/audit`
- `WS /api/v1/ws/alerts`

## Testing
```bash
cd backend
pytest -q
python ../scripts/benchmark_detection.py
```

## Limitations
- Authentication is not implemented in this starter. It is intended for a controlled local demo, not internet exposure.
- IP protection is a demo-level trigger-endpoint control, not an operating-system, router, cloud-firewall, or production-wide IP ban. Real deployments need authenticated administration, trusted proxy configuration, and safeguards for shared/NAT addresses.
- The local placement adapters are simulated and do not alter external resources.
- SQLite is used for portability. Review deployment, secret management, authorization, migrations, and rate limits before production use.
- “Under 3 seconds” is a target; benchmark output is the evidence, not a hardcoded promise.
