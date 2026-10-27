# CanaryWatch
Autonomous Cloud Honeytoken & Deception Mesh Platform

## Google sign-in

The dashboard uses Google Identity Services to sign operators in. The backend verifies each Google ID token, issues a short-lived CanaryWatch bearer token, and requires that token for dashboard, event, incident, decoy, demo, evidence, and report APIs. The `/trap` routes stay public so deployed decoys can receive trigger requests.

1. In Google Cloud Console, configure the OAuth consent screen and create an OAuth client ID with application type **Web application**.
2. Add the exact dashboard origin to **Authorized JavaScript origins**. For the local Vite server started below, use `http://127.0.0.1:5175`. No redirect URI is required for the Google Identity Services button flow.
3. Set the OAuth client ID and a persistent random signing key in a `.env` file next to `main.py`:

   ```dotenv
   GOOGLE_CLIENT_ID=your-web-client-id.apps.googleusercontent.com
   SECRET_KEY=replace-with-a-long-random-secret
   ```

   Keep `.env` private and do not commit it. Changing `SECRET_KEY` invalidates existing CanaryWatch sessions.

4. Install the backend requirements and start the API:

   ```powershell
   python -m pip install -r requirements.txt
   python -m uvicorn main:app --host 127.0.0.1 --port 8000
   ```

5. Install frontend dependencies and start the dashboard:

   ```powershell
   cd frontend
   npm install
   npm run start -- --port 5175
   ```

   If Vite selects a different port because 5175 is occupied, add that exact origin to the Google OAuth client configuration.

The browser sends the Google credential to `POST /api/auth/google`. The backend validates its signature, issuer, expiration, audience, and verified email before returning a CanaryWatch session token. The frontend keeps the session token in browser local storage and sends it as a bearer token to protected API routes. Use **Sign out** in the sidebar to clear the local session.
