import hashlib
import hmac
import json
from datetime import datetime, timedelta
from jose import jwt
from jose import JWTError
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from core.config import settings

bearer_scheme = HTTPBearer(auto_error=False)


def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

def generate_evidence_hash(event_data: dict) -> str:
    canonical_payload = json.dumps(event_data, sort_keys=True, default=str).encode("utf-8")
    return hmac.new(settings.SECRET_KEY.encode("utf-8"), canonical_payload, hashlib.sha256).hexdigest()


def require_google_session(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> dict:
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="A valid Google sign-in session is required",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise unauthorized

    try:
        claims = jwt.decode(credentials.credentials, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    except JWTError as exc:
        raise unauthorized from exc

    if claims.get("provider") != "google" or not claims.get("sub"):
        raise unauthorized
    return claims
