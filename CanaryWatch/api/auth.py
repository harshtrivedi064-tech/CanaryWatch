import logging

from fastapi import APIRouter, HTTPException, status
from google.auth.exceptions import GoogleAuthError, TransportError
from pydantic import BaseModel, Field
from core.config import settings
from core.security import create_access_token
from services.auth_service import verify_google_credential

router = APIRouter()
logger = logging.getLogger(__name__)


class GoogleLoginRequest(BaseModel):
    credential: str = Field(min_length=1, max_length=10000)


@router.get("/google/config")
def google_login_config():
    return {
        "enabled": bool(settings.GOOGLE_CLIENT_ID),
        "client_id": settings.GOOGLE_CLIENT_ID or None,
    }


@router.post("/google")
def google_login(payload: GoogleLoginRequest):
    if not settings.GOOGLE_CLIENT_ID:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Google sign-in is not configured",
        )

    try:
        claims = verify_google_credential(payload.credential, settings.GOOGLE_CLIENT_ID)
    except TransportError as exc:
        logger.exception("Google token verification service is unavailable")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Google sign-in is temporarily unavailable",
        ) from exc
    except (GoogleAuthError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Google credential is invalid or expired",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    access_token = create_access_token(
        {
            "sub": claims["sub"],
            "email": claims["email"],
            "name": claims.get("name", claims["email"]),
            "picture": claims.get("picture"),
            "provider": "google",
            "role": "SOC_COMMANDER",
        }
    )
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "email": claims["email"],
            "name": claims.get("name", claims["email"]),
            "picture": claims.get("picture"),
        },
    }
