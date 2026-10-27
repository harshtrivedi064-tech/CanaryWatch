from google.auth.transport.requests import Request
from google.oauth2 import id_token


def verify_google_credential(credential: str, audience: str) -> dict:
    claims = id_token.verify_oauth2_token(credential, Request(), audience=audience)
    if not claims.get("sub") or not claims.get("email") or not claims.get("email_verified"):
        raise ValueError("Google account has no verified email address")

    return claims
