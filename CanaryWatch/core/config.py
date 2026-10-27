import secrets

from pydantic import Field
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "CanaryWatch Deception Engine"
    VERSION: str = "1.0.0"
    DATABASE_URL: str = "sqlite:///./canarywatch.db"
    SECRET_KEY: str = Field(default_factory=lambda: secrets.token_urlsafe(32))
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440
    GOOGLE_CLIENT_ID: str = ""

    class Config:
        env_file = ".env"

settings = Settings()
