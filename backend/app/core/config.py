from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    DATABASE_URL: str = "sqlite:///./sbom.db"
    DTRACK_URL: str = ""
    DTRACK_API_KEY: str = ""
    SECRET_KEY: str = "change-me-in-production"
    DEBUG: bool = False
    ADMIN_USERNAME: str = "admin"
    ADMIN_PASSWORD: str = "sbom@2024"
    JWT_EXPIRE_HOURS: int = 8

    # SMTP (set via .env or environment variables)
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM: str = ""
    SMTP_TLS: bool = True

    class Config:
        env_file = ".env"


settings = Settings()
