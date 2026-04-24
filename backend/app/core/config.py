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

    # NVD API (optional — without key: 5 req/30s; with key: 50 req/30s)
    NVD_API_KEY: str = ""

    # GitHub token (optional — without: 60 GHSA req/h; with: 5000 req/h)
    GITHUB_TOKEN: str = ""
    ALLOWED_ORIGIN: str = "http://localhost:3000"
    UPLOAD_DIR: str = ""  # absolute path; auto-detected from __file__ if empty

    class Config:
        env_file = ".env"


settings = Settings()
