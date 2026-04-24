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

    # OIDC / SSO (optional — leave empty to disable)
    # Example (Azure AD): https://login.microsoftonline.com/{tenant}/v2.0
    # Example (Google):   https://accounts.google.com
    # Example (Keycloak): https://auth.example.com/realms/{realm}
    OIDC_ISSUER:        str = ""
    OIDC_CLIENT_ID:     str = ""
    OIDC_CLIENT_SECRET: str = ""
    # Where the browser should land after OIDC login (defaults to frontend root)
    OIDC_REDIRECT_URI:  str = ""  # e.g. https://sbom.example.com/api/auth/oidc/callback

    class Config:
        env_file = ".env"


settings = Settings()
