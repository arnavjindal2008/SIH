from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    PROJECT_NAME: str = "Email Cryptographic Security Analyzer"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api"
    
    BASE_DIR: Path = Path(__file__).resolve().parent.parent.parent
    DATA_DIR: Path = BASE_DIR / "data"
    UPLOADS_DIR: Path = DATA_DIR / "uploads"
    SAMPLES_DIR: Path = DATA_DIR / "samples"
    REPORTS_DIR: Path = BASE_DIR / "reports" / "generated"
    
    DATABASE_URL: str = f"sqlite+aiosqlite:///{BASE_DIR}/data/analyzer.db"
    
    # Monitored email ports
    EMAIL_PORTS: list[int] = [
        25,   # SMTP (Plain / STARTTLS)
        587,  # SMTP Submission (STARTTLS)
        465,  # SMTPS (Implicit TLS)
        110,  # POP3 (Plain / STARTTLS)
        995,  # POP3S (Implicit TLS)
        143,  # IMAP (Plain / STARTTLS)
        993,  # IMAPS (Implicit TLS)
    ]
    
    # Tool paths
    TSHARK_PATH: str = "tshark"
    
    # Max file upload size (default 100MB)
    MAX_UPLOAD_SIZE_BYTES: int = 100 * 1024 * 1024

    model_config = SettingsConfigDict(env_file=".env")

settings = Settings()

# Ensure directories exist
settings.UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
settings.SAMPLES_DIR.mkdir(parents=True, exist_ok=True)
settings.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
