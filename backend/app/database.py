from collections.abc import AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import declarative_base
from backend.app.config import settings

engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    connect_args={"check_same_thread": False},
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)

Base = declarative_base()

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()

async def init_db() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

        def _migrate(sync_conn):
            from sqlalchemy import text

            def add_cols_if_missing(table_name: str, new_cols: dict[str, str]):
                res = sync_conn.execute(text(f"PRAGMA table_info({table_name})")).fetchall()
                existing = {row[1] for row in res}
                if existing:
                    for col, col_def in new_cols.items():
                        if col not in existing:
                            sync_conn.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {col} {col_def}"))

            # Analyses table columns
            add_cols_if_missing("analyses", {
                "overall_score": "FLOAT DEFAULT 100.0",
                "tls_score": "FLOAT DEFAULT 100.0",
                "certificate_score": "FLOAT DEFAULT 100.0",
                "cipher_score": "FLOAT DEFAULT 100.0",
                "protocol_score": "FLOAT DEFAULT 100.0",
                "starttls_score": "FLOAT DEFAULT 100.0",
                "score_label": "VARCHAR(32) DEFAULT 'Good'",
                "score_confidence_note": "VARCHAR(255) DEFAULT 'Score confidence high: complete forensic capture.'",
                "ai_mode_note": "VARCHAR(255) DEFAULT 'AI anomaly detection is operating in prototype/baseline mode.'",
            })

            # Email sessions table columns
            add_cols_if_missing("email_sessions", {
                "transport_protocol": "VARCHAR(16) DEFAULT 'TCP'",
                "tcp_stream_id": "INTEGER DEFAULT 0",
                "status": "VARCHAR(32) DEFAULT 'UNKNOWN'",
                "protocol_evidence": "TEXT DEFAULT ''",
                "encryption_mode": "VARCHAR(32) DEFAULT 'UNKNOWN'",
                "starttls_supported": "BOOLEAN DEFAULT 0",
                "starttls_requested": "BOOLEAN DEFAULT 0",
                "starttls_accepted": "BOOLEAN DEFAULT 0",
                "tls_handshake_detected": "BOOLEAN DEFAULT 0",
                "starttls_evidence": "TEXT DEFAULT ''",
                "handshake_status": "VARCHAR(32) DEFAULT 'Not observed'",
                "tls_alerts": "TEXT DEFAULT ''",
                "elliptic_curve": "VARCHAR(64) DEFAULT 'Not observed'",
                "signature_algorithm": "VARCHAR(64) DEFAULT 'Not observed'",
                "session_resumption": "VARCHAR(64) DEFAULT 'Not observed'",
                "anomaly_status": "VARCHAR(32) DEFAULT 'NORMAL'",
                "risk_priority": "VARCHAR(16) DEFAULT 'INFORMATIONAL'",
                "anomaly_explanation": "TEXT DEFAULT ''",
            })

            # Security findings table columns
            add_cols_if_missing("security_findings", {
                "certificate_id": "VARCHAR(64)",
                "evidence": "TEXT DEFAULT ''",
                "recommendation": "TEXT DEFAULT ''",
            })

            # X.509 certificates table columns
            add_cols_if_missing("x509_certificates", {
                "subject_dn": "VARCHAR(512)",
                "issuer_dn": "VARCHAR(512)",
                "validity_status": "VARCHAR(32) DEFAULT 'VALID'",
                "days_remaining": "INTEGER",
                "chain_index": "INTEGER DEFAULT 0",
                "chain_info": "VARCHAR(128) DEFAULT 'Server / Leaf Certificate'",
                "observed_context": "VARCHAR(255) DEFAULT 'Certificate observed in capture'",
            })

        await conn.run_sync(_migrate)
