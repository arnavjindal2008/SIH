import shutil
from fastapi import APIRouter, Depends
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.database import get_db
from backend.app.models.db_models import Analysis
from backend.app.models.schemas import HealthResponse

router = APIRouter()

@router.get("/health", response_model=HealthResponse)
async def check_health(db: AsyncSession = Depends(get_db)):
    # Check database
    db_status = "connected"
    active_count = 0
    try:
        stmt = select(func.count(Analysis.id)).where(Analysis.status.in_(["PENDING", "PROCESSING"]))
        result = await db.execute(stmt)
        active_count = result.scalar() or 0
    except Exception as e:
        db_status = f"error: {str(e)}"

    # Check tools
    tshark_path = shutil.which("tshark")
    tshark_ok = tshark_path is not None

    return HealthResponse(
        status="healthy",
        version="1.0.0",
        database=db_status,
        tshark_available=tshark_ok,
        scikit_learn_available=True,
        cryptography_available=True,
        active_analyses=active_count,
    )
