from fastapi import APIRouter, Response

from .database import db
from .rate_limiter import rate_limiter
from .circuit_breaker import tax_validator
from .config import settings

router = APIRouter()


@router.get("/health")
async def health_check(response: Response):
    db_ok = await db.health_check()
    redis_ok = await rate_limiter.health_check()
    healthy = db_ok and redis_ok
    if not healthy:
        response.status_code = 503
    return {
        "status": "healthy" if healthy else "unhealthy",
        "version": settings.APP_VERSION,
        "database": db_ok,
        "redis": redis_ok,
        "circuit_breaker": tax_validator.get_state(),
    }

@router.get('/ready')
async def readiness_check(response: Response):
    db_ok = await db.health_check()
    redis_ok = await rate_limiter.health_check()
    ready = db_ok and (redis_ok or settings.RATE_LIMIT_FAIL_MODE == 'open')
    if not ready:
        response.status_code = 503
    return {'status': 'ready' if ready else 'not_ready', 'database': db_ok, 'redis': redis_ok}
