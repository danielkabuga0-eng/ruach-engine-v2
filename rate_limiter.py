import time, logging
import redis.asyncio as aioredis
from fastapi import HTTPException, status
from .config import settings

logger = logging.getLogger(__name__)

class RateLimitExceeded(HTTPException):
    def __init__(self, retry_after: int):
        super().__init__(status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                         detail="Rate limit exceeded. Slow down.",
                         headers={"Retry-After": str(retry_after)})

class RateLimiter:
    def __init__(self): self.redis = None
    async def connect(self):
        self.redis = await aioredis.from_url(settings.REDIS_URL, decode_responses=True)
    async def disconnect(self):
        if self.redis: await self.redis.aclose()
    async def check_rate_limit(self, api_key_hash: str):
        if not settings.RATE_LIMIT_ENABLED: return
        if self.redis is None:
            if settings.RATE_LIMIT_FAIL_MODE == "closed":
                raise HTTPException(503, "Rate limiter unavailable")
            logger.warning("rate_limiter.redis_unavailable")
            return
        key = f"ratelimit:{api_key_hash}:{int(time.time() // 60)}"
        try:
            count = await self.redis.incr(key)
            if count == 1: await self.redis.expire(key, 60)
            if count > settings.RATE_LIMIT_PER_MINUTE:
                raise RateLimitExceeded(60 - int(time.time() % 60))
        except RateLimitExceeded: raise
        except Exception as exc:
            logger.error("rate_limiter.check_failed", extra={"error": str(exc)})
            if settings.RATE_LIMIT_FAIL_MODE == "closed":
                raise HTTPException(503, "Rate limiter unavailable")
    async def health_check(self):
        if self.redis is None: return False
        try: await self.redis.ping(); return True
        except Exception: return False
rate_limiter = RateLimiter()
