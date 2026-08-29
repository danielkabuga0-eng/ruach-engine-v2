from fastapi import Security, HTTPException, status
from fastapi.security import APIKeyHeader
from typing import Optional
from .database import db
from .rate_limiter import rate_limiter

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

async def verify_api_key(api_key: Optional[str] = Security(api_key_header)) -> dict:
    if not api_key:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Missing X-API-Key")
    acc = await db.verify_api_key(api_key)
    if not acc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")
    await rate_limiter.check_rate_limit(acc["api_key_hash"])
    return acc
