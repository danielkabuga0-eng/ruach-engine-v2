import base64, hashlib, hmac, json, time
from fastapi import HTTPException, Request, status
from .config import settings
from .database import db

def _sign(payload: str) -> str:
    return hmac.new(settings.DASHBOARD_SESSION_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()

def make_session(api_key_hash: str) -> str:
    payload = base64.urlsafe_b64encode(json.dumps({
        "h": api_key_hash, "exp": int(time.time()) + settings.DASHBOARD_SESSION_TTL_SECONDS
    }, separators=(",", ":")).encode()).decode()
    return payload + "." + _sign(payload)

async def verify_dashboard_session(request: Request) -> dict:
    token = request.cookies.get("ruach_dashboard")
    if not token or "." not in token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Dashboard session required")
    payload, sig = token.rsplit(".", 1)
    if not hmac.compare_digest(sig, _sign(payload)):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid dashboard session")
    try:
        data = json.loads(base64.urlsafe_b64decode(payload.encode()))
        if int(data["exp"]) < int(time.time()):
            raise ValueError
        account = await db.verify_api_key_hash(data["h"])
        if not account: raise ValueError
        return account
    except Exception:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Expired or invalid dashboard session")
