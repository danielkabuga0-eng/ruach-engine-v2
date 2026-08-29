from fastapi import APIRouter, Depends, Response, Request, HTTPException
from typing import List
from pydantic import BaseModel
from datetime import datetime
from .auth import verify_api_key
from .rate_limiter import rate_limiter
from .database import db
from .dashboard_auth import make_session, verify_dashboard_session
from .config import settings

router = APIRouter(prefix="/v1/dashboard", tags=["Dashboard"])

class DashboardLogin(BaseModel):
    api_key: str

class UsageStats(BaseModel):
    total_requests: int
    requests_today: int
    requests_this_month: int
    quota_limit: int
    quota_remaining: int
    quota_percentage: float

class ClearanceHistory(BaseModel):
    clearance_id: str
    invoice_number: str
    status: str
    seller_country: str
    buyer_country: str
    grand_total: float
    currency: str
    created_at: datetime
    self_healing_count: int
    ip_country: str | None = None
    ip_currency: str | None = None
    timezone_name: str | None = None
    tax_treatment: str
    decision_code: str | None = None
    rule_version: str | None = None
    decision_confidence: float | None = None

@router.post("/login")
async def dashboard_login(body: DashboardLogin, request: Request, response: Response):
    # Dashboard authentication has its own limiter and never consumes API quota.
    client_ip = request.client.host if request.client else "unknown"
    await rate_limiter.check_rate_limit("dashboard-login:" + client_ip)
    account = await db.verify_api_key(body.api_key)
    if not account:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid API key")
    token = make_session(account["api_key_hash"])
    response.set_cookie(
        "ruach_dashboard", token,
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite="lax",
        max_age=settings.DASHBOARD_SESSION_TTL_SECONDS,
        path="/"
    )
    return {"authenticated": True}

@router.post("/logout")
async def dashboard_logout(response: Response):
    response.delete_cookie("ruach_dashboard", path="/")
    return {"authenticated": False}

@router.get("/stats", response_model=UsageStats)
async def get_usage_stats(account: dict = Depends(verify_dashboard_session)):
    used, limit = account["used_requests"], account["monthly_limit"]
    async with db.acquire() as conn:
        today = await conn.fetchval(
            "SELECT COUNT(*) FROM clearance_audit_logs WHERE api_key_hash=$1 AND created_at>=CURRENT_DATE", account["api_key_hash"]) or 0
        month = await conn.fetchval(
            "SELECT COUNT(*) FROM clearance_audit_logs WHERE api_key_hash=$1 AND created_at>=DATE_TRUNC('month',CURRENT_DATE)", account["api_key_hash"]) or 0
    return UsageStats(total_requests=used, requests_today=today, requests_this_month=month,
                      quota_limit=limit, quota_remaining=max(0, limit-used),
                      quota_percentage=round(used/limit*100 if limit else 0,2))

@router.get("/history", response_model=List[ClearanceHistory])
async def get_history(account: dict = Depends(verify_dashboard_session)):
    async with db.acquire() as conn:
        rows = await conn.fetch(
            "SELECT * FROM clearance_audit_logs WHERE api_key_hash=$1 ORDER BY created_at DESC LIMIT 20",
            account["api_key_hash"])
    return [ClearanceHistory(
        clearance_id=r["clearance_id"], invoice_number=r["invoice_number"], status=r["status"],
        seller_country=r["seller_country"], buyer_country=r["buyer_country"],
        grand_total=float(r["grand_total"]), currency=r["currency"], created_at=r["created_at"],
        self_healing_count=len(r["self_healing_log"] or []), ip_country=r["ip_country"],
        ip_currency=r["ip_currency"], timezone_name=r["timezone_name"], tax_treatment=r["tax_treatment"],
        decision_code=r["decision_code"], rule_version=r["rule_version"],
        decision_confidence=float(r["decision_confidence"]) if r["decision_confidence"] is not None else None
    ) for r in rows]
