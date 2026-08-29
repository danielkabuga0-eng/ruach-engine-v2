import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status, Request
from pydantic import BaseModel, Field, field_validator

from .auth import verify_api_key
from .database import db
from .market_expansion import TARGET_COUNTRIES
from .market_expansion import assess_market_entry

router = APIRouter(prefix="/v1/client", tags=["Client SaaS"])

PLAN_PRICES = {"starter": 299, "growth": 999, "scale": 2500, "enterprise": 5000}
PLAN_LIMITS = {
    "starter": {"products": 100, "markets": 2},
    "growth": {"products": 1000, "markets": 8},
    "scale": {"products": 10000, "markets": 27},
    "enterprise": {"products": 100000, "markets": 27},
}

class CompanyProfile(BaseModel):
    company_name: str = Field(min_length=1, max_length=200)
    country: str = Field(min_length=2, max_length=2)
    industry: str = Field(min_length=1, max_length=120)
    website: str | None = Field(default=None, max_length=300)
    employee_count: int | None = Field(default=None, ge=1, le=5_000_000)

    @field_validator("country", mode="before")
    @classmethod
    def normalize_country(cls, v):
        return v.strip().upper() if isinstance(v, str) else v

class InviteRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    full_name: str = Field(min_length=1, max_length=200)
    role: str = Field(default="viewer")

class AcceptInviteRequest(BaseModel):
    token: str = Field(min_length=20, max_length=256)

class ProductRequest(BaseModel):
    sku: str = Field(min_length=1, max_length=128)
    product_name: str = Field(min_length=1, max_length=200)
    category: str = Field(min_length=1, max_length=120)
    manufacturer_role: str = Field(default="manufacturer", max_length=80)
    attributes: dict[str, Any] = Field(default_factory=dict)
    evidence: list[dict[str, Any]] = Field(default_factory=list)

class MarketRequest(BaseModel):
    country: str = Field(min_length=2, max_length=2)
    market_type: str = Field(default="TARGET")
    planned_launch_date: str | None = None

    @field_validator("country", mode="before")
    @classmethod
    def normalize_country(cls, v):
        return v.strip().upper() if isinstance(v, str) else v

    @field_validator("market_type", mode="before")
    @classmethod
    def normalize_type(cls, v):
        return v.strip().upper() if isinstance(v, str) else v

class EvidenceRequest(BaseModel):
    product_id: str | None = None
    evidence_type: str = Field(min_length=1, max_length=120)
    filename: str = Field(min_length=1, max_length=255)
    content_hash: str = Field(min_length=16, max_length=128)
    metadata: dict[str, Any] = Field(default_factory=dict)

class PlanRequest(BaseModel):
    plan: str

class ProvisionRequest(BaseModel):
    company_name: str = Field(min_length=1, max_length=200)
    slug: str = Field(min_length=2, max_length=120, pattern=r"^[a-z0-9-]+$")
    owner_email: str = Field(min_length=3, max_length=320)
    owner_name: str = Field(min_length=1, max_length=200)
    plan: str = "starter"


def _require_org_owner(account: dict):
    if account.get("role") not in {"owner", "admin"}:
        raise HTTPException(status_code=403, detail="Owner/admin role required")

@router.post("/provision")
async def provision_client(body: ProvisionRequest, request: Request):
    provided = request.headers.get("X-RUACH-Platform-Secret", "")
    if provided != __import__("app.config", fromlist=["settings"]).settings.PLATFORM_ADMIN_SECRET or not provided:
        raise HTTPException(status_code=401, detail="Platform provisioning authorization required")
    try:
        return await db.provision_organization(body.company_name, body.slug, body.plan.lower(), body.owner_email, body.owner_name)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        if "organizations_slug_key" in str(exc):
            raise HTTPException(status_code=409, detail="Organization slug already exists")
        raise

@router.get("/workspace")
async def get_workspace(account: dict = Depends(verify_api_key)):
    return await db.get_client_workspace(account["organization_id"])

@router.put("/company")
async def update_company(body: CompanyProfile, account: dict = Depends(verify_api_key)):
    _require_org_owner(account)
    return await db.update_company_profile(account["organization_id"], body.model_dump())

@router.post("/users/invite")
async def invite_user(body: InviteRequest, account: dict = Depends(verify_api_key)):
    _require_org_owner(account)
    invite = await db.create_org_invite(account["organization_id"], body.email.lower(), body.full_name, body.role)
    return {"invite_id": str(invite["id"]), "email": invite["email"], "expires_at": invite["expires_at"], "invite_token": invite["raw_token"], "delivery": "APPLICATION_HANDOFF"}

@router.post("/users/accept")
async def accept_invite(body: AcceptInviteRequest):
    result = await db.accept_org_invite(body.token)
    if not result:
        raise HTTPException(status_code=400, detail="Invite is invalid, expired, or already accepted")
    return result

@router.get("/users")
async def list_users(account: dict = Depends(verify_api_key)):
    return [dict(r) for r in await db.list_org_users(account["organization_id"])]

@router.post("/products")
async def add_product(body: ProductRequest, account: dict = Depends(verify_api_key)):
    return await db.create_org_product(account["organization_id"], body.model_dump())

@router.post("/products/bulk")
async def bulk_products(products: list[ProductRequest], account: dict = Depends(verify_api_key)):
    return await db.bulk_create_org_products(account["organization_id"], [p.model_dump() for p in products])

@router.get("/products")
async def list_products(account: dict = Depends(verify_api_key)):
    return [dict(r) for r in await db.list_org_products(account["organization_id"])]

@router.post("/markets")
async def add_market(body: MarketRequest, account: dict = Depends(verify_api_key)):
    if body.country not in TARGET_COUNTRIES:
        raise HTTPException(status_code=422, detail="Unsupported target market")
    return await db.create_org_market(account["organization_id"], body.model_dump())

@router.get("/markets")
async def list_markets(account: dict = Depends(verify_api_key)):
    return [dict(r) for r in await db.list_org_markets(account["organization_id"])]

@router.post("/evidence")
async def add_evidence(body: EvidenceRequest, account: dict = Depends(verify_api_key)):
    return await db.create_org_evidence(account["organization_id"], body.model_dump())

@router.get("/evidence")
async def list_evidence(account: dict = Depends(verify_api_key)):
    return [dict(r) for r in await db.list_org_evidence(account["organization_id"])]

@router.put("/lifecycle")
async def change_lifecycle(body: dict, account: dict = Depends(verify_api_key)):
    _require_org_owner(account)
    lifecycle_status = str(body.get("lifecycle_status", "")).strip().upper()
    try:
        row = await db.set_lifecycle_status(account["organization_id"], lifecycle_status)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    if not row:
        raise HTTPException(status_code=404, detail="Organization not found")
    return row

@router.put("/plan")
async def change_plan(body: PlanRequest, account: dict = Depends(verify_api_key)):
    _require_org_owner(account)
    plan = body.plan.strip().lower()
    if plan not in PLAN_PRICES:
        raise HTTPException(status_code=422, detail="Unsupported plan")
    return await db.set_org_plan(account["organization_id"], plan, PLAN_PRICES[plan])

@router.post("/onboarding/complete")
async def complete_onboarding(step: dict, account: dict = Depends(verify_api_key)):
    step_name = str(step.get("step", "")).strip().upper()
    allowed = {"PROFILE", "CATALOG", "MARKETS", "EVIDENCE", "ASSESSMENT", "ACTIVE", "EXPANSION"}
    if step_name not in allowed:
        raise HTTPException(status_code=422, detail="Unsupported onboarding step")
    return await db.complete_onboarding_step(account["organization_id"], step_name)

@router.post("/market-readiness/run")
async def run_market_readiness(account: dict = Depends(verify_api_key)):
    products = [dict(r) for r in await db.list_org_products(account["organization_id"])]
    markets = [dict(r) for r in await db.list_org_markets(account["organization_id"])]
    if not products or not markets:
        raise HTTPException(status_code=422, detail="Add products and target markets before running readiness")
    results = []
    for product in products:
        for market in markets:
            if market["market_type"] != "TARGET":
                continue
            assessment = assess_market_entry({
                "product_id": str(product["id"]),
                "product_name": product["product_name"],
                "category": product["category"],
                **(product["attributes"] or {}),
                "evidence": product["evidence"] or [],
            }, market["country"])
            row = await db.save_market_entry(account["organization_id"], str(product["id"]), product["product_name"], market["country"], product, assessment)
            results.append({"assessment_id": str(row["id"]), "product_id": str(product["id"]), "country": market["country"], "assessment": assessment})
    await db.complete_onboarding_step(account["organization_id"], "ASSESSMENT")
    return {"count": len(results), "results": results}
