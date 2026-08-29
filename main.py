import logging, os, secrets, string, uuid, hashlib, json, time, asyncio
import ipaddress
from decimal import Decimal
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import structlog
from fastapi import Depends, FastAPI, Request, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from .auth import verify_api_key
from .circuit_breaker import tax_validator
from .config import settings
from .dashboard_routes import router as dashboard_router
from .database import db
from .health import router as health_router
from .geo import localize_ip
from .models import ClearanceRequest, ClearanceResponse
from .rate_limiter import rate_limiter
from .jurisdiction import assess_jurisdictions
from .providers import providers
from .compliance import decide, build_evidence, RULE_VERSION
from .metrics import inc, observe, prometheus_text
from .country_registry import capabilities, registry, coverage_summary
from .permissions import require_permission
from .webhooks import queue_and_deliver, validate_destination
from .regulatory_intelligence import sources as regulatory_sources, build_change_proposal, diff_requirements, classify_document_requirement, safe_source_url, hash_snapshot, extract_machine_requirements, semantic_requirement_diff, build_customer_impact_plan, execute_document_compliance
from .regulatory_monitor import check_source
from .defensibility import build_regulatory_knowledge_edges, build_customer_execution_edges, build_feedback_event, canonical_hash
from .market_expansion import assess_market_entry, TARGET_COUNTRIES
from .market_cockpit import create_cockpit, recompute_status
from .client_saas import router as client_saas_router
import httpx

logging.basicConfig(level=logging.INFO if not settings.DEBUG else logging.DEBUG)
logger = structlog.get_logger()

def _generate_dev_api_key():
    return "sk_dev_" + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))

def _client_ip(request: Request):
    direct = request.client.host if request.client else None
    if not direct:
        return None
    # Only trust forwarding headers when the immediate peer is explicitly trusted.
    if direct in settings.TRUSTED_PROXY_IPS:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            for candidate in forwarded.split(","):
                candidate = candidate.strip()
                try:
                    ipaddress.ip_address(candidate)
                    return candidate
                except ValueError:
                    continue
    return direct

@asynccontextmanager
async def lifespan(app: FastAPI):
    if settings.ENVIRONMENT == "production" and settings.DASHBOARD_SESSION_SECRET == "CHANGE-ME-IN-PRODUCTION":
        raise RuntimeError("DASHBOARD_SESSION_SECRET must be changed in production")
    if settings.ENVIRONMENT == "production" and settings.DEBUG:
        raise RuntimeError("DEBUG must be false in production")
    if settings.ENVIRONMENT == "production" and settings.SEED_TEST_API_KEY:
        raise RuntimeError("SEED_TEST_API_KEY must be false in production")
    if settings.ENVIRONMENT == "production" and not settings.ALLOWED_CORS_ORIGINS:
        logger.info("cors_restricted_to_same_origin")
    if settings.ENVIRONMENT == "production" and not settings.COOKIE_SECURE:
        raise RuntimeError("COOKIE_SECURE must be true in production")
    await db.connect()
    try: await rate_limiter.connect()
    except Exception as e:
        logger.warning("startup.redis_connect_failed", error=str(e))
    if settings.SEED_TEST_API_KEY and settings.DEBUG:
        dev_key = _generate_dev_api_key()
        await db.seed_dev_account(dev_key, "Local Dev Account")
        logger.warning("dev_api_key_seeded", api_key=dev_key, note="DEV ONLY")
    monitor_task = None
    if settings.REGULATORY_MONITOR_ENABLED:
        monitor_task = asyncio.create_task(_regulatory_monitor_loop())
    yield
    if monitor_task:
        monitor_task.cancel()
        try: await monitor_task
        except asyncio.CancelledError: pass
    await tax_validator.close()
    await db.disconnect()
    try: await rate_limiter.disconnect()
    except Exception: pass

async def _regulatory_monitor_loop():
    interval = max(60, settings.REGULATORY_MONITOR_INTERVAL_SECONDS)
    while True:
        try:
            for source in regulatory_sources():
                result = await check_source(source)
                if result.get("changed"):
                    logger.warning("regulatory_source_changed", source_id=result["source_id"], content_hash=result.get("content_hash"))
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.exception("regulatory_monitor_cycle_failed", error=str(exc))
        await asyncio.sleep(interval)

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    lifespan=lifespan,
    docs_url=None if settings.ENVIRONMENT == 'production' else '/docs',
    redoc_url=None if settings.ENVIRONMENT == 'production' else '/redoc',
    openapi_url=None if settings.ENVIRONMENT == 'production' else '/openapi.json',
)
app.add_middleware(CORSMiddleware, allow_origins=settings.ALLOWED_CORS_ORIGINS,
                   allow_credentials=True, allow_methods=["GET","POST"],
                   allow_headers=["X-API-Key","Content-Type"])
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    started = time.perf_counter()
    response = await call_next(request)
    elapsed = time.perf_counter() - started
    inc(f"http_requests_total_{request.method}_{response.status_code}")
    observe("http_request_latency", elapsed)
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'; script-src 'self'"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cache-Control"] = "no-store" if request.url.path.startswith("/v1/") else "no-cache"
    response.headers["X-Request-ID"] = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    return response

@app.exception_handler(Exception)
async def global_handler(request: Request, exc: Exception):
    reference_id = f"ERR-{uuid.uuid4()}"
    logger.error("unhandled_exception", reference_id=reference_id, path=request.url.path,
                 method=request.method, error=str(exc), exc_info=exc)
    return JSONResponse(500, {"status":"ERROR","message":"Internal service error","reference_id":reference_id})

app.include_router(dashboard_router)
app.include_router(client_saas_router)
app.include_router(health_router, prefix="/v1")
if os.path.exists("dashboard/static"): app.mount("/static", StaticFiles(directory="dashboard/static"), name="static")

@app.get("/")
async def root():
    return {
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "dashboard": "/login",
        "health": "/v1/health",
        "status": "/v1/status",
        "docs": "/docs",
        "disclaimer": (
            "RUACH provides baseline EU B2B decisioning and a governed regulatory-change layer. "
            "Registry entries are metadata only. LIVE coverage exists only where an authoritative "
            "provider or rule pack is explicitly configured. Not legal or tax advice."
        ),
    }

@app.get("/login")
async def login_page(): return FileResponse("dashboard/static/login.html")
@app.get("/dashboard")
async def dashboard_page(): return FileResponse("dashboard/static/index.html")

@app.get("/v1/status", tags=["Operations"])
async def platform_status():
    """Honest platform coverage matrix. Prefer this over assumptions from the jurisdiction registry."""
    summary = coverage_summary()
    return {
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "rule_version": RULE_VERSION,
        "primary_region": settings.COMPLIANCE_PRIMARY_REGION,
        "coverage": {
            "baseline_eu_b2b_count": summary["baseline"],
            "metadata_only_count": summary["metadata_only"],
            "total_registry": summary["total"],
            "live_providers": summary["live_providers"],
            "baseline_rule": "EU-B2B-BASELINE (reverse charge + standard rate)",
            "policy": summary["policy"],
        },
        "capabilities_summary": {
            "vat_validation": "LIVE for EU VIES-supported numbers",
            "tax_determination": "BASELINE for intra-EU B2B; NOT_CONFIGURED elsewhere",
            "e_invoicing": "NOT_CONFIGURED (framework ready via regulatory intelligence)",
            "government_clearance": "NOT_CONFIGURED",
            "regulatory_change_governance": "LIVE (detect → review → approve → publish)",
            "evidence_export": "LIVE (single + bulk)",
        },
        "honesty_policy": (
            "A country in the registry does NOT mean full legal coverage. "
            "Unsupported paths return REVIEW or NOT_CONFIGURED. "
            "Regulatory source changes never auto-activate production rules."
        ),
        "endpoints": {
            "capabilities": "/v1/compliance/capabilities",
            "jurisdictions": "/v1/compliance/jurisdictions",
            "evidence_export": "/v1/compliance/evidence/{clearance_id}/export",
            "health": "/v1/health",
            "docs": "/docs",
        },
        "not_legal_advice": True,
    }

@app.post("/v1/clearance/preflight", response_model=ClearanceResponse, tags=["Clearance"])
async def preflight(request: Request, payload: ClearanceRequest, account: dict = Depends(require_permission("clearance:write"))):
    received_at = datetime.now(timezone.utc)
    idem_key = request.headers.get("Idempotency-Key")
    if idem_key:
        if len(idem_key) > 255:
            raise HTTPException(400, "Idempotency-Key is too long")
        canonical = json.dumps(payload.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        request_hash = hashlib.sha256(canonical.encode()).hexdigest()
        record = await db.begin_idempotency(account["api_key_hash"], idem_key, request_hash)
        if record["request_hash"] != request_hash:
            raise HTTPException(409, "Idempotency-Key was already used with a different request")
        if record["status"] == "COMPLETED":
            return JSONResponse(record["response_status"] or 200, record["response_body"])
        if record["status"] == "FAILED":
            return JSONResponse(record["response_status"] or 500, record["response_body"])
        if not record.get("_created"):
            raise HTTPException(409, "An identical request with this Idempotency-Key is already being processed")

    try:
        try:
            await db.consume_quota(account["api_key_hash"])
        except PermissionError:
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Monthly API quota exceeded")

        client_ip = _client_ip(request)
        localization = await localize_ip(client_ip)
        assessment = assess_jurisdictions(payload.seller.country, payload.buyer.country,
                                          payload.seller.country, payload.buyer.country)
        seller_country, buyer_country = assessment.seller_country, assessment.buyer_country
        if not seller_country or not buyer_country:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Both seller and buyer jurisdictions must be established")

        seller_check = await providers.validate(payload.seller.tax_id, seller_country)
        buyer_check = await providers.validate(payload.buyer.tax_id, buyer_country)
        decision = decide(assessment, seller_check, buyer_check, payload.supply_type)

        if decision.treatment == "REVERSE_CHARGE":
            payload.tax_total = Decimal("0.00")
            payload.grand_total = payload.subtotal
            payload.self_healing_log.append("Applied baseline EU B2B reverse-charge treatment after authoritative buyer VAT validation")

        overall_status = decision.status
        message = {"CLEARED": "Compliance decision cleared with recorded evidence",
                   "REVIEW": "Compliance decision requires review because evidence is incomplete or unavailable",
                   "REJECTED": "Compliance decision rejected the transaction"}[overall_status]
        validated_at = datetime.now(timezone.utc)
        clearance_id = f"CLR-{uuid.uuid4()}"
        evidence = build_evidence(payload, assessment, seller_check, buyer_check, decision, localization)
        await db.log_clearance(clearance_id=clearance_id, invoice_number=payload.invoice_number,
            api_key_hash=account["api_key_hash"], seller_country=seller_country, buyer_country=buyer_country,
            currency=payload.currency, grand_total=payload.grand_total, status=overall_status, client_ip=client_ip,
            self_healing_log=list(payload.self_healing_log), issue_date=payload.issue_date, received_at=received_at,
            validated_at=validated_at, ip_country=localization.get("country"), ip_currency=localization.get("currency"),
            timezone_name=localization.get("timezone"), tax_treatment=decision.treatment,
            seller_validation=seller_check, buyer_validation=buyer_check, decision_code=decision.code,
            rule_version=RULE_VERSION, decision_confidence=decision.confidence, decision_reasons=decision.reasons,
            evidence_graph=evidence)
        result = ClearanceResponse(clearance_id=clearance_id, status=overall_status, message=message,
            invoice_number=payload.invoice_number, grand_total=payload.grand_total, currency=payload.currency,
            self_healing_log=payload.self_healing_log, seller_validation=seller_check, buyer_validation=buyer_check,
            localization=localization, tax_treatment=decision.treatment, decision_code=decision.code,
            decision_confidence=decision.confidence, decision_reasons=decision.reasons, evidence_graph=evidence)
        body = result.model_dump(mode="json")
        if idem_key:
            await db.complete_idempotency(account["api_key_hash"], idem_key, 200, body, clearance_id)
        await queue_and_deliver(account["api_key_hash"], "compliance.decision", body)
        return result
    except Exception as exc:
        if idem_key:
            code = exc.status_code if isinstance(exc, HTTPException) else 500
            body = {"status": "ERROR", "message": str(exc.detail) if isinstance(exc, HTTPException) else "Internal service error"}
            await db.fail_idempotency(account["api_key_hash"], idem_key, code, body)
        raise


@app.post("/v1/compliance/simulate")
async def simulate_compliance(
    request: Request,
    payload: ClearanceRequest,
    account: dict = Depends(verify_api_key),
):
    """Run a what-if compliance decision without consuming quota or writing an audit event.

    Overrides are supplied as headers so the original invoice payload stays unchanged:
    X-RUACH-Seller-Country, X-RUACH-Buyer-Country, X-RUACH-Buyer-VAT-Registered.
    This endpoint is intentionally non-authoritative: assumptions are clearly returned.
    """
    seller_override = request.headers.get("X-RUACH-Seller-Country")
    buyer_override = request.headers.get("X-RUACH-Buyer-Country")
    buyer_registered = request.headers.get("X-RUACH-Buyer-VAT-Registered")
    seller_country = (seller_override or payload.seller.country or "").upper()
    buyer_country = (buyer_override or payload.buyer.country or "").upper()
    if len(seller_country) != 2 or len(buyer_country) != 2:
        raise HTTPException(422, "Simulation requires valid seller and buyer country codes")

    # Simulation deliberately avoids live VAT calls. The user chooses the assumption.
    assumed_buyer_valid = True if buyer_registered is None else buyer_registered.strip().lower() in {"true", "1", "yes", "valid"}
    assessment = assess_jurisdictions(seller_country, buyer_country, seller_country, buyer_country)
    seller_check = {"status": "ASSUMED_VALID", "provider": "simulation", "authoritative": False}
    buyer_check = {"status": "ASSUMED_VALID" if assumed_buyer_valid else "ASSUMED_NOT_REGISTERED", "provider": "simulation", "authoritative": False}
    decision = decide(assessment, seller_check, buyer_check, payload.supply_type)
    return {
        "mode": "WHAT_IF",
        "authoritative": False,
        "assumptions": {
            "seller_country": seller_country,
            "buyer_country": buyer_country,
            "buyer_vat_registered": assumed_buyer_valid,
        },
        "decision": decision.code,
        "status": decision.status,
        "tax_rate": str(decision.tax_rate),
        "treatment": decision.treatment,
        "confidence": decision.confidence,
        "reasons": decision.reasons,
        "rule_version": RULE_VERSION,
    }

@app.get("/v1/compliance/explain/{clearance_id}")
async def explain_clearance(clearance_id: str, account: dict = Depends(verify_api_key)):
    """Turn a stored decision into a concise, machine-readable explanation."""
    async with db.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM clearance_audit_logs WHERE clearance_id=$1 AND api_key_hash=$2",
            clearance_id, account["api_key_hash"]
        )
    if not row:
        raise HTTPException(404, "Clearance not found")
    reasons = list(row["decision_reasons"] or [])
    recommendation = {
        "CLEARED": "Proceed using the recorded tax treatment and retain the evidence package.",
        "REVIEW": "Do not rely on the automated result until the missing evidence is resolved.",
        "REJECTED": "Correct the failed compliance condition and submit a new clearance request.",
    }.get(row["status"], "Review the recorded evidence before acting.")
    return {
        "clearance_id": clearance_id,
        "answer": {
            "decision": row["decision_code"],
            "status": row["status"],
            "treatment": row["tax_treatment"],
            "tax_rate": next((n.get("rate") for n in (row["evidence_graph"].get("nodes", []) if row["evidence_graph"] else []) if n.get("id") == "tax_decision"), None),
            "why": reasons,
            "rule_version": row["rule_version"],
            "confidence": float(row["decision_confidence"] or 0),
            "recommendation": recommendation,
        },
        "evidence_graph": row["evidence_graph"],
    }

@app.get("/v1/compliance/evidence/{clearance_id}/export", tags=["Compliance"])
async def export_clearance_evidence(clearance_id: str, account: dict = Depends(require_permission("audit:read"))):
    """One-click evidence package for a single clearance.

    Returns a self-contained JSON package suitable for auditors: decision, reasons,
    rule version, hashes, timestamps, and evidence graph. Read-only; does not mutate data.
    """
    async with db.acquire() as conn:
        row = await conn.fetchrow(
            """SELECT clearance_id, invoice_number, seller_country, buyer_country, currency, grand_total,
                      status, received_at, validated_at, tax_treatment, decision_code, rule_version,
                      decision_confidence, decision_reasons, evidence_graph, previous_hash, event_hash, created_at
               FROM clearance_audit_logs WHERE clearance_id=$1 AND api_key_hash=$2""",
            clearance_id, account["api_key_hash"]
        )
    if not row:
        raise HTTPException(404, "Clearance not found")
    package = {
        "package_type": "RUACH_EVIDENCE_PACKAGE",
        "package_version": "1.0",
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "service": settings.APP_NAME,
        "service_version": settings.APP_VERSION,
        "clearance": {
            "clearance_id": row["clearance_id"],
            "invoice_number": row["invoice_number"],
            "seller_country": row["seller_country"],
            "buyer_country": row["buyer_country"],
            "currency": row["currency"],
            "grand_total": str(row["grand_total"]) if row["grand_total"] is not None else None,
            "status": row["status"],
            "tax_treatment": row["tax_treatment"],
            "decision_code": row["decision_code"],
            "rule_version": row["rule_version"],
            "decision_confidence": float(row["decision_confidence"] or 0),
            "decision_reasons": list(row["decision_reasons"] or []),
            "received_at": row["received_at"].isoformat() if row["received_at"] else None,
            "validated_at": row["validated_at"].isoformat() if row["validated_at"] else None,
            "created_at": row["created_at"].isoformat() if row["created_at"] else None,
        },
        "integrity": {
            "previous_hash": row["previous_hash"],
            "event_hash": row["event_hash"],
            "tamper_evident": True,
            "note": "Audit records are append-only. DB triggers reject updates/deletes on the log table.",
        },
        "evidence_graph": row["evidence_graph"],
        "disclaimer": (
            "This package records the automated decision produced by RUACH under the stated rule version. "
            "It is evidence of system behaviour, not a substitute for professional tax or legal advice."
        ),
    }
    return package

@app.post("/v1/compliance/impact-scan")
async def compliance_impact_scan(body: dict, account: dict = Depends(verify_api_key)):
    """Scan historical RUACH decisions against a proposed rule-change scenario.

    This is a planning tool, not a legal/tax opinion. It identifies records that match
    the supplied scope so a compliance team can review them before a rule takes effect.
    """
    country = str(body.get("country", "")).upper()
    decision_codes = [str(x).upper() for x in body.get("decision_codes", [])]
    if len(country) != 2:
        raise HTTPException(422, "country must be a two-letter jurisdiction code")
    async with db.acquire() as conn:
        rows = await conn.fetch(
            """SELECT clearance_id, invoice_number, status, decision_code, rule_version, created_at
               FROM clearance_audit_logs
               WHERE api_key_hash=$1 AND (seller_country=$2 OR buyer_country=$2)
                 AND ($3::text[] IS NULL OR decision_code = ANY($3::text[]))
               ORDER BY created_at DESC LIMIT 1000""",
            account["api_key_hash"], country, decision_codes or None
        )
    return {
        "mode": "IMPACT_SCAN",
        "authoritative": False,
        "scope": {
            "country": country,
            "decision_codes": decision_codes,
            "proposed_change": body.get("proposed_change", ""),
            "effective_date": body.get("effective_date"),
        },
        "matched_records": len(rows),
        "affected_clearances": [
            {"clearance_id": r["clearance_id"], "invoice_number": r["invoice_number"],
             "status": r["status"], "decision_code": r["decision_code"],
             "rule_version": r["rule_version"], "created_at": r["created_at"]}
            for r in rows
        ],
        "next_action": "Review matched records and publish a versioned rule pack before relying on the proposed change.",
    }

@app.post("/v1/market-entry/assess", tags=["Market Entry"])
async def market_entry_assess(body: dict, account: dict = Depends(verify_api_key)):
    """Assess a product's EU market-entry readiness using conservative, review-gated requirements."""
    product = body.get("product") or {}
    product_id = str(product.get("id", "")).strip()
    product_name = str(product.get("name", "")).strip()
    target_country = str(body.get("target_country", "")).upper().strip()
    if not product_id or not product_name:
        raise HTTPException(422, "product.id and product.name are required")
    try:
        assessment = assess_market_entry(product, target_country)
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    row = await db.save_market_entry(account["organization_id"], product_id, product_name, target_country, product, assessment)
    return {"assessment_id": str(row["id"]), "product_id": product_id, "product_name": product_name, **assessment}

@app.get("/v1/market-entry/markets", tags=["Market Entry"])
async def market_entry_markets():
    return {"markets": [{"country": k, "name": v, "mode": "REVIEW_GATED"} for k, v in TARGET_COUNTRIES.items()], "policy": "Configured launch markets are product-specific review coverage, not a claim of complete legal coverage."}

@app.get("/v1/market-entry/assessments", tags=["Market Entry"])
async def market_entry_assessments(product_id: str | None = None, target_country: str | None = None, account: dict = Depends(verify_api_key)):
    rows = await db.list_market_entries(account["organization_id"], product_id, target_country.upper() if target_country else None)
    return {"count": len(rows), "assessments": [dict(r) for r in rows], "organization_scoped": True}

@app.post("/v1/market-entry/cockpit", tags=["Market Entry"])
async def market_entry_cockpit(body: dict, account: dict = Depends(verify_api_key)):
    assessment_id = str(body.get("assessment_id", "")).strip()
    if not assessment_id:
        raise HTTPException(422, "assessment_id is required")
    rows = await db.list_market_entries(account["organization_id"])
    row = next((r for r in rows if str(r["id"]) == assessment_id), None)
    if not row:
        raise HTTPException(404, "Assessment not found")
    cockpit = create_cockpit(dict(row["assessment"]))
    items = await db.create_market_work_items(account["organization_id"], row["id"], cockpit["work_items"])
    return {"assessment_id": assessment_id, "product_id": row["product_id"], "target_country": row["target_country"], "cockpit_hash": cockpit["cockpit_hash"], "status": recompute_status([dict(x) for x in items]), "work_items": [dict(x) for x in items], "review_gate": cockpit["review_gate"]}

@app.get("/v1/market-entry/cockpit/{assessment_id}", tags=["Market Entry"])
async def market_entry_cockpit_get(assessment_id: str, account: dict = Depends(verify_api_key)):
    rows = await db.list_market_entries(account["organization_id"])
    row = next((r for r in rows if str(r["id"]) == assessment_id), None)
    if not row:
        raise HTTPException(404, "Assessment not found")
    items = await db.list_market_work_items(account["organization_id"], row["id"])
    status = recompute_status([dict(x) for x in items])
    return {"assessment_id": assessment_id, "product_id": row["product_id"], "target_country": row["target_country"], "status": status, "work_items": [dict(x) for x in items], "review_gate": "AUTHORIZED_REVIEW_REQUIRED"}

@app.patch("/v1/market-entry/work-items/{item_id}", tags=["Market Entry"])
async def market_entry_work_item_update(item_id: str, body: dict, account: dict = Depends(verify_api_key)):
    status = str(body.get("status", "")).upper()
    if status not in {"OPEN","IN_PROGRESS","BLOCKED","READY_FOR_REVIEW","APPROVED"}:
        raise HTTPException(422, "Invalid work-item status")
    row = await db.update_market_work_item(account["organization_id"], item_id, status, body.get("owner_email"), body.get("evidence"), body.get("notes"))
    if not row:
        raise HTTPException(404, "Work item not found")
    return dict(row)

@app.post("/v1/market-entry/review", tags=["Market Entry"])
async def market_entry_review(body: dict, account: dict = Depends(verify_api_key)):
    assessment_id = str(body.get("assessment_id", "")).strip()
    decision = str(body.get("decision", "")).upper()
    rationale = str(body.get("rationale", "")).strip()
    reviewer = str(body.get("reviewer_email", "")).strip()
    if not assessment_id or decision not in {"APPROVED","REJECTED","RETURNED"} or not rationale or not reviewer:
        raise HTTPException(422, "assessment_id, decision, rationale and reviewer_email are required")
    items = [dict(x) for x in await db.list_market_work_items(account["organization_id"], assessment_id)]
    if decision == "APPROVED" and any(x["status"] != "APPROVED" for x in items):
        raise HTTPException(409, "Every work item must be APPROVED before the market-entry review can be approved")
    evidence_hash = __import__("hashlib").sha256(__import__("json").dumps({"assessment_id": assessment_id, "items": items, "decision": decision, "rationale": rationale}, sort_keys=True, default=str).encode()).hexdigest()
    row = await db.record_market_review(account["organization_id"], assessment_id, reviewer, decision, rationale, evidence_hash)
    return {"review_id": str(row["id"]), "assessment_id": assessment_id, "decision": decision, "evidence_hash": evidence_hash, "market_ready": decision == "APPROVED"}

@app.get("/v1/market-entry/positioning", tags=["Market Entry"])
async def market_entry_positioning():
    return {
        "product": "RUACH Market Entry",
        "promise": "Turn a European expansion plan into a reviewable compliance worklist before launch.",
        "north_star_metric": "days_to_compliant_market_entry",
        "workflow": ["product_profile", "target_market", "requirements", "evidence", "owners", "review", "market_ready"],
        "guardrail": "RUACH does not declare legal marketability from automated assessment alone.",
    }

@app.get("/v1/compliance/capabilities", tags=["Compliance"])
async def compliance_capabilities():
    return {
        "region": settings.COMPLIANCE_PRIMARY_REGION,
        "rule_version": RULE_VERSION,
        "decision_codes": ["STANDARD_VAT", "REVERSE_CHARGE", "INVALID_TAX_ID", "VALIDATION_UNAVAILABLE", "REVIEW_JURISDICTION"],
        "provider_architecture": {"VAT_validation": ["EU_VIES"], "extensible": True},
        "evidence": {
            "tamper_evident": True,
            "graph": True,
            "reason_codes": True,
            "single_clearance_export": "/v1/compliance/evidence/{clearance_id}/export",
            "bulk_audit_export": "/v1/audit/export",
        },
        "developer_platform": {"api_version": "v1", "idempotency": True, "webhooks": True, "sdk_contract": "OpenAPI"},
        "enterprise": {"rbac": True, "organizations": True, "environments": True, "audit_export": True},
        "regulatory_intelligence": {
            "source_catalog": True,
            "source_hash_monitoring": True,
            "change_governance": True,
            "document_requirement_checks": True,
            "requirement_diff": True,
            "extract_and_impact": True,
            "automatic_rule_activation": False,
        },
        "coverage_matrix": {
            "LIVE": ["EU VIES VAT-number validation"],
            "BASELINE": ["Intra-EU B2B reverse charge / standard rate decisioning"],
            "FRAMEWORK_ONLY": ["Regulatory change detection, approval, versioned document requirements"],
            "NOT_CONFIGURED": ["Most non-EU tax determination, e-invoicing schemas, government clearance channels"],
        },
        "scope_note": (
            "EU-first baseline B2B decisioning. Registry metadata is NOT a claim of live tax or "
            "e-invoicing coverage outside configured providers and rule packs. "
            "Unsupported jurisdictions return REVIEW / NOT_CONFIGURED rather than fabricated approval."
        ),
        "not_legal_advice": True,
    }

@app.get("/v1/compliance/jurisdictions", tags=["Compliance"])
async def compliance_jurisdictions():
    return {"count": len(registry()), "jurisdictions": registry(), "note": "A capability is LIVE only when an authoritative provider/rule pack is configured."}

@app.get("/v1/compliance/jurisdictions/{country}", tags=["Compliance"])
async def compliance_jurisdiction(country: str):
    result = capabilities(country)
    if not result["known"]:
        raise HTTPException(404, "Jurisdiction is not in the RUACH registry")
    return result


@app.get("/v1/compliance/regulatory/sources", tags=["Regulatory Intelligence"])
async def regulatory_sources_list():
    """Return configured primary regulatory sources. A source is not itself an active rule."""
    return {"sources": regulatory_sources(), "policy": "Source references never activate rules automatically."}

@app.post("/v1/compliance/regulatory/sources/{source_id}/check", tags=["Regulatory Intelligence"])
async def regulatory_source_check(source_id: str, account: dict = Depends(require_permission("regulatory:manage"))):
    source = next((x for x in regulatory_sources() if x["source_id"] == source_id), None)
    if not source:
        raise HTTPException(404, "Regulatory source not configured")
    result = await check_source(source)
    if result.get("status") == "INVALID_URL":
        raise HTTPException(422, "Configured regulatory source URL is not a safe HTTPS URL")
    if result.get("status") == "ERROR":
        raise HTTPException(502, "Regulatory source could not be reached")
    return {**result, "activation": "NOT_AUTOMATIC", "next_step": "Create a DETECTED proposal and require authorized review before activating any rule."}

@app.post("/v1/compliance/regulatory/changes", tags=["Regulatory Intelligence"])
async def create_regulatory_change(body: dict, account: dict = Depends(require_permission("regulatory:manage"))):
    try:
        proposal = build_change_proposal(body)
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    async with db.acquire() as conn:
        row = await conn.fetchrow(
            """INSERT INTO regulatory_changes
               (organization_id,jurisdiction,rule_id,version,effective_from,change_type,title,summary,source_id,source_url,affected_document_types,required_formats,submission_channel,confidence,status)
               VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'DETECTED') RETURNING id,created_at""",
            account["organization_id"], proposal.jurisdiction, proposal.rule_id, proposal.version, proposal.effective_from,
            proposal.change_type, proposal.title, proposal.summary, proposal.source_id, proposal.source_url,
            list(proposal.affected_document_types), list(proposal.required_formats), proposal.submission_channel, proposal.confidence
        )
    return {"id": str(row["id"]), "status": "DETECTED", "proposal": proposal.__dict__,
            "activation": "BLOCKED_UNTIL_REVIEW", "message": "Detected regulatory changes cannot change production tax logic until explicitly approved."}

@app.get("/v1/compliance/regulatory/changes", tags=["Regulatory Intelligence"])
async def list_regulatory_changes(account: dict = Depends(verify_api_key), status_filter: str | None = None):
    async with db.acquire() as conn:
        rows = await conn.fetch(
            """SELECT id,jurisdiction,rule_id,version,effective_from,change_type,title,summary,source_id,source_url,affected_document_types,required_formats,submission_channel,confidence,status,created_at,reviewed_at
               FROM regulatory_changes WHERE (organization_id=$1 OR organization_id IS NULL) AND ($2::text IS NULL OR status=$2) ORDER BY created_at DESC LIMIT 500""",
            account["organization_id"], status_filter.upper() if status_filter else None
        )
    return {"count": len(rows), "changes": [dict(r) for r in rows]}

@app.post("/v1/compliance/regulatory/changes/{change_id}/approve", tags=["Regulatory Intelligence"])
async def approve_regulatory_change(change_id: str, account: dict = Depends(require_permission("regulatory:manage"))):
    async with db.acquire() as conn:
        row = await conn.fetchrow(
            """UPDATE regulatory_changes SET status='APPROVED',reviewed_at=now(),organization_id=$2
               WHERE id=$1 AND (organization_id=$2 OR organization_id IS NULL) AND status IN ('DETECTED','REVIEW_REQUIRED')
               RETURNING id,jurisdiction,rule_id,version,effective_from,status,source_id,confidence""",
            change_id, account["organization_id"]
        )
    if not row:
        raise HTTPException(404, "Change not found or not eligible for approval")
    return {"approved": True, "change": dict(row), "warning": "Approval records governance intent; publish an explicit document requirement/rule pack before production activation."}


@app.post("/v1/compliance/regulatory/document-requirements", tags=["Regulatory Intelligence"])
async def publish_document_requirement(body: dict, account: dict = Depends(require_permission("regulatory:manage"))):
    """Publish a versioned document requirement only from an approved regulatory change."""
    change_id = str(body.get("change_id", "")).strip()
    accepted = [str(x).upper().strip() for x in (body.get("accepted_document_types") or [])]
    required = [str(x).upper().strip() for x in (body.get("required_formats") or [])]
    required_fields = [str(x).strip() for x in (body.get("required_fields") or [])]
    try:
        # Reuse the strict format validator via a tiny proposal-like payload.
        proposal = build_change_proposal({
            "jurisdiction": str(body.get("jurisdiction", "")).upper(),
            "source_id": str(body.get("source_id", "")).strip(),
            "rule_id": str(body.get("rule_id", "")).strip(),
            "version": str(body.get("version", "")).strip(),
            "title": "document requirement",
            "summary": "published requirement",
            "confidence": float(body.get("confidence", 1)),
            "required_formats": required,
        })
    except (ValueError, TypeError) as exc:
        raise HTTPException(422, str(exc))
    async with db.acquire() as conn:
        async with conn.transaction():
            approved = await conn.fetchrow(
                """SELECT id FROM regulatory_changes WHERE id=$1 AND organization_id=$2 AND status='APPROVED'\n                   AND jurisdiction=$3 AND rule_id=$4 AND version=$5""",
                change_id, account["organization_id"], proposal.jurisdiction, proposal.rule_id, proposal.version
            )
            if not approved:
                raise HTTPException(409, "Requirement can only be published from a matching APPROVED regulatory change")
            await conn.execute(
                """UPDATE document_requirements SET status='EXPIRED'\n                   WHERE organization_id=$1 AND jurisdiction=$2 AND status='ACTIVE'""",
                account["organization_id"], proposal.jurisdiction
            )
            row = await conn.fetchrow(
                """INSERT INTO document_requirements\n                   (organization_id,jurisdiction,rule_id,version,effective_from,accepted_document_types,required_formats,required_fields,submission_channel,source_id,status)\n                   VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'ACTIVE')\n                   ON CONFLICT (organization_id,jurisdiction,rule_id,version) DO UPDATE SET\n                     effective_from=EXCLUDED.effective_from,accepted_document_types=EXCLUDED.accepted_document_types,\n                     required_formats=EXCLUDED.required_formats,required_fields=EXCLUDED.required_fields,\n                     submission_channel=EXCLUDED.submission_channel,source_id=EXCLUDED.source_id,status='ACTIVE'\n                   RETURNING id,jurisdiction,rule_id,version,effective_from,status""",
                account["organization_id"], proposal.jurisdiction, proposal.rule_id, proposal.version, proposal.effective_from,
                accepted, required, required_fields, proposal.submission_channel, proposal.source_id
            )
    return {"published": True, "requirement": dict(row), "governance": {"approved_change_id": change_id, "source_id": proposal.source_id}}

@app.post("/v1/compliance/regulatory/document-check", tags=["Regulatory Intelligence"])
async def regulatory_document_check(body: dict, account: dict = Depends(verify_api_key)):
    country = str(body.get("jurisdiction", "")).upper()
    document_format = str(body.get("document_format", "")).upper()
    async with db.acquire() as conn:
        row = await conn.fetchrow(
            """SELECT jurisdiction,rule_id,version,effective_from,accepted_document_types,required_formats,required_fields,submission_channel,source_id,status
               FROM document_requirements WHERE organization_id=$1 AND jurisdiction=$2 AND status='ACTIVE'
                 AND (effective_from IS NULL OR effective_from <= CURRENT_DATE)
               ORDER BY effective_from DESC NULLS LAST, created_at DESC LIMIT 1""",
            account["organization_id"], country
        )
    if not row:
        return {"status": "REVIEW", "accepted": False, "jurisdiction": country, "document_format": document_format,
                "reason": "No authoritative active document requirement is configured for this jurisdiction."}
    result = classify_document_requirement(dict(row), document_format)
    return {**result, "jurisdiction": country, "document_format": document_format,
            "rule_id": row["rule_id"], "rule_version": row["version"], "effective_from": row["effective_from"],
            "submission_channel": row["submission_channel"], "source_id": row["source_id"]}

@app.post("/v1/compliance/regulatory/execute", tags=["Regulatory Execution"])
async def regulatory_execute(body: dict, account: dict = Depends(verify_api_key)):
    """Execute the currently effective approved document requirement against a concrete transaction.

    This is deterministic enforcement, not regulatory interpretation. If no effective
    authoritative requirement exists, RUACH returns REVIEW rather than guessing.
    """
    country = str(body.get("jurisdiction", "")).upper()
    if not country:
        raise HTTPException(422, "jurisdiction is required")
    async with db.acquire() as conn:
        row = await conn.fetchrow(
            """SELECT jurisdiction,rule_id,version,effective_from,accepted_document_types,required_formats,required_fields,submission_channel,source_id,status
               FROM document_requirements WHERE organization_id=$1 AND jurisdiction=$2 AND status='ACTIVE'
                 AND (effective_from IS NULL OR effective_from <= CURRENT_DATE)
               ORDER BY effective_from DESC NULLS LAST, created_at DESC LIMIT 1""",
            account["organization_id"], country
        )
    if not row:
        return {"status": "REVIEW", "decision_code": "NO_EFFECTIVE_AUTHORITATIVE_RULE", "review_required": True,
                "jurisdiction": country, "reason": "No effective approved regulatory requirement is configured."}
    requirement = dict(row)
    document = body.get("document") or {}
    result = execute_document_compliance(requirement, document)
    transaction_id = str(body.get("transaction_id", "")).strip()
    if transaction_id and result.get("rule_id") and result.get("evidence"):
        decision = {**result, "evidence_hash": result["evidence"].get("evaluation_hash")}
        edges = build_customer_execution_edges(account["organization_id"], transaction_id, decision)
        await db.upsert_knowledge_edges(account["organization_id"], [e.as_dict() for e in edges])
        result["defensibility"] = {"transaction_id": transaction_id, "knowledge_edges_recorded": len(edges)}
    return {"jurisdiction": country, **result, "execution_policy": "ACTIVE_APPROVED_RULE_ONLY"}


@app.post("/v1/compliance/regulatory/diff", tags=["Regulatory Intelligence"])
async def regulatory_requirement_diff(body: dict, account: dict = Depends(verify_api_key)):
    before = body.get("before") or {}
    after = body.get("after") or {}
    return {"authoritative": False, "diff": diff_requirements(before, after),
            "warning": "A diff is an engineering impact analysis, not a legal opinion. Activate only from an approved authoritative rule pack."}

@app.post("/v1/compliance/regulatory/extract", tags=["Regulatory Intelligence"])
async def regulatory_extract(body: dict, account: dict = Depends(require_permission("regulatory:manage"))):
    """Turn regulatory prose into a conservative, review-gated machine-rule proposal."""
    try:
        result = extract_machine_requirements(
            body.get("text", ""), jurisdiction=body.get("jurisdiction", ""),
            source_id=body.get("source_id", ""), rule_id=body.get("rule_id", ""),
            version=body.get("version", ""), effective_from=body.get("effective_from"),
        )
    except Exception as exc:
        raise HTTPException(422, str(exc))
    return result

@app.post("/v1/compliance/regulatory/semantic-diff", tags=["Regulatory Intelligence"])
async def regulatory_semantic_diff(body: dict, account: dict = Depends(verify_api_key)):
    return {"authoritative": False, "diff": semantic_requirement_diff(body.get("before") or {}, body.get("after") or {}),
            "warning": "Semantic diff identifies engineering impact; it is not a legal opinion."}

@app.post("/v1/compliance/regulatory/impact-plan", tags=["Regulatory Intelligence"])
async def regulatory_impact_plan(body: dict, account: dict = Depends(verify_api_key)):
    return build_customer_impact_plan(body.get("requirement") or {}, body.get("customer_systems") or [])

@app.post("/v1/compliance/regulatory/knowledge-graph/ingest", tags=["Defensibility"])
async def ingest_regulatory_knowledge(body: dict, account: dict = Depends(require_permission("regulatory:manage"))):
    """Persist provenance-linked regulatory and customer-system mappings."""
    requirement = body.get("requirement") or {}
    source_id = str(body.get("source_id") or requirement.get("source_id") or "").strip()
    if not source_id:
        raise HTTPException(422, "source_id is required")
    edges = build_regulatory_knowledge_edges(requirement, source_id)
    for system in body.get("customer_systems") or []:
        sid = str(system.get("id", "")).strip()
        if not sid:
            continue
        for predicate in ("IMPACTS_SYSTEM", "REMEDIATION_TARGET"):
            edges.append(type(edges[0])("rule", str(requirement.get("rule_id")), predicate, "customer_system", sid, source_id, str(requirement.get("rule_id")), str(requirement.get("version", ""))))
    rows = await db.upsert_knowledge_edges(account["organization_id"], [e.as_dict() for e in edges])
    return {"stored": len(rows), "graph_version": canonical_hash([r for r in [e.as_dict() for e in edges]])[:16], "provenance_required": True}

@app.get("/v1/compliance/regulatory/knowledge-graph", tags=["Defensibility"])
async def get_regulatory_knowledge(subject_type: str | None = None, subject_id: str | None = None, account: dict = Depends(verify_api_key)):
    rows = await db.list_knowledge_edges(account["organization_id"], subject_type, subject_id)
    return {"edges": [dict(r) for r in rows], "count": len(rows), "organization_scoped": True}

@app.post("/v1/compliance/regulatory/execution-feedback", tags=["Defensibility"])
async def execution_feedback(body: dict, account: dict = Depends(verify_api_key)):
    transaction_id = str(body.get("transaction_id", "")).strip()
    decision = body.get("decision") or {}
    outcome = body.get("outcome") or {}
    if not transaction_id or not decision.get("rule_id") or not decision.get("decision_code"):
        raise HTTPException(422, "transaction_id, decision.rule_id and decision.decision_code are required")
    event = build_feedback_event(transaction_id, decision, outcome)
    row = await db.record_execution_feedback(account["organization_id"], event)
    if row is None:
        return {"recorded": False, "event_hash": event["event_hash"], "reason": "duplicate_event"}
    return {"recorded": True, "event": dict(row), "privacy": "tenant_scoped"}

@app.get("/v1/metrics", response_class=PlainTextResponse, tags=["Operations"])
async def metrics():
    return PlainTextResponse(prometheus_text(), media_type="text/plain; version=0.0.4")

@app.get("/v1/platform/me", tags=["Enterprise"])
async def platform_me(account: dict = Depends(require_permission("organization:read"))):
    return {k: account.get(k) for k in ("id", "client_name", "tier", "organization_id", "role", "environment", "monthly_limit", "used_requests")}

@app.post("/v1/platform/api-keys", tags=["Enterprise"])
async def create_platform_api_key(body: dict, account: dict = Depends(require_permission("keys:manage"))):
    role = str(body.get("role", "developer")).lower()
    if role not in {"admin", "developer", "finance", "auditor", "readonly"}:
        raise HTTPException(422, "Unsupported role")
    environment = str(body.get("environment", "production")).lower()
    if environment not in {"sandbox", "production"}:
        raise HTTPException(422, "environment must be sandbox or production")
    limit = int(body.get("monthly_limit", 1000))
    if limit < 1 or limit > 100_000_000:
        raise HTTPException(422, "monthly_limit is out of range")
    key_name = str(body.get("key_name", "RUACH API key")).strip()[:100]
    created = await db.create_api_key(account["organization_id"], str(body.get("client_name", account["client_name"])), role, environment, str(body.get("tier", account["tier"])), limit, key_name)
    return {**created, "warning": "The secret is shown once. Store it securely; RUACH cannot recover it."}

@app.get("/v1/platform/api-keys", tags=["Enterprise"])
async def list_platform_api_keys(account: dict = Depends(require_permission("keys:manage"))):
    rows = await db.list_api_keys(account["organization_id"])
    return [{"id": str(r["id"]), "key_name": r["key_name"], "client_name": r["client_name"], "tier": r["tier"], "role": r["role"], "environment": r["environment"], "monthly_limit": r["monthly_limit"], "active": r["is_active"], "last_used_at": r["last_used_at"], "created_at": r["created_at"]} for r in rows]

@app.delete("/v1/platform/api-keys/{key_id}", tags=["Enterprise"])
async def revoke_platform_api_key(key_id: str, account: dict = Depends(require_permission("keys:manage"))):
    await db.revoke_api_key(account["organization_id"], key_id)
    return {"revoked": True, "key_id": key_id}

@app.get("/v1/audit/export", tags=["Enterprise"])
async def audit_export(limit: int = 1000, account: dict = Depends(require_permission("audit:read"))):
    limit = max(1, min(limit, 10000))
    async with db.acquire() as conn:
        rows = await conn.fetch(
            """SELECT clearance_id, invoice_number, seller_country, buyer_country, currency, grand_total, status,
                      received_at, validated_at, tax_treatment, decision_code, rule_version, decision_confidence,
                      decision_reasons, evidence_graph, previous_hash, event_hash, created_at
               FROM clearance_audit_logs WHERE api_key_hash=$1 ORDER BY created_at DESC LIMIT $2""",
            account["api_key_hash"], limit)
    return {
        "format": "json",
        "count": len(rows),
        "records": [dict(r) for r in rows],
        "note": "Export is read-only. Audit records are append-only and tamper-evident; this endpoint does not mutate them.",
    }

@app.post("/v1/webhooks", tags=["Webhooks"])
async def create_webhook(body: dict, account: dict = Depends(require_permission("webhooks:manage"))):
    url = str(body.get("url", "")).strip()
    events = body.get("events") or ["*"]
    try:
        validate_destination(url)
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    if not isinstance(events, list) or not events or len(events) > 20:
        raise HTTPException(422, "events must be a non-empty list of at most 20 event types")
    secret = secrets.token_urlsafe(32)
    row = await db.create_webhook_sub(account["api_key_hash"], url, secret, [str(x) for x in events])
    return {"id": str(row["id"]), "url": row["url"], "events": row["events"], "secret": secret,
            "warning": "Store the webhook secret now; it is not returned by the list endpoint."}

@app.get("/v1/webhooks", tags=["Webhooks"])
async def list_webhooks(account: dict = Depends(require_permission("webhooks:manage"))):
    rows = await db.list_webhook_subs(account["api_key_hash"])
    return [{"id": str(r["id"]), "url": r["url"], "events": r["events"], "active": r["is_active"], "created_at": r["created_at"]} for r in rows]
