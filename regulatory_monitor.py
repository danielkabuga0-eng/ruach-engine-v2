"""Durable regulatory-source monitoring worker for RUACH."""
from __future__ import annotations
import asyncio
import logging
import re
from datetime import datetime, timezone
from html import unescape
from urllib.parse import urljoin, urlparse
import httpx
from pypdf import PdfReader
from io import BytesIO
from .config import settings
from .database import db
from .regulatory_intelligence import hash_snapshot, safe_source_url, sources, extract_machine_requirements, semantic_requirement_diff, source_authority_profile

log = logging.getLogger(__name__)


def _html_to_text(body: bytes, encoding: str | None) -> str:
    text = body.decode(encoding or "utf-8", errors="replace")
    text = re.sub(r"(?is)<(script|style|noscript).*?>.*?</\1>", " ", text)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", unescape(text)).strip()


def _pdf_to_text(body: bytes) -> str:
    reader = PdfReader(BytesIO(body))
    chunks: list[str] = []
    remaining = min(settings.REGULATORY_MAX_TEXT_CHARS, 2_000_000)
    for page_number, page in enumerate(reader.pages):
        if page_number >= settings.REGULATORY_MAX_PDF_PAGES:
            break
        if remaining <= 0:
            break
        text = page.extract_text() or ""
        if text:
            text = text[:remaining]
            chunks.append(text)
            remaining -= len(text)
    return re.sub(r"\s+", " ", " ".join(chunks)).strip()


def _content_to_text(body: bytes, content_type: str, encoding: str | None) -> str:
    ctype = (content_type or "").lower()
    if "pdf" in ctype or body.startswith(b"%PDF"):
        return _pdf_to_text(body)
    if any(x in ctype for x in ("text/", "json", "xml", "html")):
        text = _html_to_text(body, encoding) if "html" in ctype else body.decode(encoding or "utf-8", errors="replace")
        return re.sub(r"\s+", " ", text).strip()[:settings.REGULATORY_MAX_TEXT_CHARS]
    return ""


async def _fetch_source(url: str) -> tuple[httpx.Response, bytes]:
    allowed = {urlparse(s["url"]).hostname.lower().rstrip('.') for s in sources() if urlparse(s["url"]).hostname}
    if not safe_source_url(url, allowed_hosts=allowed):
        raise ValueError('unsafe or non-allowlisted source URL')
    current = url
    timeout = httpx.Timeout(settings.REGULATORY_SOURCE_TIMEOUT)
    limits = httpx.Limits(max_connections=10, max_keepalive_connections=5)
    async with httpx.AsyncClient(timeout=timeout, limits=limits, follow_redirects=False, headers={
        'User-Agent': settings.REGULATORY_USER_AGENT,
        'Accept': 'text/html,application/xhtml+xml,application/xml,application/json,text/plain,application/pdf,*/*',
    }) as client:
        for _ in range(settings.REGULATORY_MAX_REDIRECTS + 1):
            if not safe_source_url(current, allowed_hosts=allowed):
                raise ValueError('unsafe or non-allowlisted redirect URL')
            response = await client.get(current)
            if response.status_code in {301, 302, 303, 307, 308}:
                location = response.headers.get('location')
                if not location:
                    raise httpx.HTTPStatusError('redirect without location', request=response.request, response=response)
                current = urljoin(current, location)
                continue
            response.raise_for_status()
            content_length = response.headers.get('content-length')
            if content_length and int(content_length) > settings.REGULATORY_MAX_SOURCE_BYTES:
                raise ValueError('regulatory source exceeds configured size limit')
            chunks = []
            total = 0
            async for chunk in response.aiter_bytes(64 * 1024):
                total += len(chunk)
                if total > settings.REGULATORY_MAX_SOURCE_BYTES:
                    raise ValueError('regulatory source exceeds configured size limit')
                chunks.append(chunk)
            return response, b''.join(chunks)
    raise httpx.TooManyRedirects('too many redirects')


async def check_source(source: dict) -> dict:
    source_id = source["source_id"]
    url = source["url"]
    if not safe_source_url(url):
        return {"source_id": source_id, "status": "INVALID_URL", "changed": False}
    try:
        response, body = await _fetch_source(url)
        digest = hash_snapshot(body)
        content_type = response.headers.get("content-type", "").lower()
        text_body = _content_to_text(body, content_type, response.encoding)

        async with db.acquire() as conn:
            previous = await conn.fetchrow(
                """SELECT id, content_hash, text_content, extracted_requirement
                   FROM regulatory_source_snapshots
                   WHERE source_id=$1 ORDER BY observed_at DESC LIMIT 1""", source_id
            )
            changed = previous is not None and previous["content_hash"] != digest
            extracted = None
            diff = {}
            if text_body:
                extracted = extract_machine_requirements(
                    text_body, jurisdiction=source["jurisdiction"], source_id=source_id,
                    rule_id=f"OBS-{source_id}-{digest[:12]}", version=digest[:12]
                )
                if previous and previous["extracted_requirement"]:
                    diff = semantic_requirement_diff(previous["extracted_requirement"], extracted)

            snapshot_id = await conn.fetchval(
                """INSERT INTO regulatory_source_snapshots
                   (source_id,content_hash,http_status,content_type,metadata,content,text_content,extracted_requirement,processing_status,decoded_text_hash,previous_snapshot_id,semantic_diff)
                   VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
                   ON CONFLICT (source_id,content_hash) DO UPDATE SET
                     observed_at=now(), content=$6, text_content=$7, extracted_requirement=$8,
                     processing_status=$9, decoded_text_hash=$10, previous_snapshot_id=$11, semantic_diff=$12
                   RETURNING id""",
                source_id, digest, response.status_code, content_type,
                {"final_url": str(response.url), "content_length": len(body), "checked_at": datetime.now(timezone.utc).isoformat()},
                body, text_body or None, extracted,
                "PROCESSED" if text_body else "STORED_BINARY",
                hash_snapshot(text_body.encode("utf-8")) if text_body else None,
                previous["id"] if previous else None, diff,
            )

            if changed and extracted and extracted.get("review_required"):
                # Source observations are global evidence. A tenant claims the
                # proposal when an authorized reviewer approves it.
                await conn.execute(
                    """INSERT INTO regulatory_changes
                       (organization_id,jurisdiction,rule_id,version,effective_from,change_type,title,summary,source_id,source_url,affected_document_types,required_formats,rejected_formats,submission_channel,confidence,status,semantic_diff,previous_snapshot_id,current_snapshot_id)
                       SELECT NULL,$1,$2,$3,$4,'REGULATORY_SOURCE_CHANGE',$5,$6,$7,$8,$9,$10,$11,$12,$13,'REVIEW_REQUIRED',$14,$15,$16
                       WHERE NOT EXISTS (
                         SELECT 1 FROM regulatory_changes WHERE organization_id IS NULL AND source_id=$7 AND version=$3
                       )""",
                    source["jurisdiction"], extracted["rule_id"], extracted["version"], extracted.get("effective_from"),
                    f"Regulatory change detected: {source['title']}",
                    "Authoritative source version changed; extracted requirements and evidence require authorized review before activation.",
                    source_id, str(response.url), extracted.get("accepted_document_types", []),
                    extracted.get("required_formats", []), extracted.get("rejected_formats", []), extracted.get("submission_channel"),
                    extracted.get("confidence", 0.0), diff, previous["id"] if previous else None, snapshot_id,
                )
            await conn.execute(
                """UPDATE regulatory_sources SET last_checked_at=now(),last_content_hash=$2,last_http_status=$3 WHERE source_id=$1""",
                source_id, digest, response.status_code,
            )
        return {"source_id": source_id, "status": "OK", "changed": changed, "content_hash": digest,
                "http_status": response.status_code, "snapshot_id": str(snapshot_id), "extracted": bool(extracted), "diff": diff}
    except (httpx.HTTPError, OSError, UnicodeError, ValueError) as exc:
        log.warning("regulatory_source_check_failed source=%s error=%s", source_id, exc.__class__.__name__)
        return {"source_id": source_id, "status": "ERROR", "changed": False, "error": exc.__class__.__name__}


async def monitor_once() -> list[dict]:
    results = []
    for source in sources():
        results.append(await check_source(source))
    return results


async def run_forever() -> None:
    interval = max(60, settings.REGULATORY_MONITOR_INTERVAL_SECONDS)
    log.info("RUACH regulatory monitor started interval=%ss sources=%s", interval, len(sources()))
    while True:
        try:
            results = await monitor_once()
            changed = [r["source_id"] for r in results if r.get("changed")]
            if changed:
                log.warning("regulatory_changes_detected sources=%s", changed)
        except Exception:
            log.exception("regulatory_monitor_cycle_failed")
        await asyncio.sleep(interval)
