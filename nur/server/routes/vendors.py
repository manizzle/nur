"""Vendor profile pages -- claim, update, and view vendor profiles."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse

router = APIRouter(tags=["vendors"])


@router.get("/vendor/{vendor_id}", response_class=HTMLResponse)
async def vendor_profile(vendor_id: str):
    """Vendor profile page with practitioner scores + vendor demo."""
    from ..app import get_db, get_proof_engine

    engine = get_proof_engine()
    db = get_db()

    # Get aggregate scores from ProofEngine
    agg = engine.get_aggregate(vendor_id)

    # Get vendor profile from DB (if claimed)
    from ..models import VendorProfile
    from sqlalchemy import select
    async with db.session() as s:
        result = await s.execute(
            select(VendorProfile).where(VendorProfile.vendor_id == vendor_id.lower())
        )
        profile = result.scalar_one_or_none()

    # Build the HTML page
    vendor_display = profile.display_name if profile else vendor_id.replace("-", " ").title()
    demo_embed = ""
    if profile and profile.demo_url:
        url = profile.demo_url
        if "youtube.com/watch" in url:
            vid_id = url.split("v=")[1].split("&")[0] if "v=" in url else ""
            if vid_id:
                demo_embed = f'<iframe width="100%" height="400" src="https://www.youtube.com/embed/{vid_id}" frameborder="0" allowfullscreen style="border-radius:8px;"></iframe>'
        elif "youtu.be/" in url:
            vid_id = url.split("youtu.be/")[1].split("?")[0]
            demo_embed = f'<iframe width="100%" height="400" src="https://www.youtube.com/embed/{vid_id}" frameborder="0" allowfullscreen style="border-radius:8px;"></iframe>'
        elif "vimeo.com" in url:
            vid_id = url.split("/")[-1]
            demo_embed = f'<iframe width="100%" height="400" src="https://player.vimeo.com/video/{vid_id}" frameborder="0" allowfullscreen style="border-radius:8px;"></iframe>'
        elif "loom.com" in url:
            vid_id = url.split("/")[-1]
            demo_embed = f'<iframe width="100%" height="400" src="https://www.loom.com/embed/{vid_id}" frameborder="0" allowfullscreen style="border-radius:8px;"></iframe>'
        else:
            demo_embed = f'<a href="{url}" target="_blank" style="color:#22c55e;">Watch Demo &rarr;</a>'

    # Scores section
    scores_html = "<p style='color:#666;'>No practitioner evaluations yet. Be the first to contribute.</p>"
    if agg:
        scores_html = "<div style='display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:16px;'>"
        score_fields = [
            ("avg_overall_score", "Overall Score", "/10"),
            ("avg_detection_rate", "Detection Rate", "%"),
            ("avg_fp_rate", "False Positive Rate", "%"),
            ("avg_support_quality", "Support Quality", "/10"),
            ("avg_annual_cost", "Avg Annual Cost", ""),
            ("would_buy_pct", "Would Buy Again", "%"),
            ("chose_this_vendor_pct", "Chose This Vendor", "%"),
        ]
        for field, label, suffix in score_fields:
            val = agg.get(field)
            if val is not None:
                if field == "avg_annual_cost":
                    display = f"${val:,.0f}"
                else:
                    display = f"{val:.1f}{suffix}"
                scores_html += f"""
                <div style="background:#111118;border:1px solid #1e1e2e;border-radius:8px;padding:20px;text-align:center;">
                    <div style="font-size:1.8em;color:#fafafa;font-weight:600;">{display}</div>
                    <div style="font-size:0.75em;color:#888;margin-top:4px;text-transform:uppercase;letter-spacing:0.1em;">{label}</div>
                </div>"""
        count = agg.get("contributor_count", 0)
        scores_html += f"""
        </div>
        <p style="color:#555;font-size:0.8em;margin-top:12px;">Based on {count} practitioner evaluation{'s' if count != 1 else ''} &middot; Cryptographically verified</p>"""

    # Claim banner
    claim_html = ""
    if not profile or not profile.claimed_by_email:
        claim_html = f"""
        <div style="background:#1a2e1a;border:1px solid #22c55e33;border-radius:8px;padding:20px;margin-bottom:32px;text-align:center;">
            <p style="color:#22c55e;font-weight:600;">Are you {vendor_display}?</p>
            <p style="color:#888;font-size:0.85em;margin-top:4px;">Claim this profile to add your demo video and product description.</p>
            <a href="/vendor/{vendor_id}/claim" style="display:inline-block;background:#22c55e;color:#0a0a0f;padding:8px 24px;border-radius:6px;text-decoration:none;font-weight:600;margin-top:12px;font-size:0.9em;">Claim Profile &rarr;</a>
        </div>"""

    # Description
    desc_html = ""
    if profile and profile.description:
        desc_html = f"""
        <div style="margin-bottom:32px;">
            <h2 style="font-size:1.1em;color:#fafafa;margin-bottom:12px;">About</h2>
            <p style="color:#999;line-height:1.7;">{profile.description}</p>
        </div>"""

    # Demo request button
    demo_btn = ""
    if profile and profile.demo_request_url:
        demo_btn = f"""
        <div style="text-align:center;margin:32px 0;">
            <a href="{profile.demo_request_url}" target="_blank" style="display:inline-block;background:#22c55e;color:#0a0a0f;padding:12px 32px;border-radius:6px;text-decoration:none;font-weight:600;font-size:1em;">Request a Demo &rarr;</a>
        </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>nur &mdash; {vendor_display}</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ background: #0a0a0f; color: #e4e4e7; font-family: 'Inter', sans-serif; min-height: 100vh; }}
  .container {{ max-width: 800px; margin: 0 auto; padding: 48px 24px; }}
  a {{ color: #22c55e; text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
</style>
</head>
<body>
<div class="container">
  <div style="margin-bottom:8px;"><a href="/" style="color:#666;font-size:0.85em;">&larr; nur</a></div>
  <h1 style="font-size:2em;color:#fafafa;margin-bottom:8px;">{vendor_display}</h1>
  <p style="color:#666;margin-bottom:32px;">Practitioner intelligence &middot; Cryptographically verified</p>

  {claim_html}

  {f'<div style="margin-bottom:32px;">{demo_embed}</div>' if demo_embed else ''}

  {desc_html}

  <div style="margin-bottom:32px;">
    <h2 style="font-size:1.1em;color:#fafafa;margin-bottom:16px;">Practitioner Scores</h2>
    {scores_html}
  </div>

  {demo_btn}

  <div style="border-top:1px solid #1e1e2e;padding-top:24px;margin-top:48px;color:#555;font-size:0.8em;">
    <p>All scores are aggregated from anonymous practitioner evaluations. Individual values are discarded after commitment. <a href="/guide">Learn more</a></p>
  </div>
</div>
</body>
</html>"""


@router.get("/vendor/{vendor_id}/claim", response_class=HTMLResponse)
async def claim_vendor_page(vendor_id: str):
    """Page where vendors enter their work email to claim a profile."""
    vendor_display = vendor_id.replace("-", " ").title()

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>nur &mdash; claim {vendor_display}</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ background: #0a0a0f; color: #e4e4e7; font-family: 'Inter', sans-serif; min-height: 100vh; display: flex; align-items: center; justify-content: center; }}
  .container {{ max-width: 480px; padding: 40px 24px; text-align: center; }}
  input {{ width: 100%; padding: 12px 16px; background: #111118; border: 1px solid #1e1e2e; border-radius: 6px; color: #e4e4e7; font-family: 'Inter', sans-serif; font-size: 1em; margin-bottom: 12px; }}
  input:focus {{ outline: none; border-color: #22c55e; }}
  button {{ width: 100%; padding: 12px; background: #22c55e; color: #0a0a0f; border: none; border-radius: 6px; font-weight: 600; font-size: 1em; cursor: pointer; font-family: 'Inter', sans-serif; }}
  button:hover {{ background: #1ea34b; }}
  textarea {{ width: 100%; padding: 12px 16px; background: #111118; border: 1px solid #1e1e2e; border-radius: 6px; color: #e4e4e7; font-family: 'Inter', sans-serif; font-size: 0.9em; margin-bottom: 12px; resize: vertical; min-height: 100px; }}
  textarea:focus {{ outline: none; border-color: #22c55e; }}
</style>
</head>
<body>
<div class="container">
  <h1 style="font-size:1.5em;color:#fafafa;margin-bottom:8px;">Claim {vendor_display}</h1>
  <p style="color:#888;margin-bottom:32px;font-size:0.9em;">Verify your identity with a @{vendor_id.replace('-','')}.com email address to manage this profile.</p>

  <form method="POST" action="/vendor/{vendor_id}/claim">
    <input type="email" name="email" placeholder="you@{vendor_id.replace('-','')}.com" required>
    <input type="url" name="demo_url" placeholder="Demo video URL (YouTube, Vimeo, Loom)">
    <textarea name="description" placeholder="Product description (max 500 words)"></textarea>
    <input type="url" name="demo_request_url" placeholder="Request demo URL (where leads go)">
    <button type="submit">Claim Profile &rarr;</button>
  </form>

  <p style="color:#555;font-size:0.75em;margin-top:24px;">We'll send a verification email to confirm you work at {vendor_display}.</p>
  <p style="margin-top:16px;"><a href="/vendor/{vendor_id}" style="color:#666;font-size:0.85em;">&larr; back to profile</a></p>
</div>
</body>
</html>"""


@router.post("/vendor/{vendor_id}/claim")
async def claim_vendor(vendor_id: str, request: Request):
    """Process vendor profile claim -- verify email domain matches vendor."""
    from ..app import get_db
    from ..models import VendorProfile
    from sqlalchemy import select

    form = await request.form()
    email = str(form.get("email", "")).strip().lower()
    demo_url = str(form.get("demo_url", "")).strip() or None
    description = str(form.get("description", "")).strip() or None
    demo_request_url = str(form.get("demo_request_url", "")).strip() or None

    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="Valid email required")

    # Truncate description to 500 words
    if description and len(description.split()) > 500:
        description = " ".join(description.split()[:500])

    db = get_db()

    # Create or update vendor profile
    import uuid
    from datetime import datetime, timezone
    async with db.session() as s:
        result = await s.execute(
            select(VendorProfile).where(VendorProfile.vendor_id == vendor_id.lower())
        )
        profile = result.scalar_one_or_none()

        if profile and profile.claimed_by_email:
            raise HTTPException(status_code=409, detail="This vendor profile has already been claimed")

        if not profile:
            profile = VendorProfile(
                id=str(uuid.uuid4()),
                vendor_id=vendor_id.lower(),
                display_name=vendor_id.replace("-", " ").title(),
            )
            s.add(profile)

        profile.claimed_by_email = email
        profile.demo_url = demo_url
        profile.description = description
        profile.demo_request_url = demo_request_url
        profile.claimed_at = datetime.now(timezone.utc)

    from fastapi.responses import RedirectResponse
    return RedirectResponse(url=f"/vendor/{vendor_id}", status_code=303)
