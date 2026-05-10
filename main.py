"""
VeriTrade AI — FastAPI Backend
Blockchain-Backed Trade Compliance Engine
"""
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import hashlib
import json
import datetime
import uuid
import os
from dotenv import load_dotenv
import requests

app = FastAPI(title="VeriTrade AI Compliance Engine", version="1.0.0")
load_dotenv()
NOAH_API_KEY = os.getenv("NOAH_API_KEY")

  
# Allow all origins for hackathon demo
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─────────────────────────────────────────────
# RISK MATRICES  (Rules-Based AI Logic)
# ─────────────────────────────────────────────

# Countries with elevated geopolitical / sanctions risk
HIGH_RISK_COUNTRIES = {
    "Russia": 90, "Iran": 95, "North Korea": 99, "Myanmar": 80,
    "Belarus": 75, "Sudan": 85, "Syria": 92, "Venezuela": 70,
    "Libya": 78, "Somalia": 82, "Yemen": 88, "Afghanistan": 86,
    "Cuba": 65, "Eritrea": 72, "Haiti": 68,
}

# Conflict or high-environmental-impact minerals
CONFLICT_MATERIALS = {
    "Cobalt": {"risk": 60, "reason": "DRC conflict mineral supply chain risk"},
    "Tantalum": {"risk": 75, "reason": "Coltan sourcing linked to armed groups"},
    "Tungsten": {"risk": 65, "reason": "Tin/Tungsten/Tantalum 3T conflict mineral"},
    "Tin": {"risk": 55, "reason": "3T conflict mineral — sourcing scrutiny required"},
    "Gold": {"risk": 50, "reason": "LBMA provenance verification required"},
    "Diamonds": {"risk": 70, "reason": "Kimberley Process compliance required"},
    "Lithium": {"risk": 35, "reason": "Indigenous land / water-use concerns"},
    "Palm Oil": {"risk": 45, "reason": "Deforestation risk — RSPO certification needed"},
    "Soy": {"risk": 40, "reason": "Amazon deforestation linkage possible"},
}

# Positive ESG certifications lower the risk score
ESG_MITIGATORS = {
    "ISO-14001": -15,
    "Fair Trade": -20,
    "Rainforest Alliance": -18,
    "B-Corp": -12,
    "RSPO": -22,
    "RMI (Responsible Minerals)": -25,
    "Kimberley Process": -20,
    "LBMA Chain of Custody": -18,
    "SA8000 (Social Accountability)": -10,
    "Carbon Neutral Certified": -8,
}

# ─────────────────────────────────────────────
# MODELS
# ─────────────────────────────────────────────

class ManifestInput(BaseModel):
    supplier_id: str
    supplier_name: str
    origin_country: str
    destination_country: str
    cargo_items: list[str]          # e.g. ["Cobalt", "Recycled Steel"]
    esg_certifications: list[str]   # e.g. ["ISO-14001", "Fair Trade"]
    declared_value_usd: float
    weight_kg: float
    vessel_id: Optional[str] = None

class VerifyHashInput(BaseModel):
    original_hash: str
    audit_record: dict              # The full audit JSON to re-hash and compare

# ─────────────────────────────────────────────
# CORE ENGINE
# ─────────────────────────────────────────────

def compute_risk(manifest: ManifestInput) -> dict:
    """
    Rules-Based AI Risk Scoring Engine.
    Returns a structured risk assessment with natural language reasoning.
    """
    risk_score = 0
    reasoning_log = []
    flags = []

    # 1. Geopolitical / Sanctions screening
    country_risk = HIGH_RISK_COUNTRIES.get(manifest.origin_country, 0)
    if country_risk > 0:
        risk_score += country_risk
        flags.append("GEOPOLITICAL_RISK")
        reasoning_log.append(
            f"⚠ Origin country '{manifest.origin_country}' carries a geopolitical risk "
            f"score of {country_risk}/100. Subject to OFAC/EU sanctions screening."
        )
    else:
        reasoning_log.append(
            f"✓ Origin country '{manifest.origin_country}' — no active sanctions detected."
        )

    # 2. Conflict Mineral / High-Carbon Material Screening
    material_risk_total = 0
    for item in manifest.cargo_items:
        material = CONFLICT_MATERIALS.get(item)
        if material:
            material_risk_total += material["risk"]
            flags.append(f"CONFLICT_MATERIAL:{item.upper()}")
            reasoning_log.append(
                f"⚠ Cargo item '{item}' flagged: {material['reason']} "
                f"(+{material['risk']} risk points)."
            )
        else:
            reasoning_log.append(f"✓ Cargo item '{item}' — not on conflict materials registry.")

    # Apply material risk (capped at 80 to avoid double-penalising)
    risk_score += min(material_risk_total, 80)

    # 3. ESG Certification Mitigation
    esg_reduction = 0
    for cert in manifest.esg_certifications:
        reduction = ESG_MITIGATORS.get(cert, 0)
        if reduction:
            esg_reduction += abs(reduction)
            reasoning_log.append(
                f"✓ ESG certification '{cert}' verified — risk reduced by {abs(reduction)} points."
            )
        else:
            reasoning_log.append(f"ℹ Certification '{cert}' not in recognised ESG registry.")

    risk_score = max(0, risk_score - esg_reduction)

    # 4. Value-Based AML Screening
    if manifest.declared_value_usd > 1_000_000:
        risk_score += 10
        flags.append("HIGH_VALUE_AML")
        reasoning_log.append(
            f"⚠ Declared value ${manifest.declared_value_usd:,.2f} exceeds AML threshold "
            f"of $1,000,000. Enhanced due diligence required."
        )

    # 5. Final verdict
    risk_score = min(risk_score, 100)

    if risk_score >= 60:
        verdict = "FLAGGED"
        verdict_detail = "Shipment requires manual customs review before clearance."
    elif risk_score >= 30:
        verdict = "REVIEW"
        verdict_detail = "Shipment passes automated screening with advisory notes."
    else:
        verdict = "CLEARED"
        verdict_detail = "Shipment cleared by AI compliance engine. No significant risk factors."

    return {
        "risk_score": risk_score,
        "verdict": verdict,
        "verdict_detail": verdict_detail,
        "flags": flags,
        "reasoning_log": reasoning_log,
    }



async def get_noah_insights(manifest: ManifestInput):
    """Calls Noah AI for deep ethical reasoning and vibe-checks."""
    if not NOAH_API_KEY:
        return {"score": 0, "reason": "⚠️ Noah AI not configured. Add NOAH_API_KEY to .env file"}

    # Custom prompt for the trade use-case
    prompt = f"Analyze ethical risk for: {manifest.cargo_items} from {manifest.origin_country}."
    
    # Try multiple possible endpoints
    endpoints = [
        "https://api.trynoah.ai/v1/analyze",
        "https://api.trynoah.ai/v1/chat/completions",
        "https://api.trynoah.ai/v1/completions"
    ]
    
    for url in endpoints:
        headers = {"Authorization": f"Bearer {NOAH_API_KEY}", "Content-Type": "application/json"}
        
        # Try different payload formats
        payloads = [
            {"prompt": prompt},
            {"messages": [{"role": "user", "content": prompt}]},
            {"input": prompt}
        ]
        
        for payload in payloads:
            try:
                print(f"Trying: {url} with payload type: {list(payload.keys())}")
                response = requests.post(url, headers=headers, json=payload, timeout=5)
                print(f"Response status: {response.status_code}")
                
                if response.status_code == 200:
                    data = response.json()
                    # Try to extract the response from different formats
                    explanation = (
                        data.get("explanation") or 
                        data.get("text") or 
                        data.get("response") or
                        data.get("choices", [{}])[0].get("message", {}).get("content") or
                        data.get("choices", [{}])[0].get("text") or
                        str(data)
                    )
                    return {"score": 0, "reason": explanation[:500]}
                else:
                    print(f"Failed with status {response.status_code}: {response.text[:200]}")
                    
            except requests.exceptions.Timeout:
                print(f"Timeout on {url}")
            except Exception as e:
                print(f"Error on {url}: {str(e)}")
    
    # If all attempts fail, return a helpful error message
    return {"score": 0, "reason": "⚠️ Noah AI connection failed. Check: 1) API key validity 2) Internet connection 3) Correct API endpoint URL"}

def build_audit_record(manifest: ManifestInput, risk_result: dict) -> dict:
    """
    Build a fully deterministic, JSON-serialisable audit record.
    Keys are sorted alphabetically to guarantee SHA-256 reproducibility.
    """
    record = {
        "audit_id": str(uuid.uuid4()),
        "cargo_items": sorted(manifest.cargo_items),
        "declared_value_usd": manifest.declared_value_usd,
        "destination_country": manifest.destination_country,
        "esg_certifications": sorted(manifest.esg_certifications),
        "flags": sorted(risk_result["flags"]),
        "origin_country": manifest.origin_country,
        "reasoning_log": risk_result["reasoning_log"],
        "risk_score": risk_result["risk_score"],
        "supplier_id": manifest.supplier_id,
        "supplier_name": manifest.supplier_name,
        "timestamp_utc": datetime.datetime.utcnow().isoformat() + "Z",
        "verdict": risk_result["verdict"],
        "verdict_detail": risk_result["verdict_detail"],
        "vessel_id": manifest.vessel_id or "UNKNOWN",
        "weight_kg": manifest.weight_kg,
    }
    return record


def sha256_of_record(record: dict) -> str:
    """
    Deterministic SHA-256 hash. Keys sorted → JSON string → UTF-8 bytes → hex digest.
    """
    canonical_json = json.dumps(record, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()




# ─────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────
@app.get("/")
def root():
    return {"service": "VeriTrade AI Compliance Engine", "status": "operational"}

@app.post("/api/assess")
async def assess_manifest(manifest: ManifestInput):
    """
    Primary endpoint: Submit a shipping manifest for AI risk assessment.
    Returns the full audit record + SHA-256 hash ready for blockchain anchoring.
    """
    # Run the rules-based AI engine
    risk_result = compute_risk(manifest)

    # Call Noah AI for deep ethical reasoning
    noah_data = await get_noah_insights(manifest)

    # Build deterministic audit record
    audit_record = build_audit_record(manifest, risk_result)

    # Generate the cryptographic fingerprint
    audit_hash = sha256_of_record(audit_record)

    return {
        "success": True,
        "audit_record": audit_record,
        "audit_hash": audit_hash,
        "blockchain_ready": True,
        "ai_insight": noah_data.get("reason", "AI analysis unavailable"),
    }


@app.post("/api/verify")
def verify_integrity(payload: VerifyHashInput):
    """
    Verification endpoint: Re-compute the hash of a submitted audit record
    and compare against the original. Used for tamper detection.
    """
    recomputed_hash = sha256_of_record(payload.audit_record)
    tampered = recomputed_hash != payload.original_hash

    return {
        "original_hash": payload.original_hash,
        "recomputed_hash": recomputed_hash,
        "integrity_valid": not tampered,
        "tamper_detected": tampered,
        "message": (
            "CRITICAL: DATA TAMPERING DETECTED. Hash mismatch — blockchain record is authoritative."
            if tampered else
            "VERIFIED: Audit record matches on-chain hash. Integrity confirmed."
        ),
    }


@app.get("/api/risk-matrix")
def get_risk_matrix():
    """Expose the risk matrix for frontend display."""
    return {
        "high_risk_countries": list(HIGH_RISK_COUNTRIES.keys()),
        "conflict_materials": list(CONFLICT_MATERIALS.keys()),
        "esg_certifications": list(ESG_MITIGATORS.keys()),
    }