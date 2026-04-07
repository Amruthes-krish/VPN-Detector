from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel
import httpx
import geoip2.database
import geoip2.errors
import ipaddress
import asyncio
import csv
import io
from pathlib import Path

app = FastAPI(title="VPN Detector API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).parent
MMDB_ASN  = BASE_DIR / "mmdb" / "GeoLite2-ASN.mmdb"
MMDB_CITY = BASE_DIR / "mmdb" / "GeoLite2-City.mmdb"

VPN_KEYWORDS = [
    "vpn", "mullvad", "nordvpn", "expressvpn", "protonvpn", "surfshark",
    "ipvanish", "cyberghost", "pia", "private internet access", "hidemyass",
    "torguard", "windscribe", "tunnelbear", "hotspot shield", "purevpn",
    "avast", "hide.me", "vyprvpn", "strongvpn", "ivacy", "perfect privacy",
    "astrill", "cactusvpn", "fastestvpn", "safervpn", "zenmate",
    "privatevpn", "anonine", "ovpn", "azirevpn", "trust.zone",
    "tor", "torproject", "exit node", "anonymizer", "anonymous",
]

DATACENTER_KEYWORDS = [
    "amazon", "aws", "google", "microsoft", "azure", "digitalocean",
    "linode", "vultr", "hetzner", "ovh", "cloudflare", "leaseweb",
    "hostinger", "contabo", "scaleway", "choopa", "wholesale",
    "datacenter", "data center", "hosting", "colocation", "colo",
    "server", "cloud", "vps", "packethub", "packetexchange",
    "m247", "datacamp", "tzulo", "psychz", "sharktech", "quadranet",
    "spartanhost", "frantech", "buyvm", "ramnode",
    "akamai", "fastly", "cdn", "zscaler", "incapsula",
]


class BulkRequest(BaseModel):
    ips: list[str]


def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def score_vpn(org: str, ip_api_data: dict) -> dict:
    org_lower = org.lower()
    score = 0
    flags = []

    for kw in VPN_KEYWORDS:
        if kw in org_lower:
            score += 60
            flags.append("known_vpn_provider")
            break

    for kw in DATACENTER_KEYWORDS:
        if kw in org_lower:
            score += 30
            flags.append("datacenter")
            break

    if ip_api_data.get("proxy"):
        score += 25
        flags.append("proxy")
    if ip_api_data.get("hosting"):
        score += 20
        flags.append("hosting")
    if ip_api_data.get("vpn"):
        score += 40
        flags.append("vpn_flag")

    score = min(score, 100)

    if score >= 60:
        verdict = "VPN / Proxy"
        level = "high"
    elif score >= 30:
        verdict = "Datacenter / Cloud"
        level = "medium"
    else:
        verdict = "Residential"
        level = "low"

    return {"score": score, "verdict": verdict, "level": level, "flags": list(set(flags))}


async def lookup_single(ip: str) -> dict:
    result = {
        "ip": ip,
        "asn": None, "org": "Unknown", "country": None,
        "country_code": None, "city": None, "latitude": None,
        "longitude": None, "timezone": None, "isp": None,
        "detection": {}, "raw_ip_api": {}, "mmdb_available": False,
    }

    if not is_valid_ip(ip):
        result["error"] = "Invalid IP address"
        return result

    if MMDB_ASN.exists():
        try:
            with geoip2.database.Reader(str(MMDB_ASN)) as reader:
                asn_resp = reader.asn(ip)
                result["asn"] = f"AS{asn_resp.autonomous_system_number}"
                result["org"] = asn_resp.autonomous_system_organization or "Unknown"
                result["mmdb_available"] = True
        except geoip2.errors.AddressNotFoundError:
            pass

    if MMDB_CITY.exists():
        try:
            with geoip2.database.Reader(str(MMDB_CITY)) as reader:
                city_resp = reader.city(ip)
                result["country"] = city_resp.country.name
                result["country_code"] = city_resp.country.iso_code
                result["city"] = city_resp.city.name
                result["latitude"] = city_resp.location.latitude
                result["longitude"] = city_resp.location.longitude
                result["timezone"] = city_resp.location.time_zone
        except geoip2.errors.AddressNotFoundError:
            pass

    ip_api_data = {}
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": "status,message,country,countryCode,city,isp,org,as,proxy,hosting,vpn,timezone,lat,lon"},
            )
            if resp.status_code == 200:
                ip_api_data = resp.json()
                if ip_api_data.get("status") == "success":
                    result["raw_ip_api"] = ip_api_data
                    if not result["country"]:    result["country"] = ip_api_data.get("country")
                    if not result["country_code"]: result["country_code"] = ip_api_data.get("countryCode")
                    if not result["city"]:       result["city"] = ip_api_data.get("city")
                    if not result["timezone"]:   result["timezone"] = ip_api_data.get("timezone")
                    if not result["latitude"]:   result["latitude"] = ip_api_data.get("lat")
                    if not result["longitude"]:  result["longitude"] = ip_api_data.get("lon")
                    if not result["asn"]:        result["asn"] = ip_api_data.get("as", "").split(" ")[0]
                    result["isp"] = ip_api_data.get("isp")
                    if result["org"] == "Unknown":
                        result["org"] = ip_api_data.get("org") or ip_api_data.get("isp") or "Unknown"
    except Exception:
        pass

    result["detection"] = score_vpn(result["org"], ip_api_data)
    return result


# ── Single lookup ─────────────────────────────────────────────────────────────
@app.get("/api/lookup/{ip}")
async def lookup_ip(ip: str):
    if not is_valid_ip(ip):
        raise HTTPException(status_code=400, detail="Invalid IP address")
    return await lookup_single(ip)


# ── Bulk lookup ───────────────────────────────────────────────────────────────
@app.post("/api/bulk")
async def bulk_lookup(req: BulkRequest):
    if len(req.ips) > 100:
        raise HTTPException(status_code=400, detail="Maximum 100 IPs per request")
    ips = [ip.strip() for ip in req.ips if ip.strip()]

    # ip-api rate limit: 45/min on free — batch with small delay
    results = []
    for i, ip in enumerate(ips):
        result = await lookup_single(ip)
        results.append(result)
        if (i + 1) % 40 == 0:
            await asyncio.sleep(1.5)

    return {"results": results, "total": len(results)}


# ── CSV export ────────────────────────────────────────────────────────────────
@app.post("/api/export/csv")
async def export_csv(req: BulkRequest):
    ips = [ip.strip() for ip in req.ips if ip.strip()]
    results = []
    for i, ip in enumerate(ips):
        result = await lookup_single(ip)
        results.append(result)
        if (i + 1) % 40 == 0:
            await asyncio.sleep(1.5)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "IP", "Verdict", "Risk Score", "Level",
        "ASN", "Provider/Org", "ISP",
        "Country", "City", "Timezone",
        "Latitude", "Longitude", "Flags",
        "MMDB Available"
    ])
    for r in results:
        det = r.get("detection", {})
        writer.writerow([
            r.get("ip", ""),
            det.get("verdict", ""),
            det.get("score", ""),
            det.get("level", ""),
            r.get("asn", ""),
            r.get("org", ""),
            r.get("isp", ""),
            r.get("country", ""),
            r.get("city", ""),
            r.get("timezone", ""),
            r.get("latitude", ""),
            r.get("longitude", ""),
            ", ".join(det.get("flags", [])),
            r.get("mmdb_available", False),
        ])

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=vpn_lookup_results.csv"}
    )


# ── Serve frontend ────────────────────────────────────────────────────────────
FRONTEND_DIR = BASE_DIR / "frontend"
if FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
