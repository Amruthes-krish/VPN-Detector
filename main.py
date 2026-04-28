from fastapi import FastAPI, HTTPException
from fastapi.responses import StreamingResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import httpx
import geoip2.database
import geoip2.errors
import ipaddress
import asyncio
import csv
import io
import re
import os
import json
from pathlib import Path
import anthropic
import socket
import ssl
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict

# Open ports detection module
from open_ports_module import (
    OpenPortsData, OpenService, get_open_ports, 
    calculate_port_risk_score, get_port_risk_description,
    get_port_recommendations, DANGEROUS_PORTS
)


app = FastAPI(title="Advanced IP Intelligence & Threat Analysis")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

BASE_DIR = Path(__file__).parent
MMDB_ASN = BASE_DIR / "mmdb" / "GeoLite2-ASN.mmdb"
MMDB_CITY = BASE_DIR / "mmdb" / "GeoLite2-City.mmdb"

PROXYCHECK_KEY = os.environ.get("PROXYCHECK_KEY", "")
ANTHROPIC_KEY = os.environ.get("ANTHROPIC_API_KEY", "")

# ════════════════════════════════════════════════════════════════════════════════
# FEATURE 1: NETWORK & OWNERSHIP DETAILS
# ════════════════════════════════════════════════════════════════════════════════

class NetworkOwnershipData(BaseModel):
    """ISP, ASN, geolocation (country, region, city)"""
    isp_name: Optional[str] = None
    asn: Optional[str] = None
    asn_org: Optional[str] = None
    country: Optional[str] = None
    country_code: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    timezone: Optional[str] = None
    accuracy_radius: Optional[int] = None  # in km, from MMDB
    reliability_score: float = 0.0  # 0-1, confidence in geolocation

# ════════════════════════════════════════════════════════════════════════════════
# FEATURE 2: REPUTATION & ABUSE HISTORY
# ════════════════════════════════════════════════════════════════════════════════

class AbuseReport(BaseModel):
    """Individual abuse/threat report"""
    source: str  # e.g., "AbuseIPDB", "Proxycheck", "GetIPIntel"
    type: str  # e.g., "spam", "scanning", "brute_force", "malware", "c2c"
    confidence: float  # 0-1
    last_reported: Optional[str] = None
    report_count: Optional[int] = None
    description: Optional[str] = None

class ReputationData(BaseModel):
    """Blocklist presence, threat intelligence, abuse history"""
    is_blacklisted: bool = False
    blocklist_sources: List[str] = []  # DNSBL, spamhaus, etc.
    abuse_reports: List[AbuseReport] = []
    threat_intel_matches: List[str] = []  # APT groups, campaigns, malware families
    spam_score: float = 0.0  # 0-100
    fraud_score: float = 0.0  # 0-100
    overall_reputation: str = "unknown"  # excellent/good/neutral/poor/dangerous

# ════════════════════════════════════════════════════════════════════════════════
# FEATURE 3: ASSOCIATED INFRASTRUCTURE
# ════════════════════════════════════════════════════════════════════════════════

class SSLCertificateData(BaseModel):
    """SSL/TLS certificate information"""
    issuer: Optional[str] = None
    subject: Optional[str] = None
    valid_from: Optional[str] = None
    valid_until: Optional[str] = None
    san: List[str] = []  # Subject Alternative Names
    is_self_signed: bool = False
    common_name: Optional[str] = None

class InfrastructureData(BaseModel):
    """Known domains, reverse DNS, certificate data"""
    reverse_dns: List[str] = []
    associated_domains: List[str] = []
    known_subdomains: List[str] = []
    ssl_certificate: Optional[SSLCertificateData] = None
    hostname_patterns: List[str] = []  # e.g., patterns in reverse DNS
    infrastructure_notes: Optional[str] = None

# ════════════════════════════════════════════════════════════════════════════════
# FEATURE 4: PASSIVE EXPOSURE (SHODAN/CENSYS)
# ════════════════════════════════════════════════════════════════════════════════

class OpenService(BaseModel):
    """Open port/service from passive scanning"""
    port: int
    protocol: str  # tcp, udp
    service_name: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    last_seen: Optional[str] = None  # ISO date

class PassiveExposureData(BaseModel):
    """From Shodan, Censys, BinaryEdge, etc."""
    last_scanned: Optional[str] = None
    open_ports: List[OpenService] = []
    service_count: int = 0
    vulnerability_count: int = 0
    data_sources: List[str] = []  # shodan, censys, binary_edge, greynoise
    exposure_level: str = "unknown"  # low/medium/high
    honeypot_probability: float = 0.0  # 0-1

# ════════════════════════════════════════════════════════════════════════════════
# FEATURE 5: ANONYMIZATION & HOSTING INDICATORS
# ════════════════════════════════════════════════════════════════════════════════

class AnonymizationIndicators(BaseModel):
    """VPN, Proxy, TOR, Hosting detection with confidence"""
    is_vpn: bool = False
    vpn_confidence: float = 0.0  # 0-1
    vpn_provider: Optional[str] = None
    
    is_proxy: bool = False
    proxy_confidence: float = 0.0
    proxy_type: Optional[str] = None  # http, socks, datacenter, etc.
    
    is_tor: bool = False
    tor_confidence: float = 0.0
    tor_exit_node: Optional[str] = None
    
    is_hosting_provider: bool = False
    hosting_confidence: float = 0.0
    hosting_provider: Optional[str] = None
    hosting_tier: Optional[str] = None  # cloud, shared, dedicated
    
    is_datacenter: bool = False
    datacenter_name: Optional[str] = None
    
    anonymization_score: float = 0.0  # 0-100, overall anonymity level
    supporting_evidence: List[str] = []

# ════════════════════════════════════════════════════════════════════════════════
# FEATURE 6: RISK CLASSIFICATION
# ════════════════════════════════════════════════════════════════════════════════

class RiskClassification(BaseModel):
    """Risk level with detailed justification"""
    level: str  # critical/high/medium/low/unknown
    score: float  # 0-100
    primary_risk_factors: List[str] = []
    corroborated_signals: List[str] = []
    justification: str = ""
    business_impact: str = ""
    confidence: float = 0.0  # 0-1, based on evidence quality
    last_updated: str = ""

# ════════════════════════════════════════════════════════════════════════════════
# FEATURE 7: KEY PIVOTS & INVESTIGATION LEADS
# ════════════════════════════════════════════════════════════════════════════════

class InvestigationLead(BaseModel):
    """Related IP, domain, ASN pivot"""
    type: str  # "related_ip", "shared_asn", "shared_domain", "shared_cert", "apt_group"
    value: str
    confidence: float = 0.0
    description: str = ""
    investigation_priority: str = "low"  # low/medium/high/critical

class AdvancedIntelligence(BaseModel):
    """7-feature comprehensive IP intelligence"""
    ip: str
    
    # Feature 1: Network & Ownership
    network_ownership: NetworkOwnershipData
    
    # Feature 2: Reputation & Abuse
    reputation: ReputationData
    
    # Feature 3: Associated Infrastructure
    infrastructure: InfrastructureData
    
    # Feature 4: Passive Exposure
    passive_exposure: PassiveExposureData
    
    # Feature 5: Anonymization Indicators
    anonymization: AnonymizationIndicators
    
    # Feature 6: Risk Classification
    risk: RiskClassification
    
    # Feature 7: Investigation Leads
    investigation_leads: List[InvestigationLead] = []
    
    # Metadata
    analysis_timestamp: str = ""
    data_completeness: float = 0.0  # 0-1, % of available data sources

# ════════════════════════════════════════════════════════════════════════════════
# DATA ENRICHMENT FUNCTIONS
# ════════════════════════════════════════════════════════════════════════════════

def extract_network_ownership(ip: str, mmdb_asn_path: Path, mmdb_city_path: Path, ip_api_data: dict) -> NetworkOwnershipData:
    """Extract Feature 1: Network ownership from MMDB + APIs"""
    data = NetworkOwnershipData()
    
    # Try MMDB first (most reliable)
    if mmdb_asn_path.exists():
        try:
            with geoip2.database.Reader(str(mmdb_asn_path)) as reader:
                asn_response = reader.asn(ip)
                data.asn = str(asn_response.autonomous_system_number)
                data.asn_org = asn_response.autonomous_system_organization
        except: pass
    
    if mmdb_city_path.exists():
        try:
            with geoip2.database.Reader(str(mmdb_city_path)) as reader:
                city_response = reader.city(ip)
                data.country = city_response.country.name
                data.country_code = city_response.country.iso_code
                data.city = city_response.city.name
                data.latitude = city_response.location.latitude
                data.longitude = city_response.location.longitude
                data.timezone = city_response.location.time_zone
                data.accuracy_radius = city_response.location.accuracy_radius
                data.reliability_score = 0.95  # MMDB is very reliable
        except: pass
    
    # Fallback to ip-api
    if ip_api_data:
        if not data.isp_name:
            data.isp_name = ip_api_data.get("isp")
        if not data.asn:
            asn_str = ip_api_data.get("as", "")
            if asn_str:
                data.asn = asn_str.split()[0]
        if not data.country:
            data.country = ip_api_data.get("country")
        if not data.country_code:
            data.country_code = ip_api_data.get("countryCode")
        if not data.city:
            data.city = ip_api_data.get("city")
        if not data.latitude:
            data.latitude = ip_api_data.get("lat")
        if not data.longitude:
            data.longitude = ip_api_data.get("lon")
        if not data.timezone:
            data.timezone = ip_api_data.get("timezone")
        data.reliability_score = min(data.reliability_score, 0.75)
    
    return data

def extract_reputation(proxycheck_data: dict, abuseipdb_data: dict, getipintel_data: dict) -> ReputationData:
    """Extract Feature 2: Reputation & abuse history"""
    data = ReputationData()
    abuse_reports = []
    
    # From ProxyCheck
    if isinstance(proxycheck_data, dict):
        if proxycheck_data.get("proxy") == "yes":
            data.is_blacklisted = True
            data.blocklist_sources.append("ProxyCheck")
        if proxycheck_data.get("threat"):
            threat_val = proxycheck_data.get("threat", "")
            abuse_reports.append(AbuseReport(
                source="ProxyCheck",
                type=threat_val if threat_val in ["spam", "scanning", "brute_force"] else "malicious",
                confidence=float(proxycheck_data.get("threatscore", 0)) / 100.0
            ))
    
    # From GetIPIntel
    if isinstance(getipintel_data, dict):
        fraud_score = float(getipintel_data.get("result", 0))
        if fraud_score > 0:
            data.fraud_score = fraud_score * 100
            if fraud_score > 0.7:
                data.is_blacklisted = True
                data.blocklist_sources.append("GetIPIntel")
    
    data.abuse_reports = abuse_reports
    
    # Determine overall reputation
    if data.fraud_score > 80 or any(r.confidence > 0.7 for r in abuse_reports):
        data.overall_reputation = "dangerous"
    elif data.fraud_score > 50 or any(r.confidence > 0.5 for r in abuse_reports):
        data.overall_reputation = "poor"
    elif data.is_blacklisted:
        data.overall_reputation = "poor"
    else:
        data.overall_reputation = "neutral"
    
    return data

def extract_infrastructure(ip: str) -> InfrastructureData:
    """Extract Feature 3: Associated infrastructure (domains, certs, reverse DNS)"""
    data = InfrastructureData()
    
    # Attempt reverse DNS
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        data.reverse_dns.append(hostname)
        
        # Extract domain from hostname
        if hostname:
            parts = hostname.split('.')
            if len(parts) >= 2:
                domain = '.'.join(parts[-2:])
                if domain not in data.associated_domains:
                    data.associated_domains.append(domain)
    except (socket.herror, socket.error):
        pass
    
    return data

def extract_passive_exposure(ip: str) -> PassiveExposureData:
    """Extract Feature 4: Passive exposure from Shodan/Censys (mocked)"""
    # In production, integrate Shodan API, Censys API, BinaryEdge, etc.
    data = PassiveExposureData()
    data.last_scanned = datetime.utcnow().isoformat()
    
    # Placeholder - integrate real APIs
    # Common ports often found open
    common_ports = [22, 80, 443, 3306, 5432, 6379]
    for port in common_ports[:2]:  # Mock: show 2 ports
        data.open_ports.append(OpenService(
            port=port,
            protocol="tcp",
            service_name={22: "ssh", 80: "http", 443: "https", 3306: "mysql", 5432: "postgresql", 6379: "redis"}.get(port),
            last_seen=datetime.utcnow().isoformat()
        ))
    
    data.service_count = len(data.open_ports)
    data.exposure_level = "low" if data.service_count < 5 else "medium" if data.service_count < 10 else "high"
    data.data_sources = ["mock"]  # Replace with real sources
    
    return data

def extract_anonymization(
    ip: str,
    ip_api_data: dict,
    proxycheck_data: dict,
    org: str
) -> AnonymizationIndicators:
    """Extract Feature 5: Anonymization & hosting detection"""
    data = AnonymizationIndicators()
    
    # VPN detection
    vpn_keywords = ["vpn", "mullvad", "nordvpn", "expressvpn", "protonvpn", "surfshark"]
    if any(kw in org.lower() for kw in vpn_keywords):
        data.is_vpn = True
        data.vpn_confidence = 0.85
        data.vpn_provider = org
    
    # Proxy detection
    if isinstance(proxycheck_data, dict):
        if proxycheck_data.get("proxy") == "yes":
            data.is_proxy = True
            data.proxy_confidence = 0.9
            data.proxy_type = proxycheck_data.get("type", "unknown")
    
    # Hosting detection
    hosting_keywords = ["amazon", "aws", "google", "microsoft", "azure", "digitalocean", "linode", "vultr"]
    if any(kw in org.lower() for kw in hosting_keywords):
        data.is_hosting_provider = True
        data.hosting_confidence = 0.9
        data.hosting_provider = org
        data.hosting_tier = "cloud"
    
    # Calculate overall anonymization score
    data.anonymization_score = (
        (data.vpn_confidence * 40) +
        (data.proxy_confidence * 30) +
        (data.hosting_confidence * 30)
    )
    
    data.supporting_evidence = []
    if data.is_vpn:
        data.supporting_evidence.append(f"VPN provider: {data.vpn_provider}")
    if data.is_proxy:
        data.supporting_evidence.append(f"Proxy detected: {data.proxy_type}")
    if data.is_hosting_provider:
        data.supporting_evidence.append(f"Hosting: {data.hosting_provider}")
    
    return data

def classify_risk(
    network_data: NetworkOwnershipData,
    reputation_data: ReputationData,
    anonymization_data: AnonymizationIndicators,
    infrastructure_data: InfrastructureData
) -> RiskClassification:
    """Extract Feature 6: Risk classification with detailed justification"""
    data = RiskClassification()
    data.last_updated = datetime.utcnow().isoformat()
    
    score = 0.0
    signals = []
    risk_factors = []
    
    # Reputation signals
    if reputation_data.overall_reputation == "dangerous":
        score += 40
        risk_factors.append("Dangerous reputation")
        signals.append(f"Fraud score: {reputation_data.fraud_score}")
    elif reputation_data.overall_reputation == "poor":
        score += 25
        risk_factors.append("Poor reputation")
        signals.append(f"Fraud score: {reputation_data.fraud_score}")
    
    if reputation_data.is_blacklisted:
        score += 20
        risk_factors.append("On blocklists")
        signals.append(f"Sources: {', '.join(reputation_data.blocklist_sources)}")
    
    # Anonymization signals
    if anonymization_data.is_vpn:
        score += 15
        risk_factors.append("VPN detected")
        signals.append(f"Provider: {anonymization_data.vpn_provider}")
    
    if anonymization_data.is_hosting_provider:
        score += 10
        risk_factors.append("Cloud/Hosting provider")
        signals.append(f"Provider: {anonymization_data.hosting_provider}")
    
    if anonymization_data.is_proxy:
        score += 20
        risk_factors.append("Proxy detected")
        signals.append(f"Type: {anonymization_data.proxy_type}")
    
    # Infrastructure signals
    if not network_data.asn or not network_data.isp_name:
        score += 5
        risk_factors.append("Limited network data")
    
    # Determine risk level
    data.score = min(score, 100.0)
    
    if data.score >= 80:
        data.level = "critical"
        data.confidence = 0.95
        data.business_impact = "Block immediately - severe threat indicators"
    elif data.score >= 60:
        data.level = "high"
        data.confidence = 0.85
        data.business_impact = "High priority review - multiple risk signals"
    elif data.score >= 40:
        data.level = "medium"
        data.confidence = 0.75
        data.business_impact = "Monitor closely - moderate risk indicators"
    elif data.score >= 20:
        data.level = "low"
        data.confidence = 0.65
        data.business_impact = "Low threat - likely legitimate but monitor"
    else:
        data.level = "unknown"
        data.confidence = 0.5
        data.business_impact = "Insufficient data for assessment"
    
    data.primary_risk_factors = risk_factors
    data.corroborated_signals = signals
    data.justification = f"Score: {data.score}/100. Level: {data.level}. " + \
                        f"Risk factors: {', '.join(risk_factors) if risk_factors else 'None'}. " + \
                        f"Confidence: {data.confidence*100:.0f}%"
    
    return data

def generate_investigation_leads(
    ip: str,
    network_data: NetworkOwnershipData,
    infrastructure_data: InfrastructureData,
    asn: Optional[str] = None
) -> List[InvestigationLead]:
    """Extract Feature 7: Investigation leads & pivots"""
    leads = []
    
    # ASN pivot
    if network_data.asn:
        leads.append(InvestigationLead(
            type="shared_asn",
            value=network_data.asn,
            confidence=0.9,
            description=f"All IPs in ASN {network_data.asn} ({network_data.asn_org})",
            investigation_priority="high"
        ))
    
    # Domain pivots
    for domain in infrastructure_data.associated_domains:
        leads.append(InvestigationLead(
            type="shared_domain",
            value=domain,
            confidence=0.8,
            description=f"Domain: {domain}",
            investigation_priority="medium"
        ))
    
    # Country pivot (if high-risk)
    if network_data.country_code:
        leads.append(InvestigationLead(
            type="shared_country",
            value=network_data.country_code,
            confidence=0.6,
            description=f"All IPs from {network_data.country}",
            investigation_priority="low"
        ))
    
    return leads

async def fetch_advanced_ip_intelligence(ip: str) -> AdvancedIntelligence:
    """Main function: Fetch all 7 features of IP intelligence"""
    
    # Validate IP
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid IP: {ip}")
    
    # Fetch IP data in parallel
    async with httpx.AsyncClient(timeout=10.0) as client:
        ip_api_resp, pc_resp = await asyncio.gather(
            client.get(f"http://ip-api.com/json/{ip}", params={
                "fields": "status,message,country,countryCode,city,isp,org,as,proxy,hosting,vpn,timezone,lat,lon"
            }),
            client.get(f"https://proxycheck.abuseipdb.com/v2/check", params={
                "ip": ip,
                "key": PROXYCHECK_KEY,
                "format": "json"
            }) if PROXYCHECK_KEY else asyncio.sleep(0),
            return_exceptions=True
        )
    
    ip_api_data = ip_api_resp.json() if not isinstance(ip_api_resp, Exception) else {}
    pc_data = pc_resp.json() if not isinstance(pc_resp, Exception) and hasattr(pc_resp, 'json') else {}
    
    # Extract all 7 features
    network_ownership = extract_network_ownership(ip, MMDB_ASN, MMDB_CITY, ip_api_data)
    reputation = extract_reputation(pc_data, {}, {})
    infrastructure = extract_infrastructure(ip)
    passive_exposure = extract_passive_exposure(ip)
    anonymization = extract_anonymization(ip, ip_api_data, pc_data, ip_api_data.get("org", ""))
    risk = classify_risk(network_ownership, reputation, anonymization, infrastructure)
    investigation_leads = generate_investigation_leads(ip, network_ownership, infrastructure, network_ownership.asn)
    
    # Calculate data completeness
    data_completeness = 0.0
    completeness_sources = [
        bool(network_ownership.country),
        bool(network_ownership.asn),
        bool(reputation.overall_reputation != "unknown"),
        bool(infrastructure.reverse_dns),
        bool(anonymization.anonymization_score > 0),
        bool(passive_exposure.open_ports),
        bool(investigation_leads)
    ]
    data_completeness = sum(completeness_sources) / len(completeness_sources)
    
    result = AdvancedIntelligence(
        ip=ip,
        network_ownership=network_ownership,
        reputation=reputation,
        infrastructure=infrastructure,
        passive_exposure=passive_exposure,
        anonymization=anonymization,
        risk=risk,
        investigation_leads=investigation_leads,
        analysis_timestamp=datetime.utcnow().isoformat(),
        data_completeness=data_completeness
    )
    
    return result

# ════════════════════════════════════════════════════════════════════════════════
# API ENDPOINTS
# ════════════════════════════════════════════════════════════════════════════════

class AdvancedAnalysisRequest(BaseModel):
    ip: str

@app.post("/api/advanced/intelligence")
async def advanced_intelligence(req: AdvancedAnalysisRequest) -> Dict[str, Any]:
    """Endpoint 1: Full 7-feature IP intelligence analysis"""
    try:
        result = await fetch_advanced_ip_intelligence(req.ip)
        return result.dict()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/advanced/reputation-report")
async def reputation_report(req: AdvancedAnalysisRequest) -> Dict[str, Any]:
    """Endpoint 2: Detailed reputation & abuse history"""
    try:
        result = await fetch_advanced_ip_intelligence(req.ip)
        return {
            "ip": result.ip,
            "reputation": result.reputation.dict(),
            "risk_level": result.risk.level,
            "risk_score": result.risk.score
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/advanced/infrastructure-map")
async def infrastructure_map(req: AdvancedAnalysisRequest) -> Dict[str, Any]:
    """Endpoint 3: Associated infrastructure (domains, certs, reverse DNS)"""
    try:
        result = await fetch_advanced_ip_intelligence(req.ip)
        return {
            "ip": result.ip,
            "infrastructure": result.infrastructure.dict(),
            "network_ownership": {
                "asn": result.network_ownership.asn,
                "asn_org": result.network_ownership.asn_org,
                "isp": result.network_ownership.isp_name
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/advanced/exposure-analysis")
async def exposure_analysis(req: AdvancedAnalysisRequest) -> Dict[str, Any]:
    """Endpoint 4: Passive exposure (open ports, services)"""
    try:
        result = await fetch_advanced_ip_intelligence(req.ip)
        return {
            "ip": result.ip,
            "passive_exposure": result.passive_exposure.dict(),
            "anonymization": {
                "is_hosting_provider": result.anonymization.is_hosting_provider,
                "hosting_provider": result.anonymization.hosting_provider,
                "anonymization_score": result.anonymization.anonymization_score
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/advanced/anonymization-check")
async def anonymization_check(req: AdvancedAnalysisRequest) -> Dict[str, Any]:
    """Endpoint 5: VPN/Proxy/TOR detection"""
    try:
        result = await fetch_advanced_ip_intelligence(req.ip)
        return {
            "ip": result.ip,
            "anonymization": result.anonymization.dict(),
            "network_ownership": {
                "country": result.network_ownership.country,
                "isp": result.network_ownership.isp_name
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/advanced/risk-assessment")
async def risk_assessment(req: AdvancedAnalysisRequest) -> Dict[str, Any]:
    """Endpoint 6: Risk classification with detailed justification"""
    try:
        result = await fetch_advanced_ip_intelligence(req.ip)
        return {
            "ip": result.ip,
            "risk": result.risk.dict(),
            "summary": {
                "level": result.risk.level,
                "score": result.risk.score,
                "business_impact": result.risk.business_impact,
                "confidence": result.risk.confidence
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/advanced/investigation-leads")
async def investigation_leads_endpoint(req: AdvancedAnalysisRequest) -> Dict[str, Any]:
    """Endpoint 7: Investigation pivots (related IPs, ASNs, domains)"""
    try:
        result = await fetch_advanced_ip_intelligence(req.ip)
        return {
            "ip": result.ip,
            "investigation_leads": [lead.dict() for lead in result.investigation_leads],
            "priorities": {
                "critical": [l for l in result.investigation_leads if l.investigation_priority == "critical"],
                "high": [l for l in result.investigation_leads if l.investigation_priority == "high"],
                "medium": [l for l in result.investigation_leads if l.investigation_priority == "medium"]
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

class BulkLookupRequest(BaseModel):
    ips: List[str]

@app.post("/api/advanced/bulk")
async def bulk_lookup(req: BulkLookupRequest) -> List[Dict[str, Any]]:
    """Bulk IP lookup: returns key fields including ASN for each IP"""
    if len(req.ips) > 100:
        raise HTTPException(status_code=400, detail="Maximum 100 IPs per request")

    results = []
    async def lookup_one(ip: str) -> Dict[str, Any]:
        ip = ip.strip()
        try:
            data = await fetch_advanced_ip_intelligence(ip)
            return {
                "ip": data.ip,
                "asn": data.network_ownership.asn or "N/A",
                "asn_org": data.network_ownership.asn_org or "N/A",
                "isp": data.network_ownership.isp_name or "N/A",
                "country": data.network_ownership.country or "N/A",
                "country_code": data.network_ownership.country_code or "N/A",
                "city": data.network_ownership.city or "N/A",
                "risk_level": data.risk.level,
                "risk_score": round(data.risk.score, 1),
                "is_vpn": data.anonymization.is_vpn,
                "is_proxy": data.anonymization.is_proxy,
                "is_tor": data.anonymization.is_tor,
                "reputation": data.reputation.overall_reputation,
                "error": None,
            }
        except Exception as e:
            return {
                "ip": ip,
                "asn": "N/A",
                "asn_org": "N/A",
                "isp": "N/A",
                "country": "N/A",
                "country_code": "N/A",
                "city": "N/A",
                "risk_level": "unknown",
                "risk_score": 0,
                "is_vpn": False,
                "is_proxy": False,
                "is_tor": False,
                "reputation": "unknown",
                "error": str(e),
            }

    tasks = [lookup_one(ip) for ip in req.ips if ip.strip()]
    results = await asyncio.gather(*tasks)
    return list(results)

# ════════════════════════════════════════════════════════════════════════════════
# OPEN PORTS DETECTION ENDPOINTS
# ════════════════════════════════════════════════════════════════════════════════

@app.post("/api/advanced/open-ports")
async def open_ports_endpoint(req: AdvancedAnalysisRequest) -> dict:
    """Scan and analyze open ports for an IP address"""
    try:
        ports_data = await get_open_ports(req.ip, use_shodan=True, use_censys=True)
        port_risk_score = calculate_port_risk_score(ports_data)
        risk_description = get_port_risk_description(ports_data)
        recommendations = get_port_recommendations(ports_data)
        
        return {
            "ip": req.ip,
            "open_ports": ports_data.dict(),
            "risk_score": port_risk_score,
            "risk_description": risk_description,
            "recommendations": recommendations,
            "dangerous_ports": ports_data.most_dangerous_ports,
            "service_summary": ports_data.service_summary,
            "total_ports": ports_data.total_open_ports,
            "exposure_level": ports_data.exposure_level,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/advanced/port-details")
async def port_details_endpoint(req: AdvancedAnalysisRequest) -> dict:
    """Get detailed information about specific ports"""
    try:
        ports_data = await get_open_ports(req.ip, use_shodan=True, use_censys=True)
        detailed_ports = []
        
        for port_obj in ports_data.open_ports:
            port_info = {
                "port": port_obj.port,
                "service": port_obj.service_name,
                "product": port_obj.product,
                "version": port_obj.version,
                "state": port_obj.state,
                "source": port_obj.source,
                "confidence": port_obj.confidence,
                "last_seen": port_obj.last_seen,
                "is_dangerous": port_obj.port in DANGEROUS_PORTS,
            }
            
            if port_obj.port in DANGEROUS_PORTS:
                danger_info = DANGEROUS_PORTS[port_obj.port]
                port_info["danger_level"] = "CRITICAL"
                port_info["danger_reason"] = danger_info["risk"]
            
            detailed_ports.append(port_info)
        
        return {
            "ip": req.ip,
            "ports": detailed_ports,
            "total": len(detailed_ports),
            "exposure_level": ports_data.exposure_level,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/advanced/port-recommendations")
async def port_recommendations_endpoint(req: AdvancedAnalysisRequest) -> dict:
    """Get security recommendations based on open ports"""
    try:
        ports_data = await get_open_ports(req.ip, use_shodan=True, use_censys=True)
        recommendations = get_port_recommendations(ports_data)
        
        return {
            "ip": req.ip,
            "open_port_count": ports_data.total_open_ports,
            "dangerous_port_count": len(ports_data.most_dangerous_ports),
            "recommendations": recommendations,
            "risk_level": ports_data.exposure_level,
            "action_required": bool(ports_data.most_dangerous_ports),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Health check
@app.get("/health")
async def health():
    return {"status": "ok", "service": "Advanced IP Intelligence"}

# Mount static files if frontend exists
FRONTEND_DIR = BASE_DIR / "frontend"
if FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
