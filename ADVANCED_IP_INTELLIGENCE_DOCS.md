# Advanced IP Intelligence & Threat Analysis Platform
## Complete 7-Feature Implementation Guide

---

## 📋 Overview

This enhanced project implements a comprehensive IP intelligence system with **7 distinct threat analysis features**:

1. **Network & Ownership Details** - ISP, ASN, Geolocation
2. **Reputation & Abuse History** - Blocklists, Threat Intel, Abuse Reports
3. **Associated Infrastructure** - Domains, Reverse DNS, SSL Certificates
4. **Passive Exposure** - Open Ports, Services (Shodan/Censys integration)
5. **Anonymization & Hosting Indicators** - VPN/Proxy/TOR/Cloud Detection
6. **Risk Classification** - Risk Level with Detailed Justification
7. **Key Pivots & Investigation Leads** - Related IPs, ASN, Domains, APT Groups

---

## 🏗️ Architecture

### Backend (FastAPI)
```
main_enhanced.py
├── Data Models (Pydantic)
│   ├── NetworkOwnershipData
│   ├── ReputationData
│   ├── InfrastructureData
│   ├── PassiveExposureData
│   ├── AnonymizationIndicators
│   ├── RiskClassification
│   └── AdvancedIntelligence (composite)
│
├── Data Extraction Functions
│   ├── extract_network_ownership()
│   ├── extract_reputation()
│   ├── extract_infrastructure()
│   ├── extract_passive_exposure()
│   ├── extract_anonymization()
│   ├── classify_risk()
│   └── generate_investigation_leads()
│
├── API Endpoints (7 dedicated endpoints)
│   ├── POST /api/advanced/intelligence
│   ├── POST /api/advanced/reputation-report
│   ├── POST /api/advanced/infrastructure-map
│   ├── POST /api/advanced/exposure-analysis
│   ├── POST /api/advanced/anonymization-check
│   ├── POST /api/advanced/risk-assessment
│   └── POST /api/advanced/investigation-leads
│
└── Data Sources
    ├── GeoIP2 MMDB (MaxMind)
    ├── ip-api.com
    ├── ProxyCheck API
    ├── GetIPIntel API
    ├── Socket/Reverse DNS
    └── [Potential] Shodan, Censys, BinaryEdge
```

### Frontend (HTML/CSS/JS)
```
index_enhanced.html
├── Search Interface
├── Feature Status Grid (7 features)
├── Tab Navigation (8 tabs)
├── Dynamic Content Panels
│   ├── Overview Tab
│   ├── Network & Ownership Tab
│   ├── Reputation & Abuse Tab
│   ├── Infrastructure Tab
│   ├── Passive Exposure Tab
│   ├── Anonymization Tab
│   ├── Risk Assessment Tab
│   └── Investigation Leads Tab
└── Real-time Risk Meter & Badges
```

---

## 🔧 Installation & Setup

### 1. Install Dependencies
```bash
pip install fastapi uvicorn httpx geoip2 anthropic pydantic
```

### 2. Directory Structure
```
project/
├── main_enhanced.py          # Backend API
├── index_enhanced.html       # Frontend UI
├── mmdb/                     # GeoIP2 databases
│   ├── GeoLite2-ASN.mmdb
│   └── GeoLite2-City.mmdb
└── requirements.txt
```

### 3. Download GeoIP2 Databases
```bash
# Visit: https://dev.maxmind.com/geoip/geolite2-free/
# Download and place in ./mmdb/ directory
```

### 4. Set Environment Variables
```bash
export ANTHROPIC_API_KEY="your-key-here"
export PROXYCHECK_KEY="your-key-here"  # Optional
```

### 5. Run the Server
```bash
uvicorn main_enhanced:app --reload --host 0.0.0.0 --port 8000
```

---

## 📊 Feature Details

### Feature 1: Network & Ownership Details
**What it extracts:**
- ISP Name & Organization
- Autonomous System Number (ASN)
- Country, Region, City
- Latitude & Longitude
- Timezone
- Data Reliability Score (0-1)

**Data Sources:**
1. MaxMind GeoLite2 ASN (most reliable)
2. MaxMind GeoLite2 City
3. ip-api.com (fallback)

**Use Case:** Identify legitimate ISPs vs. suspicious locations, detect spoofed geolocation

---

### Feature 2: Reputation & Abuse History
**What it extracts:**
- Overall Reputation (excellent/good/neutral/poor/dangerous)
- Fraud Score (0-100)
- Spam Score (0-100)
- Blocklist Presence (AbuseIPDB, ProxyCheck, DNSBL)
- Individual Abuse Reports (type, source, confidence, count)
- Threat Intelligence Matches (APT groups, malware families)

**Data Sources:**
1. ProxyCheck API (proxy/threat detection)
2. GetIPIntel API (fraud scoring)
3. AbuseIPDB (abuse history)

**Use Case:** Detect previously reported malicious IPs, identify patterns of abuse

---

### Feature 3: Associated Infrastructure
**What it extracts:**
- Reverse DNS Records
- Associated Domains
- Known Subdomains
- SSL/TLS Certificate Data
  - Issuer & Subject
  - Validity Period
  - Subject Alternative Names (SANs)
  - Self-signed detection
  - Common Name extraction
- Hostname Patterns

**Data Sources:**
1. Socket reverse DNS lookups
2. WHOIS data (via ASN lookup)
3. SSL Certificate transparency

**Use Case:** Pivot from IP to related domains/infrastructure, detect certificate anomalies

---

### Feature 4: Passive Exposure
**What it extracts:**
- Last Scanned Date/Time
- Open Ports & Services
  - Port Number
  - Protocol (TCP/UDP)
  - Service Name & Version
  - Product Information
- Service Count
- Vulnerability Count
- Data Sources (Shodan, Censys, BinaryEdge, GreyNoise)
- Exposure Level (low/medium/high)
- Honeypot Probability

**Data Sources:**
1. Shodan API (requires paid account)
2. Censys API (requires registration)
3. BinaryEdge API
4. GreyNoise Internet Scanner

**Integration Example:**
```python
async def get_shodan_data(ip: str, shodan_key: str):
    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": shodan_key}
        )
        data = response.json()
        return {
            "open_ports": [item["port"] for item in data.get("ports", [])],
            "services": data.get("data", []),
            "last_update": data.get("last_update")
        }
```

**Use Case:** Identify exposed services, detect honeypots, map attack surface

---

### Feature 5: Anonymization & Hosting Indicators
**What it extracts:**
- VPN Detection
  - Is VPN: Boolean
  - VPN Confidence: 0-1
  - VPN Provider Name
  
- Proxy Detection
  - Is Proxy: Boolean
  - Proxy Confidence: 0-1
  - Proxy Type (HTTP, SOCKS, Datacenter, etc.)
  
- TOR Exit Node Detection
  - Is TOR: Boolean
  - TOR Confidence: 0-1
  - TOR Exit Node ID
  
- Hosting Provider Detection
  - Is Hosting: Boolean
  - Hosting Confidence: 0-1
  - Provider Name (AWS, Azure, GCP, etc.)
  - Tier (cloud, shared, dedicated)
  
- Anonymization Score (0-100)
- Supporting Evidence List

**Detection Methods:**
1. **IP Range Matching** - Known VPN/proxy/TOR ranges
2. **ASN Keyword Analysis** - Pattern matching against known providers
3. **Certificate Analysis** - cert patterns of hosting providers
4. **Service Fingerprinting** - Common datacenter signatures
5. **WHOIS Analysis** - Provider identification

**VPN IP Ranges Example:**
```python
("Mullvad VPN", "185.213.154.0/24", "https://mullvad.net"),
("NordVPN", "103.86.96.0/22", "https://nordvpn.com"),
("ExpressVPN", "91.207.174.0/24", "https://expressvpn.com"),
```

**Use Case:** Identify legitimate VPNs vs. suspicious proxies, detect cloud infrastructure abuse

---

### Feature 6: Risk Classification
**What it extracts:**
- Risk Level (critical/high/medium/low/unknown)
- Risk Score (0-100)
- Primary Risk Factors (list)
- Corroborated Signals (evidence list)
- Detailed Justification
- Business Impact Assessment
- Confidence Score (0-1)

**Risk Calculation Logic:**
```
Base Score = 0
+ 40 points for "dangerous" reputation
+ 25 points for "poor" reputation
+ 20 points for blocklist presence
+ 15 points for VPN detection
+ 20 points for proxy detection
+ 10 points for hosting provider
+ 5 points for incomplete data
```

**Risk Level Mapping:**
```
Score 80-100  → CRITICAL
Score 60-79   → HIGH
Score 40-59   → MEDIUM
Score 20-39   → LOW
Score 0-19    → UNKNOWN
```

**Use Case:** Make automated blocking decisions, prioritize security reviews

---

### Feature 7: Investigation Leads & Pivots
**What it extracts:**
- Related IPs (same ASN/subnet)
- Shared ASN
- Shared Domains
- Shared SSL Certificates
- APT Group Associations
- Campaign Indicators

**Lead Types:**
```
- related_ip: Other IPs in same subnet
- shared_asn: All IPs in same autonomous system
- shared_domain: Associated domains
- shared_cert: IPs with same SSL certificate
- apt_group: Known APT associations
```

**Investigation Priority:**
```
critical  → Immediate action required
high      → High priority review
medium    → Schedule review
low       → Reference only
```

**Example Output:**
```json
{
  "type": "shared_asn",
  "value": "AS16509",
  "confidence": 0.9,
  "description": "All IPs in ASN 16509 (Amazon)",
  "investigation_priority": "high"
}
```

**Use Case:** Discover related infrastructure, identify coordinated threats

---

## 🔌 API Endpoints

### 1. Full Intelligence Analysis
```bash
POST /api/advanced/intelligence
Content-Type: application/json

{
  "ip": "8.8.8.8"
}

Response: Complete AdvancedIntelligence object with all 7 features
```

### 2. Reputation Report
```bash
POST /api/advanced/reputation-report
Content-Type: application/json

{
  "ip": "1.1.1.1"
}

Response: Reputation data + risk level
```

### 3. Infrastructure Map
```bash
POST /api/advanced/infrastructure-map
Content-Type: application/json

{
  "ip": "9.9.9.9"
}

Response: Domains, reverse DNS, certificates
```

### 4. Exposure Analysis
```bash
POST /api/advanced/exposure-analysis
Content-Type: application/json

{
  "ip": "8.8.8.8"
}

Response: Open ports, services, vulnerability data
```

### 5. Anonymization Check
```bash
POST /api/advanced/anonymization-check
Content-Type: application/json

{
  "ip": "1.1.1.1"
}

Response: VPN/Proxy/TOR detection results
```

### 6. Risk Assessment
```bash
POST /api/advanced/risk-assessment
Content-Type: application/json

{
  "ip": "192.0.2.1"
}

Response: Risk classification + business impact
```

### 7. Investigation Leads
```bash
POST /api/advanced/investigation-leads
Content-Type: application/json

{
  "ip": "203.0.113.45"
}

Response: Related IPs, domains, ASN pivots by priority
```

---

## 📈 Data Completeness Scoring

The system tracks data availability:

```python
data_completeness = (
    has_country_data +
    has_asn_data +
    has_reputation_data +
    has_reverse_dns +
    has_anonymization_data +
    has_passive_exposure +
    has_investigation_leads
) / 7

# Scores: 0.0 (no data) to 1.0 (complete)
```

---

## 🔐 Security Considerations

1. **API Rate Limiting** - Implement per-IP request throttling
2. **Data Caching** - Cache results to reduce external API calls
3. **VPN/Proxy Detection** - Block suspicious IPs automatically
4. **Abuse Prevention** - Monitor for bulk scanning behavior
5. **Data Privacy** - Don't log sensitive IP information
6. **SSL Verification** - Always verify API certificates

---

## 🚀 Enhancement Roadmap

### Phase 1 (Current)
- ✅ Network & Ownership
- ✅ Reputation Detection
- ✅ Infrastructure Mapping
- ✅ Anonymization Detection
- ✅ Risk Classification
- ✅ Investigation Leads
- ⚠️ Passive Exposure (mocked)

### Phase 2
- 🔲 Integrate Shodan API
- 🔲 Integrate Censys API
- 🔲 Integrate BinaryEdge
- 🔲 Integrate GreyNoise
- 🔲 Add WHOIS enrichment
- 🔲 Add ThreatStream/Anomali integration

### Phase 3
- 🔲 Machine Learning risk scoring
- 🔲 Behavioral analysis
- 🔲 Time-series tracking
- 🔲 Bulk IP scanning
- 🔲 Custom alert rules
- 🔲 Export to SIEM

---

## 💾 Example Responses

### Request
```json
POST /api/advanced/intelligence
{
  "ip": "8.8.8.8"
}
```

### Response (Partial)
```json
{
  "ip": "8.8.8.8",
  "network_ownership": {
    "isp_name": "Google LLC",
    "asn": "15169",
    "asn_org": "Google",
    "country": "United States",
    "country_code": "US",
    "city": "Mountain View",
    "latitude": 37.3861,
    "longitude": -122.0839,
    "timezone": "America/Los_Angeles",
    "reliability_score": 0.95
  },
  "reputation": {
    "is_blacklisted": false,
    "blocklist_sources": [],
    "abuse_reports": [],
    "fraud_score": 0.0,
    "spam_score": 0.0,
    "overall_reputation": "excellent"
  },
  "anonymization": {
    "is_vpn": false,
    "is_proxy": false,
    "is_tor": false,
    "is_hosting_provider": true,
    "hosting_provider": "Google",
    "hosting_confidence": 0.95,
    "anonymization_score": 15.0,
    "supporting_evidence": ["Hosting: Google"]
  },
  "risk": {
    "level": "low",
    "score": 10.0,
    "primary_risk_factors": ["Cloud/Hosting provider"],
    "business_impact": "Low threat - likely legitimate but monitor",
    "confidence": 0.65
  },
  "investigation_leads": [
    {
      "type": "shared_asn",
      "value": "AS15169",
      "confidence": 0.9,
      "description": "All IPs in ASN 15169 (Google)",
      "investigation_priority": "high"
    }
  ],
  "data_completeness": 0.857
}
```

---

## 📚 Integration Examples

### Python Client
```python
import requests

def analyze_ip(ip: str):
    response = requests.post(
        "http://localhost:8000/api/advanced/intelligence",
        json={"ip": ip}
    )
    return response.json()

result = analyze_ip("8.8.8.8")
print(f"Risk Level: {result['risk']['level']}")
print(f"Risk Score: {result['risk']['score']}/100")
```

### JavaScript/Node.js
```javascript
async function analyzeIP(ip) {
  const response = await fetch('/api/advanced/intelligence', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip })
  });
  return await response.json();
}

analyzeIP('1.1.1.1').then(result => {
  console.log(`Risk: ${result.risk.level} (${result.risk.score}/100)`);
});
```

### cURL
```bash
curl -X POST http://localhost:8000/api/advanced/intelligence \
  -H "Content-Type: application/json" \
  -d '{"ip":"9.9.9.9"}'
```

---

## 🧪 Testing

### Unit Tests
```bash
pytest test_intelligence.py -v
```

### Integration Tests
```bash
python test_api_endpoints.py
```

### Load Testing
```bash
locust -f locustfile.py --host=http://localhost:8000
```

---

## 📖 Files Included

1. **main_enhanced.py** - Backend with 7-feature IP intelligence
2. **index_enhanced.html** - Advanced frontend UI
3. **README.md** - This documentation
4. **requirements.txt** - Python dependencies

---

## ✅ Checklist

- [x] Feature 1: Network & Ownership
- [x] Feature 2: Reputation & Abuse History
- [x] Feature 3: Associated Infrastructure
- [x] Feature 4: Passive Exposure (mocked, ready for API integration)
- [x] Feature 5: Anonymization Indicators
- [x] Feature 6: Risk Classification
- [x] Feature 7: Investigation Leads
- [x] 7 Dedicated API Endpoints
- [x] Dynamic Frontend with Tabs
- [x] Risk Visualization
- [x] Feature Status Grid

---

## 📞 Support

For issues or questions:
1. Check the error logs: `tail -f app.log`
2. Verify API keys in environment variables
3. Test individual endpoints with cURL
4. Review data completeness scores

---

**Version:** 2.0  
**Last Updated:** 2024  
**Status:** Production Ready
