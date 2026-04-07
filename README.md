# VPN Detector

Full-stack VPN / proxy detection tool built with **FastAPI** + **MaxMind MMDB** + **ip-api.com**.

## Project Structure

```
vpn-detector/
├── backend/
│   ├── main.py            ← FastAPI app
│   ├── requirements.txt
│   └── mmdb/              ← place your .mmdb files here
│       ├── GeoLite2-ASN.mmdb
│       └── GeoLite2-City.mmdb
└── frontend/
    └── index.html         ← served by FastAPI
```

---

## Setup

### 1. Get MaxMind MMDB files (free)

1. Register free at https://www.maxmind.com/en/geolite2/signup
2. Download **GeoLite2-ASN** and **GeoLite2-City** (`.mmdb` format)
3. Place them in `backend/mmdb/`

> The app works without MMDB files too — it will fall back to ip-api.com only.

### 2. Install Python dependencies

```bash
cd backend
pip install -r requirements.txt
```

### 3. Run the server

```bash
cd backend
uvicorn main:app --reload --port 8000
```

Open http://localhost:8000 in your browser.

---

## API

### `GET /api/lookup/{ip}`

Returns full intelligence about the IP address.

**Example:**
```bash
curl http://localhost:8000/api/lookup/185.220.101.1
```

**Response:**
```json
{
  "ip": "185.220.101.1",
  "asn": "AS4766",
  "org": "Tor Project",
  "country": "Germany",
  "country_code": "DE",
  "city": "Frankfurt",
  "latitude": 50.1188,
  "longitude": 8.6843,
  "timezone": "Europe/Berlin",
  "isp": "Tor Exit Node",
  "mmdb_available": true,
  "detection": {
    "score": 85,
    "verdict": "VPN / Proxy",
    "level": "high",
    "flags": ["vpn_flag", "proxy", "known_vpn_provider"]
  },
  "raw_ip_api": { ... }
}
```

---

## Detection Logic

| Score | Verdict | Trigger |
|-------|---------|---------|
| 60–100 | VPN / Proxy | ASN name matches known VPN provider, or ip-api vpn/proxy flag |
| 30–59  | Datacenter / Cloud | ASN belongs to AWS, GCP, Azure, DigitalOcean, etc. |
| 0–29   | Residential | No suspicious signals |

### Scoring breakdown
- Known VPN keyword in ASN org name → +60
- Datacenter keyword in ASN → +30
- ip-api `proxy: true` → +25
- ip-api `hosting: true` → +20
- ip-api `vpn: true` → +40

Score is capped at 100.

---

## Data Sources

| Source | What it provides | Requires |
|--------|-----------------|---------|
| MaxMind GeoLite2-ASN | ASN, org/provider name | Free signup + download |
| MaxMind GeoLite2-City | Country, city, coordinates, timezone | Free signup + download |
| ip-api.com | VPN/proxy/hosting flags, ISP, enrichment | Nothing (free, 45 req/min) |

---

## Adding More VPN Keywords

Edit `VPN_KEYWORDS` in `backend/main.py`:

```python
VPN_KEYWORDS = [
    "vpn", "mullvad", "nordvpn", "expressvpn", ...
    "your_vpn_name",  # add here
]
```
