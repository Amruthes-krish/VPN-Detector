# Quick Start & Deployment Guide

## ⚡ Quick Start (5 minutes)

### 1. Install & Run
```bash
# Install dependencies
pip install fastapi uvicorn httpx geoip2

# Download MaxMind databases (free tier)
# https://dev.maxmind.com/geoip/geolite2-free/
# Extract to ./mmdb/ folder

# Run the server
uvicorn main_enhanced:app --reload

# Access UI at: http://localhost:8000
```

### 2. Test with cURL
```bash
# Full intelligence analysis
curl -X POST http://localhost:8000/api/advanced/intelligence \
  -H "Content-Type: application/json" \
  -d '{"ip":"8.8.8.8"}'

# Reputation report
curl -X POST http://localhost:8000/api/advanced/reputation-report \
  -H "Content-Type: application/json" \
  -d '{"ip":"1.1.1.1"}'

# Risk assessment
curl -X POST http://localhost:8000/api/advanced/risk-assessment \
  -H "Content-Type: application/json" \
  -d '{"ip":"192.0.2.1"}'

# Investigation leads
curl -X POST http://localhost:8000/api/advanced/investigation-leads \
  -H "Content-Type: application/json" \
  -d '{"ip":"203.0.113.45"}'
```

---

## 📦 Production Deployment

### Option 1: Docker
```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main_enhanced.py .
COPY index_enhanced.html ./frontend/
COPY mmdb/ ./mmdb/

ENV ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
ENV PROXYCHECK_KEY=${PROXYCHECK_KEY}

CMD ["uvicorn", "main_enhanced:app", "--host", "0.0.0.0", "--port", "8000"]
```

Build & Run:
```bash
docker build -t ip-intelligence:2.0 .
docker run -p 8000:8000 \
  -e ANTHROPIC_API_KEY="your-key" \
  -e PROXYCHECK_KEY="your-key" \
  ip-intelligence:2.0
```

### Option 2: Systemd Service
```ini
# /etc/systemd/system/ip-intelligence.service
[Unit]
Description=Advanced IP Intelligence Service
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/opt/ip-intelligence
EnvironmentFile=/opt/ip-intelligence/.env
ExecStart=/usr/bin/python3 -m uvicorn main_enhanced:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Start service:
```bash
sudo systemctl start ip-intelligence
sudo systemctl status ip-intelligence
sudo journalctl -u ip-intelligence -f
```

### Option 3: Gunicorn + Nginx
```bash
# Install
pip install gunicorn

# Run with Gunicorn
gunicorn -w 4 -b 0.0.0.0:8000 main_enhanced:app

# Nginx reverse proxy config
# /etc/nginx/sites-available/ip-intelligence
upstream ip_intelligence {
    server 127.0.0.1:8000;
}

server {
    listen 80;
    server_name ip-intel.example.com;

    client_max_body_size 10M;

    location / {
        proxy_pass http://ip_intelligence;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Cache static files
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$ {
        expires 30d;
        add_header Cache-Control "public, immutable";
    }
}
```

Enable:
```bash
sudo ln -s /etc/nginx/sites-available/ip-intelligence /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

---

## 🔄 API Integration Examples

### Slack Integration
```python
import requests
from slack_sdk import WebClient

def check_ip_slack(ip: str, slack_token: str):
    # Analyze IP
    intel = requests.post(
        "http://localhost:8000/api/advanced/intelligence",
        json={"ip": ip}
    ).json()
    
    # Send to Slack
    client = WebClient(token=slack_token)
    color = {
        "critical": "danger",
        "high": "warning",
        "medium": "warning",
        "low": "good"
    }.get(intel['risk']['level'], "")
    
    client.chat_postMessage(
        channel="#security-alerts",
        attachments=[{
            "color": color,
            "title": f"IP Analysis: {ip}",
            "fields": [
                {"title": "Risk Level", "value": intel['risk']['level'], "short": True},
                {"title": "Risk Score", "value": str(intel['risk']['score']), "short": True},
                {"title": "Country", "value": intel['network_ownership']['country'], "short": True},
                {"title": "ISP", "value": intel['network_ownership']['isp_name'], "short": True},
            ]
        }]
    )
```

### Splunk HEC Integration
```python
import requests
import json
import time

def send_to_splunk_hec(event: dict, hec_token: str, hec_endpoint: str):
    payload = {
        "time": time.time(),
        "source": "ip_intelligence",
        "sourcetype": "_json",
        "event": event
    }
    
    requests.post(
        f"{hec_endpoint}/services/collector",
        headers={"Authorization": f"Splunk {hec_token}"},
        data=json.dumps(payload),
        verify=False
    )

# Usage
intel = requests.post(
    "http://localhost:8000/api/advanced/intelligence",
    json={"ip": "8.8.8.8"}
).json()

send_to_splunk_hec(intel, "your-hec-token", "https://splunk.example.com:8088")
```

### AWS Security Hub Integration
```python
import boto3
import time

def send_to_security_hub(ip: str, intel: dict):
    client = boto3.client('securityhub', region_name='us-east-1')
    
    severity_map = {
        "critical": "CRITICAL",
        "high": "HIGH",
        "medium": "MEDIUM",
        "low": "LOW"
    }
    
    finding = {
        "SchemaVersion": "2018-10-08",
        "Id": f"ip-intel/{ip}",
        "ProductArn": "arn:aws:securityhub:us-east-1:123456789012:product/custom/ip-intelligence",
        "GeneratorId": "ip-intelligence-system",
        "AwsAccountId": "123456789012",
        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
        "CreatedAt": time.isoformat(),
        "UpdatedAt": time.isoformat(),
        "Severity": {
            "Label": severity_map.get(intel['risk']['level'], "INFORMATIONAL")
        },
        "Title": f"IP Intelligence Analysis: {ip}",
        "Description": intel['risk']['business_impact'],
        "Resources": [
            {
                "Type": "Network/IP",
                "Id": ip,
                "Partition": "aws",
                "Region": "us-east-1",
                "Details": {
                    "Network": {
                        "SourceIpV4": ip,
                        "SourceAsn": intel['network_ownership']['asn'],
                        "SourceCountry": intel['network_ownership']['country_code']
                    }
                }
            }
        ]
    }
    
    client.batch_import_findings(Findings=[finding])
```

---

## 📊 Configuration Examples

### .env File
```bash
# API Keys
ANTHROPIC_API_KEY=sk-...
PROXYCHECK_KEY=...
SHODAN_API_KEY=...  # Optional
CENSYS_API_ID=...   # Optional
CENSYS_API_SECRET=...

# Database Paths
MMDB_ASN_PATH=./mmdb/GeoLite2-ASN.mmdb
MMDB_CITY_PATH=./mmdb/GeoLite2-City.mmdb

# Server Settings
HOST=0.0.0.0
PORT=8000
WORKERS=4
LOG_LEVEL=info

# Feature Flags
ENABLE_SHODAN=false
ENABLE_CENSYS=false
ENABLE_CACHE=true
CACHE_TTL=3600

# Security
RATE_LIMIT_PER_MINUTE=60
RATE_LIMIT_PER_HOUR=1000
BLOCK_COMMON_SCANDEBRIS=true
```

Load in main_enhanced.py:
```python
from dotenv import load_dotenv
import os

load_dotenv()

ANTHROPIC_KEY = os.getenv("ANTHROPIC_API_KEY")
PROXYCHECK_KEY = os.getenv("PROXYCHECK_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
```

---

## 🛡️ Security Hardening

### 1. API Authentication
```python
from fastapi.security import HTTPBearer, HTTPAuthCredential
from fastapi import Depends, HTTPException

security = HTTPBearer()

async def verify_api_key(credentials: HTTPAuthCredential = Depends(security)):
    valid_keys = os.getenv("VALID_API_KEYS", "").split(",")
    if credentials.credentials not in valid_keys:
        raise HTTPException(status_code=403, detail="Invalid API key")
    return credentials.credentials

@app.post("/api/advanced/intelligence")
async def intelligence(req: AdvancedAnalysisRequest, api_key: str = Depends(verify_api_key)):
    # ... endpoint code
```

### 2. Rate Limiting
```python
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

@app.post("/api/advanced/intelligence")
@limiter.limit("60/minute")
async def intelligence(req: AdvancedAnalysisRequest):
    # ... endpoint code
```

### 3. CORS Configuration
```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://ip-intel.example.com"],  # Specific domain
    allow_credentials=True,
    allow_methods=["POST"],
    allow_headers=["Content-Type", "Authorization"],
    max_age=600,
)
```

### 4. Request Validation
```python
from pydantic import BaseModel, validator, Field

class AdvancedAnalysisRequest(BaseModel):
    ip: str = Field(..., regex=r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$")
    
    @validator('ip')
    def validate_ip(cls, v):
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError('Invalid IP address')
        return v
```

---

## 🔍 Monitoring & Logging

### Logging Setup
```python
import logging
from logging.handlers import RotatingFileHandler

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        RotatingFileHandler(
            'ip_intelligence.log',
            maxBytes=10485760,  # 10MB
            backupCount=10
        )
    ]
)

logger = logging.getLogger(__name__)

@app.post("/api/advanced/intelligence")
async def intelligence(req: AdvancedAnalysisRequest):
    logger.info(f"Analyzing IP: {req.ip}")
    try:
        result = await fetch_advanced_ip_intelligence(req.ip)
        logger.info(f"Analysis complete for {req.ip} - Risk: {result.risk.level}")
        return result.dict()
    except Exception as e:
        logger.error(f"Error analyzing {req.ip}: {str(e)}")
        raise
```

### Prometheus Metrics
```python
from prometheus_client import Counter, Histogram, start_http_server

analysis_counter = Counter(
    'ip_analysis_total',
    'Total IP analyses',
    ['risk_level']
)
analysis_duration = Histogram(
    'ip_analysis_duration_seconds',
    'IP analysis duration'
)

@app.post("/api/advanced/intelligence")
async def intelligence(req: AdvancedAnalysisRequest):
    with analysis_duration.time():
        result = await fetch_advanced_ip_intelligence(req.ip)
        analysis_counter.labels(risk_level=result.risk.level).inc()
        return result.dict()

# Start metrics server
start_http_server(8001)  # Expose at :8001/metrics
```

---

## 🧪 Testing Checklist

- [ ] All 7 endpoints return valid responses
- [ ] Invalid IPs are rejected with 400 status
- [ ] Rate limiting works
- [ ] API authentication required
- [ ] CORS headers correct
- [ ] Database files accessible
- [ ] External APIs responding
- [ ] Logging working
- [ ] Error handling robust
- [ ] Load testing passed

---

## 📈 Performance Optimization

### Caching
```python
from cachetools import TTLCache
import asyncio

intelligence_cache = TTLCache(maxsize=1000, ttl=3600)  # 1 hour

async def fetch_advanced_ip_intelligence(ip: str) -> AdvancedIntelligence:
    if ip in intelligence_cache:
        return intelligence_cache[ip]
    
    # Fetch data...
    result = AdvancedIntelligence(...)
    intelligence_cache[ip] = result
    return result
```

### Connection Pooling
```python
async def fetch_data(ip: str):
    connector = httpx.AsyncHTTPConnection(
        pool_connections=20,
        pool_maxsize=20,
        max_keepalive_connections=10
    )
    async with httpx.AsyncClient(connector=connector, timeout=10.0) as client:
        # Make requests...
```

### Async Optimization
```python
async def fetch_advanced_ip_intelligence(ip: str):
    # Parallel API calls
    tasks = [
        fetch_mmdb_data(ip),
        fetch_ip_api(ip),
        fetch_proxycheck(ip),
        fetch_getipintel(ip),
        fetch_reverse_dns(ip)
    ]
    
    results = await asyncio.gather(*tasks, return_exceptions=True)
```

---

## 🆘 Troubleshooting

### Issue: "GeoIP2 database not found"
```bash
# Solution: Download and place MaxMind DBs
wget https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN&license_key=YOUR_KEY&suffix=tar.gz
mkdir -p mmdb/
tar xzf GeoLite2-ASN_*.tar.gz -C mmdb/ --strip-components=1
```

### Issue: "External API timeout"
```python
# Increase timeout
async with httpx.AsyncClient(timeout=30.0) as client:
    # requests with 30 second timeout
```

### Issue: "High memory usage"
```python
# Reduce cache size
intelligence_cache = TTLCache(maxsize=100, ttl=300)  # 100 items, 5 min TTL

# Or disable caching
ENABLE_CACHE = False
```

### Issue: "Rate limit exceeded"
```bash
# Check rate limiter settings
# Increase limits if needed
@limiter.limit("100/minute")
```

---

## 📞 Support Resources

- **Documentation**: See ADVANCED_IP_INTELLIGENCE_DOCS.md
- **Issues**: Check logs in `/var/log/ip-intelligence.log`
- **Health Check**: `curl http://localhost:8000/health`

---

**Version:** 2.0  
**Last Updated:** 2024
