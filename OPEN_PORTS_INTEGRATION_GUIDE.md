# 🔌 COMPLETE GUIDE: Adding Open Ports Feature

This guide shows you exactly how to add comprehensive open ports detection to your IP intelligence project.

---

## 📋 What You'll Get

After following this guide, your project will have:

✅ **Open Port Detection**
- Scans common ports (22, 80, 443, 3306, 5432, 27017, 6379, 2375, 9200, etc.)
- Detects 30+ critical services
- Multiple data source support (Shodan, Censys, direct scan)

✅ **Risk Assessment**
- Risk scores for open ports
- Dangerous port detection
- Security exposure levels

✅ **Security Recommendations**
- Specific action items for each dangerous port
- Best practices for port security
- Remediation guidance

✅ **Beautiful UI**
- New "Open Ports" tab in web interface
- Port statistics dashboard
- Service summary visualization
- Risk recommendations panel

✅ **3 New API Endpoints**
- `/api/advanced/open-ports` - Full port analysis
- `/api/advanced/port-details` - Individual port details
- `/api/advanced/port-recommendations` - Security recommendations

---

## 🚀 Step 1: Add the Open Ports Module

### 1a. Copy the open_ports_module.py file

You have two options:

**Option A: Download from outputs (if using updated version)**
- Download `open_ports_module.py` from the project

**Option B: Create it manually**
1. In your project directory, create a new file: `open_ports_module.py`
2. Copy the entire content from `OPEN_PORTS_MODULE_CODE.txt`

Your directory structure should look like:
```
ip-intelligence/
├── main_enhanced.py
├── index_enhanced.html
├── open_ports_module.py          ← NEW FILE
├── requirements.txt
└── mmdb/
    ├── GeoLite2-ASN.mmdb
    └── GeoLite2-City.mmdb
```

### 1b. Verify the module works

Test the module:
```bash
python -c "from open_ports_module import get_open_ports; print('✅ Module loaded successfully!')"
```

Expected output:
```
✅ Module loaded successfully!
```

---

## 🔧 Step 2: Update main_enhanced.py

### 2a. Add the import statement

Open `main_enhanced.py` and find this line near the top:
```python
from datetime import datetime
```

Add this import right after it:
```python
# Open ports detection
from open_ports_module import (
    OpenPortsData, OpenService, get_open_ports, 
    calculate_port_risk_score, get_port_risk_description,
    get_port_recommendations, DANGEROUS_PORTS, COMMON_PORTS_DB
)
```

### 2b. Add the three new API endpoints

Find the end of your file (before `app.mount()`) and add these endpoints:

```python
# ════════════════════════════════════════════════════════════════════════════════
# OPEN PORTS DETECTION ENDPOINTS
# ════════════════════════════════════════════════════════════════════════════════

@app.post("/api/advanced/open-ports")
async def open_ports_endpoint(req: AdvancedAnalysisRequest) -> Dict[str, Any]:
    """Scan and analyze open ports for an IP address"""
    try:
        # Get open ports data
        ports_data = await get_open_ports(
            req.ip,
            use_shodan=True,    # Try Shodan if key available
            use_censys=True     # Try Censys if keys available
        )
        
        # Calculate risk score
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
async def port_details_endpoint(req: AdvancedAnalysisRequest) -> Dict[str, Any]:
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
async def port_recommendations_endpoint(req: AdvancedAnalysisRequest) -> Dict[str, Any]:
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
```

---

## 🎨 Step 3: Update index_enhanced.html

### 3a. Add the new tab button

Find this section in index_enhanced.html (around line 200):
```html
<button class="tab-btn" onclick="showTab('investigation')">🎯 Investigation</button>
```

Add this line right after it:
```html
<button class="tab-btn" onclick="showTab('openports')">⚡ Open Ports</button>
```

### 3b. Add the tab panel content

Find this section (around line 250):
```html
<div id="investigation" class="tab-panel">
  <div id="investigationContent"></div>
</div>
```

Add this right after it:
```html
<div id="openports" class="tab-panel">
  <div id="openportsContent"></div>
</div>
```

### 3c. Add the CSS styling

Find the `<style>` section and add this CSS at the end (before `</style>`):

```css
/* ════════════════════════════════════════════════════════════════════════════ */
/* OPEN PORTS STYLING */
/* ════════════════════════════════════════════════════════════════════════════ */

.port-card {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 12px;
  margin-bottom: 16px;
}

.port-item {
  background: var(--bg3);
  border: 1px solid var(--border2);
  border-radius: 8px;
  padding: 12px;
  transition: all 0.2s;
}

.port-item:hover {
  border-color: var(--accent);
  transform: translateY(-2px);
}

.port-number {
  font-family: var(--mono);
  font-size: 18px;
  font-weight: 600;
  color: var(--accent);
  margin-bottom: 4px;
}

.port-service {
  font-family: var(--mono);
  font-size: 12px;
  color: var(--muted);
  text-transform: uppercase;
  margin-bottom: 4px;
}

.port-product {
  font-family: var(--mono);
  font-size: 11px;
  color: var(--text);
  margin-bottom: 8px;
}

.port-danger {
  display: inline-block;
  padding: 3px 8px;
  border-radius: 4px;
  font-family: var(--mono);
  font-size: 10px;
  font-weight: 600;
  margin-bottom: 4px;
}

.port-danger.critical {
  background: rgba(239, 68, 68, 0.3);
  color: #ff6b6b;
  border: 1px solid rgba(239, 68, 68, 0.5);
}

.port-danger.high {
  background: rgba(249, 115, 22, 0.3);
  color: #ffa94d;
  border: 1px solid rgba(249, 115, 22, 0.5);
}

.port-stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 12px;
  margin-bottom: 20px;
}

.port-stat-item {
  background: var(--bg3);
  border: 1px solid var(--border2);
  border-radius: 8px;
  padding: 16px;
  text-align: center;
}

.port-stat-number {
  font-family: var(--mono);
  font-size: 24px;
  font-weight: 600;
  color: var(--accent);
  margin-bottom: 4px;
}

.port-stat-label {
  font-family: var(--mono);
  font-size: 11px;
  color: var(--muted);
  text-transform: uppercase;
}

.exposure-gauge {
  width: 100%;
  height: 30px;
  background: var(--bg3);
  border-radius: 8px;
  overflow: hidden;
  border: 1px solid var(--border2);
  margin: 12px 0;
}

.exposure-fill {
  height: 100%;
  display: flex;
  align-items: center;
  justify-content: center;
  font-family: var(--mono);
  font-size: 11px;
  font-weight: 600;
  color: var(--bg);
  transition: width 0.3s ease;
}

.exposure-fill.none {
  background: var(--green);
}

.exposure-fill.low {
  background: linear-gradient(90deg, var(--green), var(--yellow));
}

.exposure-fill.medium {
  background: linear-gradient(90deg, var(--yellow), var(--orange));
}

.exposure-fill.high {
  background: linear-gradient(90deg, var(--orange), var(--red));
}

.exposure-fill.critical {
  background: var(--red);
}

.recommendation-item {
  padding: 12px;
  background: var(--bg3);
  border-radius: 8px;
  margin-bottom: 8px;
  border-left: 3px solid var(--border2);
  font-family: var(--mono);
  font-size: 12px;
  line-height: 1.6;
}

.recommendation-item.critical {
  border-left-color: var(--red);
  background: rgba(239, 68, 68, 0.05);
}

.recommendation-item.warning {
  border-left-color: var(--yellow);
  background: rgba(234, 179, 8, 0.05);
}

.recommendation-item.info {
  border-left-color: var(--accent);
  background: rgba(59, 130, 246, 0.05);
}

.service-summary {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
  gap: 12px;
  margin: 16px 0;
}

.service-tag {
  background: var(--bg3);
  border: 1px solid var(--border2);
  border-radius: 6px;
  padding: 8px 12px;
  text-align: center;
}

.service-tag-name {
  font-family: var(--mono);
  font-size: 11px;
  color: var(--muted);
  text-transform: uppercase;
  margin-bottom: 4px;
}

.service-tag-count {
  font-family: var(--mono);
  font-size: 16px;
  font-weight: 600;
  color: var(--accent);
}
```

### 3d. Add the JavaScript functions

Find the `<script>` section and add these functions (before the closing `</script>`):

```javascript
// ════════════════════════════════════════════════════════════════════════════
// OPEN PORTS FUNCTIONS
// ════════════════════════════════════════════════════════════════════════════

function renderOpenPorts() {
  if (!currentData) return;
  
  const html = `
    <div class="card">
      <div class="card-title">📊 Open Ports Scan</div>
      <p style="font-family: var(--mono); font-size: 12px; color: var(--muted); margin-bottom: 16px;">
        Real-time port scanning and service detection
      </p>
      
      <div class="port-stats-grid">
        <div class="port-stat-item">
          <div class="port-stat-number" id="portCount">0</div>
          <div class="port-stat-label">Open Ports</div>
        </div>
        <div class="port-stat-item">
          <div class="port-stat-number" id="dangerCount">0</div>
          <div class="port-stat-label">Critical Ports</div>
        </div>
        <div class="port-stat-item">
          <div class="port-stat-number" id="exposureLevel">-</div>
          <div class="port-stat-label">Exposure</div>
        </div>
        <div class="port-stat-item">
          <div class="port-stat-number" id="riskScore">0</div>
          <div class="port-stat-label">Port Risk</div>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="card-title">⚡ Exposure Level</div>
      <div class="exposure-gauge">
        <div class="exposure-fill" id="exposureFill" style="width: 50%; background: var(--yellow);">
        </div>
      </div>
      <p style="font-family: var(--mono); font-size: 12px; color: var(--muted); margin-top: 8px;">
        <span id="exposureText">Scanning...</span>
      </p>
    </div>

    <div class="card">
      <div class="card-title">🔍 Detected Open Ports</div>
      <div class="port-card" id="portsContainer">
        <p style="color: var(--muted);">Scanning for open ports...</p>
      </div>
    </div>

    <div class="card">
      <div class="card-title">📋 Service Summary</div>
      <div class="service-summary" id="serviceSummary">
        <p style="color: var(--muted);">No services detected</p>
      </div>
    </div>

    <div class="card">
      <div class="card-title">🔒 Security Recommendations</div>
      <div id="recommendationsContainer">
        <p style="color: var(--muted);">Generating recommendations...</p>
      </div>
    </div>
  `;
  
  document.getElementById('openportsContent').innerHTML = html;
  fetchOpenPorts();
}

async function fetchOpenPorts() {
  if (!currentData) return;
  
  try {
    const response = await fetch('/api/advanced/open-ports', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip: currentData.ip })
    });
    
    if (!response.ok) throw new Error('Failed to fetch ports');
    const data = await response.json();
    updateOpenPortsDisplay(data);
  } catch (error) {
    console.error('Error:', error);
    document.getElementById('portsContainer').innerHTML = 
      '<p style="color: var(--muted);">Error fetching port data. Server may not have port scanning enabled.</p>';
  }
}

function updateOpenPortsDisplay(data) {
  // Update statistics
  document.getElementById('portCount').textContent = data.total_ports || 0;
  document.getElementById('dangerCount').textContent = data.dangerous_ports.length || 0;
  document.getElementById('exposureLevel').textContent = (data.exposure_level || 'none').toUpperCase();
  document.getElementById('riskScore').textContent = Math.round(data.risk_score || 0);
  
  // Update exposure meter
  const exposureLevel = data.exposure_level || 'none';
  const exposureFill = document.getElementById('exposureFill');
  const exposurePercentages = { none: 10, low: 30, medium: 60, high: 80, critical: 100 };
  
  exposureFill.className = `exposure-fill ${exposureLevel}`;
  exposureFill.style.width = exposurePercentages[exposureLevel] + '%';
  exposureFill.textContent = exposureLevel.toUpperCase();
  
  document.getElementById('exposureText').textContent = data.risk_description || 'Analyzing...';
  
  // Display open ports
  if (data.open_ports.open_ports && data.open_ports.open_ports.length > 0) {
    const portsHtml = data.open_ports.open_ports.map(port => {
      const isDangerous = data.dangerous_ports.includes(port.port);
      const dangerLevel = getDangerLevel(port.port);
      
      return `
        <div class="port-item">
          <div class="port-number">${port.port}</div>
          <div class="port-service">${port.service_name || 'unknown'}</div>
          ${port.product ? `<div class="port-product">${port.product}${port.version ? ' ' + port.version : ''}</div>` : ''}
          ${isDangerous ? `<div class="port-danger ${dangerLevel}">⚠️ ${dangerLevel.toUpperCase()}</div>` : ''}
          <div style="font-family: var(--mono); font-size: 10px; color: var(--muted);">
            ${port.source} · ${(port.confidence * 100).toFixed(0)}%
          </div>
        </div>
      `;
    }).join('');
    
    document.getElementById('portsContainer').innerHTML = portsHtml;
  } else {
    document.getElementById('portsContainer').innerHTML = 
      '<p style="color: var(--muted);">No open ports detected - good security posture!</p>';
  }
  
  // Display service summary
  if (data.service_summary && Object.keys(data.service_summary).length > 0) {
    const servicesHtml = Object.entries(data.service_summary).map(([service, count]) => `
      <div class="service-tag">
        <div class="service-tag-name">${service}</div>
        <div class="service-tag-count">${count}</div>
      </div>
    `).join('');
    
    document.getElementById('serviceSummary').innerHTML = servicesHtml;
  }
  
  // Display recommendations
  if (data.recommendations && data.recommendations.length > 0) {
    const recsHtml = data.recommendations.map(rec => {
      let level = 'info';
      if (rec.includes('NEVER') || rec.includes('CRITICAL')) level = 'critical';
      else if (rec.includes('⚠️')) level = 'warning';
      
      return `<div class="recommendation-item ${level}">${rec}</div>`;
    }).join('');
    
    document.getElementById('recommendationsContainer').innerHTML = recsHtml;
  }
}

function getDangerLevel(port) {
  const criticalPorts = [22, 3306, 5432, 27017, 6379, 2375, 9200];
  const highPorts = [3389, 23, 21, 80, 8080];
  
  if (criticalPorts.includes(port)) return 'critical';
  if (highPorts.includes(port)) return 'high';
  return 'medium';
}
```

### 3e. Update the renderAllTabs function

Find this function in the script section and add `renderOpenPorts();` at the end:

```javascript
function renderAllTabs() {
  renderOverview();
  renderNetwork();
  renderReputation();
  renderInfrastructure();
  renderExposure();
  renderAnonymization();
  renderRisk();
  renderInvestigation();
  renderOpenPorts();  // ← ADD THIS LINE
}
```

---

## ⚙️ Step 4: Configure Optional API Keys (For Better Results)

### Without API Keys
- The system will use direct port scanning (slower but works)
- Tests common ports: 22, 80, 443, 3306, 5432, 27017, 6379, 2375, 9200, etc.

### With Shodan API (Recommended)
1. Get a free Shodan API key: https://shodan.io/
2. Set the environment variable:

**Windows (PowerShell):**
```powershell
$env:SHODAN_API_KEY = "your-shodan-api-key"
```

**Mac/Linux:**
```bash
export SHODAN_API_KEY="your-shodan-api-key"
```

### With Censys API (Optional)
1. Create a Censys account: https://censys.io/
2. Set environment variables:

**Windows (PowerShell):**
```powershell
$env:CENSYS_API_ID = "your-censys-api-id"
$env:CENSYS_API_SECRET = "your-censys-api-secret"
```

**Mac/Linux:**
```bash
export CENSYS_API_ID="your-censys-api-id"
export CENSYS_API_SECRET="your-censys-api-secret"
```

---

## ✅ Step 5: Test the Feature

### 5a. Restart your server

```bash
# Stop the server (Ctrl+C)

# Start it again:
uvicorn main_enhanced:app --reload
```

### 5b. Test in web UI

1. Open http://localhost:8000
2. Enter an IP address
3. Click "Analyze"
4. Click the "⚡ Open Ports" tab
5. You should see:
   - Open ports detected
   - Service names (ssh, http, mysql, etc.)
   - Risk assessment
   - Security recommendations

### 5c. Test with API

```bash
# Get open ports for an IP
curl -X POST http://localhost:8000/api/advanced/open-ports \
  -H "Content-Type: application/json" \
  -d '{"ip":"8.8.8.8"}'

# Get port details
curl -X POST http://localhost:8000/api/advanced/port-details \
  -H "Content-Type: application/json" \
  -d '{"ip":"8.8.8.8"}'

# Get recommendations
curl -X POST http://localhost:8000/api/advanced/port-recommendations \
  -H "Content-Type: application/json" \
  -d '{"ip":"8.8.8.8"}'
```

---

## 🎯 Test IPs to Try

### Safe/Normal IPs
- `8.8.8.8` - Google DNS (few ports)
- `1.1.1.1` - Cloudflare DNS (few ports)
- `208.67.222.222` - OpenDNS (few ports)

### More Ports (Legitimate)
- `208.67.222.123` - Another OpenDNS
- `9.9.9.9` - Quad9 DNS

---

## 🐛 Troubleshooting

### Issue: "Error fetching port data"

**Solution:** This might mean:
1. Direct port scanning is slow - give it 10-30 seconds
2. Server doesn't have Shodan/Censys keys (that's OK!)
3. Firewall is blocking the scan

### Issue: "No open ports detected" for obviously open IPs

**Solution:**
1. Direct scanning might be blocked by firewall
2. Add Shodan API key for more accurate results
3. Some IPs might actually have no open ports

### Issue: Module import error

**Solution:** Make sure `open_ports_module.py` is in the same directory as `main_enhanced.py`

---

## 📊 Feature Details

### Detected Ports & Services

The system detects and classifies 30+ critical services:

| Port | Service | Risk | Category |
|------|---------|------|----------|
| 22 | SSH | Medium | Remote Access |
| 80 | HTTP | Medium | Web |
| 443 | HTTPS | Low | Web |
| 3306 | MySQL | Critical | Database |
| 5432 | PostgreSQL | Critical | Database |
| 27017 | MongoDB | Critical | Database |
| 6379 | Redis | Critical | Cache |
| 2375 | Docker | Critical | Container |
| 9200 | Elasticsearch | Critical | Search |
| 3389 | RDP | High | Remote |

### Risk Calculation

```
Risk Score = Base Score
  + 30 points for >20 open ports
  + 20 points for >10 open ports
  + 10 points for >5 open ports
  + 10 points for SSH
  + 30 points for MySQL
  + 30 points for PostgreSQL
  + 35 points for MongoDB
  + 35 points for Redis
  + 40 points for Docker
  + 35 points for Elasticsearch
  + 25 points for RDP
  + 5 points for HTTP/HTTPS

Max: 100 points
```

### Exposure Levels

```
NONE     → 0 open ports
LOW      → 1-5 ports (likely normal)
MEDIUM   → 6-10 ports (review)
HIGH     → 11-20 ports (investigate)
CRITICAL → Dangerous ports detected
```

---

## 🎉 You're Done!

Your IP intelligence project now has professional-grade open ports detection with:

✅ Multi-source scanning (Shodan, Censys, direct)
✅ Risk assessment and scoring
✅ Security recommendations
✅ Beautiful UI visualization
✅ 3 new API endpoints
✅ 30+ detected services

Enjoy your enhanced project! 🚀
