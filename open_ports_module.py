# ════════════════════════════════════════════════════════════════════════════════
# ENHANCED OPEN PORTS DETECTION SYSTEM
# This module provides comprehensive open port scanning and detection for IPs
# ════════════════════════════════════════════════════════════════════════════════

import httpx
import asyncio
from typing import List, Dict, Optional, Any
from datetime import datetime
from pydantic import BaseModel

# ════════════════════════════════════════════════════════════════════════════════
# DATA MODELS FOR OPEN PORTS
# ════════════════════════════════════════════════════════════════════════════════

class OpenService(BaseModel):
    """Information about an open port/service"""
    port: int
    protocol: str  # tcp, udp
    service_name: Optional[str] = None  # ssh, http, https, mysql, etc.
    product: Optional[str] = None  # Apache, Nginx, OpenSSH, etc.
    version: Optional[str] = None  # 2.4.41, 5.6.0, etc.
    state: str = "open"  # open, closed, filtered
    confidence: float = 0.95  # 0-1, how sure we are this port is open
    source: str = "unknown"  # shodan, censys, nmap, direct, etc.
    last_seen: Optional[str] = None  # ISO date
    banner: Optional[str] = None  # Service banner info
    vulnerability_count: int = 0
    tags: List[str] = []  # e.g., ["web", "database", "ssh"]

class OpenPortsData(BaseModel):
    """Complete open ports information"""
    ip: str
    total_open_ports: int = 0
    open_ports: List[OpenService] = []
    last_scanned: Optional[str] = None
    data_sources: List[str] = []  # shodan, censys, direct_scan, etc.
    exposure_level: str = "unknown"  # critical/high/medium/low/none
    most_dangerous_ports: List[int] = []  # Top ports for risk assessment
    service_summary: Dict[str, int] = {}  # e.g., {"ssh": 1, "http": 1, "https": 1}
    last_updated: str = ""
    scan_accuracy: float = 0.0  # 0-1

# ════════════════════════════════════════════════════════════════════════════════
# COMMON PORTS DATABASE
# ════════════════════════════════════════════════════════════════════════════════

COMMON_PORTS_DB = {
    # SSH
    22: {"name": "ssh", "product": "SSH", "category": "remote_access", "risk": "medium"},
    
    # HTTP/HTTPS
    80: {"name": "http", "product": "HTTP", "category": "web", "risk": "medium"},
    443: {"name": "https", "product": "HTTPS", "category": "web", "risk": "low"},
    8080: {"name": "http-alt", "product": "HTTP (Alt)", "category": "web", "risk": "medium"},
    8443: {"name": "https-alt", "product": "HTTPS (Alt)", "category": "web", "risk": "low"},
    
    # Mail Services
    25: {"name": "smtp", "product": "SMTP", "category": "mail", "risk": "medium"},
    110: {"name": "pop3", "product": "POP3", "category": "mail", "risk": "medium"},
    143: {"name": "imap", "product": "IMAP", "category": "mail", "risk": "medium"},
    587: {"name": "smtp", "product": "SMTP (TLS)", "category": "mail", "risk": "low"},
    993: {"name": "imaps", "product": "IMAPS", "category": "mail", "risk": "low"},
    995: {"name": "pop3s", "product": "POP3S", "category": "mail", "risk": "low"},
    
    # Database Services
    3306: {"name": "mysql", "product": "MySQL", "category": "database", "risk": "critical"},
    5432: {"name": "postgresql", "product": "PostgreSQL", "category": "database", "risk": "critical"},
    5984: {"name": "couchdb", "product": "CouchDB", "category": "database", "risk": "critical"},
    6379: {"name": "redis", "product": "Redis", "category": "database", "risk": "critical"},
    27017: {"name": "mongodb", "product": "MongoDB", "category": "database", "risk": "critical"},
    27018: {"name": "mongodb", "product": "MongoDB", "category": "database", "risk": "critical"},
    27019: {"name": "mongodb", "product": "MongoDB", "category": "database", "risk": "critical"},
    28017: {"name": "mongodb", "product": "MongoDB REST", "category": "database", "risk": "critical"},
    
    # Remote Desktop
    3389: {"name": "rdp", "product": "RDP", "category": "remote_access", "risk": "high"},
    
    # VNC
    5900: {"name": "vnc", "product": "VNC", "category": "remote_access", "risk": "high"},
    
    # FTP
    21: {"name": "ftp", "product": "FTP", "category": "file_transfer", "risk": "high"},
    
    # DNS
    53: {"name": "dns", "product": "DNS", "category": "infrastructure", "risk": "low"},
    
    # NTP
    123: {"name": "ntp", "product": "NTP", "category": "infrastructure", "risk": "low"},
    
    # LDAP
    389: {"name": "ldap", "product": "LDAP", "category": "directory", "risk": "medium"},
    636: {"name": "ldaps", "product": "LDAPS", "category": "directory", "risk": "low"},
    
    # Syslog
    514: {"name": "syslog", "product": "Syslog", "category": "logging", "risk": "low"},
    
    # SNMP
    161: {"name": "snmp", "product": "SNMP", "category": "monitoring", "risk": "medium"},
    
    # HTTP Proxy
    8888: {"name": "proxy", "product": "HTTP Proxy", "category": "proxy", "risk": "high"},
    3128: {"name": "squid", "product": "Squid Proxy", "category": "proxy", "risk": "high"},
    
    # Elasticsearch
    9200: {"name": "elasticsearch", "product": "Elasticsearch", "category": "search", "risk": "critical"},
    9300: {"name": "elasticsearch", "product": "Elasticsearch (node)", "category": "search", "risk": "critical"},
    
    # Kibana
    5601: {"name": "kibana", "product": "Kibana", "category": "visualization", "risk": "high"},
    
    # Jenkins
    8080: {"name": "jenkins", "product": "Jenkins", "category": "ci_cd", "risk": "high"},
    
    # Docker
    2375: {"name": "docker", "product": "Docker API", "category": "container", "risk": "critical"},
    2376: {"name": "docker", "product": "Docker API (TLS)", "category": "container", "risk": "high"},
}

# ════════════════════════════════════════════════════════════════════════════════
# DANGEROUS PORTS (IMMEDIATE SECURITY CONCERN)
# ════════════════════════════════════════════════════════════════════════════════

DANGEROUS_PORTS = {
    22: {"service": "SSH", "risk": "Unauthorized remote access"},
    3306: {"service": "MySQL", "risk": "Exposed database - data breach"},
    5432: {"service": "PostgreSQL", "risk": "Exposed database - data breach"},
    27017: {"service": "MongoDB", "risk": "Exposed database - data breach"},
    6379: {"service": "Redis", "risk": "Exposed cache - data breach"},
    2375: {"service": "Docker", "risk": "Container escape possible"},
    9200: {"service": "Elasticsearch", "risk": "Exposed search engine"},
    3389: {"service": "RDP", "risk": "Remote desktop exploit"},
}

# ════════════════════════════════════════════════════════════════════════════════
# OPEN PORTS DETECTION FUNCTIONS
# ════════════════════════════════════════════════════════════════════════════════

async def scan_ports_shodan(ip: str, shodan_key: Optional[str] = None) -> List[OpenService]:
    """
    Scan open ports using Shodan API
    
    Requires: SHODAN_API_KEY environment variable
    Returns: List of OpenService objects
    """
    if not shodan_key:
        return []
    
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                f"https://api.shodan.io/shodan/host/{ip}",
                params={"key": shodan_key}
            )
            
            if response.status_code != 200:
                return []
            
            data = response.json()
            ports = []
            
            for item in data.get("data", []):
                port_num = item.get("port")
                service_info = COMMON_PORTS_DB.get(port_num, {})
                
                port = OpenService(
                    port=port_num,
                    protocol="tcp",
                    service_name=service_info.get("name", item.get("_shodan", {}).get("module", "unknown")),
                    product=item.get("product", service_info.get("product")),
                    version=item.get("version"),
                    state="open",
                    confidence=0.99,
                    source="shodan",
                    banner=item.get("data", "")[:100] if item.get("data") else None,
                    last_seen=data.get("last_update"),
                )
                ports.append(port)
            
            return ports
    except Exception as e:
        print(f"Shodan scan error: {e}")
        return []

async def scan_ports_censys(ip: str, censys_id: Optional[str] = None, censys_secret: Optional[str] = None) -> List[OpenService]:
    """
    Scan open ports using Censys API
    
    Requires: CENSYS_API_ID and CENSYS_API_SECRET environment variables
    Returns: List of OpenService objects
    """
    if not censys_id or not censys_secret:
        return []
    
    try:
        async with httpx.AsyncClient(timeout=10.0, auth=(censys_id, censys_secret)) as client:
            response = await client.get(
                f"https://censys.io/api/v1/ipv4/{ip}"
            )
            
            if response.status_code != 200:
                return []
            
            data = response.json()
            ports = []
            
            for port_num in data.get("ports", []):
                service_info = COMMON_PORTS_DB.get(port_num, {})
                
                port = OpenService(
                    port=port_num,
                    protocol="tcp",
                    service_name=service_info.get("name", "unknown"),
                    product=service_info.get("product"),
                    state="open",
                    confidence=0.95,
                    source="censys",
                    last_seen=datetime.utcnow().isoformat(),
                )
                ports.append(port)
            
            return ports
    except Exception as e:
        print(f"Censys scan error: {e}")
        return []

async def scan_ports_direct(ip: str, timeout: float = 2.0) -> List[OpenService]:
    """
    Scan common ports directly (no API required)
    
    Tests connectivity to common ports to detect open services
    Returns: List of OpenService objects
    """
    import socket
    
    ports_to_test = [
        22, 25, 53, 80, 110, 123, 143, 161, 389, 443, 445, 514, 587, 636,
        993, 995, 1433, 3306, 3389, 5432, 5601, 5900, 6379, 8000, 8080,
        8443, 8888, 9200, 27017, 3128, 2375, 2376, 21, 23
    ]
    
    open_ports = []
    
    # Test each port with timeout
    tasks = []
    for port_num in ports_to_test:
        task = test_single_port(ip, port_num, timeout)
        tasks.append(task)
    
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    for port_num, is_open in zip(ports_to_test, results):
        if isinstance(is_open, bool) and is_open:
            service_info = COMMON_PORTS_DB.get(port_num, {})
            
            port = OpenService(
                port=port_num,
                protocol="tcp",
                service_name=service_info.get("name", "unknown"),
                product=service_info.get("product"),
                state="open",
                confidence=0.85,
                source="direct_scan",
                last_seen=datetime.utcnow().isoformat(),
            )
            open_ports.append(port)
    
    return open_ports

async def test_single_port(ip: str, port: int, timeout: float = 2.0) -> bool:
    """Test if a single port is open"""
    import socket
    
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return True
    except (asyncio.TimeoutError, OSError, ConnectionRefusedError, Exception):
        return False

async def get_open_ports(ip: str, use_shodan: bool = False, use_censys: bool = False) -> OpenPortsData:
    """
    Get open ports for an IP address
    
    Tries multiple sources:
    1. Shodan API (if key provided and use_shodan=True)
    2. Censys API (if keys provided and use_censys=True)
    3. Direct port scanning (always available, but slower)
    
    Returns: OpenPortsData object with all port information
    """
    import os
    
    all_ports = []
    data_sources = []
    
    # Try Shodan
    if use_shodan:
        shodan_key = os.environ.get("SHODAN_API_KEY")
        if shodan_key:
            shodan_ports = await scan_ports_shodan(ip, shodan_key)
            all_ports.extend(shodan_ports)
            if shodan_ports:
                data_sources.append("shodan")
    
    # Try Censys
    if use_censys:
        censys_id = os.environ.get("CENSYS_API_ID")
        censys_secret = os.environ.get("CENSYS_API_SECRET")
        if censys_id and censys_secret:
            censys_ports = await scan_ports_censys(ip, censys_id, censys_secret)
            all_ports.extend(censys_ports)
            if censys_ports:
                data_sources.append("censys")
    
    # Direct scan (always try)
    direct_ports = await scan_ports_direct(ip)
    all_ports.extend(direct_ports)
    if direct_ports:
        data_sources.append("direct_scan")
    
    # Deduplicate ports (keep highest confidence)
    unique_ports = {}
    for port_obj in all_ports:
        key = port_obj.port
        if key not in unique_ports or port_obj.confidence > unique_ports[key].confidence:
            unique_ports[key] = port_obj
    
    all_ports = list(unique_ports.values())
    all_ports.sort(key=lambda x: x.port)
    
    # Calculate exposure level
    if not all_ports:
        exposure_level = "none"
    elif any(p.port in DANGEROUS_PORTS for p in all_ports):
        exposure_level = "critical"
    elif len(all_ports) > 10:
        exposure_level = "high"
    elif len(all_ports) > 5:
        exposure_level = "medium"
    else:
        exposure_level = "low"
    
    # Find dangerous ports
    dangerous = [p.port for p in all_ports if p.port in DANGEROUS_PORTS]
    dangerous.sort()
    
    # Create service summary
    service_summary = {}
    for port_obj in all_ports:
        service = port_obj.service_name or "unknown"
        service_summary[service] = service_summary.get(service, 0) + 1
    
    return OpenPortsData(
        ip=ip,
        total_open_ports=len(all_ports),
        open_ports=all_ports,
        last_scanned=datetime.utcnow().isoformat(),
        data_sources=list(set(data_sources)),
        exposure_level=exposure_level,
        most_dangerous_ports=dangerous,
        service_summary=service_summary,
        last_updated=datetime.utcnow().isoformat(),
        scan_accuracy=0.90 if all_ports else 0.50,
    )

# ════════════════════════════════════════════════════════════════════════════════
# RISK ASSESSMENT FOR OPEN PORTS
# ════════════════════════════════════════════════════════════════════════════════

def calculate_port_risk_score(ports_data: OpenPortsData) -> float:
    """
    Calculate risk score based on open ports
    
    Returns: 0-100 risk score
    """
    score = 0.0
    
    if not ports_data.open_ports:
        return 0.0
    
    # Base score for number of ports
    port_count = len(ports_data.open_ports)
    if port_count > 20:
        score += 30
    elif port_count > 10:
        score += 20
    elif port_count > 5:
        score += 10
    
    # Heavy penalty for dangerous ports
    for port_obj in ports_data.open_ports:
        if port_obj.port == 22:  # SSH
            score += 10
        elif port_obj.port == 3306:  # MySQL
            score += 30
        elif port_obj.port == 5432:  # PostgreSQL
            score += 30
        elif port_obj.port == 27017:  # MongoDB
            score += 35
        elif port_obj.port == 6379:  # Redis
            score += 35
        elif port_obj.port == 2375:  # Docker
            score += 40
        elif port_obj.port == 9200:  # Elasticsearch
            score += 35
        elif port_obj.port == 3389:  # RDP
            score += 25
        elif port_obj.port in [80, 443]:  # Web servers
            score += 5
    
    return min(score, 100.0)

def get_port_risk_description(ports_data: OpenPortsData) -> str:
    """Get human-readable risk description for open ports"""
    if not ports_data.open_ports:
        return "No open ports detected - secure configuration"
    
    if ports_data.exposure_level == "critical":
        return "CRITICAL: Exposed databases or container engines detected!"
    elif ports_data.exposure_level == "high":
        return "HIGH: Multiple services exposed - investigate immediately"
    elif ports_data.exposure_level == "medium":
        return "MEDIUM: Several ports open - review for necessity"
    else:
        return "LOW: Standard services open - likely normal"

# ════════════════════════════════════════════════════════════════════════════════
# PORT ANALYSIS & RECOMMENDATIONS
# ════════════════════════════════════════════════════════════════════════════════

def get_port_recommendations(ports_data: OpenPortsData) -> List[str]:
    """Get security recommendations based on open ports"""
    recommendations = []
    
    for port_obj in ports_data.open_ports:
        if port_obj.port == 22:
            recommendations.append("🔒 SSH (22): Restrict to specific IPs using a firewall")
        elif port_obj.port == 3306:
            recommendations.append("🚨 MySQL (3306): NEVER expose to public! Move behind firewall/VPN")
        elif port_obj.port == 5432:
            recommendations.append("🚨 PostgreSQL (5432): NEVER expose to public! Move behind firewall/VPN")
        elif port_obj.port == 27017:
            recommendations.append("🚨 MongoDB (27017): CRITICAL! Immediately block this port from internet")
        elif port_obj.port == 6379:
            recommendations.append("🚨 Redis (6379): CRITICAL! Disable external access immediately")
        elif port_obj.port == 2375:
            recommendations.append("🚨 Docker (2375): CRITICAL! This allows full container access!")
        elif port_obj.port == 9200:
            recommendations.append("⚠️ Elasticsearch (9200): Add authentication and restrict access")
        elif port_obj.port == 3389:
            recommendations.append("⚠️ RDP (3389): Restrict to specific IPs, use VPN if possible")
        elif port_obj.port == 23:
            recommendations.append("⚠️ Telnet (23): Deprecated! Use SSH instead")
    
    if not recommendations:
        recommendations.append("✅ Standard web services open - appears normal")
    
    return recommendations
