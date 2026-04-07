"""
Run this script on Render to download MMDB files at build time.
Usage: python download_mmdb.py
Requires: MAXMIND_LICENSE_KEY environment variable set in Render dashboard.
"""
import os
import urllib.request
import tarfile
from pathlib import Path

LICENSE_KEY = os.environ.get("MAXMIND_LICENSE_KEY", "")
BASE_DIR = Path(__file__).parent
MMDB_DIR = BASE_DIR / "mmdb"
MMDB_DIR.mkdir(exist_ok=True)

DATABASES = [
    ("GeoLite2-ASN",  "GeoLite2-ASN.mmdb"),
    ("GeoLite2-City", "GeoLite2-City.mmdb"),
]

if not LICENSE_KEY:
    print("⚠  MAXMIND_LICENSE_KEY not set — skipping MMDB download")
    raise SystemExit(0)

for edition, filename in DATABASES:
    dest = MMDB_DIR / filename
    if dest.exists():
        print(f"✓ {filename} already exists, skipping")
        continue
    url = (
        f"https://download.maxmind.com/app/geoip_download"
        f"?edition_id={edition}&license_key={LICENSE_KEY}&suffix=tar.gz"
    )
    tar_path = MMDB_DIR / f"{edition}.tar.gz"
    print(f"↓ Downloading {edition}...")
    urllib.request.urlretrieve(url, tar_path)
    with tarfile.open(tar_path, "r:gz") as tar:
        for member in tar.getmembers():
            if member.name.endswith(".mmdb"):
                member.name = filename
                tar.extract(member, MMDB_DIR)
                break
    tar_path.unlink()
    print(f"✓ {filename} saved")

print("All MMDB files ready.")
