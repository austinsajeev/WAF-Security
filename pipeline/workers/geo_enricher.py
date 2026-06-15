"""
AegisAI-X — Geo + ASN Enricher
================================
Reads validated request logs from ClickHouse that are missing country_code/asn,
enriches them using MaxMind GeoLite2 local databases, and updates in place.

- Uses offline MaxMind GeoLite2-City and GeoLite2-ASN databases (zero external calls)
- lru_cache for repeated IPs (near-zero cost)
- Run as a sidecar worker alongside hmac_worker

Requirements:
    pip install geoip2

Database files must be mounted at:
    /var/lib/aegisai/geoip/GeoLite2-City.mmdb
    /var/lib/aegisai/geoip/GeoLite2-ASN.mmdb

Get free databases from: https://www.maxmind.com/en/geolite2/signup
"""

import os
import time
import logging
import clickhouse_connect
from functools import lru_cache
from datetime import datetime, timezone, timedelta

log = logging.getLogger("aegisai.geo_enricher")
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

CH_HOST     = os.environ.get("CH_HOST", "clickhouse")
CH_USER     = os.environ.get("CH_USER", "aegisai")
CH_PASSWORD = os.environ.get("CH_PASSWORD", "aegisai_ch_pass")
CH_DB       = os.environ.get("CH_DB", "aegisai_db")

CITY_DB_PATH = os.environ.get("GEOIP_CITY_DB", "/var/lib/aegisai/geoip/GeoLite2-City.mmdb")
ASN_DB_PATH  = os.environ.get("GEOIP_ASN_DB",  "/var/lib/aegisai/geoip/GeoLite2-ASN.mmdb")
POLL_INTERVAL = int(os.environ.get("GEO_POLL_INTERVAL", "60"))  # seconds

# ---------------------------------------------------------------------------
# GeoIP Reader (lazy init — skips gracefully if DBs not mounted)
# ---------------------------------------------------------------------------
_city_reader = None
_asn_reader  = None

def _init_readers():
    global _city_reader, _asn_reader
    try:
        import geoip2.database
        if os.path.exists(CITY_DB_PATH):
            _city_reader = geoip2.database.Reader(CITY_DB_PATH)
            log.info("GeoLite2-City loaded from %s", CITY_DB_PATH)
        else:
            log.warning("GeoLite2-City DB not found at %s — skipping geo enrichment", CITY_DB_PATH)

        if os.path.exists(ASN_DB_PATH):
            _asn_reader = geoip2.database.Reader(ASN_DB_PATH)
            log.info("GeoLite2-ASN loaded from %s", ASN_DB_PATH)
        else:
            log.warning("GeoLite2-ASN DB not found at %s — skipping ASN enrichment", ASN_DB_PATH)
    except ImportError:
        log.warning("geoip2 library not installed — geo enrichment disabled. Run: pip install geoip2")


@lru_cache(maxsize=10_000)
def lookup_geo(ip: str) -> tuple[str, int, str]:
    """Return (country_code, asn, asn_org) for an IP. Cached per process lifetime."""
    country_code = ""
    asn          = 0
    asn_org      = ""

    try:
        if _city_reader:
            resp = _city_reader.city(ip)
            country_code = resp.country.iso_code or ""
    except Exception:
        pass

    try:
        if _asn_reader:
            resp = _asn_reader.asn(ip)
            asn     = resp.autonomous_system_number or 0
            asn_org = resp.autonomous_system_organization or ""
    except Exception:
        pass

    return country_code, asn, asn_org


# ---------------------------------------------------------------------------
# Enrichment Loop
# ---------------------------------------------------------------------------
def enrich_batch(ch):
    """Find request_logs rows with blank country_code and enrich them."""
    # Read a batch of un-enriched IPs
    result = ch.query("""
        SELECT DISTINCT remote_addr
        FROM request_logs
        WHERE country_code = ''
          AND timestamp >= now() - INTERVAL 1 HOUR
        LIMIT 500
    """)

    if not result.row_count:
        return 0

    enriched = 0
    for row in result.named_results():
        ip = str(row["remote_addr"])
        country_code, asn, asn_org = lookup_geo(ip)
        if not country_code and not asn:
            continue

        ch.command(f"""
            ALTER TABLE request_logs UPDATE
                country_code = '{country_code}',
                asn = {asn},
                asn_org = '{asn_org.replace("'", "''")}'
            WHERE remote_addr = toIPv4('{ip}')
              AND timestamp >= now() - INTERVAL 1 HOUR
              AND country_code = ''
        """)
        enriched += 1

    log.info("Geo-enriched %d IPs", enriched)
    return enriched


def run():
    log.info("AegisAI-X Geo Enricher starting...")
    _init_readers()

    if not _city_reader and not _asn_reader:
        log.warning("No GeoIP databases loaded. Worker will idle until databases are mounted.")

    ch = clickhouse_connect.get_client(
        host=CH_HOST, port=8123, username=CH_USER,
        password=CH_PASSWORD, database=CH_DB, secure=False
    )

    while True:
        try:
            enrich_batch(ch)
        except Exception as e:
            log.exception("Error during enrichment cycle: %s", e)
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    run()
