"""
ip_geo_enrich.py
----------------
Geolocate one or more IP addresses using the ip-api.com API (free tier,
no key required for single lookups) and flag anomalies relevant to SOC
investigation: VPN/proxy/Tor exit nodes, datacentre hosting, known
high-risk countries, and impossible travel between two sign-in IPs.

Inputs:
    ip_address  : str  — an IPv4 or IPv6 address to enrich
    baseline_ip : str  — (optional) a previously known good IP for the same
                          user, used to calculate impossible travel

Outputs (dict):
    {
        "ip":               str   — the queried IP address
        "country":          str   — country name (e.g. "United States")
        "country_code":     str   — ISO 3166-1 alpha-2 (e.g. "US")
        "region":           str   — region/state name
        "city":             str   — city name
        "lat":              float — latitude
        "lon":              float — longitude
        "isp":              str   — Internet Service Provider name
        "org":              str   — Organisation name (AS description)
        "asn":              str   — Autonomous System Number (e.g. "AS15169")
        "is_vpn":           bool  — True if flagged as VPN/proxy by ip-api
        "is_tor":           bool  — True if flagged as Tor exit node
        "is_datacenter":    bool  — True if flagged as hosting/datacenter IP
        "is_high_risk_geo": bool  — True if country is in the high-risk list
        "impossible_travel":bool  — True if travel from baseline_ip is physically impossible
        "travel_km":        float — estimated distance from baseline IP in km
        "travel_time_h":    float — hours elapsed between the two sign-in times (if provided)
        "anomaly_flags":    list  — plain-language list of triggered anomaly flags
        "error":            str | None
    }

Usage:
    python ip_geo_enrich.py

Environment variables:
    HIGH_RISK_COUNTRIES  — comma-separated ISO country codes to treat as high-risk
                           Defaults to a conservative built-in list if not set.
                           Example: export HIGH_RISK_COUNTRIES="KP,IR,RU,CN,BY"

    IMPOSSIBLE_TRAVEL_SPEED_KPH — max plausible travel speed in km/h between sign-ins
                                   Default: 900 (approximate max commercial flight speed)

Note:
    ip-api.com free tier allows 45 requests/minute without a key.
    For production use, consider a paid tier or MaxMind GeoIP2 with a local database.
    The 'proxy' field in ip-api requires the 'pro' plan. This script uses the
    free endpoint and supplements with ASN/org name heuristics for VPN/DC detection.
"""

import os
import math
import datetime
import requests


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

IP_API_URL = "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,lat,lon,isp,org,as,proxy,hosting,query"

# High-risk country codes — customisable via environment variable
DEFAULT_HIGH_RISK_COUNTRIES = {"KP", "IR", "BY", "CU", "SY"}
_env_high_risk = os.environ.get("HIGH_RISK_COUNTRIES", "")
HIGH_RISK_COUNTRIES = (
    set(c.strip().upper() for c in _env_high_risk.split(",") if c.strip())
    if _env_high_risk
    else DEFAULT_HIGH_RISK_COUNTRIES
)

# Maximum plausible travel speed in km/h (commercial aviation ≈ 900 km/h)
MAX_TRAVEL_SPEED_KPH = float(os.environ.get("IMPOSSIBLE_TRAVEL_SPEED_KPH", 900))

# Keywords in ISP/org names that strongly suggest VPN or datacenter infrastructure
VPN_ORG_KEYWORDS = [
    "nordvpn", "expressvpn", "mullvad", "protonvpn", "surfshark",
    "private internet access", "pia", "cyberghost", "hotspot shield",
    "torguard", "windscribe", "ipvanish",
]
DATACENTER_ORG_KEYWORDS = [
    "amazon", "aws", "google cloud", "azure", "microsoft", "digitalocean",
    "linode", "vultr", "hetzner", "ovh", "rackspace", "cloudflare",
    "fastly", "akamai", "leaseweb", "choopa", "packet", "equinix",
]


# ---------------------------------------------------------------------------
# Helper: Haversine distance between two lat/lon points
# ---------------------------------------------------------------------------

def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculate the great-circle distance in km between two coordinates."""
    R = 6371.0  # Earth's radius in km
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


# ---------------------------------------------------------------------------
# Helper: heuristic VPN / datacenter detection from org name
# ---------------------------------------------------------------------------

def _heuristic_flags(isp: str, org: str, is_proxy: bool, is_hosting: bool):
    """Return (is_vpn, is_datacenter) based on ip-api flags and org name heuristics."""
    combined = (isp + " " + org).lower()
    is_vpn = is_proxy or any(kw in combined for kw in VPN_ORG_KEYWORDS)
    is_datacenter = is_hosting or any(kw in combined for kw in DATACENTER_ORG_KEYWORDS)
    return is_vpn, is_datacenter


# ---------------------------------------------------------------------------
# Core enrichment function
# ---------------------------------------------------------------------------

def enrich_ip(
    ip_address: str,
    baseline_ip: str = None,
    baseline_lat: float = None,
    baseline_lon: float = None,
    hours_elapsed: float = None,
) -> dict:
    """
    Geolocate an IP address and flag SOC-relevant anomalies.

    Parameters
    ----------
    ip_address : str
        The IP to enrich.
    baseline_ip : str, optional
        A previously known good IP for the same user (for travel calculation).
        If provided without baseline_lat/lon, will be geolocated automatically.
    baseline_lat : float, optional
        Latitude of the baseline location (skips second API call if provided).
    baseline_lon : float, optional
        Longitude of the baseline location (skips second API call if provided).
    hours_elapsed : float, optional
        Time in hours between the baseline sign-in and the current sign-in.
        Required for impossible travel calculation.

    Returns
    -------
    dict
        Enrichment result including geo data, anomaly flags, and travel analysis.
    """
    result = {
        "ip": ip_address,
        "country": "",
        "country_code": "",
        "region": "",
        "city": "",
        "lat": 0.0,
        "lon": 0.0,
        "isp": "",
        "org": "",
        "asn": "",
        "is_vpn": False,
        "is_tor": False,
        "is_datacenter": False,
        "is_high_risk_geo": False,
        "impossible_travel": False,
        "travel_km": 0.0,
        "travel_time_h": hours_elapsed or 0.0,
        "anomaly_flags": [],
        "error": None,
    }

    # --- Query ip-api for the primary IP ---
    try:
        response = requests.get(
            IP_API_URL.format(ip=ip_address), timeout=10
        )
        response.raise_for_status()
        data = response.json()
    except requests.exceptions.ConnectionError:
        result["error"] = "Network error: could not reach ip-api.com."
        return result
    except requests.exceptions.Timeout:
        result["error"] = "Request timed out after 10 seconds."
        return result
    except requests.exceptions.HTTPError as e:
        result["error"] = f"HTTP error: {e}"
        return result

    if data.get("status") != "success":
        result["error"] = f"ip-api error: {data.get('message', 'unknown')}"
        return result

    # Populate geo fields
    result.update({
        "country": data.get("country", ""),
        "country_code": data.get("countryCode", ""),
        "region": data.get("regionName", ""),
        "city": data.get("city", ""),
        "lat": data.get("lat", 0.0),
        "lon": data.get("lon", 0.0),
        "isp": data.get("isp", ""),
        "org": data.get("org", ""),
        "asn": data.get("as", ""),
    })

    # VPN / datacenter flags
    is_vpn, is_datacenter = _heuristic_flags(
        result["isp"], result["org"],
        bool(data.get("proxy")), bool(data.get("hosting"))
    )
    result["is_vpn"] = is_vpn
    result["is_datacenter"] = is_datacenter

    # Tor detection — ip-api proxy field covers Tor exit nodes on paid plan
    # On free plan we use a simple heuristic: "tor" in org name
    result["is_tor"] = "tor" in (result["isp"] + result["org"]).lower()

    # High-risk geography
    result["is_high_risk_geo"] = result["country_code"] in HIGH_RISK_COUNTRIES

    # --- Impossible travel calculation ---
    if baseline_ip and hours_elapsed is not None:
        # Get baseline coordinates (use provided or re-query)
        if baseline_lat is None or baseline_lon is None:
            try:
                b_resp = requests.get(
                    IP_API_URL.format(ip=baseline_ip), timeout=10
                ).json()
                baseline_lat = b_resp.get("lat", 0.0)
                baseline_lon = b_resp.get("lon", 0.0)
            except Exception:
                baseline_lat, baseline_lon = 0.0, 0.0

        if baseline_lat and baseline_lon:
            distance_km = _haversine_km(
                baseline_lat, baseline_lon, result["lat"], result["lon"]
            )
            result["travel_km"] = round(distance_km, 1)

            # If time is very small, avoid division by zero
            if hours_elapsed > 0.05:
                required_speed = distance_km / hours_elapsed
                result["impossible_travel"] = required_speed > MAX_TRAVEL_SPEED_KPH
            elif distance_km > 100:
                # Essentially simultaneous sign-ins from different cities
                result["impossible_travel"] = True

    # --- Build anomaly flag list ---
    flags = []
    if result["is_vpn"]:
        flags.append("VPN or anonymous proxy detected — source IP may mask true location")
    if result["is_tor"]:
        flags.append("Tor exit node detected — high anonymity, frequently abused")
    if result["is_datacenter"]:
        flags.append("Datacenter/cloud IP — sign-in from infrastructure, not a user device")
    if result["is_high_risk_geo"]:
        flags.append(f"High-risk geography: {result['country']} ({result['country_code']})")
    if result["impossible_travel"]:
        flags.append(
            f"IMPOSSIBLE TRAVEL: {result['travel_km']} km in {hours_elapsed:.1f} hours "
            f"(requires >{result['travel_km']/max(hours_elapsed,0.01):.0f} km/h)"
        )

    result["anomaly_flags"] = flags
    return result


# ---------------------------------------------------------------------------
# Example / smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=== Single IP Enrichment ===")
    r = enrich_ip("185.220.101.45")  # Known Tor exit node example
    print(f"IP            : {r['ip']}")
    print(f"Location      : {r['city']}, {r['region']}, {r['country']}")
    print(f"ASN / ISP     : {r['asn']} / {r['isp']}")
    print(f"VPN           : {r['is_vpn']}")
    print(f"Tor           : {r['is_tor']}")
    print(f"Datacenter    : {r['is_datacenter']}")
    print(f"High-risk geo : {r['is_high_risk_geo']}")
    print(f"Anomaly flags : {r['anomaly_flags']}")

    print("\n=== Impossible Travel Example ===")
    # Simulate: user signed in from London (51.5,-0.1) 30 minutes ago,
    # now signing in from an IP geolocating to Tokyo
    r2 = enrich_ip(
        "203.0.113.55",         # Replace with a real Tokyo-geolocated IP
        baseline_lat=51.5074,   # London latitude
        baseline_lon=-0.1278,   # London longitude
        hours_elapsed=0.5,      # 30 minutes between sign-ins
    )
    print(f"IP              : {r2['ip']}")
    print(f"Location        : {r2['city']}, {r2['country']}")
    print(f"Distance        : {r2['travel_km']} km")
    print(f"Impossible?     : {r2['impossible_travel']}")
    print(f"Anomaly flags   : {r2['anomaly_flags']}")
