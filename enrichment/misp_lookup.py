"""
misp_lookup.py
--------------
Query a MISP (Malware Information Sharing Platform) instance for a given
indicator of compromise (IOC). Returns all matching attributes, associated
events, threat actor tags, and a confidence assessment.

MISP is an open-source threat intelligence platform used by ISACs, CERTs,
and SOC teams to share and correlate IOCs. This script uses the MISP REST API
directly (via requests) rather than PyMISP, so there are no extra dependencies
beyond the standard library + requests.

Inputs:
    indicator   : str  — a file hash (MD5/SHA1/SHA256), IP address, domain,
                          email address, or URL
    ioc_type    : str  — "hash" | "ip" | "domain" | "email" | "url"

Outputs (dict):
    {
        "indicator":        str   — the queried indicator
        "type":             str   — normalised MISP attribute type
        "found":            bool  — True if at least one match was found
        "match_count":      int   — number of matching attributes in MISP
        "events":           list  — list of associated MISP events (id, info, date, tags)
        "threat_actors":    list  — threat actor tags extracted from event galaxy clusters
        "tlp":              str   — highest TLP level seen across matching events
        "confidence":       str   — "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN"
        "first_seen":       str   — earliest event date (ISO 8601)
        "last_seen":        str   — most recent event date (ISO 8601)
        "error":            str | None
    }

Usage:
    python misp_lookup.py

Environment variables required:
    MISP_URL      — base URL of your MISP instance (e.g. https://misp.yourdomain.com)
                    Set with: export MISP_URL="https://misp.yourdomain.com"
    MISP_API_KEY  — your MISP automation key (found in MISP under My Profile → Auth keys)
                    Set with: export MISP_API_KEY="your_misp_auth_key_here"
                    DO NOT hard-code secrets in this file.
    MISP_VERIFY_SSL — set to "false" to skip TLS verification for self-signed certs
                      Default: "true". For production, always use a valid certificate.

Note:
    MISP attribute type mapping:
        "hash"   → searches MD5, SHA1, SHA256 attribute types
        "ip"     → searches ip-dst, ip-src attribute types
        "domain" → searches domain, hostname attribute types
        "email"  → searches email-src, email-dst attribute types
        "url"    → searches url attribute type
"""

import os
import requests
from urllib.parse import urljoin


# ---------------------------------------------------------------------------
# Configuration — loaded from environment variables
# ---------------------------------------------------------------------------

MISP_URL = os.environ.get("MISP_URL", "")            # e.g. https://misp.example.com
MISP_API_KEY = os.environ.get("MISP_API_KEY", "")    # Your MISP automation key
MISP_VERIFY_SSL = os.environ.get("MISP_VERIFY_SSL", "true").lower() != "false"

# Map our generic IOC types to MISP attribute type lists for the search query
IOC_TYPE_MAP = {
    "hash":   ["md5", "sha1", "sha256", "sha512", "ssdeep", "tlsh"],
    "ip":     ["ip-dst", "ip-src", "ip-dst|port", "ip-src|port"],
    "domain": ["domain", "hostname", "domain|ip"],
    "email":  ["email-src", "email-dst", "email-reply-to"],
    "url":    ["url", "link"],
}

# TLP ranking for determining the highest TLP across events
TLP_RANK = {"TLP:WHITE": 0, "TLP:GREEN": 1, "TLP:AMBER": 2, "TLP:RED": 3}


# ---------------------------------------------------------------------------
# Helper: extract threat actor names from MISP galaxy clusters / tags
# ---------------------------------------------------------------------------

def _extract_threat_actors(tags: list) -> list:
    """
    Extract threat actor names from MISP event tags.
    MISP galaxy clusters use the format: misp-galaxy:threat-actor="GroupName"
    """
    actors = []
    for tag in tags:
        tag_name = tag.get("name", "") if isinstance(tag, dict) else str(tag)
        if "threat-actor" in tag_name.lower():
            # Extract the value between quotes: misp-galaxy:threat-actor="APT28"
            if '"' in tag_name:
                actor = tag_name.split('"')[1]
                if actor and actor not in actors:
                    actors.append(actor)
    return actors


# ---------------------------------------------------------------------------
# Helper: extract TLP from tags
# ---------------------------------------------------------------------------

def _extract_tlp(tags: list) -> str:
    """Return the highest TLP level found in the event's tag list."""
    highest = "TLP:WHITE"
    for tag in tags:
        tag_name = tag.get("name", "") if isinstance(tag, dict) else str(tag)
        for tlp in TLP_RANK:
            if tlp in tag_name.upper():
                if TLP_RANK[tlp] > TLP_RANK[highest]:
                    highest = tlp
    return highest


# ---------------------------------------------------------------------------
# Helper: derive confidence from match count and event recency
# ---------------------------------------------------------------------------

def _derive_confidence(match_count: int, event_count: int) -> str:
    """Simple heuristic: more independent events = higher confidence."""
    if event_count >= 3 or match_count >= 5:
        return "HIGH"
    if event_count >= 1 or match_count >= 2:
        return "MEDIUM"
    if match_count == 1:
        return "LOW"
    return "UNKNOWN"


# ---------------------------------------------------------------------------
# Core MISP lookup function
# ---------------------------------------------------------------------------

def misp_lookup(indicator: str, ioc_type: str) -> dict:
    """
    Search a MISP instance for a given indicator of compromise.

    Parameters
    ----------
    indicator : str
        The IOC value to search for.
    ioc_type : str
        One of: "hash", "ip", "domain", "email", "url"

    Returns
    -------
    dict
        Structured result. Errors are returned in the 'error' field —
        this function never raises so callers can handle failures gracefully.
    """
    result = {
        "indicator": indicator,
        "type": ioc_type,
        "found": False,
        "match_count": 0,
        "events": [],
        "threat_actors": [],
        "tlp": "TLP:WHITE",
        "confidence": "UNKNOWN",
        "first_seen": "",
        "last_seen": "",
        "error": None,
    }

    # Validate configuration
    if not MISP_URL:
        result["error"] = (
            "MISP_URL environment variable is not set. "
            "Export your MISP instance URL: export MISP_URL='https://misp.example.com'"
        )
        return result

    if not MISP_API_KEY:
        result["error"] = (
            "MISP_API_KEY environment variable is not set. "
            "Export your MISP automation key: export MISP_API_KEY='your_key_here'"
        )
        return result

    # Validate IOC type
    if ioc_type not in IOC_TYPE_MAP:
        result["error"] = (
            f"Unknown ioc_type '{ioc_type}'. "
            f"Must be one of: {list(IOC_TYPE_MAP.keys())}"
        )
        return result

    misp_types = IOC_TYPE_MAP[ioc_type]

    headers = {
        "Authorization": MISP_API_KEY,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    # Build the search payload
    # MISP REST API: POST /attributes/restSearch
    search_payload = {
        "returnFormat": "json",
        "value": indicator,
        "type": misp_types,
        "includeEventTags": True,
        "includeGalaxy": True,
        "limit": 100,
    }

    search_url = urljoin(MISP_URL.rstrip("/") + "/", "attributes/restSearch")

    try:
        response = requests.post(
            search_url,
            json=search_payload,
            headers=headers,
            verify=MISP_VERIFY_SSL,
            timeout=20,
        )
    except requests.exceptions.SSLError:
        result["error"] = (
            "SSL certificate verification failed. "
            "Set MISP_VERIFY_SSL=false if using a self-signed certificate (not recommended for production)."
        )
        return result
    except requests.exceptions.ConnectionError:
        result["error"] = f"Network error: could not reach MISP at {MISP_URL}"
        return result
    except requests.exceptions.Timeout:
        result["error"] = "MISP request timed out after 20 seconds."
        return result

    if response.status_code == 401:
        result["error"] = "Authentication failed. Check your MISP_API_KEY."
        return result

    if response.status_code == 403:
        result["error"] = "Forbidden. Your MISP API key may lack read permissions."
        return result

    if response.status_code != 200:
        result["error"] = f"Unexpected HTTP {response.status_code}: {response.text[:200]}"
        return result

    # Parse the response
    try:
        data = response.json()
        attributes = data.get("response", {}).get("Attribute", [])
    except (ValueError, KeyError) as e:
        result["error"] = f"Failed to parse MISP response: {e}"
        return result

    if not attributes:
        # No matches found — this is normal, not an error
        result["found"] = False
        return result

    result["found"] = True
    result["match_count"] = len(attributes)

    # Collect unique events referenced by matching attributes
    seen_event_ids = set()
    events_list = []
    all_tags = []
    all_dates = []

    for attr in attributes:
        event = attr.get("Event", {})
        event_id = event.get("id")

        if event_id and event_id not in seen_event_ids:
            seen_event_ids.add(event_id)
            event_tags = event.get("Tag", [])
            all_tags.extend(event_tags)

            event_date = event.get("date", "")
            if event_date:
                all_dates.append(event_date)

            events_list.append({
                "event_id": event_id,
                "title": event.get("info", ""),
                "date": event_date,
                "threat_level": event.get("threat_level_id", ""),
                "tags": [t.get("name", "") for t in event_tags if isinstance(t, dict)],
            })

    result["events"] = events_list
    result["threat_actors"] = _extract_threat_actors(all_tags)
    result["tlp"] = _extract_tlp(all_tags)
    result["confidence"] = _derive_confidence(result["match_count"], len(events_list))

    if all_dates:
        sorted_dates = sorted(all_dates)
        result["first_seen"] = sorted_dates[0]
        result["last_seen"] = sorted_dates[-1]

    return result


# ---------------------------------------------------------------------------
# Example / smoke test — runs when called directly
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # These will fail gracefully if MISP_URL and MISP_API_KEY are not set
    test_cases = [
        # Known malicious hash (replace with a real IOC from your MISP instance)
        ("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "hash"),
        # Known C2 IP (replace with a real IOC)
        ("185.220.101.45", "ip"),
        # Known phishing domain (replace with a real IOC)
        ("malicious-phishing-example.com", "domain"),
    ]

    for indicator, ioc_type in test_cases:
        print(f"\n{'='*60}")
        print(f"MISP lookup [{ioc_type}]: {indicator}")
        result = misp_lookup(indicator, ioc_type)

        if result["error"]:
            print(f"  ERROR: {result['error']}")
            continue

        print(f"  Found         : {result['found']}")
        print(f"  Match count   : {result['match_count']}")
        print(f"  Events        : {len(result['events'])}")
        print(f"  Threat actors : {result['threat_actors']}")
        print(f"  TLP           : {result['tlp']}")
        print(f"  Confidence    : {result['confidence']}")
        print(f"  First seen    : {result['first_seen']}")
        print(f"  Last seen     : {result['last_seen']}")
        if result["events"]:
            print("  Event titles  :")
            for ev in result["events"][:3]:
                print(f"    [{ev['event_id']}] {ev['date']} — {ev['title']}")
