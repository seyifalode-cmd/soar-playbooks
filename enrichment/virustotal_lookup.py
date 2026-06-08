"""
virustotal_lookup.py
--------------------
Query the VirusTotal v3 API to look up the reputation of a file hash,
IP address, or URL.

Inputs:
    indicator   : str  — a SHA256/MD5 file hash, IPv4 address, or URL
    ioc_type    : str  — "hash", "ip", or "url"

Outputs (dict):
    {
        "indicator":        str   — the original indicator
        "type":             str   — "hash" | "ip" | "url"
        "malicious":        int   — number of engines flagging as malicious
        "suspicious":       int   — number of engines flagging as suspicious
        "harmless":         int   — number of engines flagging as harmless
        "total_engines":    int   — total engines that analysed the indicator
        "verdict":          str   — "MALICIOUS" | "SUSPICIOUS" | "CLEAN" | "UNKNOWN"
        "permalink":        str   — URL to the full VirusTotal report
        "last_analysis":    str   — ISO 8601 timestamp of last analysis
        "error":            str | None — error message if the request failed
    }

Usage:
    python virustotal_lookup.py

Environment variables required:
    VT_API_KEY   — your VirusTotal API key
                   Set with: export VT_API_KEY="your_api_key_here"
                   DO NOT hard-code secrets in this file.

Error handling:
    - Missing API key raises EnvironmentError
    - HTTP errors are caught and returned in the "error" field
    - Rate limit (429) is detected and reported clearly
    - Unknown indicator types raise ValueError
"""

import os
import hashlib
import base64
import datetime
import requests


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

VT_API_KEY = os.environ.get("VT_API_KEY")  # Load from environment — never hard-code
VT_BASE_URL = "https://www.virustotal.com/api/v3"

VERDICT_THRESHOLDS = {
    "MALICIOUS": 5,   # ≥ 5 malicious votes → MALICIOUS
    "SUSPICIOUS": 1,  # ≥ 1 malicious or suspicious vote → SUSPICIOUS
}


# ---------------------------------------------------------------------------
# Helper: build the correct API endpoint for each IOC type
# ---------------------------------------------------------------------------

def _build_endpoint(indicator: str, ioc_type: str) -> str:
    """Return the VirusTotal v3 API endpoint for the given indicator type."""
    if ioc_type == "hash":
        return f"{VT_BASE_URL}/files/{indicator.lower()}"
    elif ioc_type == "ip":
        return f"{VT_BASE_URL}/ip_addresses/{indicator}"
    elif ioc_type == "url":
        # VirusTotal requires the URL to be base64url-encoded (no padding)
        encoded = base64.urlsafe_b64encode(indicator.encode()).decode().rstrip("=")
        return f"{VT_BASE_URL}/urls/{encoded}"
    else:
        raise ValueError(f"Unknown ioc_type '{ioc_type}'. Must be 'hash', 'ip', or 'url'.")


# ---------------------------------------------------------------------------
# Helper: derive a verdict from analysis stats
# ---------------------------------------------------------------------------

def _derive_verdict(malicious: int, suspicious: int, total: int) -> str:
    """Map raw engine counts to a human-readable verdict."""
    if total == 0:
        return "UNKNOWN"
    if malicious >= VERDICT_THRESHOLDS["MALICIOUS"]:
        return "MALICIOUS"
    if malicious >= VERDICT_THRESHOLDS["SUSPICIOUS"] or suspicious >= 3:
        return "SUSPICIOUS"
    return "CLEAN"


# ---------------------------------------------------------------------------
# Core lookup function
# ---------------------------------------------------------------------------

def virustotal_lookup(indicator: str, ioc_type: str) -> dict:
    """
    Query VirusTotal for the reputation of a hash, IP, or URL.

    Parameters
    ----------
    indicator : str
        The IOC to look up (SHA256 hash, IPv4, or full URL).
    ioc_type : str
        One of: "hash", "ip", "url"

    Returns
    -------
    dict
        Structured result with verdict, engine counts, permalink, and
        any error information. Never raises — errors are returned in
        the 'error' field so callers can handle them gracefully.
    """
    result = {
        "indicator": indicator,
        "type": ioc_type,
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "total_engines": 0,
        "verdict": "UNKNOWN",
        "permalink": "",
        "last_analysis": "",
        "error": None,
    }

    # Validate API key is present
    if not VT_API_KEY:
        result["error"] = (
            "VT_API_KEY environment variable is not set. "
            "Export your VirusTotal API key before running: "
            "export VT_API_KEY='your_api_key_here'"
        )
        return result

    # Build endpoint
    try:
        endpoint = _build_endpoint(indicator, ioc_type)
    except ValueError as e:
        result["error"] = str(e)
        return result

    headers = {"x-apikey": VT_API_KEY}

    # Make the API request
    try:
        response = requests.get(endpoint, headers=headers, timeout=15)
    except requests.exceptions.ConnectionError:
        result["error"] = "Network error: could not reach VirusTotal API."
        return result
    except requests.exceptions.Timeout:
        result["error"] = "Request timed out after 15 seconds."
        return result

    # Handle HTTP error codes
    if response.status_code == 404:
        result["verdict"] = "UNKNOWN"
        result["error"] = "Indicator not found in VirusTotal database (may be new/zero-day)."
        return result

    if response.status_code == 401:
        result["error"] = "Authentication failed. Check your VT_API_KEY value."
        return result

    if response.status_code == 429:
        result["error"] = "Rate limit exceeded. VirusTotal free tier: 4 lookups/min, 500/day."
        return result

    if response.status_code != 200:
        result["error"] = f"Unexpected HTTP {response.status_code}: {response.text[:200]}"
        return result

    # Parse response JSON
    try:
        data = response.json()
        attributes = data["data"]["attributes"]
        stats = attributes.get("last_analysis_stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total = malicious + suspicious + harmless + undetected

        # Parse last analysis date
        last_analysis_epoch = attributes.get("last_analysis_date", 0)
        if last_analysis_epoch:
            last_analysis_str = datetime.datetime.utcfromtimestamp(
                last_analysis_epoch
            ).isoformat() + "Z"
        else:
            last_analysis_str = "unknown"

        # Build permalink
        if ioc_type == "hash":
            permalink = f"https://www.virustotal.com/gui/file/{indicator.lower()}"
        elif ioc_type == "ip":
            permalink = f"https://www.virustotal.com/gui/ip-address/{indicator}"
        else:
            permalink = f"https://www.virustotal.com/gui/url/{indicator}"

        result.update({
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "total_engines": total,
            "verdict": _derive_verdict(malicious, suspicious, total),
            "permalink": permalink,
            "last_analysis": last_analysis_str,
        })

    except (KeyError, ValueError) as e:
        result["error"] = f"Failed to parse VirusTotal response: {e}"

    return result


# ---------------------------------------------------------------------------
# Example / smoke test — runs when called directly
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # --- Replace these with real IOCs for live testing ---
    test_cases = [
        # Known malicious hash (NotPetya / EternalBlue — safe to query, not to execute)
        ("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "hash"),
        # Google DNS — should be clean
        ("8.8.8.8", "ip"),
        # Example URL (replace with a real phishing URL for live testing)
        ("https://example-phishing-site.com/login", "url"),
    ]

    for indicator, ioc_type in test_cases:
        print(f"\n{'='*60}")
        print(f"Querying VirusTotal for [{ioc_type}]: {indicator}")
        result = virustotal_lookup(indicator, ioc_type)
        if result["error"]:
            print(f"  ERROR: {result['error']}")
        else:
            print(f"  Verdict      : {result['verdict']}")
            print(f"  Malicious    : {result['malicious']} / {result['total_engines']} engines")
            print(f"  Suspicious   : {result['suspicious']} / {result['total_engines']} engines")
            print(f"  Last analysis: {result['last_analysis']}")
            print(f"  Report URL   : {result['permalink']}")
