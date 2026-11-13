"""
WAF Client for testing payloads against the live Web Application Firewall.
"""

import time
from typing import Optional
import requests
from requests.adapters import HTTPAdapter

# Shared session with connection pooling for high throughput and keep-alive
_session = requests.Session()
_adapter = HTTPAdapter(pool_connections=50, pool_maxsize=50)
_session.mount("http://", _adapter)
_session.mount("https://", _adapter)


def check_waf(payload: str, base_url: str = "http://localhost:8080") -> Optional[int]:
    """
    Sends payload as 'q' param to /search on base_url.

    Returns:
        1 if HTTP 403 (blocked by WAF)
        0 otherwise (allowed)
        None if connection error persists after 1 retry
    """
    url = f"{base_url.rstrip('/')}/search"
    params = {"q": payload}

    for attempt in range(2):
        try:
            resp = _session.get(url, params=params, timeout=5.0)
            return 1 if resp.status_code == 403 else 0
        except (requests.ConnectionError, requests.Timeout, requests.RequestException):
            if attempt == 1:
                return None
            time.sleep(0.5)

    return None


if __name__ == "__main__":
    test_payloads = [
        "shoes",
        "' OR 1=1 --",
        "<script>alert(1)</script>",
    ]

    print("=== Testing WAF Client against http://localhost:8080 ===")
    for p in test_payloads:
        result = check_waf(p)
        status_desc = "BLOCKED (1)" if result == 1 else ("ALLOWED (0)" if result == 0 else "ERROR (None)")
        print(f"Payload: {p!r:<30} -> WAF Result: {result} ({status_desc})")
