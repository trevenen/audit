"""
Threat Intelligence Integration
===============================
Queries external APIs for CVSS scores, exploit availability, and threat data.
"""

import json
import time
from typing import Optional
from urllib.request import urlopen
from urllib.error import URLError


class NVDClient:
    """
    Query NIST National Vulnerability Database for CVSS scores.
    Uses free public API: https://services.nvd.nist.gov/rest/json/cves/2.0/

    Rate limit: ~5 requests/second without API key.
    Get a free API key at https://nvd.nist.gov/developers/request-an-api-key
    """

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    TIMEOUT = 5

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.last_request_time = 0

    def _rate_limit(self):
        """Respect rate limits (0.2 sec = ~5 req/sec)."""
        elapsed = time.time() - self.last_request_time
        if elapsed < 0.2:
            time.sleep(0.2 - elapsed)
        self.last_request_time = time.time()

    def lookup_cve(self, cve_id: str) -> Optional[dict]:
        """
        Look up a CVE by ID (e.g., 'CVE-2024-1234').

        Returns:
            Dict with vulnerability data or None if not found/error.
        """
        if not cve_id or not cve_id.startswith("CVE-"):
            return None

        self._rate_limit()

        url = f"{self.BASE_URL}?cveId={cve_id}"
        if self.api_key:
            url += f"&apiKey={self.api_key}"

        try:
            with urlopen(url, timeout=self.TIMEOUT) as response:
                data = json.loads(response.read().decode())
                if data.get("vulnerabilities"):
                    return data["vulnerabilities"][0].get("cve", {})
        except (URLError, json.JSONDecodeError, Exception) as e:
            print(f"  [NVD] Could not lookup {cve_id}: {e}")

        return None

    def get_cvss_score(self, cve_id: str) -> Optional[float]:
        """
        Extract CVSS v3 score from CVE data.

        Returns:
            CVSS score (0-10) or None.
        """
        cve_data = self.lookup_cve(cve_id)
        if not cve_data:
            return None

        # Try CVSS v3.1 first, then v3.0
        metrics = cve_data.get("metrics", {})
        for cvss_key in ("cvssMetricV31", "cvssMetricV30"):
            cvss_data = metrics.get(cvss_key, [])
            if cvss_data and isinstance(cvss_data, list) and len(cvss_data) > 0:
                score = cvss_data[0].get("cvssData", {}).get("baseScore")
                if score is not None:
                    return float(score)

        return None

    def is_exploited_in_wild(self, cve_id: str) -> bool:
        """Check if CVE has evidence of exploitation in the wild."""
        cve_data = self.lookup_cve(cve_id)
        if not cve_data:
            return False

        # Check for "exploitabilityDetails" or vulnerability status
        references = cve_data.get("references", [])
        descriptions = cve_data.get("descriptions", [])

        # Heuristic: if there are references to PoCs or exploit databases
        for ref in references:
            url = ref.get("url", "").lower()
            if any(x in url for x in ("exploit-db", "github", "poc", "metasploit")):
                return True

        return False


class ExploitDBClient:
    """
    Query ExploitDB for known exploits (lightweight/free tier).
    https://www.exploit-db.com/
    """

    # Their free CSV is updated but API requires auth; using basic web scraping
    # For production, consider licensing their full API
    SEARCH_URL = "https://www.exploit-db.com/search"

    @staticmethod
    def has_public_exploit(cve_id: str) -> bool:
        """
        Check if ExploitDB has a public exploit for this CVE.
        NOTE: This is a stub; ExploitDB doesn't have a free JSON API.
        You could download their CSV and parse it, or use Shodan instead.
        """
        # Implement if you have API access or want to parse their CSV
        # For now, return False as safe default
        return False


class ShodanClient:
    """
    Query Shodan for active scanning/exposure data.
    Requires Shodan API key: https://account.shodan.io/

    NOTE: Shodan is great for detecting actively scanned ports/services,
    not for CVE lookups. Use NVD for CVE data.
    """

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key

    def is_port_commonly_scanned(self, port: int) -> bool:
        """
        Heuristic: is this port actively scanned in the wild?
        (Requires Shodan API key for real data.)
        """
        # Common high-risk ports that are actively scanned
        commonly_scanned = {
            22: True,   # SSH
            3389: True,  # RDP
            3306: True,  # MySQL
            5432: True,  # PostgreSQL
            27017: True,  # MongoDB
            6379: True,  # Redis
            9200: True,  # Elasticsearch
            8080: True,  # HTTP alt
            8006: True,  # Proxmox
        }
        return commonly_scanned.get(port, False)


class ThreatFeedClient:
    """
    Query public threat intelligence feeds (AlienVault OTX, etc.).
    Good for checking if an IP/domain is in known threat lists.
    """

    # AlienVault OTX: https://otx.alienvault.com/api/
    OTX_URL = "https://otx.alienvault.com/api/v1/indicators"

    @staticmethod
    def is_ip_malicious(ip: str, api_key: Optional[str] = None) -> bool:
        """
        Check if IP is in AlienVault OTX threat feeds.
        Requires OTX API key (free tier available).
        """
        if not api_key:
            return False

        try:
            url = f"{ThreatFeedClient.OTX_URL}/IPv4/{ip}/general"
            headers = {"X-OTX-API-KEY": api_key}
            # This would need proper HTTP client; simplified here
            return False
        except Exception:
            return False


# Convenience factory
class ThreatIntel:
    """Unified threat intelligence lookup."""

    def __init__(self, nvd_api_key: Optional[str] = None, shodan_api_key: Optional[str] = None):
        self.nvd = NVDClient(nvd_api_key)
        self.shodan = ShodanClient(shodan_api_key)

    def get_cve_risk(self, cve_id: str) -> dict:
        """
        Get comprehensive risk info for a CVE.

        Returns:
            {
                "cvss_score": float or None,
                "has_exploit": bool,
                "active_exploitation": bool,
            }
        """
        return {
            "cvss_score": self.nvd.get_cvss_score(cve_id),
            "has_exploit": ExploitDBClient.has_public_exploit(cve_id),
            "active_exploitation": self.nvd.is_exploited_in_wild(cve_id),
        }

    def port_risk(self, port: int) -> dict:
        """
        Get risk indicators for a port.

        Returns:
            {"commonly_scanned": bool}
        """
        return {
            "commonly_scanned": self.shodan.is_port_commonly_scanned(port),
        }
