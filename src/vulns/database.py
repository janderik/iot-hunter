"""Known vulnerability database for IoT devices."""

from typing import List, Dict
from ..hunter.models import Vulnerability, RiskLevel


class VulnerabilityDatabase:
    """Database of known IoT vulnerabilities."""

    def __init__(self):
        self._entries = self._load_default_entries()

    def _load_default_entries(self) -> List[Dict]:
        return [
            {
                "cve": "CVE-2019-11219",
                "title": "Realtek SDK buffer overflow",
                "risk": RiskLevel.CRITICAL,
                "affected": ["realtek_sdk"],
            },
            {
                "cve": "CVE-2020-15366",
                "title": "LUPX command injection in OpenWrt",
                "risk": RiskLevel.HIGH,
                "affected": ["openwrt"],
            },
            {
                "cve": "CVE-2021-33054",
                "title": "D-Link camera auth bypass",
                "risk": RiskLevel.CRITICAL,
                "affected": ["dlink_camera"],
            },
        ]

    def search(self, vendor: str = "", product: str = "") -> List[Vulnerability]:
        """Search database for vulnerabilities matching criteria."""
        results = []
        for entry in self._entries:
            if vendor.lower() in str(entry.get("affected", [])).lower():
                results.append(Vulnerability(
                    cve_id=entry["cve"],
                    title=entry["title"],
                    risk_level=entry["risk"],
                ))
        return results
