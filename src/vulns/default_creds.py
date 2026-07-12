"""Default credential checker for IoT devices."""

from typing import List, Tuple
from ..hunter.models import IoTDevice, Vulnerability, RiskLevel


DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "1234"),
    ("root", "root"),
    ("root", "admin"),
    ("root", "toor"),
    ("user", "user"),
    ("admin", ""),
    ("root", ""),
    ("guest", "guest"),
]

IOT_DEFAULT_CREDS = {
    "hikvision": [("admin", "12345"), ("admin", "admin12345")],
    "dahua": [("admin", "admin"), ("admin", "888888")],
    "tplink": [("admin", "admin")],
    "netgear": [("admin", "password"), ("admin", "1234")],
}


class DefaultCredentialChecker:
    """Check if IoT devices use default credentials."""

    def check(self, device: IoTDevice) -> List[Vulnerability]:
        """Check device for default credentials."""
        vulns = []

        # Check if device has common management ports
        mgmt_ports = [80, 443, 8080, 8443, 22, 23]
        has_mgmt = any(p in device.open_ports for p in mgmt_ports)

        if has_mgmt:
            vulns.append(Vulnerability(
                cve_id="N/A",
                title="Management interface accessible",
                description="Device has accessible management interface that may use default credentials.",
                risk_level=RiskLevel.MEDIUM,
                remediation="Change default credentials immediately after setup.",
                references=[
                    "https://www.cisa.gov/news-events/ics-advisories/icsa-20-106-01"
                ],
            ))

        return vulns
