"""Vulnerability checker for IoT devices."""

import logging
from typing import List

from ..hunter.models import IoTDevice, Vulnerability, RiskLevel

logger = logging.getLogger(__name__)


class VulnerabilityChecker:
    """Check IoT devices for known vulnerabilities."""

    def check(self, device: IoTDevice) -> List[Vulnerability]:
        """Check a device for vulnerabilities."""
        vulns = []

        # Check for common IoT issues
        if 23 in device.open_ports:
            vulns.append(Vulnerability(
                cve_id="N/A",
                title="Telnet service exposed",
                description="Telnet transmits data in cleartext, including credentials.",
                risk_level=RiskLevel.HIGH,
                remediation="Disable Telnet and use SSH instead.",
            ))

        if 1883 in device.open_ports and 8883 not in device.open_ports:
            vulns.append(Vulnerability(
                cve_id="N/A",
                title="MQTT without TLS",
                description="MQTT broker accessible without encryption.",
                risk_level=RiskLevel.MEDIUM,
                remediation="Enable TLS on port 8883 for MQTT communications.",
            ))

        if 554 in device.open_ports:
            vulns.append(Vulnerability(
                cve_id="N/A",
                title="RTSP camera accessible",
                description="RTSP video stream may be accessible without authentication.",
                risk_level=RiskLevel.HIGH,
                remediation="Require authentication and use RTSPS (TLS).",
            ))

        if 1900 in device.open_ports:
            vulns.append(Vulnerability(
                cve_id="N/A",
                title="UPnP/SSDP exposed",
                description="UPnP service may allow unauthorized device configuration.",
                risk_level=RiskLevel.MEDIUM,
                remediation="Disable UPnP if not needed or restrict to internal network.",
            ))

        return vulns
