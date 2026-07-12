"""UPnP/SSDP device discovery."""

import socket
import logging
import time
from typing import List

from ..hunter.models import IoTDevice

logger = logging.getLogger(__name__)

SSDP_MULTICAST = "239.255.255.250"
SSDP_PORT = 1900

SSDP_MSEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    "MAN: \"ssdp:discover\"\r\n"
    "MX: 3\r\n"
    "ST: ssdp:all\r\n"
    "\r\n"
)


class UPnPDiscovery:
    """Discover devices using UPnP/SSDP."""

    def __init__(self, timeout: int = 3):
        self.timeout = timeout

    def discover(self) -> List[IoTDevice]:
        """Send SSDP M-SEARCH and collect responses."""
        devices = []
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            sock.settimeout(self.timeout)
            sock.sendto(SSDP_MSEARCH.encode(), (SSDP_MULTICAST, SSDP_PORT))

            start = time.time()
            while time.time() - start < self.timeout:
                try:
                    data, addr = sock.recvfrom(4096)
                    device = self._parse_response(data.decode("utf-8", errors="ignore"), addr[0])
                    if device:
                        devices.append(device)
                except socket.timeout:
                    break

            sock.close()
        except Exception as e:
            logger.debug(f"UPnP discovery error: {e}")

        return devices

    def _parse_response(self, response: str, ip: str) -> IoTDevice:
        """Parse SSDP response into IoTDevice."""
        headers = {}
        for line in response.split("\r\n"):
            if ":" in line:
                key, _, value = line.partition(":")
                headers[key.strip().upper()] = value.strip()

        if not headers:
            return None

        return IoTDevice(
            ip_address=ip,
            hostname=headers.get("SERVER", ""),
            discovery_method="upnp",
            protocols=["upnp"],
            metadata={
                "st": headers.get("ST", ""),
                "location": headers.get("LOCATION", ""),
                "server": headers.get("SERVER", ""),
            }
        )
