"""mDNS/Bonjour device discovery."""

import socket
import struct
import logging
from typing import List

from ..hunter.models import IoTDevice

logger = logging.getLogger(__name__)

MDNS_ADDR = "224.0.0.251"
MDNS_PORT = 5353

MDNS_QUERY = bytearray([
    0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x04, 0x5f, 0x68, 0x74,
    0x74, 0x70, 0x04, 0x5f, 0x74, 0x63, 0x70, 0x05,
    0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00, 0x00, 0x0c,
    0x00, 0x01,
])


class MDNSDiscovery:
    """Discover devices using mDNS (multicast DNS)."""

    def __init__(self, timeout: int = 3):
        self.timeout = timeout

    def discover(self) -> List[IoTDevice]:
        """Send mDNS query and collect responses."""
        devices = []
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(self.timeout)

            sock.setsockopt(
                socket.IPPROTO_IP,
                socket.IP_ADD_MEMBERSHIP,
                struct.pack("4s4s",
                           socket.inet_aton(MDNS_ADDR),
                           socket.inet_aton("0.0.0.0"))
            )

            sock.sendto(MDNS_QUERY, (MDNS_ADDR, MDNS_PORT))

            import time
            start = time.time()
            while time.time() - start < self.timeout:
                try:
                    data, addr = sock.recvfrom(4096)
                    device = self._parse_response(data, addr[0])
                    if device:
                        devices.append(device)
                except socket.timeout:
                    break

            sock.close()
        except Exception as e:
            logger.debug(f"mDNS discovery error: {e}")

        return devices

    def _parse_response(self, data: bytes, ip: str) -> IoTDevice:
        """Parse mDNS response."""
        if len(data) < 12:
            return None

        return IoTDevice(
            ip_address=ip,
            discovery_method="mdns",
            protocols=["mdns"],
        )
