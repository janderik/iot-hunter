"""CoAP device discovery."""

import socket
import struct
import logging
from typing import List

from ..hunter.models import IoTDevice

logger = logging.getLogger(__name__)

COAP_MULTICAST = "224.0.1.187"
COAP_PORT = 5683


class CoAPDiscovery:
    """Discover IoT devices using CoAP (Constrained Application Protocol)."""

    def __init__(self, timeout: int = 3):
        self.timeout = timeout

    def discover(self) -> List[IoTDevice]:
        """Send CoAP GET to well-known URI for device discovery."""
        devices = []
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)

            # CoAP GET for /.well-known/core
            packet = self._build_coap_request()
            sock.sendto(packet, (COAP_MULTICAST, COAP_PORT))

            import time
            start = time.time()
            while time.time() - start < self.timeout:
                try:
                    data, addr = sock.recvfrom(1024)
                    device = self._parse_response(data, addr[0])
                    if device:
                        devices.append(device)
                except socket.timeout:
                    break

            sock.close()
        except Exception as e:
            logger.debug(f"CoAP discovery error: {e}")

        return devices

    def _build_coap_request(self) -> bytes:
        """Build CoAP GET request for /.well-known/core."""
        # CoAP header: Version(2) | Type(0=CON) | Token Length(0)
        header = 0x40  # Ver=1, Type=CON, TKL=0
        code = 0x01    # GET
        msg_id = 0x0001

        # URI path: /.well-known/core
        uri_path = bytes([
            0x0B, 0x77, 0x65, 0x6C, 0x6C, 0x2D, 0x6B,  # .well-
            0x6E, 0x6F, 0x77, 0x6E,                      # known
            0x04, 0x63, 0x6F, 0x72, 0x65                 # core
        ])

        return bytes([header, code]) + struct.pack(">H", msg_id) + uri_path

    def _parse_response(self, data: bytes, ip: str) -> IoTDevice:
        """Parse CoAP response."""
        if len(data) < 4:
            return None

        return IoTDevice(
            ip_address=ip,
            discovery_method="coap",
            protocols=["coap"],
        )
