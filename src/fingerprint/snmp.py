"""SNMP-based device discovery."""

import socket
import struct
import logging
from typing import Optional, Dict

logger = logging.getLogger(__name__)


class SNMPFingerprinter:
    """Fingerprint devices via SNMP."""

    def __init__(self, community: str = "public", timeout: int = 3):
        self.community = community
        self.timeout = timeout

    def query(self, ip: str, oid: str = "1.3.6.1.2.1.1.1.0") -> Optional[str]:
        """Query a device via SNMP."""
        # Simplified SNMP GET request
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)

            packet = self._build_get_request(oid)
            sock.sendto(packet, (ip, 161))

            data, _ = sock.recvfrom(1024)
            sock.close()

            return self._parse_response(data)
        except Exception as e:
            logger.debug(f"SNMP query failed for {ip}: {e}")
            return None

    def _build_get_request(self, oid: str) -> bytes:
        """Build SNMP GET request packet."""
        # Simplified - real implementation would use proper ASN.1 encoding
        oid_parts = [int(x) for x in oid.split(".")]
        oid_bytes = bytes(oid_parts)

        community = self.community.encode()
        packet = bytearray([
            0x30, 0x00,  # SEQUENCE, length placeholder
            0x02, 0x01, 0x01,  # Version: SNMPv1
            0x04, len(community),
        ]) + community + bytearray([
            0xA0, 0x00,  # GET request
            0x02, 0x01, 0x00,  # Request ID
            0x02, 0x01, 0x00,  # Error status
            0x02, 0x01, 0x00,  # Error index
            0x30, len(oid_bytes) + 4,
            0x30, len(oid_bytes) + 2,
            0x06, len(oid_bytes),
        ]) + oid_bytes + bytearray([0x05, 0x00])

        # Fix lengths
        packet[1] = len(packet) - 2
        return bytes(packet)

    def _parse_response(self, data: bytes) -> Optional[str]:
        """Parse SNMP response to extract value."""
        try:
            # Very simplified parsing
            if len(data) > 20:
                return data[20:].decode("utf-8", errors="ignore").strip("\x00")
        except Exception:
            pass
        return None
