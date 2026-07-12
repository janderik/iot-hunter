"""Protocol-based fingerprinting."""

from typing import Dict, Optional


class ProtocolFingerprinter:
    """Identify services and protocols running on devices."""

    PROTOCOL_SIGNATURES = {
        b"RTSP/": "RTSP",
        b"HTTP/": "HTTP",
        b"MQTT": "MQTT",
        b"\x16\x03": "TLS",
        b"SSH-": "SSH",
        b"220 ": "FTP/SMTP",
    }

    def identify(self, ip: str, port: int, banner: bytes = b"") -> Optional[str]:
        """Identify protocol from banner or connection behavior."""
        for sig, proto in self.PROTOCOL_SIGNATURES.items():
            if banner.startswith(sig):
                return proto
        return None

    def grab_banner(self, ip: str, port: int, timeout: int = 3) -> bytes:
        """Grab service banner from a port."""
        import socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            banner = sock.recv(1024)
            sock.close()
            return banner
        except Exception:
            return b""
