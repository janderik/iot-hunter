"""HTTP-based device fingerprinting."""

import urllib.request
import urllib.error
import logging
from typing import Optional, Dict

logger = logging.getLogger(__name__)


class HTTPFingerprinter:
    """Fingerprint devices via HTTP responses."""

    def __init__(self, timeout: int = 3):
        self.timeout = timeout

    def fingerprint(self, ip: str, port: int = 80) -> Optional[Dict]:
        """Probe a device via HTTP for fingerprint information."""
        info = {}

        for scheme in ["http", "https"]:
            for path in ["/", "/favicon.ico", "/cgi-bin/main.cgi"]:
                url = f"{scheme}://{ip}:{port}{path}"
                try:
                    req = urllib.request.Request(url, method="HEAD")
                    req.add_header("User-Agent", "Mozilla/5.0")
                    context = __import__("ssl").create_default_context()
                    context.check_hostname = False
                    context.verify_mode = __import__("ssl").CERT_NONE
                    with urllib.request.urlopen(req, timeout=self.timeout, context=context) as resp:
                        headers = dict(resp.headers)
                        if "Server" in headers:
                            info["server"] = headers["Server"]
                        if "X-Powered-By" in headers:
                            info["powered_by"] = headers["X-Powered-By"]
                        if "WWW-Authenticate" in headers:
                            info["auth_required"] = True
                        break
                except Exception:
                    continue

        return info if info else None
