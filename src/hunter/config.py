"""Hunter configuration."""
import json
import os
from dataclasses import dataclass, field
from typing import Optional, List


@dataclass
class HunterConfig:
    network: str = "192.168.1.0/24"
    protocols: List[str] = field(default_factory=lambda: ["upnp", "mdns", "network"])
    timeout: int = 5
    max_threads: int = 50
    scan_ports: List[int] = field(default_factory=lambda: [80, 443, 554, 1883, 8080, 8443, 1900, 5353])
    check_vulns: bool = True
    check_default_creds: bool = True
    output_format: str = "table"
    output_file: Optional[str] = None

    @classmethod
    def from_file(cls, path: str) -> "HunterConfig":
        if not os.path.exists(path):
            return cls()
        with open(path) as f:
            data = json.load(f)
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}
