"""Data models for IoT device discovery."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict


class DeviceType(Enum):
    CAMERA = "camera"
    ROUTER = "router"
    SMART_SPEAKER = "smart_speaker"
    THERMOSTAT = "thermostat"
    LIGHT_BULB = "light_bulb"
    SENSOR = "sensor"
    GATEWAY = "gateway"
    SMART_TV = "smart_tv"
    PRINTER = "printer"
    UNKNOWN = "unknown"


class RiskLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class IoTDevice:
    """Represents a discovered IoT device."""
    ip_address: str
    mac_address: str = ""
    hostname: str = ""
    device_type: DeviceType = DeviceType.UNKNOWN
    manufacturer: str = ""
    model: str = ""
    firmware_version: str = ""
    open_ports: List[int] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)
    protocols: List[str] = field(default_factory=list)
    discovery_method: str = ""
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    vulnerabilities: List["Vulnerability"] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)

    @property
    def risk_score(self) -> int:
        """Compute risk score based on vulnerabilities."""
        score = 0
        for vuln in self.vulnerabilities:
            if vuln.risk_level == RiskLevel.CRITICAL:
                score += 10
            elif vuln.risk_level == RiskLevel.HIGH:
                score += 7
            elif vuln.risk_level == RiskLevel.MEDIUM:
                score += 4
            elif vuln.risk_level == RiskLevel.LOW:
                score += 1
        return score

    def to_dict(self) -> dict:
        return {
            "ip": self.ip_address,
            "mac": self.mac_address,
            "hostname": self.hostname,
            "type": self.device_type.value,
            "manufacturer": self.manufacturer,
            "model": self.model,
            "firmware": self.firmware_version,
            "ports": self.open_ports,
            "services": self.services,
            "protocols": self.protocols,
            "risk_score": self.risk_score,
            "vulns": len(self.vulnerabilities),
        }


@dataclass
class Vulnerability:
    """Represents a vulnerability found on a device."""
    cve_id: str = ""
    title: str = ""
    description: str = ""
    risk_level: RiskLevel = RiskLevel.MEDIUM
    affected_component: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
