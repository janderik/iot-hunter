"""Main IoT device discovery engine."""

import logging
import socket
import struct
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional

from .models import IoTDevice, DeviceType
from .config import HunterConfig
from ..discovery.upnp import UPnPDiscovery
from ..discovery.mdns import MDNSDiscovery
from ..discovery.network import NetworkScanner

logger = logging.getLogger(__name__)


class HunterEngine:
    """Core IoT device discovery engine."""

    def __init__(self, config: Optional[HunterConfig] = None):
        self.config = config or HunterConfig()
        self._devices: dict = {}

    def scan(self, network: str = None) -> List[IoTDevice]:
        """Scan network for IoT devices.

        Args:
            network: CIDR network to scan (overrides config)

        Returns:
            List of discovered IoT devices
        """
        target = network or self.config.network
        logger.info(f"Scanning network: {target}")

        # Run discovery methods in parallel
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = []

            if "upnp" in self.config.protocols:
                futures.append(executor.submit(self._run_upnp, target))
            if "mdns" in self.config.protocols:
                futures.append(executor.submit(self._run_mdns, target))
            if "network" in self.config.protocols:
                futures.append(executor.submit(self._run_network_scan, target))

            for future in as_completed(futures):
                try:
                    devices = future.result()
                    for device in devices:
                        self._devices[device.ip_address] = device
                except Exception as e:
                    logger.error(f"Discovery error: {e}")

        return list(self._devices.values())

    def check_device(self, ip_address: str) -> Optional[IoTDevice]:
        """Perform detailed check on a specific device."""
        device = self._devices.get(ip_address)
        if not device:
            device = IoTDevice(ip_address=ip_address)
            self._devices[ip_address] = device

        # Fingerprint the device
        device = self._fingerprint_device(device)

        # Check vulnerabilities
        if self.config.check_vulns:
            from ..vulns.checker import VulnerabilityChecker
            checker = VulnerabilityChecker()
            device.vulnerabilities = checker.check(device)

        return device

    def _run_upnp(self, network: str) -> List[IoTDevice]:
        """Run UPnP discovery."""
        discovery = UPnPDiscovery()
        return discovery.discover()

    def _run_mdns(self, network: str) -> List[IoTDevice]:
        """Run mDNS discovery."""
        discovery = MDNSDiscovery()
        return discovery.discover()

    def _run_network_scan(self, network: str) -> List[IoTDevice]:
        """Run network port scan."""
        scanner = NetworkScanner(self.config)
        return scanner.scan(network)

    def _fingerprint_device(self, device: IoTDevice) -> IoTDevice:
        """Fingerprint a device to determine type and manufacturer."""
        from ..fingerprint.http import HTTPFingerprinter
        fp = HTTPFingerprinter()
        info = fp.fingerprint(device.ip_address)

        if info:
            device.manufacturer = info.get("manufacturer", "")
            device.model = info.get("model", "")
            device.firmware_version = info.get("firmware", "")
            device.hostname = info.get("hostname", "")
            device.device_type = self._classify_device(info)

        return device

    def _classify_device(self, info: dict) -> DeviceType:
        """Classify device type based on fingerprint info."""
        product = (info.get("server", "") + info.get("model", "")).lower()
        if any(kw in product for kw in ["camera", "rtsp", "ipc"]):
            return DeviceType.CAMERA
        elif any(kw in product for kw in ["router", "gateway", "ap"]):
            return DeviceType.ROUTER
        elif any(kw in product for kw in ["echo", "google", "speaker"]):
            return DeviceType.SMART_SPEAKER
        elif any(kw in product for kw in ["thermostat", "nest"]):
            return DeviceType.THERMOSTAT
        return DeviceType.UNKNOWN

    def get_devices(self) -> List[IoTDevice]:
        return list(self._devices.values())
