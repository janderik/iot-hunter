"""Network scanning for IoT device discovery."""

import socket
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

from ..hunter.models import IoTDevice, DeviceType
from ..hunter.config import HunterConfig

logger = logging.getLogger(__name__)

COMMON_IOT_PORTS = {
    80: "HTTP",
    443: "HTTPS",
    554: "RTSP",
    1883: "MQTT",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    1900: "UPnP",
    5353: "mDNS",
    5683: "CoAP",
    22: "SSH",
    23: "Telnet",
    8883: "MQTTS",
    9100: "Printer",
}


class NetworkScanner:
    """Scan network ranges for IoT devices."""

    def __init__(self, config: HunterConfig):
        self.config = config

    def scan(self, network: str) -> List[IoTDevice]:
        """Scan a network CIDR for open IoT ports."""
        devices = []
        hosts = self._expand_network(network)

        with ThreadPoolExecutor(max_workers=self.config.max_threads) as executor:
            futures = {executor.submit(self._scan_host, h): h for h in hosts}
            for future in as_completed(futures):
                host = futures[future]
                try:
                    device = future.result()
                    if device:
                        devices.append(device)
                except Exception as e:
                    logger.debug(f"Error scanning {host}: {e}")

        return devices

    def _scan_host(self, host: str) -> IoTDevice:
        """Scan a single host for open IoT ports."""
        open_ports = []

        for port in self.config.scan_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((host, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except Exception:
                pass

        if not open_ports:
            return None

        services = {}
        for port in open_ports:
            services[port] = COMMON_IOT_PORTS.get(port, "unknown")

        device = IoTDevice(
            ip_address=host,
            open_ports=open_ports,
            services=services,
            discovery_method="network",
            device_type=self._classify_by_ports(open_ports),
        )

        return device

    def _expand_network(self, network: str) -> List[str]:
        """Expand CIDR notation to list of IPs."""
        if "/" not in network:
            return [network]

        ip_str, cidr = network.split("/")
        cidr = int(cidr)
        ip_int = struct.unpack("!I", socket.inet_aton(ip_str))[0]
        mask = (0xFFFFFFFF << (32 - cidr)) & 0xFFFFFFFF
        network_int = ip_int & mask
        broadcast = network_int | (~mask & 0xFFFFFFFF)

        hosts = []
        for i in range(network_int + 1, broadcast):
            hosts.append(socket.inet_ntoa(struct.pack("!I", i)))

        return hosts

    def _classify_by_ports(self, ports: List[int]) -> DeviceType:
        """Classify device type based on open ports."""
        if 554 in ports:
            return DeviceType.CAMERA
        elif 9100 in ports:
            return DeviceType.PRINTER
        elif 1883 in ports or 8883 in ports:
            return DeviceType.SENSOR
        elif 80 in ports or 443 in ports:
            return DeviceType.GATEWAY
        return DeviceType.UNKNOWN

    def _expand_network(self, network: str) -> List[str]:
        """Expand CIDR notation to list of IPs."""
        import struct as _struct
        if "/" not in network:
            return [network]
        ip_str, cidr = network.split("/")
        cidr = int(cidr)
        ip_int = _struct.unpack("!I", socket.inet_aton(ip_str))[0]
        mask = (0xFFFFFFFF << (32 - cidr)) & 0xFFFFFFFF
        network_int = ip_int & mask
        broadcast = network_int | (~mask & 0xFFFFFFFF)
        return [socket.inet_ntoa(_struct.pack("!I", i)) for i in range(network_int + 1, min(broadcast, network_int + 256))]
