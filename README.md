# iot-hunter

[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![IoT](https://img.shields.io/badge/IoT-UPnP%20mDNS%20CoAP-blue.svg)]()
[![Code Style](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

---

**IoT device discovery and security assessment toolkit for identifying connected devices across networks.**

`iot-hunter` discovers, fingerprints, and assesses IoT devices using multiple discovery protocols including UPnP, mDNS, CoAP, and network scanning. It identifies device types, checks for known vulnerabilities, and generates security reports.

---

## Architecture

```
iot-hunter/
├── src/
│   ├── hunter/            # Core engine
│   │   ├── __init__.py
│   │   ├── engine.py      # Main discovery engine
│   │   ├── models.py      # Device and vulnerability models
│   │   └── config.py      # Configuration
│   ├── discovery/         # Discovery protocols
│   │   ├── __init__.py
│   │   ├── upnp.py        # UPnP/SSDP discovery
│   │   ├── mdns.py        # mDNS/Bonjour discovery
│   │   ├── coap.py        # CoAP device discovery
│   │   └── network.py     # Network scanning
│   ├── fingerprint/       # Device fingerprinting
│   │   ├── __init__.py
│   │   ├── http.py        # HTTP fingerprinting
│   │   ├── snmp.py        # SNMP discovery
│   │   └── protocol.py    # Protocol identification
│   └── vulns/             # Vulnerability checks
│       ├── __init__.py
│       ├── checker.py     # Vulnerability checker
│       ├── database.py    # Known vulnerability database
│       └── default_creds.py  # Default credential checker
├── cli.py
├── requirements.txt
├── setup.py
├── Dockerfile
├── docker-compose.yml
├── .gitignore
└── LICENSE
```

## Features

- **Multi-protocol discovery** - UPnP, mDNS, CoAP, network scanning
- **Device fingerprinting** - HTTP headers, SNMP, service identification
- **Vulnerability checking** - Known CVEs, default credentials, weak configs
- **Real-time monitoring** - Continuous device discovery
- **Report generation** - JSON, HTML, CSV output formats

## Installation

```bash
git clone https://github.com/janderik/iot-hunter.git
cd iot-hunter
pip install -e .
```

## Usage

```bash
# Scan local network
iot-hunter scan --network 192.168.1.0/24

# UPnP discovery
iot-hunter discover --protocol upnp

# mDNS discovery
iot-hunter discover --protocol mdns

# Check device for vulnerabilities
iot-hunter check --target 192.168.1.100

# Monitor for new devices
iot-hunter monitor --duration 300
```

## IoT Security Landscape

### Common IoT Vulnerabilities
- Default credentials (admin/admin, root/root)
- Unencrypted communications (HTTP, Telnet)
- Outdated firmware with known CVEs
- Exposed services (SSH, MQTT, RTSP)
- Weak authentication mechanisms

### Discovery Protocols
- **UPnP/SSDP** - Universal Plug and Play for device discovery
- **mDNS** - Multicast DNS for local service discovery
- **CoAP** - Constrained Application Protocol for IoT devices
- **MQTT** - Message Queuing Telemetry Transport
- **Zigbee/Z-Wave** - Low-power wireless protocols

## License

MIT License - see [LICENSE](LICENSE)
