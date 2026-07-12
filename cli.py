#!/usr/bin/env python3
"""iot-hunter CLI - IoT Device Discovery and Security Assessment."""

import argparse
import json
import sys
import logging

from src.hunter.engine import HunterEngine
from src.hunter.config import HunterConfig


def main():
    parser = argparse.ArgumentParser(prog="iot-hunter", description="IoT Device Discovery Toolkit")
    parser.add_argument("-v", "--verbose", action="store_true")

    sub = parser.add_subparsers(dest="command")

    scan_p = sub.add_parser("scan", help="Scan network for IoT devices")
    scan_p.add_argument("--network", default="192.168.1.0/24")
    scan_p.add_argument("-f", "--format", choices=["table", "json", "csv"], default="table")
    scan_p.add_argument("-o", "--output")

    disc_p = sub.add_parser("discover", help="Discover devices via protocol")
    disc_p.add_argument("--protocol", choices=["upnp", "mdns", "coap", "all"], default="all")

    check_p = sub.add_parser("check", help="Check device for vulnerabilities")
    check_p.add_argument("--target", required=True)

    mon_p = sub.add_parser("monitor", help="Monitor for new devices")
    mon_p.add_argument("-d", "--duration", type=int, default=60)

    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(level=log_level, format="%(asctime)s [%(levelname)s] %(message)s")

    if not args.command:
        parser.print_help()
        sys.exit(1)

    config = HunterConfig()
    engine = HunterEngine(config)

    if args.command == "scan":
        devices = engine.scan(args.network)
        if args.format == "json":
            output = json.dumps([d.to_dict() for d in devices], indent=2)
        elif args.format == "csv":
            output = "ip,hostname,type,manufacturer,ports\n"
            for d in devices:
                output += f"{d.ip_address},{d.hostname},{d.device_type.value},{d.manufacturer},{';'.join(map(str, d.open_ports))}\n"
        else:
            output = f"{'IP':<16} {'Hostname':<20} {'Type':<15} {'Manufacturer':<15} {'Ports'}\n"
            output += "-" * 90 + "\n"
            for d in devices:
                output += f"{d.ip_address:<16} {d.hostname[:19]:<20} {d.device_type.value:<15} {d.manufacturer[:14]:<15} {d.open_ports}\n"
            output += f"\nTotal: {len(devices)} devices found"

        if args.output:
            with open(args.output, "w") as f:
                f.write(output)
        else:
            print(output)

    elif args.command == "discover":
        devices = engine.scan()
        print(f"Discovered {len(devices)} devices")
        for d in devices:
            print(f"  {d.ip_address} - {d.hostname or 'Unknown'} ({d.discovery_method})")

    elif args.command == "check":
        device = engine.check_device(args.target)
        print(f"\n=== Device: {device.ip_address} ===")
        print(f"Type: {device.device_type.value}")
        print(f"Manufacturer: {device.manufacturer}")
        print(f"Open ports: {device.open_ports}")
        print(f"Risk score: {device.risk_score}")
        if device.vulnerabilities:
            print(f"\nVulnerabilities ({len(device.vulnerabilities)}):")
            for v in device.vulnerabilities:
                print(f"  [{v.risk_level.value.upper()}] {v.title}")
                print(f"    {v.description}")
                print(f"    Fix: {v.remediation}")

    elif args.command == "monitor":
        print(f"Monitoring for {args.duration} seconds...")
        import time
        seen = set()
        start = time.time()
        while time.time() - start < args.duration:
            devices = engine.scan()
            for d in devices:
                if d.ip_address not in seen:
                    seen.add(d.ip_address)
                    print(f"  [NEW] {d.ip_address} - {d.hostname or 'Unknown'} ({d.device_type.value})")
            time.sleep(10)
        print(f"\nMonitoring complete. {len(seen)} unique devices seen.")


if __name__ == "__main__":
    main()
