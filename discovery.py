import nmap
import json
import csv
import argparse
from datetime import datetime


def main():
    parser = argparse.ArgumentParser(description="Network Asset Discovery Tool")
    parser.add_argument(
        "--network",
        default="10.0.0.0/24",
        help="Network range to scan, example: 10.0.0.0/24"
    )
    args = parser.parse_args()

    scanner = nmap.PortScanner()
    network = args.network
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(f"Scanning network: {network}")
    print(f"Scan time: {timestamp}")

    scanner.scan(hosts=network, arguments="-sn")

    devices = []

    for host in scanner.all_hosts():
        host_data = scanner[host]
        addresses = host_data.get("addresses", {})
        vendor_info = host_data.get("vendor", {})

        mac = addresses.get("mac", "N/A")
        vendor = vendor_info.get(mac, "N/A")

        device = {
            "ip": host,
            "hostname": host_data.hostname(),
            "state": host_data.state(),
            "mac": mac,
            "vendor": vendor,
            "scan_time": timestamp
        }

        devices.append(device)

    print("\nDevices found:\n")
    for device in devices:
        print(device)

    with open("scan_results.json", "w") as json_file:
        json.dump(devices, json_file, indent=4)

    with open("scan_results.csv", "w", newline="") as csv_file:
        writer = csv.DictWriter(
            csv_file,
            fieldnames=["ip", "hostname", "state", "mac", "vendor", "scan_time"]
        )
        writer.writeheader()
        writer.writerows(devices)

    print("\nResults saved to scan_results.json and scan_results.csv")


if __name__ == "__main__":
    main()
