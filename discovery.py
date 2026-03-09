import nmap
import json
import csv
import argparse
import subprocess
import ipaddress
from datetime import datetime


def detect_network_gateway_and_local_ip():
    try:
        route = subprocess.check_output(
            "ip route | grep default", shell=True, text=True
        ).strip()

        parts = route.split()
        gateway = parts[2]
        interface = parts[4]

        ip_info = subprocess.check_output(
            f"ip -o -f inet addr show {interface}", shell=True, text=True
        ).strip()

        cidr = ip_info.split()[3]
        interface_ip = cidr.split("/")[0]
        network = str(ipaddress.ip_interface(cidr).network)

        return network, gateway, interface_ip

    except Exception:
        return "10.0.0.0/24", "N/A", "N/A"


def determine_role(ip, gateway, local_ip):
    if ip == gateway:
        return "Gateway"
    elif ip == local_ip:
        return "Local Host"
    return "Device"


def print_table(devices):
    headers = ["IP", "ROLE", "HOSTNAME", "STATE", "MAC", "VENDOR"]

    rows = []
    for device in devices:
        rows.append([
            device["ip"],
            device["role"],
            device["hostname"],
            device["state"],
            device["mac"],
            device["vendor"]
        ])

    col_widths = []
    for i, header in enumerate(headers):
        max_width = len(header)
        for row in rows:
            max_width = max(max_width, len(str(row[i])))
        col_widths.append(max_width)

    header_line = "  ".join(
        header.ljust(col_widths[i]) for i, header in enumerate(headers)
    )
    separator_line = "  ".join(
        "-" * col_widths[i] for i in range(len(headers))
    )

    print(header_line)
    print(separator_line)

    for row in rows:
        print("  ".join(
            str(row[i]).ljust(col_widths[i]) for i in range(len(headers))
        ))


def main():
    parser = argparse.ArgumentParser(description="Network Asset Discovery Tool")
    parser.add_argument(
        "--network",
        help="Network range to scan (example: 10.0.0.0/24)"
    )
    args = parser.parse_args()

    detected_network, gateway, local_ip = detect_network_gateway_and_local_ip()
    network = args.network if args.network else detected_network

    scanner = nmap.PortScanner()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(f"\nScanning network: {network}")
    print(f"Gateway detected: {gateway}")
    print(f"Local host IP: {local_ip}")
    print(f"Scan time: {timestamp}\n")

    scanner.scan(hosts=network, arguments="-sn")

    devices = []

    for host in scanner.all_hosts():
        host_data = scanner[host]
        addresses = host_data.get("addresses", {})
        vendor_info = host_data.get("vendor", {})

        mac = addresses.get("mac", "N/A")
        vendor = vendor_info.get(mac, "N/A")
        role = determine_role(host, gateway, local_ip)

        device = {
            "ip": host,
            "role": role,
            "hostname": host_data.hostname() or "N/A",
            "state": host_data.state(),
            "mac": mac,
            "vendor": vendor,
            "scan_time": timestamp
        }

        devices.append(device)

    devices.sort(key=lambda d: ipaddress.ip_address(d["ip"]))

    print("Devices discovered:\n")
    print_table(devices)

    with open("scan_results.json", "w") as json_file:
        json.dump(devices, json_file, indent=4)

    with open("scan_results.csv", "w", newline="") as csv_file:
        writer = csv.DictWriter(
            csv_file,
            fieldnames=["ip", "role", "hostname", "state", "mac", "vendor", "scan_time"]
        )
        writer.writeheader()
        writer.writerows(devices)

    print("\nResults saved to scan_results.json and scan_results.csv\n")


if __name__ == "__main__":
    main()
