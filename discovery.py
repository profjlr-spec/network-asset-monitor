import nmap
import json
import csv
import argparse
import subprocess
import ipaddress
import socket
from datetime import datetime


def detect_network_and_gateway():
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

        network = str(ipaddress.ip_interface(cidr).network)

        return network, gateway

    except Exception:
        return "10.0.0.0/24", "N/A"


def get_local_ip():
    try:
        return socket.gethostbyname(socket.gethostname())
    except Exception:
        return "N/A"


def determine_role(ip, gateway, local_ip):
    if ip == gateway:
        return "Gateway"
    elif ip == local_ip:
        return "Local Host"
    else:
        return "Device"


def main():

    parser = argparse.ArgumentParser(description="Network Asset Discovery Tool")

    parser.add_argument(
        "--network",
        help="Network range to scan (example: 10.0.0.0/24)"
    )

    args = parser.parse_args()

    detected_network, gateway = detect_network_and_gateway()

    network = args.network if args.network else detected_network

    local_ip = get_local_ip()

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
            "hostname": host_data.hostname() or "N/A",
            "state": host_data.state(),
            "mac": mac,
            "vendor": vendor,
            "role": role,
            "scan_time": timestamp
        }

        devices.append(device)

    devices.sort(key=lambda d: ipaddress.ip_address(d["ip"]))

    print("Devices discovered:\n")

    for device in devices:

        print(
            f"IP: {device['ip']:<15} "
            f"Role: {device['role']:<10} "
            f"Hostname: {device['hostname']:<15} "
            f"MAC: {device['mac']:<17} "
            f"Vendor: {device['vendor']}"
        )

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
