import nmap
import json
import csv
import argparse

def main():

    parser = argparse.ArgumentParser(description="Network Asset Discovery Tool")
    parser.add_argument("--network", default="10.0.0.0/24")

    args = parser.parse_args()

    scanner = nmap.PortScanner()

    print(f"Scanning network {args.network}")

    scanner.scan(hosts=args.network, arguments="-sn")

    devices = []

    for host in scanner.all_hosts():

        device = {
            "ip": host,
            "hostname": scanner[host].hostname(),
            "state": scanner[host].state()
        }

        devices.append(device)

    print("\nDevices found:\n")

    for d in devices:
        print(d)

    with open("scan_results.json", "w") as f:
        json.dump(devices, f, indent=4)

    with open("scan_results.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["ip","hostname","state"])
        writer.writeheader()
        writer.writerows(devices)

    print("\nResults saved")

if __name__ == "__main__":
    main()
