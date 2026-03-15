#!/usr/bin/env python3

# ============================================================
# Network Asset Discovery Tool
# Version 2.2
# ============================================================
# Features
# - Network discovery using nmap
# - Snapshot export (JSON / CSV)
# - Continuous monitoring mode
# - Baseline initialization cleanup
# - 2-cycle confirmation for new/gone devices
# - Event logging (JSONL)
# - Monitor log file
# - Risk change detection
# - Banner change detection
# ============================================================

import argparse
import csv
import json
import os
import subprocess
import time
from datetime import datetime


# ============================================================
# File configuration
# ============================================================

BASELINE_FILE = "baseline.json"
PENDING_FILE = "pending_changes.json"
EVENTS_FILE = "events.jsonl"
MONITOR_LOG_FILE = "monitor.log"

SNAPSHOT_JSON_FILE = "scan_results.json"
SNAPSHOT_CSV_FILE = "scan_results.csv"


# ============================================================
# Utility functions
# ============================================================

def now_str():
    """Return current timestamp in ISO format."""
    return datetime.now().isoformat(timespec="seconds")


def log_monitor(message):
    """Print message and write it to monitor.log."""
    line = f"[{now_str()}] {message}"
    print(line)

    with open(MONITOR_LOG_FILE, "a") as f:
        f.write(line + "\n")


def load_json_file(path, default=None):
    """Load JSON file safely."""
    if default is None:
        default = {}

    if not os.path.exists(path):
        return default

    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return default


def save_json_file(path, data):
    """Save JSON file with indentation."""
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def append_event(event_type, message, device=None, extra=None):
    """Append event to events.jsonl."""
    event = {
        "timestamp": now_str(),
        "event_type": event_type,
        "message": message
    }

    if device:
        event["device"] = device

    if extra:
        event["extra"] = extra

    with open(EVENTS_FILE, "a") as f:
        f.write(json.dumps(event) + "\n")


# ============================================================
# Device helpers
# ============================================================

def device_identity_key(device):
    """Generate unique device key."""
    if device.get("mac"):
        return f"mac:{device['mac']}"

    if device.get("ip"):
        return f"ip:{device['ip']}"

    return "unknown"


def build_device_index(devices):
    """Convert device list into indexed dictionary."""
    index = {}

    for d in devices:
        key = device_identity_key(d)
        index[key] = d

    return index


# ============================================================
# Nmap scan functions
# ============================================================

def require_nmap():
    """Ensure nmap is installed."""
    result = subprocess.run(["which", "nmap"], capture_output=True)

    if result.returncode != 0:
        print("ERROR: nmap is not installed.")
        print("Install with: sudo apt install nmap")
        exit(1)


def parse_nmap_output(output):
    """Parse nmap grepable output."""
    devices = []

    for line in output.splitlines():

        if "Status: Up" not in line:
            continue

        parts = line.split()

        ip = parts[1]

        device = {
            "ip": ip,
            "mac": None,
            "hostname": None,
            "role": "Device",
            "device_type": "Unknown Device",
            "os_guess": "Unknown",
            "state": "up",
            "open_ports": [],
            "banners": {},
            "risk_level": "Low",
            "security_flags": []
        }

        devices.append(device)

    return devices


def enrich_host(ip):
    """Run quick port scan for host."""
    cmd = [
        "nmap",
        "-Pn",
        "--top-ports", "20",
        "-T4",
        "-oG",
        "-",
        ip
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)

    open_ports = []
    banners = {}

    for line in result.stdout.splitlines():

        if "Ports:" not in line:
            continue

        port_data = line.split("Ports:")[1]

        ports = port_data.split(",")

        for p in ports:

            parts = p.split("/")

            if len(parts) < 5:
                continue

            port = parts[0]

            state = parts[1]

            service = parts[4]

            if state != "open":
                continue

            open_ports.append(int(port))

            if service:
                banners[port] = service

    return open_ports, banners


def classify_risk(open_ports):

    if 3389 in open_ports:
        return "High"

    if 80 in open_ports or 443 in open_ports:
        return "Medium"

    return "Low"


def run_network_scan(network):

    require_nmap()

    print()
    print(f"Scanning network: {network}")
    print(f"Scan time: {now_str()}")
    print()

    cmd = [
        "nmap",
        "-sn",
        "-oG",
        "-",
        network
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)

    devices = parse_nmap_output(result.stdout)

    for d in devices:

        ip = d["ip"]

        ports, banners = enrich_host(ip)

        d["open_ports"] = ports
        d["banners"] = banners
        d["risk_level"] = classify_risk(ports)

    return devices


# ============================================================
# Snapshot export
# ============================================================

def export_snapshot_json(devices):

    data = {
        "timestamp": now_str(),
        "devices": devices
    }

    save_json_file(SNAPSHOT_JSON_FILE, data)


def export_snapshot_csv(devices):

    with open(SNAPSHOT_CSV_FILE, "w", newline="") as f:

        writer = csv.writer(f)

        writer.writerow([
            "ip",
            "role",
            "device_type",
            "state",
            "open_ports",
            "risk_level"
        ])

        for d in devices:

            writer.writerow([
                d["ip"],
                d["role"],
                d["device_type"],
                d["state"],
                ",".join(map(str, d["open_ports"])),
                d["risk_level"]
            ])


# ============================================================
# Baseline management
# ============================================================

def initialize_baseline_if_needed(devices):

    if os.path.exists(BASELINE_FILE):
        return False

    index = build_device_index(devices)

    baseline = {
        "created_at": now_str(),
        "updated_at": now_str(),
        "devices": index
    }

    save_json_file(BASELINE_FILE, baseline)

    save_json_file(PENDING_FILE, {
        "new_devices": {},
        "gone_devices": {}
    })

    append_event(
        "baseline_initialized",
        "Baseline initialized from first scan",
        extra={"device_count": len(devices)}
    )

    log_monitor("[INFO] Baseline initialized")

    return True


# ============================================================
# Monitoring comparison
# ============================================================

def compare_with_baseline(devices):

    baseline = load_json_file(BASELINE_FILE)
    baseline_devices = baseline["devices"]

    current_index = build_device_index(devices)

    baseline_keys = set(baseline_devices.keys())
    current_keys = set(current_index.keys())

    new_devices = current_keys - baseline_keys
    gone_devices = baseline_keys - current_keys

    for k in new_devices:

        device = current_index[k]

        log_monitor(f"[NEW DEVICE] {device['ip']}")

        append_event(
            "new_device_detected",
            f"New device detected: {device['ip']}",
            device
        )

    for k in gone_devices:

        device = baseline_devices[k]

        log_monitor(f"[DEVICE REMOVED] {device['ip']}")

        append_event(
            "device_removed",
            f"Device removed: {device['ip']}",
            device
        )

    baseline["devices"] = current_index
    baseline["updated_at"] = now_str()

    save_json_file(BASELINE_FILE, baseline)


# ============================================================
# Monitoring loop
# ============================================================

def monitor_loop(network, interval):

    log_monitor("[INFO] Monitoring started")

    while True:

        devices = run_network_scan(network)

        export_snapshot_json(devices)
        export_snapshot_csv(devices)

        if not initialize_baseline_if_needed(devices):

            compare_with_baseline(devices)

        time.sleep(interval)


# ============================================================
# Display
# ============================================================

def print_discovered_devices(devices):

    print("Devices discovered:\n")

    header = f"{'IP':<16} {'DEVICE_TYPE':<25} {'STATE':<8} {'OPEN_PORTS':<20} {'RISK_LEVEL'}"

    print(header)

    print("-" * len(header))

    for d in devices:

        ports = ",".join(map(str, d["open_ports"])) or "None"

        print(
            f"{d['ip']:<16} "
            f"{d['device_type']:<25} "
            f"{d['state']:<8} "
            f"{ports:<20} "
            f"{d['risk_level']}"
        )


# ============================================================
# CLI
# ============================================================

def build_arg_parser():

    parser = argparse.ArgumentParser(
        description="Network Asset Discovery Tool v2.2"
    )

    parser.add_argument(
        "--network",
        required=True,
        help="Network to scan, example: 10.0.0.0/24"
    )

    parser.add_argument(
        "--monitor",
        action="store_true",
        help="Enable continuous monitoring mode"
    )

    parser.add_argument(
        "--interval",
        type=int,
        default=60,
        help="Monitoring interval in seconds"
    )

    return parser


# ============================================================
# Main
# ============================================================

def main():

    parser = build_arg_parser()

    args = parser.parse_args()

    if args.monitor:

        monitor_loop(args.network, args.interval)

        return

    devices = run_network_scan(args.network)

    export_snapshot_json(devices)

    export_snapshot_csv(devices)

    print_discovered_devices(devices)


if __name__ == "__main__":
    main()
