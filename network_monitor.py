#!/usr/bin/env python3

# ============================================================
# Network Asset Discovery Tool
# Version 2 - Continuous Network Monitoring Mode
# ============================================================

import os
import time
import shutil
import argparse
import subprocess
from datetime import datetime

# ============================================================
# CONFIGURATION
# ============================================================

DEFAULT_INTERVAL = 300

SNAPSHOT_DIR = "snapshots"
JSON_HISTORY_DIR = os.path.join(SNAPSHOT_DIR, "json")
CSV_HISTORY_DIR = os.path.join(SNAPSHOT_DIR, "csv")
LOG_FILE = "monitor.log"

# ============================================================
# DIRECTORY SETUP
# ============================================================

def ensure_directories():
    """
    Create required folders if they do not exist
    """
    os.makedirs(SNAPSHOT_DIR, exist_ok=True)
    os.makedirs(JSON_HISTORY_DIR, exist_ok=True)
    os.makedirs(CSV_HISTORY_DIR, exist_ok=True)

# ============================================================
# LOGGING
# ============================================================

def write_log(message):
    """
    Write a timestamped message to monitor.log
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    full_message = f"[{timestamp}] {message}"

    print(full_message)

    with open(LOG_FILE, "a") as log_file:
        log_file.write(full_message + "\n")

# ============================================================
# RUN DISCOVERY
# ============================================================

def run_discovery(network=None):
    """
    Execute discovery.py and optionally pass a custom network range
    """
    command = ["python3", "discovery.py"]

    if network:
        command.extend(["--network", network])

    write_log(f"Starting discovery scan: {' '.join(command)}")

    try:
        subprocess.run(command, check=True)
        write_log("Discovery scan completed successfully")
        return True
    except subprocess.CalledProcessError as error:
        write_log(f"Discovery scan failed with return code {error.returncode}")
        return False
    except Exception as error:
        write_log(f"Unexpected error while running discovery.py: {error}")
        return False

# ============================================================
# ARCHIVE OUTPUT FILES
# ============================================================

def archive_scan_outputs():
    """
    Save timestamped copies of the latest JSON and CSV scan outputs
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    json_source = "scan_results.json"
    csv_source = "scan_results.csv"

    json_destination = os.path.join(JSON_HISTORY_DIR, f"scan_{timestamp}.json")
    csv_destination = os.path.join(CSV_HISTORY_DIR, f"scan_{timestamp}.csv")

    if os.path.exists(json_source):
        shutil.copy2(json_source, json_destination)
        write_log(f"Archived JSON snapshot: {json_destination}")
    else:
        write_log("scan_results.json not found after scan")

    if os.path.exists(csv_source):
        shutil.copy2(csv_source, csv_destination)
        write_log(f"Archived CSV snapshot: {csv_destination}")
    else:
        write_log("scan_results.csv not found after scan")

# ============================================================
# MONITOR LOOP
# ============================================================

def monitor_network(interval, network=None):
    """
    Run discovery continuously at the selected interval
    """
    write_log("==============================================")
    write_log("Continuous Network Monitoring Mode Started")
    write_log(f"Scan interval: {interval} seconds")

    if network:
        write_log(f"Custom target network: {network}")
    else:
        write_log("Using auto-detected local network")

    write_log("Press CTRL + C to stop monitoring")
    write_log("==============================================")

    cycle = 1

    while True:
        write_log(f"--- Monitoring cycle #{cycle} ---")

        scan_ok = run_discovery(network=network)

        if scan_ok:
            archive_scan_outputs()
        else:
            write_log("Skipping archive because scan failed")

        write_log(f"Sleeping for {interval} seconds...\n")
        time.sleep(interval)
        cycle += 1

# ============================================================
# MAIN
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="Continuous monitoring mode for the Network Asset Discovery Tool"
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=DEFAULT_INTERVAL,
        help="Scan interval in seconds (default: 300)"
    )
    parser.add_argument(
        "--network",
        help="Optional network range to scan (example: 10.0.0.0/24)"
    )

    args = parser.parse_args()

    ensure_directories()
    monitor_network(interval=args.interval, network=args.network)

# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Monitoring stopped by user")
