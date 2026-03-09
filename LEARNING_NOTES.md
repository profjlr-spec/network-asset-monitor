# LEARNING NOTES - Network Asset Discovery Tool

These notes explain how the `discovery.py` script works step by step.

The goal of this file is to document the logic of the script so it is easier to understand and maintain later.

---

# 1. What this project does

This project scans a local network and builds a basic inventory of active devices.

It collects information such as:

- IP address
- device role
- guessed device type
- hostname
- state
- MAC address
- vendor
- scan timestamp

The results are also exported to:

- scan_results.json
- scan_results.csv

---

# 2. Main sections of the script

The script `discovery.py` is organized into these sections:

1. Imports
2. Network detection
3. Role classification
4. Device type guessing
5. Table formatting
6. Main program execution

---

# 3. Imports

The script imports these modules:

import nmap
import json
import csv
import argparse
import subprocess
import ipaddress
from datetime import datetime
---

# 4. Detecting network information

Function:

detect_network_gateway_and_local_ip()

This function automatically determines:

- the local network
- the default gateway
- the local host IP address

It runs the command:

ip route | grep default

Example output:

default via 10.0.0.1 dev wlan0

From this output the script extracts:

Gateway → 10.0.0.1  
Interface → wlan0

Then it retrieves the IP of that interface:

ip -o -f inet addr show wlan0

Example result:

10.0.0.221/24

This is converted into the network:

10.0.0.0/24

---

# 5. Device role classification

Function:

determine_role(ip, gateway, local_ip)

This function determines the role of each device.

Possible roles:

Gateway  
Local Host  
Device

Example:

10.0.0.1   -> Gateway  
10.0.0.221 -> Local Host  
10.0.0.215 -> Device

---

# 6. Device type guessing

Function:

guess_device_type(role, hostname, vendor)

This function attempts to guess what type of device each host might be.

Examples of possible device types:

Gateway / Router  
Local Computer  
IoT Device  
Printer  
Phone / Mobile Device  
Smart TV  
Camera  
Computer / Laptop  
Unknown Device  
Smart / Connected Device

This is not always perfect but makes the asset inventory easier to understand.

---

# 7. Running the Nmap scan

The scan is executed with:

scanner.scan(hosts=network, arguments="-sn")

The option "-sn" means:

- discover active hosts
- no port scanning

This makes the scan faster.

---

# 8. Extracting host information

For each discovered host the script collects:

- IP address
- hostname
- state
- MAC address
- vendor
- role
- device type
- scan time

Example device record:

{
 "ip": "10.0.0.215",
 "role": "Device",
 "device_type": "IoT Device",
 "hostname": "N/A",
 "state": "up",
 "mac": "18:B4:30:D1:1D:AD",
 "vendor": "Nest Labs",
 "scan_time": "2026-03-08 21:20:56"
}

---

# 9. Sorting devices by IP

Devices are sorted using:

ipaddress.ip_address()

Example order:

10.0.0.1  
10.0.0.66  
10.0.0.175  
10.0.0.215  
10.0.0.220  
10.0.0.221

---

# 10. Printing the terminal table

Function:

print_table(devices)

Example output:

IP          ROLE        DEVICE_TYPE               HOSTNAME  STATE  MAC                VENDOR
10.0.0.1    Gateway     Gateway / Router          _gateway  up     F8:79:0A:25:55:9E  Arris Group
10.0.0.221  Local Host  Local Computer            Friday    up     N/A                N/A
10.0.0.215  Device      IoT Device                N/A       up     18:B4:30:D1:1D:AD  Nest Labs

---

# 11. Saving results

The script exports results to two files:

scan_results.json  
scan_results.csv

These files are useful for:

- asset inventories
- documentation
- importing into other tools
- automation workflows

---

# 12. Running the script

Basic scan:

python discovery.py

Full scan (recommended):

sudo ./venv/bin/python discovery.py

Running with sudo usually provides better device information.
