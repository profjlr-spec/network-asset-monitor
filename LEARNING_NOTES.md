# LEARNING NOTES — Network Asset Discovery Tool

This document explains how the discovery.py script works step by step.

The goal of this file is to make the project easier to understand when reviewing the code later.

This project is a learning exercise focused on:

- Python scripting
- Linux networking
- automation
- network enumeration
- cybersecurity fundamentals

--------------------------------------------------

PROJECT OVERVIEW

The script scans a local network and builds a basic inventory of active devices.

The tool identifies:

- IP address
- device role
- device type guess
- hostname
- device state
- open ports
- MAC address
- vendor
- operating system guess
- risk level
- security flags
- scan timestamp

Results are exported to:

- scan_results.json
- scan_results.csv

--------------------------------------------------

SCRIPT ARCHITECTURE

The script is divided into these logical sections:

1. Imports
2. Network detection
3. Device role classification
4. Device type guessing
5. Port-to-service mapping
6. Common port scanning
7. OS detection
8. OS guess simplification
9. OS detection decision logic
10. Security risk detection
11. Terminal table formatting
12. Main program flow

--------------------------------------------------

1 — IMPORTS

The script imports these Python libraries:

import nmap
import json
import csv
import argparse
import subprocess
import ipaddress
from datetime import datetime

Purpose of each module:

nmap
- Runs Nmap scans from Python
- Used for host discovery, port scanning, and OS detection

json
- Exports scan results to JSON

csv
- Exports scan results to CSV

argparse
- Allows command-line arguments such as:
  --network 192.168.1.0/24

subprocess
- Runs Linux commands such as:
  ip route

ipaddress
- Calculates and sorts IP addresses correctly

datetime
- Adds timestamps to each scan

--------------------------------------------------

2 — NETWORK DETECTION

Function:
detect_network_gateway_and_local_ip()

This function automatically determines:

- the network range
- the default gateway
- the local host IP

It does this by reading Linux network information.

Example idea:

10.0.0.221/24

becomes:

10.0.0.0/24

So the script knows:

- what network to scan
- what device is the gateway
- what IP belongs to the local host

--------------------------------------------------

3 — DEVICE ROLE CLASSIFICATION

Function:
determine_role(ip, gateway, local_ip)

This determines the role of each discovered device.

Rules:

- if ip == gateway -> Gateway
- if ip == local_ip -> Local Host
- otherwise -> Device

Example:

10.0.0.1   -> Gateway
10.0.0.221 -> Local Host
10.0.0.57  -> Device

--------------------------------------------------

4 — DEVICE TYPE GUESSING

Function:
guess_device_type(role, hostname, vendor)

This function tries to guess what type of device each host may be.

It uses:

- role
- hostname
- vendor

Examples of guesses:

- Gateway / Router
- Local Computer
- IoT Device
- Computer / Laptop
- Printer
- Smart TV
- Camera
- Unknown Device
- Smart / Connected Device

Examples of logic:

- Nest in vendor -> IoT Device
- Intel in vendor -> Computer / Laptop
- Arris in vendor -> Network Device
- printer in hostname -> Printer
- tv in hostname -> Smart TV

If nothing useful is found, the function falls back to:

Unknown Device

This is only a guess, not a guaranteed identification.

--------------------------------------------------

5 — PORT TO SERVICE MAPPING

Function:
get_service_name(port)

This translates common ports into their usual service names.

Mappings used in this project:

22   -> SSH
53   -> DNS
80   -> HTTP
443  -> HTTPS
445  -> SMB
3389 -> RDP
554  -> RTSP

Example output:

80(HTTP), 443(HTTPS)

This makes the results easier to understand than just showing raw numbers.

--------------------------------------------------

6 — COMMON PORT SCANNING

Function:
scan_common_ports(host)

This function scans a small set of common ports instead of scanning every possible port.

Ports scanned:

22,53,80,443,445,3389,554

Nmap arguments used:

-Pn -p PORTLIST --open

Meaning:

- -Pn -> treat the host as up
- -p -> scan specific ports only
- --open -> only show open ports

Example result:

443(HTTPS)

If none of the selected ports are open, the script returns:

None

This keeps the project faster and more practical for learning.

--------------------------------------------------

7 — OS DETECTION

Function:
detect_os_guess(host)

This function runs Nmap OS fingerprinting.

Arguments used:

-Pn -O --osscan-guess

Meaning:

- -Pn -> treat the host as active
- -O -> attempt OS detection
- --osscan-guess -> allow Nmap to make a best guess

OS detection is useful, but slower than host discovery or common port scanning.

--------------------------------------------------

8 — OS GUESS SIMPLIFICATION

Function:
simplify_os_guess(os_guess)

Nmap often returns long operating system descriptions.

This function simplifies them into shorter categories such as:

- Linux
- Windows
- macOS / iOS
- Embedded Linux
- Router / Network OS
- Printer
- BSD / Unix-like
- Unknown
- Other / Unknown

Examples:

Linux 3.2 - 4.9            -> Linux
Apple macOS 10.13 - 10.15  -> macOS / iOS
Microsoft Windows 10       -> Windows

This makes the terminal table easier to read.

--------------------------------------------------

9 — SELECTIVE OS DETECTION

Function:
should_run_os_detection(role, open_ports)

OS detection is the slowest part of the tool.

To improve performance, the script only runs OS detection when it makes sense.

The rule is:

- run OS detection for the Gateway
- run OS detection for the Local Host
- run OS detection for any host with open ports

Otherwise the script sets:

Skipped

This keeps the scan useful while avoiding unnecessary delays.

--------------------------------------------------

10 — SECURITY RISK DETECTION

Function:
assess_security_risk(device_type, open_ports, role)

This function assigns a simple security risk score and a set of security flags.

It looks at:

- device type
- open ports
- device role

Risk logic by device type:

If device type is:

- IoT Device -> flag as possible insecure IoT device
- Smart / Connected Device -> flag for review
- Unknown Device -> flag as unknown device detected

Risk logic by ports:

If open ports include:

- 445(SMB)   -> SMB exposed
- 3389(RDP)  -> RDP exposed
- 22(SSH) on non-local device -> SSH open on network device
- 554(RTSP)  -> Camera or stream service exposed

If a normal device has any open ports, it can also be flagged with:

Open ports require review

Final risk levels:

- Low
- Medium
- High

If nothing concerning is found, the result is:

No obvious issues

--------------------------------------------------

11 — TABLE FORMATTING

Function:
print_table(devices)

This function prints a clean aligned table in the terminal.

Columns include:

- IP
- ROLE
- DEVICE_TYPE
- OS_GUESS
- STATE
- OPEN_PORTS
- RISK_LEVEL
- SECURITY_FLAGS

Example:

IP          ROLE        DEVICE_TYPE      OS_GUESS  STATE  OPEN_PORTS                     RISK_LEVEL  SECURITY_FLAGS
10.0.0.1    Gateway     Router           Linux     up     53(DNS),80(HTTP),443(HTTPS)   Low         No obvious issues
10.0.0.175  Device      Unknown Device   Linux     up     443(HTTPS)                     Medium      Unknown device detected; Open ports require review

The function dynamically calculates column widths so the table stays aligned even when values vary.

--------------------------------------------------

12 — MAIN PROGRAM FLOW

Function:
main()

This is the main workflow of the script.

Steps performed:

1. Read command-line arguments
2. Detect network, gateway, and local IP
3. Run Nmap host discovery
4. Loop through discovered hosts
5. Determine device role
6. Guess device type
7. Scan common ports
8. Decide whether OS detection should run
9. If needed, detect and simplify the OS guess
10. Assess basic security risk
11. Build a device dictionary
12. Sort results by IP address
13. Print the table
14. Export JSON and CSV

--------------------------------------------------

EXAMPLE SCAN PROCESS

Typical scan flow:

Network Detection
        ↓
Host Discovery (-sn)
        ↓
Device Role Classification
        ↓
Device Type Guessing
        ↓
Common Port Scanning
        ↓
Selective OS Detection
        ↓
Basic Risk Assessment
        ↓
Table Output
        ↓
JSON / CSV Export

--------------------------------------------------

WHAT I LEARNED

This project helped practice:

- using Nmap with Python
- automating network discovery
- parsing scan results
- structuring Python code into clear functions
- exporting structured data
- simplifying technical output for readability
- improving performance by avoiding unnecessary OS scans
- adding basic risk logic to network inventory data

--------------------------------------------------

WHY THIS PROJECT MATTERS

This project is useful because it combines multiple real technical skills:

- Linux command usage
- Python scripting
- Nmap automation
- host discovery
- service identification
- asset inventory creation
- practical cybersecurity-style enumeration
- basic security triage

It is also a strong base for future improvements.

--------------------------------------------------

FUTURE IMPROVEMENTS

Possible future improvements include:

- deeper service detection
- better device fingerprinting
- vulnerability scanning
- network topology visualization
- HTML reports
- historical scan comparison
- automated asset inventory systems
- alerting for new or suspicious devices
