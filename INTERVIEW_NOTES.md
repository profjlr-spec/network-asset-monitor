# Network Asset Discovery Tool — Interview Notes

This document contains technical explanations and interview talking points based on the development of the **Network Asset Discovery & Security Monitoring Tool** built in Python.

The goal of this project was to simulate capabilities commonly found in security tools used by SOC teams, vulnerability scanners, and asset management systems.

--------------------------------------------------

PROJECT SUMMARY

This project is a Python-based network security tool designed to discover and monitor devices on a network.

The tool performs:

- Network asset discovery
- Service detection
- Device fingerprinting
- Banner detection
- Security risk identification
- Network change detection
- Service change detection
- Export of results to JSON and CSV

The tool helps identify potentially insecure devices such as IoT devices, exposed services, or unknown devices connected to a network.

--------------------------------------------------

TECHNOLOGIES USED

The project uses several technologies and networking concepts:

- Python
- Linux networking tools
- Nmap scanning engine
- TCP socket communication
- JSON and CSV data storage

Python libraries used:

- python-nmap
- socket
- ssl
- subprocess
- argparse
- ipaddress
- datetime

--------------------------------------------------

PROBLEM THIS TOOL SOLVES

In many networks administrators do not have full visibility of what devices are connected.

Unknown devices, insecure IoT devices, and exposed services can introduce security risks.

This tool automatically:

- discovers devices on the network
- identifies services running on those devices
- classifies device types
- flags potential security risks

--------------------------------------------------

HOW NETWORK DISCOVERY WORKS

The tool uses **Nmap host discovery (-sn)** to detect active hosts on the network.

Host discovery identifies devices that respond to network probes such as:

- ARP requests
- ICMP responses
- other network probes

Once hosts are discovered, additional scans are performed to determine:

- open ports
- device characteristics
- potential services

--------------------------------------------------

SERVICE DETECTION

After discovering hosts, the tool performs a port scan against common ports:

21   FTP  
22   SSH  
23   TELNET  
53   DNS  
80   HTTP  
443  HTTPS  
445  SMB  
554  RTSP  
3389 RDP  
8080 HTTP alternative  

If a port is open, the tool associates it with its likely service.

Example mapping:

22 -> SSH  
80 -> HTTP  
554 -> RTSP (commonly used by IP cameras)

--------------------------------------------------

BANNER DETECTION

The tool attempts to retrieve **service banners** from open ports.

A banner is a response from a service that may reveal:

- server software
- service type
- device information
- version data

Examples of banners:

SSH-2.0-OpenSSH_9.6  
Server: nginx  
Server: Apache  
Server: lighttpd  

Banner detection improves device identification and security analysis.

--------------------------------------------------

DEVICE FINGERPRINTING

The tool performs device fingerprinting using:

- open ports
- MAC vendor information
- hostname patterns
- service banners
- OS guess from Nmap

Possible classifications include:

- IP Camera
- Printer
- NAS / File Server
- Web Server / Admin Interface
- Workstation
- IoT Device
- Unknown Device

--------------------------------------------------

SECURITY RISK DETECTION

The tool evaluates potential risks based on exposed services.

Examples of insecure or sensitive services:

TELNET (23)  
FTP (21)  
RDP (3389)  
SMB (445)

Example risk message:

Telnet is insecure and should not be exposed

Devices are categorized into risk levels:

Low  
Medium  
High

--------------------------------------------------

NETWORK CHANGE DETECTION

The tool stores results from the previous scan.

On future scans it detects:

- newly connected devices
- devices that disappeared from the network

Example output:

NEW DEVICES DETECTED:
+ 10.0.0.215

--------------------------------------------------

SERVICE CHANGE DETECTION

The tool also detects changes in exposed services.

Example:

SERVICE CHANGE DETECTED: 10.0.0.221
Closed ports:
- 23(TELNET)

This capability can help identify:

- newly exposed services
- misconfigurations
- potential security incidents

--------------------------------------------------

SECURITY USE CASES

This tool could be used for:

- home network security monitoring
- small business network visibility
- cybersecurity lab experimentation
- learning network enumeration techniques

The tool simulates capabilities seen in tools such as:

- Nmap
- Nessus
- Lansweeper
- Armis

--------------------------------------------------

KEY SECURITY CONCEPTS DEMONSTRATED

The project demonstrates several important cybersecurity concepts:

- Network Enumeration
- Asset Discovery
- Service Exposure Detection
- Device Fingerprinting
- Security Risk Identification
- Network Monitoring

--------------------------------------------------

LESSONS LEARNED

Building this project provided practical experience in:

- Python networking
- TCP socket communication
- interacting with Nmap through Python
- analyzing exposed services
- designing modular security tools

It also reinforced the importance of **network visibility** as a fundamental cybersecurity capability.

--------------------------------------------------

FUTURE IMPROVEMENTS

Possible future improvements include:

- real-time monitoring
- vulnerability database integration
- web dashboard visualization
- automated alerts for network changes
- machine learning device classification

--------------------------------------------------

INTERVIEW TALKING POINT

Example response when asked about a personal project:

"I built a Python-based network asset discovery and security monitoring tool that uses Nmap for host discovery and port scanning. The tool identifies devices on a network, performs device fingerprinting, retrieves service banners, and flags potential security risks such as exposed services or insecure IoT devices. It also tracks network and service changes between scans to help detect newly connected devices or newly exposed ports."

