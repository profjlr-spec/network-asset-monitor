# Network Asset Discovery Tool

A Python-based network discovery tool that scans a local network and generates an inventory of active devices.

This project was built to strengthen practical skills in:

- Linux
- Networking
- Python scripting
- IT automation

## Features

- Automatically detects the local network
- Scans for active hosts using Nmap
- Identifies:
  - IP address
  - Hostname
  - Device state
  - MAC address
  - Vendor (when available)
- Exports scan results to:
  - JSON
  - CSV
- Supports manual network range input with `--network`

## Requirements

- Python 3
- Nmap
- python-nmap

## Installation

Clone the repository:

```bash
git clone https://github.com/profjlr-spec/network-asset-discovery.git
cd network-asset-discovery
