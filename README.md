# Network Asset Discovery Tool

A Python-based network discovery tool that scans a local network and generates an inventory of active devices.

This project was built to strengthen practical skills in:

- Linux
- Networking
- Python scripting
- IT automation

## Features

- Automatically detects the local network
- Detects the default gateway
- Detects the local host IP
- Scans for active hosts using Nmap
- Identifies:
  - IP address
  - device role
  - hostname
  - device state
  - MAC address
  - vendor (when available)
- Displays results in a formatted terminal table
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
