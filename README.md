# Network Asset Discovery Tool

A Python-based network discovery tool that scans a local network and generates an inventory of active devices.

This project is part of a personal initiative to improve skills in:

- Linux
- Networking
- Python scripting
- IT automation

## Features

- Scans a network range to detect active hosts
- Identifies IP address
- Attempts hostname resolution
- Generates device inventory
- Exports results to:
  - JSON
  - CSV

## Requirements

- Python 3
- Nmap
- python-nmap library

Install Nmap (Linux):

sudo apt install nmap

Install Python dependencies:

pip install -r requirements.txt

## Usage

Run the network scan:

python discovery.py

Or specify a network range:

python discovery.py --network 10.0.0.0/24

## Example Output

Devices found:

{'ip': '10.0.0.1', 'hostname': '_gateway', 'state': 'up'}
{'ip': '10.0.0.221', 'hostname': 'Friday', 'state': 'up'}

## Output Files

After running the scan, the tool generates:

scan_results.json  
scan_results.csv  

These files contain the discovered devices and their information.

## Project Structure
