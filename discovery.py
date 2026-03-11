# ==============================
# Imports
# ==============================

import nmap
import json
import csv
import argparse
import subprocess
import ipaddress
from datetime import datetime


# ==============================
# Network detection functions
# ==============================
# Esta función detecta automáticamente:
# - la red local
# - el gateway
# - la IP local del equipo actual

def detect_network_gateway_and_local_ip():
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
        interface_ip = cidr.split("/")[0]
        network = str(ipaddress.ip_interface(cidr).network)

        return network, gateway, interface_ip

    except Exception:
        return "10.0.0.0/24", "N/A", "N/A"


# ==============================
# Device role classification
# ==============================
# Esta función clasifica el rol del dispositivo:
# - Gateway
# - Local Host
# - Device

def determine_role(ip, gateway, local_ip):
    if ip == gateway:
        return "Gateway"
    elif ip == local_ip:
        return "Local Host"
    return "Device"


# ==============================
# Device type guessing
# ==============================
# Esta función intenta adivinar el tipo de dispositivo
# basándose en:
# - rol
# - hostname
# - vendor

def guess_device_type(role, hostname, vendor):
    hostname_lower = hostname.lower() if hostname != "N/A" else ""
    vendor_lower = vendor.lower() if vendor != "N/A" else ""

    if role == "Gateway":
        return "Gateway / Router"

    if role == "Local Host":
        return "Local Computer"

    if "nest" in vendor_lower:
        return "IoT Device"

    if "arris" in vendor_lower:
        return "Network Device"

    if "apple" in vendor_lower:
        return "Phone / Computer"

    if "samsung" in vendor_lower:
        return "Phone / Smart Device"

    if "intel" in vendor_lower or "dell" in vendor_lower or "lenovo" in vendor_lower:
        return "Computer / Laptop"

    if "hp" in vendor_lower or "epson" in vendor_lower or "canon" in vendor_lower:
        return "Printer"

    if "iphone" in hostname_lower or "android" in hostname_lower:
        return "Phone / Mobile Device"

    if "printer" in hostname_lower:
        return "Printer"

    if "tv" in hostname_lower:
        return "Smart TV"

    if "cam" in hostname_lower or "camera" in hostname_lower:
        return "Camera"

    if "raspberry" in hostname_lower:
        return "Single Board Computer"

    if "laptop" in hostname_lower or "desktop" in hostname_lower or "pc" in hostname_lower:
        return "Computer / Laptop"

    if vendor == "N/A" and hostname == "N/A":
        return "Unknown Device"

    return "Smart / Connected Device"


# ==============================
# Port to service mapping
# ==============================
# Esta función traduce un puerto conocido a su servicio más común.

def get_service_name(port):
    port_map = {
        21: "FTP",
        22: "SSH",
        23: "TELNET",
        53: "DNS",
        80: "HTTP",
        443: "HTTPS",
        445: "SMB",
        554: "RTSP",
        3389: "RDP",
        8080: "HTTP-Alt"
    }
    return port_map.get(port, "Unknown")


# ==============================
# Common port scanning
# ==============================
# Esta función revisa algunos puertos comunes para un host.
# Usa un scanner separado para no sobrescribir el discovery.

def scan_common_ports(host):
    common_ports = "21,22,23,53,80,443,445,554,3389,8080"
    open_ports = []

    try:
        port_scanner = nmap.PortScanner()
        port_scanner.scan(hosts=host, arguments=f"-Pn -p {common_ports} --open")

        if host in port_scanner.all_hosts():
            protocols = port_scanner[host].all_protocols()

            for protocol in protocols:
                ports = port_scanner[host][protocol].keys()

                for port in sorted(ports):
                    state = port_scanner[host][protocol][port].get("state", "")
                    if state == "open":
                        service_name = get_service_name(port)
                        open_ports.append(f"{port}({service_name})")

    except Exception:
        pass

    if not open_ports:
        return "None"

    return ", ".join(open_ports)


# ==============================
# OS detection
# ==============================
# Esta función intenta adivinar el sistema operativo del host.

def detect_os_guess(host):
    try:
        os_scanner = nmap.PortScanner()
        os_scanner.scan(hosts=host, arguments="-Pn -O --osscan-guess")

        if host in os_scanner.all_hosts():
            os_matches = os_scanner[host].get("osmatch", [])
            if os_matches:
                return os_matches[0].get("name", "Unknown")

    except Exception:
        pass

    return "Unknown"


# ==============================
# OS guess simplification
# ==============================
# Resume la salida larga de Nmap para una tabla más limpia.

def simplify_os_guess(os_guess):
    guess = os_guess.lower()

    if guess == "unknown":
        return "Unknown"
    if "windows" in guess or "microsoft" in guess:
        return "Windows"
    if "mac os" in guess or "macos" in guess or "darwin" in guess or "ios" in guess:
        return "macOS / iOS"
    if "embedded" in guess and "linux" in guess:
        return "Embedded Linux"
    if "linux" in guess:
        return "Linux"
    if "router" in guess or "switch" in guess or "network" in guess or "cisco" in guess:
        return "Router / Network OS"
    if "printer" in guess:
        return "Printer"
    if "bsd" in guess:
        return "BSD / Unix-like"

    return "Other / Unknown"


# ==============================
# OS detection decision
# ==============================
# Solo corre OS detection si vale la pena:
# - Gateway
# - Local Host
# - Dispositivos con puertos abiertos

def should_run_os_detection(role, open_ports):
    if role in ["Gateway", "Local Host"]:
        return True
    if open_ports != "None":
        return True
    return False


# ==============================
# Security risk detection
# ==============================
# Esta función asigna un nivel de riesgo y banderas
# básicas de seguridad según el tipo de dispositivo,
# puertos abiertos y rol.

def assess_security_risk(device_type, open_ports, role):
    flags = []
    score = 0

    # Riesgos por tipo de dispositivo
    if device_type == "IoT Device":
        flags.append("Possible insecure IoT device")
        score += 2

    if device_type == "Smart / Connected Device":
        flags.append("Smart device needs review")
        score += 1

    if device_type == "Unknown Device":
        flags.append("Unknown device detected")
        score += 2

    # Riesgos por puertos abiertos
    if "21(FTP)" in open_ports:
        flags.append("Insecure FTP service exposed")
        score += 3

    if "23(TELNET)" in open_ports:
        flags.append("Telnet is insecure and should not be exposed")
        score += 4

    if "445(SMB)" in open_ports and role != "Local Host":
        flags.append("SMB exposed to network")
        score += 3

    if "445(SMB)" in open_ports and role == "Local Host":
        flags.append("SMB exposed")
        score += 2

    if "3389(RDP)" in open_ports:
        flags.append("RDP exposed - potential brute force target")
        score += 3

    if "22(SSH)" in open_ports and role != "Local Host":
        flags.append("SSH open on network device")
        score += 1

    if "554(RTSP)" in open_ports:
        flags.append("Camera or stream service exposed")
        score += 1

    if open_ports != "None" and role == "Device":
        flags.append("Open ports require review")
        score += 1

    # Clasificación final
    if score >= 4:
        risk_level = "High"
    elif score >= 2:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    if not flags:
        flags = ["No obvious issues"]

    return risk_level, "; ".join(flags)


# ==============================
# Scan history loading
# ==============================
# Carga el escaneo anterior para poder comparar
# cambios en la red.

def load_previous_scan():
    try:
        with open("previous_scan.json", "r") as file:
            return json.load(file)
    except Exception:
        return []


# ==============================
# Scan history saving
# ==============================
# Guarda el escaneo actual para usarlo como
# referencia en el próximo escaneo.

def save_current_scan(devices):
    with open("previous_scan.json", "w") as file:
        json.dump(devices, file, indent=4)


# ==============================
# Device change detection
# ==============================
# Compara el escaneo anterior con el actual para
# detectar:
# - dispositivos nuevos
# - dispositivos que ya no están

def detect_network_changes(previous_devices, current_devices):
    previous_ips = {device["ip"] for device in previous_devices}
    current_ips = {device["ip"] for device in current_devices}

    new_ips = current_ips - previous_ips
    missing_ips = previous_ips - current_ips

    if new_ips:
        print("\nNEW DEVICES DETECTED:")
        for ip in sorted(new_ips, key=ipaddress.ip_address):
            print(f" + {ip}")

    if missing_ips:
        print("\nDEVICES NO LONGER PRESENT:")
        for ip in sorted(missing_ips, key=ipaddress.ip_address):
            print(f" - {ip}")

    if not new_ips and not missing_ips:
        print("\nNo device-level network changes detected since the previous scan.")


# ==============================
# Service change detection
# ==============================
# Compara los puertos abiertos del scan anterior y el actual
# para detectar:
# - puertos nuevos
# - puertos cerrados

def detect_service_changes(previous_devices, current_devices):
    previous_map = {device["ip"]: device for device in previous_devices}
    current_map = {device["ip"]: device for device in current_devices}

    shared_ips = sorted(
        set(previous_map.keys()) & set(current_map.keys()),
        key=ipaddress.ip_address
    )

    changes_found = False

    for ip in shared_ips:
        previous_ports_raw = previous_map[ip].get("open_ports", "None")
        current_ports_raw = current_map[ip].get("open_ports", "None")

        previous_ports = set() if previous_ports_raw == "None" else set(
            port.strip() for port in previous_ports_raw.split(",")
        )
        current_ports = set() if current_ports_raw == "None" else set(
            port.strip() for port in current_ports_raw.split(",")
        )

        new_ports = sorted(current_ports - previous_ports)
        closed_ports = sorted(previous_ports - current_ports)

        if new_ports or closed_ports:
            changes_found = True
            print(f"\nSERVICE CHANGE DETECTED: {ip}")

            if new_ports:
                print(" New open ports:")
                for port in new_ports:
                    print(f"  + {port}")

            if closed_ports:
                print(" Closed ports:")
                for port in closed_ports:
                    print(f"  - {port}")

    if not changes_found:
        print("\nNo service-level port changes detected since the previous scan.")


# ==============================
# Terminal output formatting
# ==============================
# Esta función imprime una tabla alineada en la terminal.

def print_table(devices):
    headers = [
        "IP",
        "ROLE",
        "DEVICE_TYPE",
        "OS_GUESS",
        "STATE",
        "OPEN_PORTS",
        "RISK_LEVEL",
        "SECURITY_FLAGS"
    ]

    rows = []
    for device in devices:
        rows.append([
            device["ip"],
            device["role"],
            device["device_type"],
            device["os_guess"],
            device["state"],
            device["open_ports"],
            device["risk_level"],
            device["security_flags"]
        ])

    col_widths = []
    for i, header in enumerate(headers):
        max_width = len(header)
        for row in rows:
            max_width = max(max_width, len(str(row[i])))
        col_widths.append(max_width)

    header_line = "  ".join(
        header.ljust(col_widths[i]) for i, header in enumerate(headers)
    )
    separator_line = "  ".join(
        "-" * col_widths[i] for i in range(len(headers))
    )

    print(header_line)
    print(separator_line)

    for row in rows:
        print("  ".join(
            str(row[i]).ljust(col_widths[i]) for i in range(len(headers))
        ))


# ==============================
# Main program
# ==============================
# Flujo:
# 1. detectar red/gateway/IP local
# 2. discovery de hosts
# 3. clasificar dispositivos
# 4. escanear puertos
# 5. detectar OS selectivamente
# 6. evaluar riesgo
# 7. imprimir tabla
# 8. comparar con scan anterior
# 9. guardar scan actual

def main():
    parser = argparse.ArgumentParser(description="Network Asset Discovery Tool")
    parser.add_argument(
        "--network",
        help="Network range to scan (example: 10.0.0.0/24)"
    )
    args = parser.parse_args()

    detected_network, gateway, local_ip = detect_network_gateway_and_local_ip()
    network = args.network if args.network else detected_network

    discovery_scanner = nmap.PortScanner()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(f"\nScanning network: {network}")
    print(f"Gateway detected: {gateway}")
    print(f"Local host IP: {local_ip}")
    print(f"Scan time: {timestamp}\n")

    discovery_scanner.scan(hosts=network, arguments="-sn")
    discovered_hosts = discovery_scanner.all_hosts()

    previous_scan = load_previous_scan()
    devices = []

    for host in discovered_hosts:
        host_data = discovery_scanner[host]
        addresses = host_data.get("addresses", {})
        vendor_info = host_data.get("vendor", {})

        mac = addresses.get("mac", "N/A")
        vendor = vendor_info.get(mac, "N/A")
        hostname = host_data.hostname() or "N/A"
        role = determine_role(host, gateway, local_ip)
        device_type = guess_device_type(role, hostname, vendor)
        open_ports = scan_common_ports(host)

        if should_run_os_detection(role, open_ports):
            raw_os_guess = detect_os_guess(host)
            os_guess = simplify_os_guess(raw_os_guess)
        else:
            os_guess = "Skipped"

        risk_level, security_flags = assess_security_risk(
            device_type=device_type,
            open_ports=open_ports,
            role=role
        )

        device = {
            "ip": host,
            "role": role,
            "device_type": device_type,
            "os_guess": os_guess,
            "hostname": hostname,
            "state": host_data.state(),
            "open_ports": open_ports,
            "mac": mac,
            "vendor": vendor,
            "risk_level": risk_level,
            "security_flags": security_flags,
            "scan_time": timestamp
        }

        devices.append(device)

    devices.sort(key=lambda d: ipaddress.ip_address(d["ip"]))

    print("Devices discovered:\n")
    print_table(devices)

    detect_network_changes(previous_scan, devices)
    detect_service_changes(previous_scan, devices)

    save_current_scan(devices)

    with open("scan_results.json", "w") as json_file:
        json.dump(devices, json_file, indent=4)

    with open("scan_results.csv", "w", newline="") as csv_file:
        writer = csv.DictWriter(
            csv_file,
            fieldnames=[
                "ip",
                "role",
                "device_type",
                "os_guess",
                "hostname",
                "state",
                "open_ports",
                "mac",
                "vendor",
                "risk_level",
                "security_flags",
                "scan_time"
            ]
        )
        writer.writeheader()
        writer.writerows(devices)

    print("\nResults saved to scan_results.json and scan_results.csv\n")


# ==============================
# Program entry point
# ==============================

if __name__ == "__main__":
    main()
