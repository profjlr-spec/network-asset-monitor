# ==============================
# Imports
# ==============================
# Estas librerías permiten:
# - ejecutar Nmap desde Python
# - guardar resultados en JSON y CSV
# - aceptar argumentos desde la terminal
# - ejecutar comandos de Linux
# - trabajar con direcciones IP/redes
# - agregar fecha y hora al escaneo

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
# - la red local (ej. 10.0.0.0/24)
# - el gateway (ej. 10.0.0.1)
# - la IP local del equipo actual (ej. 10.0.0.221)
#
# Lo hace leyendo la ruta por defecto en Linux y luego
# consultando la IP de la interfaz activa.

def detect_network_gateway_and_local_ip():
    try:
        # Obtener la ruta por defecto del sistema
        route = subprocess.check_output(
            "ip route | grep default", shell=True, text=True
        ).strip()

        # Separar la salida para extraer gateway e interfaz
        parts = route.split()
        gateway = parts[2]
        interface = parts[4]

        # Obtener la IP de la interfaz activa
        ip_info = subprocess.check_output(
            f"ip -o -f inet addr show {interface}", shell=True, text=True
        ).strip()

        # Ejemplo de cidr: 10.0.0.221/24
        cidr = ip_info.split()[3]

        # Extraer solo la IP local: 10.0.0.221
        interface_ip = cidr.split("/")[0]

        # Convertir la IP/máscara en red: 10.0.0.0/24
        network = str(ipaddress.ip_interface(cidr).network)

        return network, gateway, interface_ip

    except Exception:
        # Valores por defecto si algo falla
        return "10.0.0.0/24", "N/A", "N/A"


# ==============================
# Device role classification
# ==============================
# Esta función decide el rol de cada IP encontrada.
#
# Reglas:
# - si la IP es el gateway => "Gateway"
# - si la IP es la del equipo actual => "Local Host"
# - si no => "Device"

def determine_role(ip, gateway, local_ip):
    if ip == gateway:
        return "Gateway"
    elif ip == local_ip:
        return "Local Host"
    return "Device"


# ==============================
# Terminal output formatting
# ==============================
# Esta función imprime una tabla alineada en la terminal.
# Calcula el ancho de cada columna para que la salida
# se vea limpia y profesional.

def print_table(devices):
    headers = ["IP", "ROLE", "HOSTNAME", "STATE", "MAC", "VENDOR"]

    # Crear las filas de la tabla
    rows = []
    for device in devices:
        rows.append([
            device["ip"],
            device["role"],
            device["hostname"],
            device["state"],
            device["mac"],
            device["vendor"]
        ])

    # Calcular ancho máximo de cada columna
    col_widths = []
    for i, header in enumerate(headers):
        max_width = len(header)
        for row in rows:
            max_width = max(max_width, len(str(row[i])))
        col_widths.append(max_width)

    # Imprimir encabezado
    header_line = "  ".join(
        header.ljust(col_widths[i]) for i, header in enumerate(headers)
    )

    # Imprimir línea separadora
    separator_line = "  ".join(
        "-" * col_widths[i] for i in range(len(headers))
    )

    print(header_line)
    print(separator_line)

    # Imprimir cada fila
    for row in rows:
        print("  ".join(
            str(row[i]).ljust(col_widths[i]) for i in range(len(headers))
        ))


# ==============================
# Main program
# ==============================
# Esta función:
# 1. lee argumentos de terminal
# 2. detecta red/gateway/IP local
# 3. ejecuta el escaneo con Nmap
# 4. construye la lista de dispositivos
# 5. ordena resultados por IP
# 6. imprime la tabla
# 7. guarda JSON y CSV

def main():
    # Crear parser para aceptar argumentos desde la terminal
    parser = argparse.ArgumentParser(description="Network Asset Discovery Tool")
    parser.add_argument(
        "--network",
        help="Network range to scan (example: 10.0.0.0/24)"
    )
    args = parser.parse_args()

    # Detectar red automáticamente
    detected_network, gateway, local_ip = detect_network_gateway_and_local_ip()

    # Si el usuario pasa --network, usar esa red manualmente
    # Si no, usar la detectada automáticamente
    network = args.network if args.network else detected_network

    # Crear objeto scanner de Nmap
    scanner = nmap.PortScanner()

    # Guardar fecha y hora del escaneo
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Mostrar información inicial
    print(f"\nScanning network: {network}")
    print(f"Gateway detected: {gateway}")
    print(f"Local host IP: {local_ip}")
    print(f"Scan time: {timestamp}\n")

    # Ejecutar escaneo de hosts activos
    # -sn = ping scan / host discovery
    scanner.scan(hosts=network, arguments="-sn")

    # Lista donde guardaremos los dispositivos encontrados
    devices = []

    # Recorrer todos los hosts detectados por Nmap
    for host in scanner.all_hosts():
        host_data = scanner[host]

        # Obtener direcciones y datos de fabricante
        addresses = host_data.get("addresses", {})
        vendor_info = host_data.get("vendor", {})

        # Obtener MAC si existe
        mac = addresses.get("mac", "N/A")

        # Obtener vendor/fabricante si existe
        vendor = vendor_info.get(mac, "N/A")

        # Determinar el rol del dispositivo
        role = determine_role(host, gateway, local_ip)

        # Construir registro del dispositivo
        device = {
            "ip": host,
            "role": role,
            "hostname": host_data.hostname() or "N/A",
            "state": host_data.state(),
            "mac": mac,
            "vendor": vendor,
            "scan_time": timestamp
        }

        devices.append(device)

    # Ordenar dispositivos por IP
    devices.sort(key=lambda d: ipaddress.ip_address(d["ip"]))

    # Mostrar tabla final en terminal
    print("Devices discovered:\n")
    print_table(devices)

    # Guardar resultados en JSON
    with open("scan_results.json", "w") as json_file:
        json.dump(devices, json_file, indent=4)

    # Guardar resultados en CSV
    with open("scan_results.csv", "w", newline="") as csv_file:
        writer = csv.DictWriter(
            csv_file,
            fieldnames=["ip", "role", "hostname", "state", "mac", "vendor", "scan_time"]
        )
        writer.writeheader()
        writer.writerows(devices)

    print("\nResults saved to scan_results.json and scan_results.csv\n")


# ==============================
# Program entry point
# ==============================
# Esto asegura que main() solo se ejecute
# cuando corremos el archivo directamente.

if __name__ == "__main__":
    main()
