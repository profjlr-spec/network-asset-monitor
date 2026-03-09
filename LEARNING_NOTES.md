# LEARNING NOTES - Network Asset Discovery Tool

## ¿Qué hace este proyecto?

Este proyecto escanea una red local y crea un inventario básico de dispositivos activos.

Puede mostrar:

- IP
- rol del dispositivo
- hostname
- estado
- MAC address
- fabricante (vendor)
- fecha y hora del escaneo

También guarda resultados en:

- `scan_results.json`
- `scan_results.csv`

---

## Estructura general de `discovery.py`

El archivo está dividido en estas secciones:

1. Imports
2. Detección de red, gateway e IP local
3. Clasificación de roles
4. Impresión de tabla
5. Programa principal (`main`)

---

## 1. Imports

Aquí se importan las librerías necesarias.

### Librerías importantes:
- `nmap`: permite usar Nmap desde Python
- `json`: guarda resultados en formato JSON
- `csv`: guarda resultados en formato CSV
- `argparse`: permite usar argumentos como `--network`
- `subprocess`: ejecuta comandos de Linux
- `ipaddress`: ayuda a trabajar con redes e IPs
- `datetime`: agrega fecha y hora

---

## 2. detect_network_gateway_and_local_ip()

Esta función detecta automáticamente:

- la red local
- el gateway
- la IP local del equipo

### Ejemplo:
Si la IP de tu equipo es:

`10.0.0.221/24`

la función obtiene:

- red: `10.0.0.0/24`
- gateway: `10.0.0.1`
- local IP: `10.0.0.221`

Esto se hace usando comandos de Linux como:

- `ip route`
- `ip -o -f inet addr show`

---

## 3. determine_role()

Esta función clasifica cada IP encontrada.

### Roles:
- `Gateway` → si la IP es el router/gateway
- `Local Host` → si la IP es tu propia máquina
- `Device` → cualquier otro dispositivo

### Ejemplo:
- `10.0.0.1` → Gateway
- `10.0.0.221` → Local Host
- `10.0.0.215` → Device

---

## 4. print_table()

Esta función imprime los resultados en formato de tabla.

Hace 3 cosas:

1. construye filas
2. calcula el ancho de columnas
3. imprime encabezados y filas alineadas

Gracias a esto, la salida se ve más profesional en terminal.

---

## 5. main()

Esta es la función principal del programa.

### Lo que hace:
1. lee argumentos de la terminal
2. detecta la red automáticamente
3. ejecuta el escaneo con Nmap
4. procesa los resultados
5. clasifica roles
6. imprime tabla
7. guarda JSON y CSV

---

## ¿Por qué a veces no sale la MAC?

Cuando ejecutas:

```bash
python discovery.py
