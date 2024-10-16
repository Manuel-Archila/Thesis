import pyshark
import nest_asyncio
import matplotlib.pyplot as plt
import pandas as pd
from collections import defaultdict
import geoip2.database

# Aplicar el parche para manejar bucles de eventos anidados
nest_asyncio.apply()

# ================== PASO 1: Cargar y mostrar los primeros paquetes ==================
def mostrar_paquetes(cap, n=1):
    """Función para imprimir los primeros n paquetes"""
    print(f"Mostrando los primeros {n} paquetes:")
    packet_count = 0
    for packet in cap:
        print(packet)
        packet_count += 1
        if packet_count >= n:
            break

# Cargar el archivo PCAP
archivo_pcap = 'analisis_paquetes.pcap'
cap = pyshark.FileCapture(archivo_pcap)

# Mostrar los primeros 5 paquetes
mostrar_paquetes(cap)

# ================== PASO 2: Detección de patrones sospechosos ==================
# Analizar los paquetes para identificar patrones como Beaconing, Escaneo de puertos, etc.

# Definir contadores para detección de patrones
ip_communication = defaultdict(int)
dns_requests = defaultdict(int)
syn_packets = defaultdict(int)
large_data_transfers = defaultdict(list)

# Analizar cada paquete en el archivo PCAP
for packet in cap:
    try:
        # Analizar solo paquetes IP
        if 'IP' in packet:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            ip_communication[dst_ip] += 1  # Contabilizar comunicación a cada IP

            # Analizar paquetes TCP para detectar patrones de SYN
            if 'TCP' in packet and packet.tcp.flags == '0x02':  # SYN Packet
                syn_packets[src_ip] += 1

            # Verificar si el tamaño del paquete es sospechosamente grande
            size = int(packet.length)
            if size > 1000:  # Umbral de transferencia grande (ajustable)
                large_data_transfers[src_ip].append(size)

        # Análisis de solicitudes DNS
        if 'DNS' in packet and packet.dns.qry_name:
            dns_requests[packet.dns.qry_name] += 1

    except AttributeError:
        # Paquetes que no tienen los atributos esperados
        continue

# ================== PASO 3: Identificación de patrones de Beaconing ==================
print("\n=== Detección de Beaconing ===")
for ip, count in ip_communication.items():
    if count > 50:  # Ajustar umbral según el contexto
        print(f"Patrón de beaconing detectado hacia IP: {ip} con {count} solicitudes")

# ================== PASO 4: Detección de Escaneo de Puertos ==================
print("\n=== Detección de Escaneo de Puertos ===")
for ip, count in syn_packets.items():
    if count > 10:  # Ajustar umbral según el contexto
        print(f"Posible escaneo de puertos desde IP: {ip} con {count} paquetes SYN")

# ================== PASO 5: Análisis de Solicitudes DNS ==================
print("\n=== Análisis de Solicitudes DNS ===")
for domain, count in dns_requests.items():
    if count > 5:  # Ajustar umbral según el contexto
        print(f"Solicitud DNS sospechosa a: {domain} con {count} peticiones")

# ================== PASO 6: Análisis de Transferencias de Datos Grandes ==================
print("\n=== Análisis de Transferencias de Datos Grandes ===")
for ip, sizes in large_data_transfers.items():
    total_size = sum(sizes)
    print(f"IP {ip} ha enviado/recibido un total de {total_size} bytes en {len(sizes)} paquetes grandes")

# ================== PASO 7: Visualización de Tráfico ==================
def graficar_comunicaciones(ip_communication):
    """Graficar el número de solicitudes por cada IP destino"""
    ips = list(ip_communication.keys())
    counts = list(ip_communication.values())

    plt.figure(figsize=(15, 5))
    plt.bar(ips, counts, color='skyblue')
    plt.xlabel('IPs Destino')
    plt.ylabel('Número de Solicitudes')
    plt.title('Número de Solicitudes por IP')
    plt.xticks(rotation=90)
    plt.show()

# Graficar la comunicación hacia las IPs detectadas
graficar_comunicaciones(ip_communication)

# ================== PASO 8: Detección de Ubicaciones Geográficas (opcional) ==================
def analizar_geolocalizacion(ip_communication, database_path='GeoLite2-City.mmdb'):
    """Analiza la ubicación geográfica de las IPs destino usando GeoIP2"""
    try:
        reader = geoip2.database.Reader(database_path)
        print("\n=== Ubicaciones Geográficas ===")
        for ip in ip_communication:
            try:
                response = reader.city(ip)
                country = response.country.name
                city = response.city.name
                print(f"IP: {ip} | País: {country} | Ciudad: {city}")
            except geoip2.errors.AddressNotFoundError:
                continue
        reader.close()
    except FileNotFoundError:
        print("Base de datos GeoIP no encontrada. Omite esta sección.")

# ================== PASO 9: Generar Reporte ==================
def generar_reporte():
    """Generar un informe final de los hallazgos"""
    print("\n=== Resumen de Hallazgos ===")
    print(f"IPs detectadas con patrones de beaconing: {len([ip for ip, count in ip_communication.items() if count > 50])}")
    print(f"IPs sospechosas de escaneo de puertos: {len([ip for ip, count in syn_packets.items() if count > 10])}")
    print(f"Solicitudes DNS sospechosas: {len([domain for domain, count in dns_requests.items() if count > 5])}")
    print(f"IPs con grandes transferencias de datos: {len(large_data_transfers)}")

# Generar reporte final
generar_reporte()
