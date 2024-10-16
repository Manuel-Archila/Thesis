import dpkt
import socket
import pandas as pd
import matplotlib.pyplot as plt
from collections import defaultdict
import requests

# ================== PASO 1: Cargar y mostrar los primeros 5 paquetes ==================
def mostrar_paquetes(pcap, n=5):
    """Función para mostrar los primeros n paquetes del archivo PCAP"""
    print(f"Mostrando los primeros {n} paquetes:")
    count = 0
    for timestamp, buf in pcap:
        # Decodificar los paquetes Ethernet
        eth = dpkt.ethernet.Ethernet(buf)
        # Revisar si el paquete es IP
        if isinstance(eth.data, dpkt.ip.IP):
            ip = eth.data
            src_ip = socket.inet_ntoa(ip.src)
            dst_ip = socket.inet_ntoa(ip.dst)
            print(f"Paquete {count + 1}: {src_ip} -> {dst_ip}")
            count += 1
        if count >= n:
            break

# ================== PASO 2: Análisis de patrones sospechosos ==================
def analizar_pcap(pcap):
    """Analizar el archivo PCAP para detectar patrones sospechosos"""
    ip_communication = defaultdict(int)
    syn_packets = defaultdict(lambda: defaultdict(int))  # Almacenar {src_ip: {dst_ip: count}}
    dns_requests = defaultdict(int)
    large_data_transfers = defaultdict(int)

    for timestamp, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)

        # Revisar si el paquete es IP
        if isinstance(eth.data, dpkt.ip.IP):
            ip = eth.data
            src_ip = socket.inet_ntoa(ip.src)
            dst_ip = socket.inet_ntoa(ip.dst)

            # Contabilizar la comunicación entre IPs
            ip_communication[dst_ip] += 1

            # Revisar si es un paquete TCP
            if isinstance(ip.data, dpkt.tcp.TCP):
                tcp = ip.data

                # Detectar SYN packets (indican posibles escaneos de puertos)
                if (tcp.flags & dpkt.tcp.TH_SYN) and not (tcp.flags & dpkt.tcp.TH_ACK):
                    syn_packets[src_ip][dst_ip] += 1  # Registrar SYN de src_ip a dst_ip

                # Detectar transferencias de datos grandes
                data_size = len(tcp.data)
                if data_size > 1000:  # Umbral de datos grandes en bytes
                    large_data_transfers[src_ip] += data_size

            # Revisar si es un paquete DNS
            if isinstance(ip.data, dpkt.udp.UDP) and ip.data.dport == 53:
                try:
                    dns = dpkt.dns.DNS(ip.data.data)
                    if dns.qr == dpkt.dns.DNS_Q and len(dns.qd) > 0:
                        for query in dns.qd:
                            dns_requests[query.name] += 1
                except (dpkt.dpkt.UnpackError, AttributeError):
                    continue

    return ip_communication, syn_packets, dns_requests, large_data_transfers


# ================== PASO 3: Mostrar resultados del análisis ==================
def mostrar_resultados(ip_communication, syn_packets, dns_requests, large_data_transfers):
    """Mostrar los hallazgos del análisis forense"""
    print("\n=== Resultados del análisis ===")

    # Mostrar patrones de beaconing
    print("\n=== Detección de Beaconing ===")
    for ip, count in ip_communication.items():
        if count > 50:  # Ajustar umbral según el contexto
            print(f"Patrón de beaconing detectado hacia IP: {ip} con {count} solicitudes")

    print("\n=== Escaneo de Puertos Detectado ===")
    for src_ip, dst_dict in syn_packets.items():
        for dst_ip, count in dst_dict.items():
            if count > 10:  # Umbral de paquetes SYN para considerar un escaneo
                print(f"IP Origen: {src_ip} está escaneando IP Destino: {dst_ip} con {count} paquetes SYN")


    # Mostrar análisis de solicitudes DNS
    print("\n=== Análisis de Solicitudes DNS ===")
    for domain, count in dns_requests.items():
        if count > 5:
            print(f"Solicitud DNS sospechosa a: {domain} con {count} peticiones")

    # Mostrar análisis de transferencias de datos grandes
    print("\n=== Análisis de Transferencias de Datos Grandes ===")
    for ip, size in large_data_transfers.items():
        print(f"IP {ip} ha transferido un total de {size} bytes en paquetes grandes")

# ================== PASO 4: Visualización del tráfico por IP ==================
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

# ================== PASO 5: Generar reporte final ==================
def generar_reporte(
ip_communication, dns_requests, large_data_transfers, 
umbral_beaconing=50, umbral_dns=5, umbral_transferencia=1000):
    with open('reporte.txt', 'w') as f:
        f.write("=== Reporte de Análisis Forense de Red ===")
        f.write("\n=== Resumen Final del Análisis ===")

        # Patrones de beaconing
        beaconing_ips = [ip for ip, count in ip_communication.items() if count > umbral_beaconing]
        f.write(f"\nIPs detectadas con patrones de beaconing (>{umbral_beaconing} solicitudes): {len(beaconing_ips)}")

        # Solicitudes DNS sospechosas
        dns_sospechosas = [domain for domain, count in dns_requests.items() if count > umbral_dns]
        f.write(f"\nSolicitudes DNS sospechosas (>{umbral_dns} peticiones): {len(dns_sospechosas)}")

        # IPs con grandes transferencias de datos
        transferencias_grandes = [ip for ip, size in large_data_transfers.items() if size > umbral_transferencia]
        f.write(f"\nIPs con grandes transferencias de datos (>{umbral_transferencia} bytes): {len(transferencias_grandes)}")


# ================== Análisis de Protocolo y Tipos de Tráfico ==================
def detectar_protocolos(pcap):
    """Detectar protocolos inusuales en el archivo PCAP"""
    protocolos_detectados = defaultdict(int)
    for timestamp, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        if isinstance(eth.data, dpkt.ip.IP):
            ip = eth.data
            protocolo = ip.p
            protocolos_detectados[protocolo] += 1

    print("\n=== Detección de Protocolos Inusuales ===")
    for protocolo, count in protocolos_detectados.items():
        if protocolo not in [6, 17]:  # TCP (6) y UDP (17) son comunes
            print(f"Protocolo inusual detectado: {protocolo} con {count} paquetes")

    return protocolos_detectados  # Devolver los protocolos detectados


# ================== Análisis de Tráfico Encriptado (TLS/SSL) ==================
def detectar_trafico_tls(pcap):
    """Detectar tráfico SSL/TLS y versiones inseguras"""
    tls_traffic = defaultdict(int)
    for timestamp, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        if isinstance(eth.data, dpkt.ip.IP):
            ip = eth.data
            if isinstance(ip.data, dpkt.tcp.TCP):
                tcp = ip.data
                if tcp.dport == 443:
                    tls_traffic[ip.src] += 1
    print("\n=== Detección de Tráfico TLS ===")
    for ip, count in tls_traffic.items():
        print(f"IP: {ip} tiene {count} conexiones TLS detectadas")

# ================== Análisis de Ataques de Red Comunes ==================
def detectar_arp_spoofing(pcap):
    """Detectar ataques de ARP Spoofing en el archivo PCAP"""
    arp_table = defaultdict(set)
    for timestamp, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        if isinstance(eth.data, dpkt.arp.ARP):
            arp = eth.data
            arp_table[arp.spa].add(arp.sha)

    print("\n=== Detección de ARP Spoofing ===")
    for ip, macs in arp_table.items():
        if len(macs) > 1:
            print(f"ARP Spoofing detectado: IP {ip} tiene {len(macs)} MACs asociadas: {macs}")

# ================== Análisis de Tiempos y Sesiones ==================
def analizar_tiempos_sesiones(pcap):
    """Analizar el tiempo de las sesiones y detectar patrones sospechosos"""
    sesion_tiempo = defaultdict(list)
    for timestamp, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        if isinstance(eth.data, dpkt.ip.IP):
            ip = eth.data
            src_ip = socket.inet_ntoa(ip.src)
            dst_ip = socket.inet_ntoa(ip.dst)
            sesion_tiempo[(src_ip, dst_ip)].append(timestamp)

    print("\n=== Análisis de Sesiones ===")
    for (src_ip, dst_ip), tiempos in sesion_tiempo.items():
        if len(tiempos) > 5:
            intervalos = [j - i for i, j in zip(tiempos[:-1], tiempos[1:])]
            print(f"Conexión entre {src_ip} y {dst_ip} tiene intervalos: {intervalos}")

# ================== Detección de Strings Sospechosos en el Payload ==================
def detectar_strings_sospechosos(
    pcap, 
    keywords=['password', 'admin', 'login', 'root', 'confidential', 'secret', 'access key', 'access', 'credential']
):
    """Detectar strings sospechosos en el payload de los paquetes y mostrar el contenido completo"""
    for timestamp, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        if isinstance(eth.data, dpkt.ip.IP):
            ip = eth.data
            if isinstance(ip.data, dpkt.tcp.TCP):
                tcp = ip.data
                payload = tcp.data.decode('latin1', errors='replace')  # Decodificar el payload

                with open('payload.txt', 'w', encoding='latin-1') as f:
                    for keyword in keywords:
                        if keyword in payload:
                            src_ip = socket.inet_ntoa(ip.src)
                            dst_ip = socket.inet_ntoa(ip.dst)
                            f.write(f"\n=== String sospechoso '{keyword}' detectado ===")
                            f.write(f"De: {src_ip} -> A: {dst_ip}")
                            f.write(f"Payload completo:\n{payload}")
                            f.write("=" * 50)



# ================== Geolocalizar IPs ==================
def geolocalizar_ips(ip_addresses):
    """Geolocalizar las IPs en la lista de direcciones IP usando la API de ipinfo.io"""
    print("\n=== Geolocalización de IPs ===")
    for ip in ip_addresses:
        response = requests.get(f'https://ipinfo.io/{ip}/json')
        if response.status_code == 200:
            data = response.json()
            print(f"IP: {ip}, Ubicación: {data.get('city', 'Desconocido')}, {data.get('country', 'Desconocido')}")

def analizar_puertos_por_ip(pcap):
    """Analizar los puertos destino por cada IP origen en el archivo PCAP."""
    puertos_por_ip = defaultdict(lambda: defaultdict(int))  # {src_ip: {puerto: count}}

    for timestamp, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        if isinstance(eth.data, dpkt.ip.IP):
            ip = eth.data
            src_ip = socket.inet_ntoa(ip.src)

            # Si el paquete es TCP, analizamos el puerto destino
            if isinstance(ip.data, dpkt.tcp.TCP):
                tcp = ip.data
                puertos_por_ip[src_ip][tcp.dport] += 1
    
    print("\n=== Análisis de Puertos por IP ===")
    for ip, puertos in puertos_por_ip.items():
        print(f"\nIP Origen: {ip}")
        for puerto, count in puertos.items():
            print(f"  Puerto {puerto}: {count} solicitudes")



# ================== Ejecución del Script ==================
# Ruta al archivo PCAP
ruta_archivo = 'c1.pcap'

# Cargar y analizar el archivo PCAP dentro del contexto de apertura del archivo
with open(ruta_archivo, 'rb') as f:
    pcap = dpkt.pcap.Reader(f)
    mostrar_paquetes(pcap)

    f.seek(0)
    pcap = dpkt.pcap.Reader(f)
    ip_communication, syn_packets, dns_requests, large_data_transfers = analizar_pcap(pcap)
    protocolos_detectados = detectar_protocolos(pcap)

    f.seek(0)
    pcap = dpkt.pcap.Reader(f)
    detectar_trafico_tls(pcap)

    f.seek(0)
    pcap = dpkt.pcap.Reader(f)
    detectar_arp_spoofing(pcap)

    f.seek(0)
    pcap = dpkt.pcap.Reader(f)
    #analizar_tiempos_sesiones(pcap)

    f.seek(0)
    pcap = dpkt.pcap.Reader(f)
    detectar_strings_sospechosos(pcap)

    f.seek(0)
    pcap = dpkt.pcap.Reader(f)
    analizar_puertos_por_ip(pcap)

    ip_list = list(ip_communication.keys())
    geolocalizar_ips(ip_list)

# ================== Graficar SYN packets por IP ==================
def graficar_syn_packets(syn_packets):
    """Graficar el número total de paquetes SYN enviados por cada IP origen"""
    # Sumar los paquetes SYN enviados por cada IP origen
    aggregated_counts = {src_ip: sum(dst_dict.values()) for src_ip, dst_dict in syn_packets.items()}

    ips = list(aggregated_counts.keys())
    counts = list(aggregated_counts.values())

    plt.figure(figsize=(15, 5))
    plt.bar(ips, counts, color='orange')
    plt.xlabel('IPs Origen')
    plt.ylabel('Total de Paquetes SYN')
    plt.title('Total de Paquetes SYN por IP Origen')
    plt.xticks(rotation=90)
    plt.tight_layout()
    plt.show()

def graficar_syn_pairs(syn_packets):
    """Graficar los paquetes SYN enviados desde IP origen a IP destino"""
    pairs = [(src_ip, dst_ip, count) for src_ip, dst_dict in syn_packets.items() for dst_ip, count in dst_dict.items()]

    # Separar los datos para graficar
    labels = [f'{src}->{dst}' for src, dst, _ in pairs]
    counts = [count for _, _, count in pairs]

    plt.figure(figsize=(15, 5))
    plt.bar(labels, counts, color='orange')
    plt.xlabel('IP Origen -> IP Destino')
    plt.ylabel('Número de Paquetes SYN')
    plt.title('Paquetes SYN por Par Origen-Destino')
    plt.xticks(rotation=90)
    plt.tight_layout()
    plt.show()


# ================== Graficar transferencias de datos grandes por IP ==================
def graficar_large_data_transfers(large_data_transfers):
    ips = list(large_data_transfers.keys())
    data_sizes = list(large_data_transfers.values())

    plt.figure(figsize=(15, 5))
    plt.bar(ips, data_sizes, color='green')
    plt.xlabel('IPs Origen')
    plt.ylabel('Bytes Transferidos')
    plt.title('Transferencias de Datos Grandes por IP Origen')
    plt.xticks(rotation=90)
    plt.tight_layout()
    plt.show()

# ================== Graficar solicitudes DNS por dominio ==================
def graficar_dns_requests(dns_requests):
    domains = list(dns_requests.keys())
    counts = list(dns_requests.values())

    plt.figure(figsize=(15, 5))
    plt.bar(domains, counts, color='purple')
    plt.xlabel('Dominios')
    plt.ylabel('Número de Solicitudes')
    plt.title('Solicitudes DNS por Dominio')
    plt.xticks(rotation=90)
    plt.tight_layout()
    plt.show()

# ================== Graficar protocolos detectados ==================
def graficar_protocolos(protocolos_detectados):
    protocolos = list(protocolos_detectados.keys())
    counts = list(protocolos_detectados.values())

    plt.figure(figsize=(10, 5))
    plt.bar(protocolos, counts, color='red')
    plt.xlabel('Protocolos')
    plt.ylabel('Número de Paquetes')
    plt.title('Protocolos Detectados')
    plt.xticks(rotation=90)
    plt.tight_layout()
    plt.show()



mostrar_resultados(ip_communication, syn_packets, dns_requests, large_data_transfers)
graficar_comunicaciones(ip_communication)
generar_reporte(ip_communication, dns_requests, large_data_transfers)

graficar_syn_packets(syn_packets)  # Graficar los paquetes SYN por IP
graficar_syn_pairs(syn_packets)  # Graficar los pares de SYN packets
graficar_large_data_transfers(large_data_transfers)  # Graficar las transferencias de datos grandes
graficar_dns_requests(dns_requests)  # Graficar las solicitudes DNS por dominio
graficar_protocolos(protocolos_detectados)  # Graficar los protocolos detectados
