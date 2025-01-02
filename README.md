# Análisis Forense de Red con Python

Este proyecto implementa un conjunto de herramientas para realizar un análisis forense de archivos PCAP capturados en una red. Utilizando Python y bibliotecas como `dpkt`, `matplotlib`, y `tabulate`, el proyecto permite identificar patrones sospechosos, analizar tráfico de red, generar reportes y visualizar resultados clave.

## Funcionalidades Principales

- Decodificación de paquetes Ethernet e IP.
- Detección de patrones sospechosos como escaneo de puertos, beaconing y transferencias de datos grandes.
- Análisis de solicitudes DNS sospechosas y tráfico TLS.
- Detección de strings sensibles en el payload de los paquetes.
- Geolocalización de direcciones IP.
- Visualización de datos mediante gráficas claras y concisas.
- Generación de reportes en formato de texto tabulado.

## Instrucciones de Instalación

### Requisitos Previos

1. **Python 3.8+**: Asegúrate de tener Python instalado en tu sistema.
2. **Dependencias**:
   - `dpkt`
   - `matplotlib`
   - `requests`
   - `tabulate`

### Instalación

1. Clonar el repositorio:

   ```bash
   git clone https://github.com/Manuel-Archila/Thesis.git
   cd Thesis
   ```

2. Crear y activar un entorno virtual (opcional pero recomendado):

   ```bash
   python3 -m venv venv
   source venv/bin/activate  # Linux/Mac
   venv\Scripts\activate   # Windows
   ```

3. Instalar las dependencias:

   ```bash
   pip install -r requirements.txt
   ```

4. Asegúrate de tener un archivo PCAP para analizar y colócalo en el directorio `./src/` con el nombre `c1.pcap` o actualiza la ruta en el código según sea necesario.

### Ejecución de la Aplicación

1. Ejecuta el script principal:

   ```bash
   python ./src/thesis_dpkt.py
   ```

2. El script realizará las siguientes tareas:

   - Decodificar y analizar el archivo PCAP.
   - Detectar patrones sospechosos.
   - Generar reportes en formato de texto.
   - Crear gráficas para la visualización de resultados.

## Contacto

Si tienes preguntas o sugerencias, no dudes en contactarme en arc161250\@uvg.edu.gt.

¡Gracias por tu interés en este proyecto!

