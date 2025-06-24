#!/usr/bin/env python3

import random
import time
from datetime import datetime

# Configuración del archivo de salida (o enviar a syslog)
LOG_FILE = "cisco_asa_simulated.log" # Cambiar a "/var/log/cisco_asa.log" si es necesario

# Datos simulados
IPS = ["10.1.2.30", "192.168.1.1", "172.16.0.5", "10.0.0.2", "192.168.100.10"]
DEST_IPS = ["192.0.0.8", "192.0.0.89", "192.0.2.10", "10.123.3.42", "192.168.33.31"]
USERS = ["usuario1", "usuario2", "admin", "usuario_de_prueba", "seguridad"]
ACCIONES = ["Denegar", "Permitir", "Desmontar", "Construido"]
PROTOCOLOS = ["tcp", "udp", "icmp"]
NIVELES_DE_REGISTRO = ["%ASA-4", "%ASA-5", "%ASA-6", "%ASA-3"]

# Función para generar un registro aleatorio
def generate_log():
timestamp = datetime.now().strftime("%b %d %Y %H:%M:%S")
nivel_de_registro = random.choice(NIVELES_DE_REGISTRO)
acción = random.choice(ACCIONES)
ip_origen = random.choice(IPS)
puerto_origen = random.randint(1000, 65000)
ip_destino = random.choice(IP_DESTINADO)
puerto_destino = random.randint(20, 8080)
usuario = aleatorio.elección(USUARIOS)
protocolo = aleatorio.elección(PROTOCOLOS)

# Formato del registro
entrada_registro = f"{marca_de_tiempo}: {nivel_registro}-106100: lista_de_acceso acl_in {acción} {protocolo} dentro/{ip_origen}({puerto_origen}) -> fuera/{ip_dst}({puerto_dst}) por usuario {usuario}"

devuelve entrada_registro

# Función principal
def main():
print("⏳ Generando registros de Cisco ASA cada 5 segundos...")

whileTrue:
registro = generate_log()
print(registro)

# Escritura en archivo
with open(ARCHIVO_REGISTRO, "a") as file:
file.write(registro + "\n")

time.sleep(5)

if _name_ == "_main_":
main()
