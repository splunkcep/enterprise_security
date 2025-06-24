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

# Función para generar un log aleatorio
def generate_log():
    timestamp = datetime.now().strftime("%b %d %Y %H:%M:%S")
    log_level = random.choice(LOG_LEVELS)
    action = random.choice(ACTIONS)
    src_ip = random.choice(IPS)
    src_port = random.randint(1000, 65000)
    dst_ip = random.choice(DEST_IPS)
    dst_port = random.randint(20, 8080)
    user = random.choice(USERS)
    protocol = random.choice(PROTOCOLS)

    # Formato del log
    log_entry = f"{timestamp}: {log_level}-106100: access-list acl_in {action} {protocol} inside/{src_ip}({src_port}) -> outside/{dst_ip}({dst_port}) by user {user}"
    
    return log_entry

  # Función principal
  def main():
    print("⏳ Generando logs de Cisco ASA cada 5 segundos...")
    
    while True:
        log = generate_log()
        print(log)

        # Escritura en archivo
        with open(LOG_FILE, "a") as file:
        file.write(log + "\n")

        time.sleep(5)

    if _name_ == "_main_":
    main()
