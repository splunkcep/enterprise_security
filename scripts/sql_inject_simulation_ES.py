import time
import random
import logging
from datetime import datetime

# Configurar del logger para escribir en un archivo de registro
log_file = '/var/log/splunk_real_env/cisco_ips.log' # Establecer la ruta del archivo de log
logging.basicConfig(filename=log_file, level=logging.INFO,
format='%(asctime)s [%(levelname)s] [%(message)s]')

# Función para generar inyección SQL (simulada)
def generate_sql_injection():
    # Inyección SQL simple que simula un ataque
    injection_attempts = [
        "OR 1=1 --",
        "' OR 'a'='a",
        "' UNION SELECT NULL, username, password FROM users --",
        "'; DROP TABLE users --",
        "' OR 'x'='x",
        "admin' --",
        "' OR 1=1#", "admin' OR '1'='1' --",
        "' OR '' = '",
        "'; EXEC xp_cmdshell('dir') --"
    ]

    # Seleccionar un intento aleatorio de inyección SQL
    return random.choice(injection_attempts)

  # Función para generar un log simulado de inyección SQL
  def log_sql_injection():
      timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
      source_ip = "192.168.1." + str(random.randint(1, 255)) # IP de origen aleatoria
      destination_ip = "10.0.0." + str(random.randint(1, 255)) # IP de destino aleatoria
      sql_injection = generate_sql_injection()

      # Log formateado
      log_message = f"[INFO] {timestamp} src_ip={source_ip} dest_ip={destination_ip} sql_injection={sql_injection} eventtype=cisco-security-events"

      # Escribir en el archivo de log
      logging.info(log_message)
      print(log_message)

    # Loop para generar un intento de inyección SQL cada 30 segundos
    try:
        while True:
            log_sql_injection()
            time.sleep(30) # Esperar 30 segundos antes del siguiente intento
    except KeyboardInterrupt:
        print("Script interrumpido por el usuario.")
