# Reglas de Firewall

1. Agregar reglas de firewall

```python
sudo iptables -I INPUT -p tcp --dport 8000 -j ACCEPT
```

```python
sudo iptables -I INPUT -p tcp --dport 8443 -j ACCEPT
```

```python
sudo iptables -I INPUT -p tcp --dport 443 -j ACCEPT
```

```python
sudo iptables -I INPUT -p tcp --dport 8088 -j ACCEPT
```

```python
sudo iptables -I INPUT -p tcp --dport 9997 -j ACCEPT
```

Integración de logs de Cisco ASA y Carbon Black EDR en Splunk ES 8

2. Guardar reglas para la persistencia tras el reinicio

Para sistemas basados ​​en Debian/Ubuntu:

```python
sudo iptables-save | sudo tee /etc/iptables.rules
```

3. Aplicar las reglas tras el reinicio

Para garantizar que las reglas se apliquen al arrancar:

```python
sudo bash -c "echo -e '#!/bin/sh\n/sbin/iptables-restore < /etc/iptables.rules' > /etc/network/if-pre-up.d/iptables"
```

```python
sudo chmod +x /etc/network/if-pre-up.d/iptables
```

4. Verificar que las reglas se hayan aplicado

```python
sudo iptables -L -n
```

Esto mostrará todas las reglas configuradas en iptables, incluidos los puertos recién añadidos.

# Desactivación Transparent Huge Pages (THP) antes de instalar la versión de prueba de Splunk Enterprise

Las Transparent Huge Pages (THP) pueden afectar negativamente el rendimiento de Splunk. Por lo tanto, Splunk recomienda desactivar esta opción antes de la instalación.


Comprobar el estado actual de THP

Antes de realizar cualquier cambio, asegúrese de que THP esté habilitado en su sistema:

```python
cat /sys/kernel/mm/transparent_hugepage/enabled
```

Si el resultado indica [always] o [madvise], THP está habilitado y debe deshabilitarse.

Editar el archivo de configuración de GRUB

Abra el archivo de configuración de GRUB con vi (u otro editor de su elección):

```python
sudo vi /etc/default/grub
```

Busque la línea que comienza con GRUB_CMDLINE_LINUX y agregue transparent_hugepage=never al final de la línea, entre comillas.

Ejemplo:

```python
GRUB_CMDLINE_LINUX="rhgb quiet transparent_hugepage=never"
```

Guarde y salga del editor (ESC → :wq → Enter).


Actualización de GRUB

Tras editar el archivo, genere una nueva configuración de GRUB con el siguiente comando:

```python
sudo grub2-mkconfig -o /boot/grub2/grub.cfg
```

Reinicie el sistema

Ahora, reinicie el servidor para aplicar los cambios:

```python
sudo reboot
```

Verifique que THP esté deshabilitado

Tras reiniciar, confirme que THP esté deshabilitado:

```python
cat /sys/kernel/mm/transparent_hugepage/enabled
```

El resultado debería mostrar "[never]", lo que indica que THP se ha deshabilitado correctamente.

🔗 Documentación oficial

Para más información, consulta la documentación oficial de Splunk:
🔗 Splunk y THP - Transparent Huge Pages


# 📌 Paso a paso: Instalación de la versión de prueba de Splunk Enterprise en Linux

🔹 Acceso al servidor por SSH

Abre una terminal y conéctate al servidor por SSH:

`ssh User_Name@<SERVER_IP>`

🔹 Reemplaza:
• User_Name con el sistema operativo o usuario del dominio.
• <SERVER_IP> con la IP real del host donde quieres instalar Splunk.

🔹 Creación de un usuario para Splunk

Para garantizar una instalación segura, crearemos un usuario dedicado para ejecutar Splunk:

🔹 Este comando:
• Crea un usuario llamado splunkuser.

```python
sudo useradd -m -r splunkuser
```

🔹 Este comando:
• Te pide que le asignes una contraseña.

```python
sudo passwd splunkuser
```

🔑 *Credenciales:
• Usuario del SO: splunkuser
• Contraseña del SO: Establecida en el comando anterior*

🔹 Añadir el usuario de Splunk al grupo Sudo

1️ Añadir splunkuser al grupo Sudo:

```python
sudo usermod -aG sudo splunkuser
```

Verificar que la adición se haya realizado correctamente:

```python
groups splunkuser
```

Para cambiar a bash, ejecute:

```python
sudo chsh -s /bin/bash splunkuser
```

Aplique los cambios cerrando sesión y volviendo a iniciarla como splunkuser:

```python
su - splunkuser
```

¿Dónde estoy?

```python
pwd
```

¿Quién soy?

```python
whoami
```

¿Qué tengo?

```python
ls
```

¿Qué permisos tengo?

```python
ls -lha
```

🔹 Descarga del instalador de Splunk

🔹 Este comando:
• Descarga la versión 9.4.1 de Splunk Enterprise.
• Si desea otra versión, ajuste el enlace en wget.

```python
sudo wget -O splunk-9.4.1-e3bdab203ac8-linux-amd64.tgz "https://download.splunk.com/products/splunk/releases/9.4.1/linux/splunk-9.4.1-e3bdab203ac8-linux-amd64.tgz"
```

Ahora, vaya al directorio de descargas:

```python
cd /home/splunkuser/
```

🔹 Ajuste de permisos en el archivo de instalación

Antes de instalar, verifique los permisos del archivo:

```python
ls -lha /home/splunkuser
```

Asigne permisos de ejecución al archivo:

```python
sudo chmod +x /home/splunkuser/splunk-9.4.1-e3bdab203ac8-linux-amd64.tgz
```

Verifique los permisos de nuevo:

```python
ls -lha /home/splunkuser
```

🔹 Creación del directorio de instalación de Splunk

```python
sudo mkdir /opt/splunk
```

Ahora, cambie el propietario de la carpeta al usuario splunkuser:

sudo chown -R splunkuser:splunkuser /opt/splunk

```python
sudo chown -R splunkuser:splunkuser /opt/splunk
```

Verifique que los permisos sean correctos:

```python
ls -lha /opt/splunk
```

🔹 Instalación de Splunk

Extracción El archivo descargado en /opt
(📌 Esto instalará Splunk en la carpeta /opt/splunk):

```python
tar -xzvf splunk-9.4.1-e3bdab203ac8-linux-amd64.tgz -C /opt
```

🔹 Iniciar Splunk

Ahora, inicie Splunk y acepte la licencia:

```python
/opt/splunk/bin/splunk start --accept-license
```

🔑
* Credenciales predeterminadas de Splunk:
* Usuario del SO: splunkuser
* Contraseña del SO: (establecida anteriormente)
* Usuario de Splunk: admin
* Contraseña de Splunk: splunkuser

🔹 Configurar Splunk para que se inicie automáticamente

Para garantizar que Splunk se ejecute automáticamente, se inicia automáticamente cuando el servidor Reinicios:

```python
sudo /opt/splunk/bin/splunk enable boot-start -user splunkuser --accept-license --answer-yes --no-prompt
```

Esto configura el servicio Splunk para que se inicie automáticamente al iniciar el sistema.

Verifique el archivo de inicio:

```python
sudo vi /etc/init.d/splunk
```

Agregue las siguientes líneas (si es necesario):

```python
RETVAL=0
USER=splunkuser
. /etc/init.d/functions
```

🔹 Comandos básicos para administrar Splunk

Comprobar estado

```python
/opt/splunk/bin/splunk status
```

Iniciar Splunk

```python
/opt/splunk/bin/splunk start
```

Detener Splunk

```python
/opt/splunk/bin/splunk stop
```

Reiniciar Splunk

```python
/opt/splunk/bin/splunk restart
```

Splunk ya está instalado y configurado en su servidor Linux. Para acceder a él mediante el navegador, abra:

```python
http://<SERVER_IP>:8000
```

# Integrar los registros de Cisco ASA Firewall y Carbon Black EDR en Splunk Enterprise Security (ES) 8, garantizando así la conformidad con el Modelo de Información Común (CIM).

1. Crear índices en Splunk

Splunk ES utiliza índices específicos para cada tipo de dato. Vamos a crear los índices correctos:

Crear índice para los registros del firewall de Cisco ASA

```python
/opt/splunk/bin/splunk add index network -datatype event -maxTotalDataSizeMB 50000 -homePath.maxDataSizeMB 10000
```

Usuario administrador

Crear índice para los registros EDR de Carbon Black

```python
/opt/splunk/bin/splunk add index edr -datatype event -maxTotalDataSizeMB 50000 -homePath.maxDataSizeMB 10000
```

🔹 network → Para los registros de seguridad de red y firewall.
🔹 edr → Para los registros de detección y respuesta de endpoints (EDR).

🚀 Reinicia Splunk para aplicar los cambios:

```python
/opt/splunk/bin/splunk restart
```

2. Crea las estrofas de entrada (inputs.conf)

Ahora, configuremos el complemento de Splunk correspondiente para que recopile los registros.

➡️ Firewall Cisco ASA

Comprobar si hay una carpeta local en el complemento Cisco ASA:

```python
ls /opt/splunk/etc/apps/Splunk_TA_cisco-asa/
```

Si no hay ninguna carpeta, créela:

```python
mkdir /opt/splunk/etc/apps/Splunk_TA_cisco-asa/local
```

Archivo: /opt/splunk/etc/apps/Splunk_TA_cisco-asa/local/inputs.conf

```python
vi /opt/splunk/etc/apps/Splunk_TA_cisco-asa/local/inputs.conf
```

Insertar con "i"

```python
i
```

Pegar la estrofa Abajo:

```python
[monitor:///var/log/splunk_real_env/cisco_firewall.log]
índice = red
tipo de origen = cisco:asa
deshabilitado = falso
```

```python
sudo -H -u splunkuser vi /opt/splunk/etc/apps/Splunk_TA_cisco-asa/local/inputs.conf
```

Carbon Black EDR

Archivo: /opt/splunk/etc/apps/Splunk_TA_carbonblack/local/inputs.conf

Si no tiene una, cree la carpeta:

```python
vi /opt/splunk/etc/apps/Splunk_TA_carbonblack/local/inputs.conf
```

```python
[monitor:///var/log/splunk_real_env/carbon_black_edr.log]
index = edr
sourcetype = carbonblack:edr
disabled = false
```

Reinicie Splunk para aplicar los cambios:

```python
/opt/splunk/bin/splunk restart
```

3. Crear scripts para generar eventos de prueba

Crear una carpeta local:

```python
sudo mkdir /var/log/splunk_real_env/
```

Comprobando la carpeta local:

```python
ls -lha /var/log/
```

Ahora creamos dos scripts para simular eventos reales.

Script para generar registros de Cisco ASA

Archivo: /var/log/splunk_real_env/generate_cisco_asa_logs.py

```python
sudo vi /var/log/splunk_real_env/generate_cisco_asa_logs.py
```

```python
import time
import random
from datetime import datetime

log_path = "/var/log/splunk_real_env/cisco_firewall.log"

sample_logs = [
f"{datetime.now(): %b %d %X} hostname %ASA-6-106100: access-list inside_access_in allowed tcp inside/192.168.1.10(12345) -> outside/8.8.8.8(443) hit-cnt 1 first hit",
f"{datetime.now(): %b %d %X} hostname %ASA-6-302015: Se creó una conexión UDP saliente 1234 para la dirección externa: 8.8.8.8/53 a la dirección interna: 192.168.1.20/54231",
]
whileTrue:

with open(log_path, "a") as log_file:
log_file.write(random.choice(sample_logs) + "\n")
time.sleep(3) # Envía registros cada 3 segundos
```

🔹 Genera eventos aleatorios del firewall y los escribe en el archivo de registro.

➡️ Script para generar registros EDR de Carbon Black

Archivo: /var/log/splunk_real_env/generate_carbon_black_edr_logs.py

```python
import time
import random

log_path = "/var/log/splunk_real_env/carbon_black_edr.log"

sample_logs = [
'Marca de tiempo: 2025-03-12 12:10:26, ID del sensor: 12345, Tipo de evento: Creación del proceso, Nombre del proceso: "cmd.exe", Ruta del proceso: "C:\\Windows\\System32\\cmd.exe", Argumentos: "/c powershell.exe -noprofile -executionpolicy bypass"',
'Marca de tiempo: 2025-03-12 12:15:10, ID del sensor: 54321, Evento Tipo: Modificación de archivo, Nombre del archivo: "malicious.exe", Ruta del archivo: "C:\\Usuarios\\Público\\Descargas\\malware.exe"',
]
whileTrue:
with open(log_path, "a") as log_file:
log_file.write(random.choice(sample_logs) + "\n")
time.sleep(30) # Enviar registros cada 30 segundos
```

🔹 Simula procesos sospechosos detectados por Carbon Black EDR.

🚀 Haga que los scripts sean ejecutables y ejecútelos en segundo plano:

```python
sudo chmod +x /var/log/splunk_real_env/generate_cisco_asa_logs.py
```

```python
sudo nohup python3 /var/log/splunk_real_env/generate_cisco_asa_logs.py > /dev/null 2>&1 &
```

Comprobar si el proceso está activo:

```python
ps aux | grep generate_cisco_asa_logs.py
```

Si ve algo como:

```python
username 35943 0.0 0.1 12345 6789 pts/0 S 14:30 0:00 python3 /var/log/splunk_real_env/generate_cisco_asa_logs.py
```

Esto significa que el script se está ejecutando.

```python
sudo chmod +x /var/log/splunk_real_env/generate_carbon_black_edr_logs.py
```

```python
sudo nohup python3 /var/log/splunk_real_env/generate_carbon_black_edr_logs.py > /dev/null 2>&1 &
```

4. Asignar índices en ES (macros.conf)

Ahora necesitamos configurar Splunk Enterprise Security (ES) para que reconozca los registros en el CIM (Modelo de Información Común).

Archivo: /opt/splunk/etc/apps/SplunkEnterpriseSecuritySuite/local/macros.conf

Cisco ASA (Tráfico de red)

```python
[Índices de tráfico de red]
definición = (índice=red O índice=principal)
iseval = 0
```

EDR de carbono negro (Punto final)

```python
[Índices de punto final]
definición = (índice=edr O índice=principal)
iseval = 0
```

Después de editar, aplique los cambios:

```python
splunk /opt/splunk/bin/splunk restart
```

5. Pruebe los registros en Splunk

Ahora, probemos si los eventos se muestran correctamente en los paneles de ES.

Prueba para Cisco ASA

```python
| tstats count FROM datamodel=Network_Traffic.All_Traffic WHERE index=network BY _time, All_Traffic.src, All_Traffic.dest
```

Prueba de Carbon Black EDR

```python
| tstats count FROM datamodel=Endpoint.Processes WHERE index=edr BY _time, Processes.process_name
```

Si aparecen los eventos, significa que los registros se están normalizando correctamente en ES. 🚀

Resumen final

* ✅ Creamos los índices (network y edr) para garantizar que los registros se almacenen correctamente.
* ✅ Configuramos las entradas (inputs.conf) para monitorizar los archivos de registro.
* ✅ Creamos scripts de Python para generar eventos reales desde Cisco ASA y Carbon Black EDR. * ✅ Hemos añadido los índices a las macros de búsqueda (macros.conf) para que Splunk ES los reconozca.
* ✅ Hemos probado los registros en Splunk ES y confirmado que los paneles funcionan correctamente.

# Transferencia de Splunk ES 8 a Splunk mediante SCP

Acceda al directorio donde descargó el archivo. Por ejemplo:

```python
cd /Users/Levi/Downloads/splunk-enterprise-security_802.spl
```

Abra la terminal y realice la transferencia:

```python
scp splunk-enterprise-security_802.spl splunkuser@YOUR_IP:/home/splunkuser
```

Compruebe si el archivo llegó correctamente:

```python
ls -lha /home/splunkuser/splunk-enterprise-security_802.spl
```

Agregue el permiso de ejecución al archivo:

```python
sudo chmod +x /home/splunkuser/splunk-enterprise-security_802.spl
```

Confirme que ahora existe el permiso de ejecución "x":

```python
ls -lha /home/splunkuser/splunk-enterprise-security_802.spl
```

# Instalación de ES 8

Acceda al directorio con el archivo spl:

```python
cd /home/splunkuser/
```

Comando para instalar Enterprise Security 8:

```python
sudo /opt/splunk/bin/splunk install app /home/splunkuser/splunk-enterprise-security_802.spl -auth admin:splunkuser
```

🕒 Aumente el tiempo de espera web de Splunk

Compruebe si la carpeta local existe:

```python
ls /opt/splunk/etc/system/
```

Si la carpeta no existe, créela:

```python
sudo mkdir /opt/splunk/etc/system/local
```

Apriete los Permisos para nuestro usuario:

```python
sudo chown -R splunkuser:splunkuser /opt/splunk
```

Edite el archivo web.conf:

```python
sudo vi /opt/splunk/etc/system/local/web.conf
```

Agregue (o edite) la siguiente sección para aumentar el tiempo de espera:

```python
[settings]
startwebserver = true
splunkdConnectionTimeout = 300
```

Esto aumentará el tiempo de espera a 300 segundos (5 minutos).

Guarde y salga del editor (ESC → :wq → Enter).


⚙️ Ajustar el tiempo de espera en splunk-launch.conf

Editar el archivo:

```python
sudo vi /opt/splunk/etc/splunk-launch.conf
```

Añadir la siguiente línea al final del archivo:

```python
SPLUNKD_CONNECTION_TIMEOUT=300
```

Guardar y salir (ESC → :wq → Intro).

Reiniciar Splunk:

```python
sudo /opt/splunk/bin/splunk restart
```

# Simulación de una inyección SQL

Script de Python para simular una inyección SQL:

```python
sudo vi /var/log/splunk_real_env/sql_injection_simulation.py
```

```python
import time
import random
import logging
from datetime import datetime

# Configurar el registrador para escribir en un archivo de registro
log_file = '/var/log/splunk_real_env/cisco_ips.log' # Establecer la ruta del archivo de registro
logging.basicConfig(filename=log_file, level=logging.INFO,
format='%(asctime)s [%(levelname)s] [%(message)s]')

# Función para generar una inyección SQL (simulada)
def generate_sql_injection():
# Simulación de un ataque simple de inyección SQL
injection_attempts = [
"OR 1=1 --",
"' OR 'a'='a",
"' UNION SELECT NULL, username, password FROM users --",
"'; DROP TABLE users --",
"' OR 'x'='x",
"admin' --",
"' OR 1=1#",
"admin' OR '1'='1' --",
"' OR '' = '",
"'; EXEC xp_cmdshell('dir') --"
]
# Seleccionar un intento aleatorio de inyección SQL
return random.choice(injection_attempts)

# Función para generar un registro simulado de inyección SQL
def log_sql_injection():
timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
source_ip = "192.168.1." + str(random.randint(1, 255)) # IP de origen aleatoria
destination_ip = "10.0.0." + str(random.randint(1, 255)) # IP de destino aleatoria
sql_injection = generate_sql_injection()

# Registro formateado
log_message = f"[INFO] {timestamp} src_ip={source_ip} dest_ip={destination_ip} sql_injection={sql_injection} eventtype=cisco-security-events"

# Escribir en el archivo de registro
logging.info(log_message)
print(log_message)

# Bucle para generar un intento de inyección SQL cada 30 segundos
try:
while True:
log_sql_injection()
time.sleep(30) # Esperar 30 segundos antes del siguiente intento
except KeyboardInterrupt:
print("Script interrumpido por el usuario.")
```

```python
sudo chmod +x sql_injection_simulation.py
```

```python
ls -lha
```

Configuración de la macro de búsqueda de conformidad con CIM:

```python
vi /opt/splunk/etc/apps/SplunkEnterpriseSecuritySuite/local/macros.conf
```

```python
[Índices de tráfico de red]
definición = (índice=red O índice=principal)
iseval = 0
```

```python
[monitor:///var/log/splunk_real_env/cisco_ips.log]
deshabilitado = falso
tipo de origen = cisco:firewall
índice = red
```

Ejecutar en segundo plano:

```python
nohup python3 /var/log/splunk_real_env/sql_injection_simulation.py > /dev/null 2>&1 &
```

Después de ejecutar el script con nohup, puede comprobar si se ejecuta en segundo plano con el comando:

```python
ps aux | grep sql_injection_simulation.py
```

# Solución de problemas

Verifique el proceso exacto:

```python
pgrep -fl sql_injection_simulation.py
```

Si no hay salida, el script no se está ejecutando.

```python
Si el script se detuvo y desea ejecutarlo de nuevo:
```

```python
sudo nohup python3 /var/log/splunk_real_env/sql_injection_simulation.py > /dev/null 2>&1 &
```

Para confirmar que se está ejecutando, utilice:

```python
sudo pgrep -fl sql_injection_simulation.py
```

# Lista de monitores

```python
/opt/splunk/bin/splunk list monitor
```

# 🛠 1️⃣ Comprobar los permisos de la carpeta

Es posible que Splunk no tenga permiso para escribir en la carpeta /var/log/splunk_real_env. Verificar con:

```python
ls -ld /var/log/splunk_real_env
```

Si el resultado es similar a:

```python
drwxr-xr-x 2 root root 4096 Mar 13 13:10 /var/log/splunk_real_env
```

Esto significa que solo el usuario root puede escribir. Para solucionarlo, ejecute:

```python
sudo chmod 777 /var/log/splunk_real_env
```

Esto le otorgará permisos completos (pruébelo y luego podremos ajustar los permisos según corresponda).

Recursivo:

```python
sudo chmod -R 777 /var/log/splunk_real_env
```

Ejecute el script de nuevo:

```python
nohup python3 /var/log/splunk_real_env/sql_injection_simulation.py > /dev/null 2>&1 &
```

Comprobar si se creó:

```python
ls -l /var/log/splunk_real_env/cisco_ips.log
```

📁 2️⃣ Comprobar si se está creando el archivo

```python
ls -l /var/log/splunk_real_env/cisco_ips.log
```

Comprobar si el script SQL se está ejecutando:

```python
pgrep -fl sql_injection_simulation.py
```

Verifique si el script del firewall se está ejecutando:

```python
pgrep -fl generate_cisco_asa_logs.py
```

Ejecute ambos scripts de nuevo:

```python
sudo nohup python3 /var/log/splunk_real_env/generate_cisco_asa_logs.py > /dev/null 2>&1 &
sudo nohup python3 /var/log/splunk_real_env/sql_injection_simulation.py > /dev/null 2>&1 &
```
