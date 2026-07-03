# INFORME TÉCNICO DE AMENAZA
## SyslogStealer — Keylogger con Cifrado AES-256-GCM y Persistencia via systemd

**Clasificación:** Confidencial — Uso académico  
**Fecha:** Julio 2026  
**Autor:** Ricardo Pérez — Desarrollo de Software para Seguridad, Universidad de Talca  
**Estilo de referencia:** FortiGuard Threat Intelligence Report  

---

## 1. Nombre y Descripción de la Amenaza

| Campo | Detalle |
|-------|---------|
| **Nombre** | SyslogStealer |
| **Familia** | Keylogger / Spyware / Credential Stealer |
| **Versión analizada** | 1.0 |
| **Severidad** | Alta |
| **Confianza** | Alta (análisis de código fuente completo) |

**SyslogStealer** es un keylogger para Linux que captura todas las pulsaciones de teclado de la víctima y las transmite cifradas a un servidor de comando y control (C2) controlado por el atacante. El malware se disfraza como el servicio legítimo `syslog-cache.service` de systemd para evadir la inspección manual y establece persistencia a nivel de usuario sin requerir privilegios de superusuario.

A diferencia de keyloggers rudimentarios, SyslogStealer implementa:
- Cifrado **AES-256-GCM** (autenticado) con derivación de clave via **PBKDF2-HMAC-SHA256** (200.000 iteraciones).
- Buffer local cifrado en disco: si la conexión al C2 falla, los datos se preservan y se retransmiten en el próximo ciclo.
- Envío periódico **configurable** (default: 30 segundos).
- **Metadata contextual** en cada transmisión (hostname, timestamp).

---

## 2. Vector de Infección y Sistema Operativo Objetivo

### Sistema Operativo Objetivo
- **Primario:** Linux (distribuciones con systemd: Ubuntu, Debian, Fedora, Arch)  
- **Sesiones de escritorio compatibles:** X11 / XWayland  
- **Incompatible:** Sesiones Wayland puras sin XWayland (limitación de la librería pynput con backend X11)

### Vectores de Infección Probables

| Vector | Descripción | Probabilidad |
|--------|-------------|:---:|
| **Phishing con adjunto** | El binario compilado (`syslog-cache`) se envía como adjunto disfrazado de herramienta de diagnóstico. | Alta |
| **Supply chain / typosquatting** | Publicación en PyPI con nombre similar a librería legítima que incluye el keylogger como dependencia. | Media |
| **Descarga directa (drive-by)** | Enlace en foro/Discord que ofrece "herramienta de optimización de sistema". | Media |
| **Acceso físico/remoto** | Atacante con acceso SSH ejecuta el instalador directamente. | Alta (en red corporativa comprometida) |
| **Post-explotación** | Desplegado como segundo payload tras comprometer el sistema con otra vulnerabilidad. | Alta |

### Flujo de Infección
```
[Víctima ejecuta binario] 
    → [keylogger.py se inicia]
    → [instala syslog-cache.service en ~/.config/systemd/user/]
    → [systemctl --user enable syslog-cache.service]
    → [inicia KeyloggerListener (captura de teclado)]
    → [inicia PeriodicSender (envío cifrado cada N segundos)]
    → [datos llegan al C2 del atacante cifrados con AES-256-GCM]
    → [atacante ejecuta server.py → descifra y visualiza keystrokes]
```

---

## 3. TTPs según MITRE ATT&CK

| ID | Táctica | Técnica | Descripción en SyslogStealer |
|----|---------|---------|------------------------------|
| **T1056.001** | Collection | Input Capture: Keylogging | Uso de `pynput.keyboard.Listener` para capturar todos los eventos de teclado a nivel de API del sistema operativo (X11 via `/dev/input`). |
| **T1543.001** | Persistence | Create or Modify System Process: Launch Daemon | Creación de unidad systemd de usuario en `~/.config/systemd/user/syslog-cache.service` con `WantedBy=default.target`. |
| **T1053.003** | Persistence | Scheduled Task/Job: Cron | Alternativa de persistencia via `crontab @reboot` si systemd no está disponible. |
| **T1027** | Defense Evasion | Obfuscated Files or Information | El binario compilado con PyInstaller ofusca el código fuente. Los datos en disco y en tránsito están cifrados, apareciendo como datos aleatorios. |
| **T1036.004** | Defense Evasion | Masquerading: Masquerade Task or Service | El servicio se nombra `syslog-cache.service`, imitando servicios legítimos del sistema. El ejecutable se llama `syslog-cache`. |
| **T1022** | Exfiltration | Data Encrypted | Los keystroke se cifran con AES-256-GCM antes de ser transmitidos. |
| **T1041** | Exfiltration | Exfiltration Over C2 Channel | Datos exfiltrados via TCP al servidor C2 del atacante en puerto configurable (default: 9999). |
| **T1071.001** | Command and Control | Application Layer Protocol: Web Protocols | Protocolo custom TCP con longitud prefija (4B big-endian + payload). |
| **T1082** | Discovery | System Information Discovery | El keylogger registra el hostname y timestamp de la víctima en cada payload. |
| **T1552.001** | Credential Access | Unsecured Credentials: Credentials In Files | Los keystroke capturan credenciales ingresadas en terminales, clientes de correo, formularios en navegadores (X11). |

---

## 4. Indicadores de Compromiso (IoCs)

### 4.1 Hashes del Binario
> **Nota:** Los hashes definitivos se calculan tras compilar con PyInstaller (`./build.sh`).  
> Los valores siguientes son **placeholders** a reemplazar con los valores reales del binario compilado:

| Algoritmo | Hash |
|-----------|------|
| MD5 | `[calcular con: md5sum dist/syslog-cache]` |
| SHA-1 | `[calcular con: sha1sum dist/syslog-cache]` |
| SHA-256 | `[calcular con: sha256sum dist/syslog-cache]` |

### 4.2 Archivos y Rutas en el Sistema de la Víctima

| Ruta | Descripción |
|------|-------------|
| `~/.config/systemd/user/syslog-cache.service` | Unidad de persistencia systemd |
| `~/.local/share/.syslog_cache/.kb_buf.enc` | Buffer cifrado de keystrokes en disco |
| `~/.local/share/.syslog_cache/.kb_sent.log` | Log de transmisiones al C2 |
| `~/.local/share/.syslog_cache/.debug.log` | Log de debug del keylogger |
| `/tmp/.syslogd.pid` | Archivo PID lock (instancia única) |

### 4.3 Indicadores de Red

| Indicador | Valor | Descripción |
|-----------|-------|-------------|
| **Puerto TCP** | 9999 (configurable) | Puerto de comunicación con el C2 |
| **Protocolo** | TCP raw | Protocolo custom: 4B longitud + AES-256-GCM blob |
| **Patrón de tráfico** | Ráfagas periódicas (cada ~30s) de 100-2000 bytes | Transmisión de keystrokes cifrados |
| **Nonce GCM** | 12 bytes aleatorios al inicio de cada blob | Identificable en captura de paquetes |
| **Dirección de conexión** | Víctima → C2 (conexión saliente TCP) | No requiere puerto abierto en la víctima |

### 4.4 Indicadores en Procesos del Sistema

```bash
# Proceso del keylogger (si no fue compilado):
python3 keylogger.py

# Proceso del binario compilado:
syslog-cache

# Servicio systemd activo:
systemctl --user status syslog-cache.service

# Verificar en crontab:
crontab -l | grep syslog-cache
```

---

## 5. Impacto Potencial y Recomendaciones de Mitigación

### 5.1 Impacto Potencial

| Área | Impacto |
|------|---------|
| **Confidencialidad** | **Crítico** — Captura de contraseñas, PINs, mensajes privados, tokens de acceso. |
| **Integridad** | **Bajo** — El malware solo lee datos, no modifica el sistema (salvo la instalación de persistencia). |
| **Disponibilidad** | **Bajo** — No afecta la disponibilidad del sistema víctima. |
| **Cumplimiento** | **Alto** — Violación de GDPR, leyes de protección de datos, confidencialidad empresarial. |

### 5.2 Escenarios de Abuso Críticos
- **Robo de credenciales corporativas:** contraseñas de VPN, SSH, Active Directory.
- **Exfiltración de secretos:** claves API, tokens OAuth, credenciales de bases de datos.
- **Espionaje industrial:** captura de código fuente, documentos confidenciales tecleados.
- **Compromiso de cuentas bancarias** si la víctima realiza transacciones desde el equipo infectado.

### 5.3 Recomendaciones de Mitigación

#### Para Usuarios Finales
| Medida | Descripción |
|--------|-------------|
| **Actualizar el sistema** | Mantener el kernel y librerías actualizadas para cerrar vectores de entrada. |
| **No ejecutar binarios desconocidos** | Verificar el hash SHA-256 de cualquier ejecutable descargado antes de ejecutarlo. |
| **Revisar servicios systemd** | `systemctl --user list-units --type=service` para detectar servicios sospechosos. |
| **Revisar crontab** | `crontab -l` para detectar entradas @reboot no reconocidas. |
| **Usar gestores de contraseñas** | Herramientas como Bitwarden o KeePassXC que autocompetan sin teclear, reduciendo lo capturado. |
| **Monitorear tráfico de red** | Herramientas como `nethogs` o `ss -tp` para detectar conexiones salientes inesperadas. |

#### Para Especialistas TI / Blue Team
| Medida | Descripción |
|--------|-------------|
| **EDR con monitoreo de `/dev/input`** | Detectar procesos que acceden a dispositivos de entrada sin ser aplicaciones legítimas. |
| **Reglas YARA** | Crear firmas para detectar el patrón de llamadas a `pynput` o el string `PBKDF2HMAC` en binarios. |
| **Análisis de comportamiento** | IDS/IPS configurado para detectar ráfagas TCP periódicas a puertos no estándar (como 9999). |
| **Auditoría de systemd units** | Monitorear creación de archivos en `~/.config/systemd/user/` con herramientas como `auditd`. |
| **Lista blanca de procesos** | AppArmor o SELinux para restringir qué procesos pueden leer `/dev/input/*`. |
| **Segmentación de red** | Bloquear conexiones salientes a puertos no estándar en el firewall perimetral. |
| **Análisis forense** | Buscar archivos `.enc` en rutas ocultas (`~/.local/share/.*`), verificar `~/.local/share/.syslog_cache/`. |
| **Honeytokens** | Credenciales falsas monitoreadas que alertan si son utilizadas (capturadas por el keylogger). |

#### Regla YARA de Ejemplo
```yara
rule SyslogStealer_Keylogger {
    meta:
        description = "Detecta SyslogStealer keylogger"
        author      = "Proyecto Seguridad UTalca 2026"
        severity    = "HIGH"

    strings:
        $s1 = "syslog-cache" ascii
        $s2 = "PBKDF2HMAC" ascii
        $s3 = "pynput" ascii
        $s4 = ".kb_buf.enc" ascii
        $s5 = "S3guridad_UTalca_2026" ascii  // hardcoded seed

    condition:
        any of ($s1, $s4, $s5) or
        (2 of ($s2, $s3, $s1))
}
```

#### Regla de red (Suricata/Snort) de Ejemplo
```
alert tcp $HOME_NET any -> $EXTERNAL_NET 9999 (
    msg:"SyslogStealer - Keylogger C2 Communication";
    flow:established,to_server;
    dsize:>100;
    threshold:type both, track by_src, count 5, seconds 180;
    classtype:trojan-activity;
    sid:9000001;
    rev:1;
)
```

---

## 6. Análisis de VirusTotal y Evasión (Ejercicio 3)

> **Instrucciones para completar esta sección:**
> 1. Compilar el binario: `./build.sh`
> 2. Subir `dist/syslog-cache` a [https://www.virustotal.com/gui/file](https://www.virustotal.com/gui/file)
> 3. Capturar pantalla del resultado y pegar el análisis aquí.

**Tipos de detección esperados en VirusTotal:**
| Tipo de Detección | Descripción | Probabilidad en este binario |
|-------------------|-------------|:---:|
| **Firma (Signature)** | El motor compara el hash o bytes del binario con firmas conocidas. | Baja (binario generado localmente, no conocido) |
| **Heurística** | El motor analiza el comportamiento esperado del código (uso de `pynput`, acceso a `/dev/input`). | Media |
| **Comportamiento** | El motor ejecuta el binario en sandbox y observa sus acciones. | Media-Alta (instala servicio systemd, captura teclado) |
| **ML/IA** | Modelos entrenados para clasificar binarios como maliciosos por características estadísticas. | Media |

---

## 7. Conclusión

SyslogStealer demuestra cómo un keylogger moderno puede combinar técnicas de persistencia sin privilegios, cifrado robusto (AES-256-GCM) y evasión básica para comprometer la confidencialidad de un sistema Linux. La principal fortaleza del malware es que los datos capturados son inútiles para cualquier tercero que los intercepte sin la clave derivada, lo que dificulta el análisis post-incidente si el atacante controla el C2.

La detección efectiva requiere un enfoque multicapa: EDR con monitoreo de dispositivos de entrada, análisis de tráfico de red, auditoría de servicios systemd y educación del usuario final para no ejecutar binarios no verificados.

---
*Informe generado con fines académicos. Todo el desarrollo y pruebas se realizaron en entornos virtualizados controlados.*
