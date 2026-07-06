#!/usr/bin/env python3
"""
Proyecto Unidad 2 - Seguridad Informática
Proxy MITM: intercepta el tráfico entre keylogger y C2, demostrando que
AES-256-GCM hace el contenido ilegible sin la clave correcta.

Escenario:
    VM1 (víctima) → keylogger → VM2 (este script) → VM3 (server.py)

Uso:
    python3 mitm_demo.py [--listen PUERTO] [--forward HOST:PUERTO]
"""

import sys
import struct
import socket
import logging
import argparse
import threading
from datetime import datetime
from pathlib import Path


DEFAULT_LISTEN_PORT  = 8888           # puerto donde escucha el proxy MITM
DEFAULT_FORWARD_HOST = "192.168.56.10"  # IP del C2 real (Kali)
DEFAULT_FORWARD_PORT = 9999
INTERCEPT_LOG        = Path("./mitm_intercept.log")


def log_intercepted(direction: str, data: bytes, from_addr: tuple):
    """Registra en consola y archivo el tráfico interceptado en hex."""
    timestamp   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    hex_preview = data[:64].hex()  # solo primeros 64 bytes para no saturar la salida

    entry = (
        f"\n[MITM] {timestamp} | {direction} | {from_addr[0]}:{from_addr[1]}\n"
        f"Tamaño: {len(data)} bytes\n"
        f"Hex (64B): {hex_preview}...\n"
        f"Contenido cifrado con AES-256-GCM — ilegible sin la clave.\n"
    )

    print(entry)
    with open(INTERCEPT_LOG, "a") as f:
        f.write(entry)


def attempt_decrypt_without_key(data: bytes):
    """Intenta descifrar sin la clave correcta, demostrando que AES-GCM lo impide."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag

    print("[MITM] Intentando descifrar con clave incorrecta...")
    try:
        # clave incorrecta de 32 bytes — cualquier intento sin la clave real falla
        AESGCM(b"A" * 32).decrypt(data[:12], data[12:], None)
        print("[MITM] ERROR: descifrado exitoso con clave incorrecta (no debería ocurrir)")
    except InvalidTag:
        # el tag GCM detecta que la clave es incorrecta y rechaza el descifrado
        print("[MITM] ✓ Tag GCM inválido — contenido ilegible sin la clave correcta.\n")
    except Exception as e:
        print(f"[MITM] Error: {e}\n")


class MITMProxy(threading.Thread):
    """Proxy TCP que intercepta, registra y reenvía el tráfico al C2 real."""

    def __init__(self, victim_conn: socket.socket, victim_addr: tuple,
                 forward_host: str, forward_port: int):
        super().__init__(daemon=True)
        self._victim_conn  = victim_conn
        self._victim_addr  = victim_addr
        self._forward_host = forward_host
        self._forward_port = forward_port

    def run(self):
        client_ip = self._victim_addr[0]
        print(f"\n[MITM] Conexión interceptada desde {client_ip}:{self._victim_addr[1]}")

        try:
            # abrir conexión hacia el C2 real para retransmitir el tráfico
            c2_sock = socket.create_connection((self._forward_host, self._forward_port), timeout=10)
            print(f"[MITM] Conectado al C2: {self._forward_host}:{self._forward_port}")

            # leer los 4 bytes de longitud del protocolo keylogger → C2
            length_bytes = self._recv_exact(self._victim_conn, 4)
            if not length_bytes:
                return

            payload_length = struct.unpack(">I", length_bytes)[0]
            print(f"[MITM] Payload: {payload_length} bytes")

            # leer el payload cifrado completo
            encrypted_blob = self._recv_exact(self._victim_conn, payload_length)
            if not encrypted_blob:
                return

            # registrar lo interceptado (en hex, ilegible)
            log_intercepted("VICTIM→C2", encrypted_blob, self._victim_addr)

            # intentar descifrar sin clave — demuestra que el MITM no puede leerlo
            attempt_decrypt_without_key(encrypted_blob)

            # reenviar al C2 sin modificar (si se modificara, el tag GCM fallaría en server.py)
            c2_sock.sendall(length_bytes + encrypted_blob)
            print(f"[MITM] Payload reenviado al C2 ({payload_length} bytes).")
            c2_sock.close()

        except (ConnectionRefusedError, socket.timeout) as e:
            print(f"[MITM] No se pudo conectar al C2: {e}")
        except Exception as e:
            print(f"[MITM] Error: {e}")
        finally:
            self._victim_conn.close()

    def _recv_exact(self, sock: socket.socket, n: int) -> bytes | None:
        """Recibe exactamente n bytes del socket."""
        data = b""
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                return None  # conexión cerrada inesperadamente
            data += chunk
        return data


def run_mitm_proxy(listen_port: int, forward_host: str, forward_port: int):
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("0.0.0.0", listen_port))  # escuchar en todas las interfaces
    server_sock.listen(5)

    print(f"[*] Proxy MITM en 0.0.0.0:{listen_port} → {forward_host}:{forward_port}")
    print(f"[*] Log: {INTERCEPT_LOG} — Ctrl+C para detener\n")

    try:
        while True:
            conn, addr = server_sock.accept()
            # cada conexión interceptada se maneja en su propio hilo
            MITMProxy(conn, addr, forward_host, forward_port).start()
    except KeyboardInterrupt:
        print("\n[*] MITM detenido.")
    finally:
        server_sock.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Proxy MITM — intercepta tráfico del keylogger")
    parser.add_argument("--listen", type=int, default=DEFAULT_LISTEN_PORT,
                        help=f"Puerto de escucha (default: {DEFAULT_LISTEN_PORT})")
    parser.add_argument("--forward", type=str,
                        default=f"{DEFAULT_FORWARD_HOST}:{DEFAULT_FORWARD_PORT}",
                        help=f"C2 real HOST:PUERTO (default: {DEFAULT_FORWARD_HOST}:{DEFAULT_FORWARD_PORT})")
    return parser.parse_args()


def main():
    args = parse_args()
    try:
        fwd_host, fwd_port_str = args.forward.rsplit(":", 1)
        fwd_port = int(fwd_port_str)
    except ValueError:
        print(f"[ERROR] Formato inválido para --forward: {args.forward}")
        sys.exit(1)

    run_mitm_proxy(args.listen, fwd_host, fwd_port)


if __name__ == "__main__":
    main()
