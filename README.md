# ChL-CyberKit v1.0 PRO

<p align="center">
  <img src="docs/logo.png" alt="ChL-CyberKit" width="200"/>
</p>

<p align="center">
  <b>Framework de auditoría WiFi/BLE para ESP32-CYD 4" (E32R40T)</b><br>
  Inspirado en Bruce y Marauder · Licencia GPL v3
</p>

<p align="center">
  <img src="https://img.shields.io/badge/platform-ESP32-blue"/>
  <img src="https://img.shields.io/badge/framework-PlatformIO-orange"/>
  <img src="https://img.shields.io/badge/license-GPLv3-green"/>
  <img src="https://img.shields.io/badge/version-1.0--PRO-red"/>
</p>

---

## ⚠️ AVISO LEGAL / LEGAL DISCLAIMER

> **Este software se proporciona EXCLUSIVAMENTE con fines educativos y de investigación en ciberseguridad.**
>
> El uso no autorizado de las técnicas implementadas en este firmware contra redes o dispositivos que no sean de tu propiedad o para los que no tengas permiso explícito y por escrito **es ilegal** en la mayoría de jurisdicciones y puede acarrear consecuencias penales graves.
>
> El autor y los colaboradores de este proyecto **no se hacen responsables** del uso indebido de este software. Al utilizar ChL-CyberKit, aceptas que lo usarás únicamente en redes propias, laboratorios controlados o con permiso explícito de los propietarios de la red objetivo.
>
> Algunas funcionalidades (Evil Twin, Deauth/DoS, Karma) pueden estar **prohibidas por ley** en tu país incluso con consentimiento. Verifica la legalidad local antes de usarlas.

---

## Tabla de contenidos

- [Características](#características)
- [Hardware requerido](#hardware-requerido)
- [Instalación](#instalación)
- [Uso del panel web](#uso-del-panel-web)
- [Uso desde la pantalla CYD](#uso-desde-la-pantalla-cyd)
- [Módulos](#módulos)
- [API REST](#api-rest)
- [Estructura de archivos SD](#estructura-de-archivos-sd)
- [Compilación avanzada](#compilación-avanzada)
- [Créditos](#créditos)
- [Licencia](#licencia)

---

## Características

### WiFi Ofensivo
| Función | Descripción |
|---|---|
| **Escaneo de redes** | Listado de APs con SSID, BSSID, canal, RSSI, cifrado |
| **Captura de Handshake WPA2** | Captura pasiva con deauth opcional → PCAP + HCCAPX + HC22000 |
| **Captura PMKID** | Ataque PMKID sin clientes (WPA*01 para hashcat) |
| **Deauth / DoS** | Flood de frames 802.11 Deauthentication |
| **Beacon Flood** | Genera cientos de SSIDs falsos por segundo |
| **Evil Twin** | AP gemelo con DNS Captive Portal y portal de login falso |
| **Karma Attack** | Responde Probe Requests con SSID coincidente (KARMA/MANA) |
| **Auto Audit** | Escaneo→ataque→guardado automático y desatendido |

### BLE
| Función | Descripción |
|---|---|
| **Escáner BLE pasivo** | Detecta dispositivos BLE con MAC, nombre, RSSI, tipo |
| **Monitor de anuncios** | Hasta 48 dispositivos simultáneos con timestamps |

### Sistema
| Función | Descripción |
|---|---|
| **Packet Monitor** | Estadísticas de frames WiFi en tiempo real (pps) |
| **Channel Hopper** | Salto automático de canales 1–13 |
| **Probe Logger** | Captura e identifica dispositivos por sus Probe Requests |
| **OTA** | Actualización de firmware por WiFi (ArduinoOTA) |
| **SD Card** | Guarda capturas en PCAP, HCCAPX, HC22000 y CSV |
| **Panel Web** | Interfaz completa en cualquier navegador |
| **SSID List** | Carga SSIDs personalizados desde `/CyberKit/ssids.txt` |

---

## Hardware requerido

| Componente | Especificación |
|---|---|
| **Placa** | ESP32-CYD 4" (modelo E32R40T) |
| **Display** | ST7796S 320×480 px, resistivo XPT2046 |
| **SoC** | ESP32-WROOM-32 (WiFi + BLE) |
| **RAM** | 520 KB SRAM + PSRAM 4 MB (si disponible) |
| **Flash** | 4 MB mínimo, 16 MB recomendado |
| **SD** | microSD (FAT32, hasta 32 GB) — bus VSPI |
| **USB** | CP2102 o CH340 para programación |

### Pines SD (bus VSPI, no modificar)
```
CS   → GPIO 5
MOSI → GPIO 23
SCK  → GPIO 18
MISO → GPIO 19
```

---

## Instalación

### 1. Requisitos previos

- [VS Code](https://code.visualstudio.com/) + extensión [PlatformIO](https://platformio.org/)
- Python 3.x
- Driver USB: [CP210x](https://www.silabs.com/developers/usb-to-uart-bridge-vcp-drivers) o [CH341](https://github.com/WCHSoftGroup/ch341ser_linux)

### 2. Clonar el repositorio

```bash
git clone https://github.com/ChL/ChL-CyberKit.git
cd ChL-CyberKit
```

### 3. Preparar la tarjeta SD

Formatea la microSD en FAT32 y crea esta estructura (opcional, se crea automáticamente):

```
/CyberKit/
    captures/          ← capturas de handshakes y PMKIDs
    logs/              ← logs de auditoría CSV
    ssids.txt          ← (opcional) SSIDs para Beacon Flood/Evil Twin
```

**Formato de `ssids.txt`** (un SSID por línea):
```
MiRed_Victima
OtraRed
TestNetwork_5G
```

### 4. Configurar credenciales del panel web (opcional)

Edita `src/webserver.c` si quieres cambiar las credenciales por defecto:

```c
#define HTTP_USER "chl"
#define HTTP_PASS "CyberKit2026"
```

### 5. Compilar y flashear

En PlatformIO:
```
pio run --target upload
pio device monitor --baud 115200
```

O desde VS Code: `Ctrl+Alt+U` para subir.

---

## Uso del panel web

### Conectarse

1. La CYD crea un punto de acceso WiFi:
   - **SSID:** `ChL-CyberKit`
   - **Contraseña:** `CyberKit2026`
2. Conecta tu dispositivo a esa red
3. Abre el navegador en `http://192.168.4.1`
4. Ingresa las credenciales:
   - **Usuario:** `chl`
   - **Contraseña:** `CyberKit2026`

### Navegación del panel

| Sección | Descripción |
|---|---|
| **Dashboard** | Estado general, uptime, contadores de capturas |
| **WiFi Scan** | Escanear redes, ver AP list con RSSI/canal/seguridad |
| **Attacks** | Control de ataques: Handshake, PMKID, Deauth, Beacon Flood |
| **Evil Twin** | Configurar y lanzar AP gemelo con portal captive |
| **Karma** | Control del ataque Karma (KARMA/MANA) |
| **BLE** | Escáner BLE, lista de dispositivos detectados |
| **Probes** | Registro de Probe Requests (fingerprinting de dispositivos) |
| **Auto Audit** | Auditoría automática de todas las redes escaneadas |
| **Files** | Explorador de archivos SD, descarga de capturas |
| **Credentials** | Credenciales capturadas por Evil Twin |

---

## Uso desde la pantalla CYD

La CYD dispone de interfaz táctil organizada en menús:

```
[SCAN]    → Escanear redes WiFi
[ATTACK]  → Seleccionar red → elegir ataque (HS/PMKID/DOS/BF/ET)
[HERRAM]  → Herramientas: BLE, Karma, Monitor, Auto Audit
[CONFIG]  → Configuración del dispositivo
[STATUS]  → Estado de módulos activos
```

**Controles táctiles:**
- Toca cualquier botón para activarlo
- En listados, desliza para hacer scroll
- Botón `[BACK]` o `[STOP]` para cancelar ataques en curso

---

## Módulos

### Handshake Capture
Captura el handshake WPA2 de 4 vías enviando frames de deautenticación al AP objetivo.  
Guarda tres formatos: `.pcap` (Wireshark), `.hccapx` (hashcat legacy), `.hc22000` (hashcat moderno).

```bash
# Crackear con hashcat
hashcat -m 22000 hs_MiRed_001.hc22000 wordlist.txt
```

### PMKID Capture
Captura el PMKID del primer frame EAPOL sin necesidad de clientes conectados.  
Formato `.hc22000` con cabecera `WPA*01*`.

```bash
hashcat -m 22001 pmkid_MiRed_001.hc22000 wordlist.txt
```

### Beacon Flood
Genera hasta ~100 SSIDs falsos por segundo usando `esp_wifi_80211_tx()`. Puede cargar SSIDs desde `/CyberKit/ssids.txt` o usar nombres aleatorios.

### Evil Twin
Crea un AP gemelo del objetivo:
1. Mismo SSID que la red víctima
2. DNS que redirige todo tráfico al ESP32
3. Portal HTTP que imita una página de login
4. Credenciales guardadas en `/CyberKit/captures/creds.csv`

### Karma Attack
Intercepta Probe Requests (solicitudes de reconexión automática de los dispositivos) y responde con el SSID que el dispositivo está buscando, forzando la conexión al ESP32.

Compatible con ataques KARMA clásico y MANA (responde a cualquier SSID).

### Auto Audit
Modo desatendido que:
1. Escanea todas las redes al alcance
2. Intenta capturar handshake + PMKID de cada una (con timeout)
3. Registra resultados en el log CSV
4. Salta redes con PMF (Protected Management Frames)

### BLE Scanner
Escaneo pasivo de anuncios BLE (Advertisement PDUs). Muestra MAC, nombre, RSSI y tipo de dirección. Hasta 48 dispositivos simultáneos.

### Probe Logger
Registra los Probe Requests de dispositivos cercanos para identificar:
- Dispositivo por MAC
- SSIDs que busca (historial de redes a las que se conectó)
- Vendor/fabricante por OUI

### Packet Monitor
Estadísticas de tráfico WiFi en tiempo real:
- Frames por tipo (mgmt, ctrl, data)
- Paquetes por segundo (ring buffer 40 muestras)
- Canal actual

### OTA Update
Actualización de firmware por WiFi. Una vez conectado a la red AP de la CYD:

```bash
# PlatformIO
pio run --target upload --upload-port 192.168.4.1

# Python
python3 -m upload esp32 192.168.4.1 ChL-CyberKit firmware.bin
```
Contraseña OTA: `CyberKit2026`

---

## API REST

El servidor web expone una API REST completa. Todas las rutas requieren Basic Auth.

**Auth header:** `Authorization: Basic Y2hsOkN5YmVyS2l0MjAyNg==`

| Método | Endpoint | Descripción |
|---|---|---|
| GET | `/api/status` | Estado completo de todos los módulos |
| POST | `/api/scan` | Iniciar escaneo WiFi |
| GET | `/api/ap/list` | Lista de APs (binario 42 bytes/AP) |
| POST | `/api/attack/start` | Iniciar ataque (handshake/pmkid/dos) |
| POST | `/api/attack/stop` | Detener ataque activo |
| POST | `/api/bf/start` | Iniciar Beacon Flood `{channel,rate_ms}` |
| POST | `/api/bf/stop` | Detener Beacon Flood |
| POST | `/api/et/start` | Iniciar Evil Twin `{ap_id}` |
| POST | `/api/et/stop` | Detener Evil Twin |
| POST | `/api/karma/start` | Iniciar Karma `{channel}` |
| POST | `/api/karma/stop` | Detener Karma |
| POST | `/api/ble/start` | Iniciar escáner BLE |
| POST | `/api/ble/stop` | Detener escáner BLE |
| POST | `/api/ble/clear` | Limpiar lista BLE |
| GET | `/api/ble/list` | Lista de dispositivos BLE (JSON) |
| GET | `/api/probe/list` | Dispositivos detectados por Probe Requests |
| POST | `/api/probe/dump` | Volcar Probe Log a SD |
| POST | `/api/probe/clear` | Limpiar Probe Log |
| POST | `/api/audit/toggle` | Activar/desactivar Auto Audit |
| GET | `/api/credentials` | Credenciales capturadas por Evil Twin |
| GET | `/api/files` | Lista de archivos en SD (JSON) |
| GET | `/api/files/dl?path=...` | Descargar archivo de SD |

### Ejemplo: `GET /api/status`
```json
{
  "uptime_s": 3600,
  "clients": 1,
  "captures": 5,
  "net_count": 12,
  "probe_count": 8,
  "ble_count": 3,
  "bf_state": 0,
  "bf_count": 0,
  "et_state": 0,
  "et_creds": 0,
  "ka_state": 0,
  "ka_probes": 0,
  "ka_responses": 0,
  "ka_unique": 0,
  "aa_state": 0,
  "aa_total": 0,
  "aa_done": 0,
  "aa_caps": 0,
  "ble_state": 0,
  "atk_state": 0
}
```

### Ejemplo: `POST /api/karma/start`
```json
{ "channel": 6 }
```

---

## Estructura de archivos SD

```
/CyberKit/
├── captures/
│   ├── hs_MiRed_001.pcap        ← Wireshark / aircrack-ng
│   ├── hs_MiRed_001.hccapx      ← hashcat --hash-type 2500
│   ├── hs_MiRed_001.hc22000     ← hashcat --hash-type 22000
│   ├── pmkid_MiRed_001.hc22000  ← hashcat --hash-type 22001
│   └── creds.csv                ← Credenciales Evil Twin
│                                   (ts,user,pass,ip)
├── logs/
│   └── audit.csv                ← Log de auditoría
│                                   (uptime_s,tipo,ssid,bssid,resultado)
└── ssids.txt                    ← SSIDs personalizados (1 por línea)
```

---

## Compilación avanzada

### `platformio.ini`
```ini
[env:esp32dev]
platform = espressif32
board = esp32dev
framework = arduino
board_build.flash_size = 4MB
board_build.partitions = min_spiffs.csv
build_flags =
    -DCORE_DEBUG_LEVEL=1
    -DARDUINO_USB_CDC_ON_BOOT=0
lib_deps =
    bodmer/TFT_eSPI@^2.5.43
    h2zero/NimBLE-Arduino@^1.4.2
```

### Partición recomendada (4 MB)
```
# Name,   Type, SubType,  Offset,   Size
nvs,      data, nvs,      0x9000,   0x5000
otadata,  data, ota,      0xe000,   0x2000
app0,     app,  ota_0,    0x10000,  0x1C0000
app1,     app,  ota_1,    0x1D0000, 0x1C0000
spiffs,   data, spiffs,   0x390000, 0x70000
```

### Monitor serie
```bash
pio device monitor --baud 115200 --filter colorize
```

---

## Comparación con proyectos similares

| Característica | ChL-CyberKit | Bruce | Marauder |
|---|:---:|:---:|:---:|
| Handshake WPA2 | ✅ | ✅ | ✅ |
| PMKID | ✅ | ✅ | ✅ |
| Deauth / DoS | ✅ | ✅ | ✅ |
| Beacon Flood | ✅ | ✅ | ✅ |
| Evil Twin | ✅ | ✅ | ✅ |
| Karma Attack | ✅ | ✅ | ❌ |
| BLE Scanner | ✅ | ✅ | ✅ |
| Panel Web | ✅ | ❌ | ✅ |
| Auto Audit | ✅ | ❌ | ❌ |
| OTA Update | ✅ | ❌ | ✅ |
| Probe Logger | ✅ | ❌ | ✅ |
| Packet Monitor | ✅ | ✅ | ✅ |
| Display táctil | ✅ CYD | ✅ | ✅ |
| SD HC22000 | ✅ | ✅ | ✅ |

---

## Créditos

**Autor:** ChinoLuis (Pedro Rezabala)  
**Versión:** 1.0 PRO  
**Fecha:** 2026  

### Inspiración y proyectos relacionados

- **[Bruce](https://github.com/pr3y/Bruce)** — ESP32 multi-tool por pr3y y colaboradores  
  Licencia: GPL v3

- **[ESP32 Marauder](https://github.com/justcallmekoko/ESP32Marauder)** — WiFi/BLE security tool por justcallmekoko  
  Licencia: GPL v3

### Librerías utilizadas

| Librería | Autor | Uso |
|---|---|---|
| [TFT_eSPI](https://github.com/Bodmer/TFT_eSPI) | Bodmer | Display ST7796S |
| [NimBLE-Arduino](https://github.com/h2zero/NimBLE-Arduino) | h2zero | Escáner BLE |
| [ArduinoOTA](https://github.com/espressif/arduino-esp32) | Espressif | OTA Update |
| [ESP-IDF](https://github.com/espressif/esp-idf) | Espressif | WiFi 802.11 raw, HTTP server |
| [Arduino-ESP32 SD](https://github.com/espressif/arduino-esp32) | Espressif | Tarjeta SD |

### Técnicas de referencia

- PMKID attack: Jens Steube (hashcat), 2018
- KARMA attack: Dino A. Dai Zovi & Shane Macaulay, 2004
- Evil Twin / Captive Portal: técnica ampliamente documentada en la literatura de seguridad WiFi

---

## Licencia

```
ChL-CyberKit v1.0 PRO
Copyright (C) 2026  ChL (Pedro Rezabala)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
```

Ver el archivo [LICENSE](LICENSE) para el texto completo de la GNU GPL v3.

---

<p align="center">
  <i>Hecho con ❤️ para la comunidad de ciberseguridad</i><br>
  <i>Úsalo con responsabilidad · Use it responsibly</i>
</p>
