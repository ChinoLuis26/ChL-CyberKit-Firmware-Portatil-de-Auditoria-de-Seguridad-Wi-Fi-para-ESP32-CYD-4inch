/*
 * ChL-CyberKit v1.0 PRO — ESP32 WiFi/BLE Security Auditing Framework
 * Copyright (C) 2026  ChL (Pedro Reza) <pedrorezabala26@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
/**
 * @file sd_storage.h
 * @brief Módulo de almacenamiento en tarjeta SD — ChL-CyberKit v1.0
 *
 * La CYD 4" (E32R40T) tiene ranura microSD en bus VSPI separado del LCD:
 *   CS=5  MOSI=23  SCK=18  MISO=19
 *
 * Estructura de archivos en la SD:
 *   /CyberKit/
 *     captures/
 *       hs_SSID_001.pcap        ← Handshake para Wireshark / aircrack-ng
 *       hs_SSID_001.hccapx      ← Handshake para hashcat (--hash-type 2500)
 *       hs_SSID_001.hc22000     ← Handshake para hashcat (--hash-type 22000, moderno)
 *       pmkid_SSID_001.hc22000  ← PMKID para hashcat (--hash-type 22001)
 *     logs/
 *       audit.csv               ← Log de todos los ataques (CSV)
 */
#pragma once
#include <Arduino.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Resultado de operación SD ───────────────────────────────────────────── */
typedef enum {
    SD_OK      = 0,
    SD_NO_CARD = 1,
    SD_ERR_IO  = 2,
    SD_ERR_FS  = 3
} sd_result_t;

/* ── Inicialización ──────────────────────────────────────────────────────── */

/**
 * Inicializa la SD en el bus VSPI (CS=5, MOSI=23, SCK=18, MISO=19).
 * @return SD_OK si la tarjeta está lista, SD_NO_CARD si no hay tarjeta.
 */
sd_result_t sd_init();

/** @return true si la SD fue inicializada correctamente. */
bool sd_ready();

/** Devuelve espacio libre en bytes (-1 si no hay SD). */
int64_t sd_free_bytes();

/* ── Guardar capturas ────────────────────────────────────────────────────── */

/**
 * Guarda un handshake WPA capturado.
 * Escribe: hs_SSID_NNN.pcap, hs_SSID_NNN.hccapx, hs_SSID_NNN.hc22000
 * @param ssid       SSID de la red objetivo
 * @param pcap_buf   Buffer PCAP (de pcap_serializer_get_buffer)
 * @param pcap_len   Tamaño del buffer PCAP
 * @param hccapx_buf Buffer HCCAPX (de hccapx_serializer_get)
 * @param hccapx_len Tamaño del HCCAPX (sizeof(hccapx_t))
 */
sd_result_t sd_save_handshake(const char *ssid,
                               const uint8_t *pcap_buf, unsigned pcap_len,
                               const uint8_t *hccapx_buf, unsigned hccapx_len);

/**
 * Guarda un PMKID capturado en formato .hc22000 (hashcat WPA*01).
 * @param ssid         SSID de la red objetivo
 * @param pmkid_data   Buffer binario del PMKID (formato interno del firmware)
 * @param pmkid_len    Tamaño del buffer
 */
sd_result_t sd_save_pmkid(const char *ssid,
                           const uint8_t *pmkid_data, unsigned pmkid_len);

/* ── Log de auditoría ────────────────────────────────────────────────────── */

/**
 * Agrega una entrada al log CSV.
 * @param type_str   Tipo de ataque ("HANDSHAKE","PMKID","DOS","PASSIVE")
 * @param ssid       SSID objetivo
 * @param bssid_str  BSSID en formato "AA:BB:CC:DD:EE:FF"
 * @param result_str Resultado ("OK","TIMEOUT","ERROR")
 */
void sd_log_event(const char *type_str, const char *ssid,
                  const char *bssid_str, const char *result_str);

/* ── Info ────────────────────────────────────────────────────────────────── */

/** Devuelve el número de capturas guardadas en esta sesión. */
uint16_t sd_capture_count();

/** Ruta al último archivo guardado (buffer estático). */
const char *sd_last_file();

/* ── Utilidades de texto ─────────────────────────────────────────────────── */

/**
 * Añade una línea de texto a un archivo (crea el archivo si no existe).
 * @param path  Ruta absoluta en la SD  (ej. "/CyberKit/probes.csv")
 * @param line  Cadena a escribir.  Se añade un '\n' automáticamente.
 * @return SD_OK en éxito.
 */
sd_result_t sd_append_line(const char *path, const char *line);

/**
 * @return true si la SD está montada y lista para escribir.
 */
bool sd_storage_available(void);

/* ── Listado y lectura de archivos (para REST API) ───────────────────────── */

/**
 * Genera un JSON con la lista de archivos bajo /CyberKit/captures y /CyberKit/logs.
 * Formato: {"files":[{"name":"hs_...pcap","path":"/CyberKit/...","size":1234},…]}
 * @param buf      Buffer de salida.
 * @param buf_size Tamaño del buffer.
 * @return Bytes escritos en buf, o 0 si la SD no está disponible.
 */
int sd_list_files_json(char *buf, int buf_size);

/**
 * Lee el contenido de un archivo de la SD.
 * @param path     Ruta absoluta del archivo (ej. "/CyberKit/captures/file.pcap").
 * @param buf      Buffer destino.
 * @param buf_size Tamaño máximo a leer.
 * @return Bytes leídos, o -1 en caso de error.
 */
int sd_read_file(const char *path, char *buf, int buf_size);

#ifdef __cplusplus
}
#endif
