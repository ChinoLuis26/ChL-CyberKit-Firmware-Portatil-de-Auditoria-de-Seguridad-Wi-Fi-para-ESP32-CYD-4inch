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
 * @file sd_storage.cpp
 * @brief Almacenamiento SD — ChL-CyberKit v1.0
 *
 * Bus VSPI separado del LCD:  CS=5  MOSI=23  SCK=18  MISO=19
 */
#include "sd_storage.h"
#include <Arduino.h>
#include <SPI.h>
/* SD integrada del framework Arduino-ESP32, no arduino-libraries/SD (AVR).
 * API Arduino-ESP32: SD.begin(cs, spi, frecuencia), totalBytes(), usedBytes(). */
#include <SD.h>

static const char *TAG = "sd";

/* ── Pines VSPI para la SD ───────────────────────────────────────────────── */
#define SD_CS    5
#define SD_SCK   18
#define SD_MISO  19
#define SD_MOSI  23

static SPIClass vspi_sd(VSPI);
static bool     sd_ok         = false;
static uint16_t capture_count = 0;
static char     last_path[64] = {0};

/* ── Helpers ─────────────────────────────────────────────────────────────── */

static void sanitize_ssid(const char *ssid, char *out, int maxlen) {
    int j = 0;
    for (int i = 0; ssid[i] && j < maxlen - 1; i++) {
        char c = ssid[i];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_')
            out[j++] = c;
        else
            out[j++] = '_';
    }
    out[j] = '\0';
}

static void next_filename(const char *dir, const char *prefix,
                          const char *ssid_safe, const char *ext,
                          char *out, int outlen) {
    for (int n = 1; n < 1000; n++) {
        snprintf(out, outlen, "%s/%s_%s_%03d.%s", dir, prefix, ssid_safe, n, ext);
        if (!SD.exists(out)) return;
    }
}

static bool write_file(const char *path, const uint8_t *data, unsigned len) {
    File f = SD.open(path, FILE_WRITE);
    if (!f) { Serial.printf("[SD] No se pudo crear %s\n", path); return false; }
    f.write(data, len);
    f.close();
    Serial.printf("[SD] Guardado: %s (%u bytes)\n", path, len);
    return true;
}

/* ── Inicialización ──────────────────────────────────────────────────────── */

sd_result_t sd_init() {
    vspi_sd.begin(SD_SCK, SD_MISO, SD_MOSI, SD_CS);
    if (!SD.begin(SD_CS, vspi_sd, 4000000U)) {  /* CS, SPI bus, frecuencia 4MHz */
        Serial.println("[SD] No hay tarjeta o error de montaje");
        return SD_NO_CARD;
    }
    /* Crear estructura de directorios */
    if (!SD.exists("/CyberKit"))         SD.mkdir("/CyberKit");
    if (!SD.exists("/CyberKit/captures"))SD.mkdir("/CyberKit/captures");
    if (!SD.exists("/CyberKit/logs"))    SD.mkdir("/CyberKit/logs");

    sd_ok = true;
    uint64_t total = SD.totalBytes() / (1024*1024);
    uint64_t used  = SD.usedBytes()  / (1024*1024);
    Serial.printf("[SD] Montada OK — %llu MB total, %llu MB usado\n", total, used);

    /* Encabezado del CSV de log si es nuevo */
    if (!SD.exists("/CyberKit/logs/audit.csv")) {
        File f = SD.open("/CyberKit/logs/audit.csv", FILE_WRITE);
        if (f) { f.println("uptime_s,tipo,ssid,bssid,resultado"); f.close(); }
    }
    return SD_OK;
}

bool    sd_ready()      { return sd_ok; }
int64_t sd_free_bytes() { return sd_ok ? (int64_t)(SD.totalBytes() - SD.usedBytes()) : -1; }
uint16_t sd_capture_count() { return capture_count; }
const char *sd_last_file()  { return last_path; }

/* ── Guardar handshake ───────────────────────────────────────────────────── */

sd_result_t sd_save_handshake(const char *ssid,
                               const uint8_t *pcap_buf, unsigned pcap_len,
                               const uint8_t *hccapx_buf, unsigned hccapx_len) {
    if (!sd_ok) return SD_NO_CARD;

    char ssid_safe[32]; sanitize_ssid(ssid, ssid_safe, sizeof(ssid_safe));
    char path[64];
    bool any_ok = false;

    /* ── 1. PCAP (Wireshark / aircrack-ng) ── */
    if (pcap_buf && pcap_len > 0) {
        next_filename("/CyberKit/captures", "hs", ssid_safe, "pcap", path, sizeof(path));
        if (write_file(path, pcap_buf, pcap_len)) {
            strncpy(last_path, path, sizeof(last_path));
            any_ok = true;
        }
    }

    /* ── 2. HCCAPX (hashcat --hash-type 2500, legacy) ── */
    if (hccapx_buf && hccapx_len > 0) {
        next_filename("/CyberKit/captures", "hs", ssid_safe, "hccapx", path, sizeof(path));
        write_file(path, hccapx_buf, hccapx_len);
    }

    /* ── 3. HC22000 (hashcat --hash-type 22000, moderno) ──
     *  Formato: WPA*02*{MIC_hex}*{AP_MAC}*{STA_MAC}*{SSID_hex}*{NONCE_AP_hex}*{EAPOL_hex}*
     *  Extraído del buffer HCCAPX ya construido
     * ─────────────────────────────────────────────────────────────────────── */
    if (hccapx_buf && hccapx_len >= 392) {
        /* Mapear la estructura HCCAPX */
        struct __attribute__((packed)) hccapx_mini {
            uint32_t sig, ver;
            uint8_t  msg_pair, essid_len, essid[32], keyver, keymic[16];
            uint8_t  mac_ap[6], nonce_ap[32], mac_sta[6], nonce_sta[32];
            uint16_t eapol_len; uint8_t eapol[256];
        };
        const struct hccapx_mini *hx = (const struct hccapx_mini *)hccapx_buf;

        char hc22000[1024]; int pos = 0;
        /* Cabecera WPA*02 */
        pos += snprintf(hc22000+pos, sizeof(hc22000)-pos, "WPA*02*");
        /* MIC */
        for(int i=0;i<16;i++) pos += snprintf(hc22000+pos, sizeof(hc22000)-pos,"%02x",hx->keymic[i]);
        pos += snprintf(hc22000+pos, sizeof(hc22000)-pos, "*");
        /* AP MAC */
        for(int i=0;i<6;i++)  pos += snprintf(hc22000+pos, sizeof(hc22000)-pos,"%02x",hx->mac_ap[i]);
        pos += snprintf(hc22000+pos, sizeof(hc22000)-pos, "*");
        /* STA MAC */
        for(int i=0;i<6;i++)  pos += snprintf(hc22000+pos, sizeof(hc22000)-pos,"%02x",hx->mac_sta[i]);
        pos += snprintf(hc22000+pos, sizeof(hc22000)-pos, "*");
        /* SSID hex */
        uint8_t sl = hx->essid_len < 32 ? hx->essid_len : 32;
        for(int i=0;i<sl;i++) pos += snprintf(hc22000+pos, sizeof(hc22000)-pos,"%02x",hx->essid[i]);
        pos += snprintf(hc22000+pos, sizeof(hc22000)-pos, "*");
        /* Nonce AP */
        for(int i=0;i<32;i++) pos += snprintf(hc22000+pos, sizeof(hc22000)-pos,"%02x",hx->nonce_ap[i]);
        pos += snprintf(hc22000+pos, sizeof(hc22000)-pos, "*");
        /* EAPOL */
        uint16_t el = hx->eapol_len < 256 ? hx->eapol_len : 256;
        for(int i=0;i<el;i++) pos += snprintf(hc22000+pos, sizeof(hc22000)-pos,"%02x",hx->eapol[i]);
        pos += snprintf(hc22000+pos, sizeof(hc22000)-pos, "*\n");

        next_filename("/CyberKit/captures", "hs", ssid_safe, "hc22000", path, sizeof(path));
        write_file(path, (const uint8_t *)hc22000, (unsigned)pos);
    }

    if (any_ok) capture_count++;
    return any_ok ? SD_OK : SD_ERR_IO;
}

/* ── Guardar PMKID ───────────────────────────────────────────────────────── */

sd_result_t sd_save_pmkid(const char *ssid,
                           const uint8_t *data, unsigned len) {
    if (!sd_ok) return SD_NO_CARD;
    if (!data || len < 13) return SD_ERR_IO;

    /* Formato interno del firmware:
     *   [0-5]  STA MAC
     *   [6-11] AP MAC (BSSID)
     *   [12]   longitud SSID
     *   [13..13+ssid_len-1]  SSID
     *   [13+ssid_len .. fin] PMKIDs (bloques de 16 bytes)
     */
    const uint8_t *sta_mac = data;
    const uint8_t *ap_mac  = data + 6;
    uint8_t ssid_len = data[12];
    const uint8_t *ssid_bytes = data + 13;
    const uint8_t *pmkids    = data + 13 + ssid_len;
    unsigned pmkid_count = (len - 13 - ssid_len) / 16;

    char hc22000[512]; int pos = 0;

    for (unsigned p = 0; p < pmkid_count; p++) {
        const uint8_t *pmkid = pmkids + p * 16;
        /* WPA*01*{PMKID}*{AP_MAC}*{STA_MAC}*{SSID_hex}*** */
        pos = 0;
        pos += snprintf(hc22000+pos, sizeof(hc22000)-pos, "WPA*01*");
        for(int i=0;i<16;i++) pos += snprintf(hc22000+pos, sizeof(hc22000)-pos,"%02x",pmkid[i]);
        pos += snprintf(hc22000+pos, sizeof(hc22000)-pos, "*");
        for(int i=0;i<6;i++)  pos += snprintf(hc22000+pos, sizeof(hc22000)-pos,"%02x",ap_mac[i]);
        pos += snprintf(hc22000+pos, sizeof(hc22000)-pos, "*");
        for(int i=0;i<6;i++)  pos += snprintf(hc22000+pos, sizeof(hc22000)-pos,"%02x",sta_mac[i]);
        pos += snprintf(hc22000+pos, sizeof(hc22000)-pos, "*");
        for(int i=0;i<ssid_len;i++) pos += snprintf(hc22000+pos, sizeof(hc22000)-pos,"%02x",ssid_bytes[i]);
        pos += snprintf(hc22000+pos, sizeof(hc22000)-pos, "***\n");
    }

    char ssid_safe[32]; sanitize_ssid(ssid, ssid_safe, sizeof(ssid_safe));
    char path[64];
    next_filename("/CyberKit/captures", "pmkid", ssid_safe, "hc22000", path, sizeof(path));
    bool ok = write_file(path, (const uint8_t *)hc22000, (unsigned)pos);
    if (ok) { strncpy(last_path, path, sizeof(last_path)); capture_count++; }
    return ok ? SD_OK : SD_ERR_IO;
}

/* ── Log CSV ─────────────────────────────────────────────────────────────── */

void sd_log_event(const char *type_str, const char *ssid,
                  const char *bssid_str, const char *result_str) {
    if (!sd_ok) return;
    File f = SD.open("/CyberKit/logs/audit.csv", FILE_APPEND);
    if (!f) return;
    f.printf("%lu,%s,\"%s\",%s,%s\n",
             (unsigned long)(millis()/1000), type_str, ssid, bssid_str, result_str);
    f.close();
}

/* ── Utilidades de texto ─────────────────────────────────────────────────── */

sd_result_t sd_append_line(const char *path, const char *line) {
    if (!sd_ok) return SD_NO_CARD;
    if (!path || !line) return SD_ERR_IO;

    File f = SD.open(path, FILE_APPEND);
    if (!f) {
        /* Intentar crear el archivo (puede que el directorio falte) */
        /* Extraer directorio */
        char dir[64];
        strncpy(dir, path, sizeof(dir) - 1);
        dir[sizeof(dir) - 1] = '\0';
        char *slash = strrchr(dir, '/');
        if (slash && slash != dir) {
            *slash = '\0';
            if (!SD.exists(dir)) SD.mkdir(dir);
        }
        f = SD.open(path, FILE_APPEND);
        if (!f) return SD_ERR_IO;
    }

    if (*line != '\0') {
        f.print(line);
        f.print('\n');
    }
    f.close();
    return SD_OK;
}

bool sd_storage_available(void) { return sd_ok; }

/* ── Listado de archivos → JSON ──────────────────────────────────────────── */

static int list_dir_json(const char *dir_path, char *buf, int buf_size,
                          int pos, bool *first) {
    if (!sd_ok) return pos;
    File dir = SD.open(dir_path);
    if (!dir) return pos;

    File entry = dir.openNextFile();
    while (entry) {
        if (!entry.isDirectory()) {
            const char *fname = entry.name();
            size_t      fsize = (size_t)entry.size();

            /* entry.name() devuelve solo el nombre, no la ruta completa */
            char full_path[80];
            snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, fname);

            if (pos < buf_size - 128) {
                pos += snprintf(buf + pos, buf_size - pos,
                    "%s{\"name\":\"%s\",\"path\":\"%s\",\"size\":%u}",
                    *first ? "" : ",", fname, full_path, (unsigned)fsize);
                *first = false;
            }
        }
        entry.close();
        entry = dir.openNextFile();
    }
    dir.close();
    return pos;
}

int sd_list_files_json(char *buf, int buf_size) {
    if (!sd_ok || !buf || buf_size < 16) return 0;
    int pos = snprintf(buf, buf_size, "{\"files\":[");
    bool first = true;
    pos = list_dir_json("/CyberKit/captures", buf, buf_size, pos, &first);
    pos = list_dir_json("/CyberKit/logs",     buf, buf_size, pos, &first);
    if (pos < buf_size - 4)
        pos += snprintf(buf + pos, buf_size - pos, "]}");
    return pos;
}

/* ── Lectura de un archivo ───────────────────────────────────────────────── */

int sd_read_file(const char *path, char *buf, int buf_size) {
    if (!sd_ok || !path || !buf || buf_size <= 0) return -1;
    File f = SD.open(path, FILE_READ);
    if (!f) return -1;
    int total = 0;
    while (f.available() && total < buf_size - 1) {
        int chunk = buf_size - 1 - total;
        int got   = f.read((uint8_t *)(buf + total), chunk);
        if (got <= 0) break;
        total += got;
    }
    buf[total] = '\0';
    f.close();
    return total;
}
