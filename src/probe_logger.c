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
 * @file probe_logger.c
 * @brief Implementación del logger de Probe Requests.
 *
 * @author Pedro Luis Rezabala — ChL-CyberKit v1.0 PRO
 */
#include "probe_logger.h"
#include "oui_lookup.h"
#include "sd_storage.h"

#include <string.h>
#include <stdio.h>
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

static const char *TAG = "probe";

/* ── Subtype 802.11 para Probe Request ──────────────────────────────────── */
#define MGMT_SUBTYPE_PROBE_REQ   0x04

/* ── Almacenamiento ─────────────────────────────────────────────────────── */
static probe_device_t  g_devices[PROBE_MAX_DEVICES];
static uint8_t         g_dev_count = 0;
static SemaphoreHandle_t g_mutex   = NULL;

/* ── Cabecera 802.11 mínima ──────────────────────────────────────────────── */
typedef struct __attribute__((packed)) {
    uint16_t frame_ctrl;
    uint16_t duration;
    uint8_t  addr1[6];   /* DA   */
    uint8_t  addr2[6];   /* SA   */
    uint8_t  addr3[6];   /* BSSID */
    uint16_t seq_ctrl;
} ieee80211_hdr_t;

/* ── Buscar o crear dispositivo ─────────────────────────────────────────── */
static probe_device_t *find_or_create(const uint8_t *mac) {
    for (uint8_t i = 0; i < g_dev_count; i++) {
        if (memcmp(g_devices[i].mac, mac, 6) == 0) return &g_devices[i];
    }
    if (g_dev_count >= PROBE_MAX_DEVICES) return NULL;
    probe_device_t *d = &g_devices[g_dev_count++];
    memset(d, 0, sizeof(probe_device_t));
    memcpy(d->mac, mac, 6);
    const char *v = oui_vendor(mac);
    strncpy(d->vendor, v, sizeof(d->vendor) - 1);
    return d;
}

/* ── Agregar SSID al dispositivo si es nuevo ─────────────────────────────── */
static void add_ssid(probe_device_t *d, const char *ssid, uint8_t ssid_len) {
    if (ssid_len == 0) return;                  /* Probe wildcard — ignorar */
    if (ssid_len > PROBE_SSID_LEN - 1) ssid_len = PROBE_SSID_LEN - 1;

    for (uint8_t i = 0; i < d->ssid_count; i++) {
        if (strncmp(d->ssids[i], ssid, ssid_len) == 0) return;
    }
    if (d->ssid_count >= PROBE_MAX_SSIDS) return;
    memcpy(d->ssids[d->ssid_count], ssid, ssid_len);
    d->ssids[d->ssid_count][ssid_len] = '\0';
    d->ssid_count++;
}

/* ── Init ────────────────────────────────────────────────────────────────── */
void probe_logger_init(void) {
    memset(g_devices, 0, sizeof(g_devices));
    g_dev_count = 0;
    g_mutex = xSemaphoreCreateMutex();
    ESP_LOGI(TAG, "Probe logger inicializado (max %d dispositivos)", PROBE_MAX_DEVICES);
}

/* ── Handler de frames de gestión ───────────────────────────────────────── */
void probe_logger_handle_mgmt(const wifi_promiscuous_pkt_t *frame) {
    if (!frame) return;

    const uint8_t *payload = frame->payload;
    int len = (int)frame->rx_ctrl.sig_len;

    /* Necesitamos al menos la cabecera (24 bytes) */
    if (len < 24) return;

    const ieee80211_hdr_t *hdr = (const ieee80211_hdr_t *)payload;
    uint8_t type    = (hdr->frame_ctrl >> 2) & 0x03;
    uint8_t subtype = (hdr->frame_ctrl >> 4) & 0x0F;

    /* Filtrar: solo Management (type=0) Probe Request (subtype=4) */
    if (type != 0 || subtype != MGMT_SUBTYPE_PROBE_REQ) return;

    /* Parsear IEs buscando SSID (Tag 0) */
    const uint8_t *ies    = payload + sizeof(ieee80211_hdr_t);
    int            ies_len = len - (int)sizeof(ieee80211_hdr_t);

    char    ssid[PROBE_SSID_LEN] = {0};
    uint8_t ssid_len = 0;

    int pos = 0;
    while (pos + 2 <= ies_len) {
        uint8_t tag_id  = ies[pos];
        uint8_t tag_len = ies[pos + 1];
        if (pos + 2 + tag_len > ies_len) break;

        if (tag_id == 0) {  /* SSID */
            ssid_len = (tag_len < PROBE_SSID_LEN - 1) ? tag_len : (PROBE_SSID_LEN - 1);
            memcpy(ssid, &ies[pos + 2], ssid_len);
            ssid[ssid_len] = '\0';
            break;
        }
        pos += 2 + tag_len;
    }

    /* Fuente (SA = addr2) */
    const uint8_t *sa = hdr->addr2;

    if (g_mutex && xSemaphoreTake(g_mutex, pdMS_TO_TICKS(5)) == pdTRUE) {
        probe_device_t *d = find_or_create(sa);
        if (d) {
            d->rssi_last = frame->rx_ctrl.rssi;
            d->count++;
            d->last_seen = (uint32_t)(esp_timer_get_time() / 1000);
            add_ssid(d, ssid, ssid_len);
        }
        xSemaphoreGive(g_mutex);
    }
}

/* ── Consultas ───────────────────────────────────────────────────────────── */
uint8_t probe_logger_device_count(void) {
    return g_dev_count;
}

const probe_device_t *probe_logger_get_device(uint8_t idx) {
    if (idx >= g_dev_count) return NULL;
    return &g_devices[idx];
}

void probe_logger_clear(void) {
    if (g_mutex) xSemaphoreTake(g_mutex, portMAX_DELAY);
    memset(g_devices, 0, sizeof(g_devices));
    g_dev_count = 0;
    if (g_mutex) xSemaphoreGive(g_mutex);
    ESP_LOGI(TAG, "Registros borrados");
}

/* ── Volcado a SD ────────────────────────────────────────────────────────── */
void probe_logger_dump_to_sd(void) {
    if (g_dev_count == 0) return;

    char line[128];
    for (uint8_t i = 0; i < g_dev_count; i++) {
        const probe_device_t *d = &g_devices[i];
        /* Primera línea: dispositivo */
        snprintf(line, sizeof(line),
                 "PROBE,%02X:%02X:%02X:%02X:%02X:%02X,%s,%d,cnt=%lu",
                 d->mac[0], d->mac[1], d->mac[2],
                 d->mac[3], d->mac[4], d->mac[5],
                 d->vendor, (int)d->rssi_last, (unsigned long)d->count);
        sd_append_line("/CyberKit/logs/audit.csv", line);

        /* SSIDs buscados */
        for (uint8_t j = 0; j < d->ssid_count; j++) {
            snprintf(line, sizeof(line), "  -> SSID: %s", d->ssids[j]);
            sd_append_line("/CyberKit/logs/audit.csv", line);
        }
    }
    ESP_LOGI(TAG, "Volcados %d dispositivos a SD", (int)g_dev_count);
}
