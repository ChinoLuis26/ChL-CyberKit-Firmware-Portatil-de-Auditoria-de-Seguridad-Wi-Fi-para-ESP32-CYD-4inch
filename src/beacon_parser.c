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
 * @file beacon_parser.c
 * @brief Implementación del parser de beacons 802.11.
 *
 * @author Pedro Luis Rezabala — ChL-CyberKit v1.0 PRO
 */
#include "beacon_parser.h"

#include <string.h>
#include <stdio.h>
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

static const char *TAG = "beacon_parser";

/* ── Subtypes 802.11 ────────────────────────────────────────────────────── */
#define MGMT_SUBTYPE_BEACON        0x08
#define MGMT_SUBTYPE_PROBE_RESP    0x05

/* ── OUI WPS (Vendor Specific Tag 221) ──────────────────────────────────── */
static const uint8_t WPS_OUI[4] = {0x00, 0x50, 0xF2, 0x04};

/* ── Almacenamiento ─────────────────────────────────────────────────────── */
static bp_ap_info_t       g_aps[BP_MAX_APS];
static uint8_t            g_ap_count = 0;
static SemaphoreHandle_t  g_mutex    = NULL;

/* ── Cabecera 802.11 ────────────────────────────────────────────────────── */
typedef struct __attribute__((packed)) {
    uint16_t frame_ctrl;
    uint16_t duration;
    uint8_t  addr1[6];
    uint8_t  addr2[6];
    uint8_t  addr3[6];
    uint16_t seq_ctrl;
} ieee80211_mgmt_hdr_t;

/* ── Buscar o crear entrada de AP ────────────────────────────────────────── */
static bp_ap_info_t *find_or_create_ap(const uint8_t *bssid) {
    for (uint8_t i = 0; i < g_ap_count; i++) {
        if (memcmp(g_aps[i].bssid, bssid, 6) == 0) return &g_aps[i];
    }
    if (g_ap_count >= BP_MAX_APS) return NULL;
    bp_ap_info_t *ap = &g_aps[g_ap_count++];
    memset(ap, 0, sizeof(bp_ap_info_t));
    memcpy(ap->bssid, bssid, 6);
    return ap;
}

/* ── Parsear IEs del beacon/probe response ───────────────────────────────── */
static void parse_ies(bp_ap_info_t *ap, const uint8_t *ies, int ies_len) {
    int pos = 0;
    while (pos + 2 <= ies_len) {
        uint8_t tag_id  = ies[pos];
        uint8_t tag_len = ies[pos + 1];
        if (pos + 2 + tag_len > ies_len) break;
        const uint8_t *tag_data = &ies[pos + 2];

        switch (tag_id) {
            case 0: { /* SSID */
                uint8_t slen = (tag_len < BP_SSID_LEN - 1) ? tag_len : (BP_SSID_LEN - 1);
                memcpy(ap->ssid, tag_data, slen);
                ap->ssid[slen] = '\0';
                break;
            }
            case 3: { /* DS Parameter Set → canal actual */
                if (tag_len >= 1) ap->channel = tag_data[0];
                break;
            }
            case 48: { /* RSN Information Element (WPA2/3) */
                /* Offset 0-1: Version
                 * Offset 2-5: Group Cipher Suite
                 * Offset 6-7: Pairwise Cipher Suite Count
                 *   entonces saltamos: 2 + 4 + 2 + (count * 4) bytes
                 *   + AKM Suite Count (2 bytes) + AKM Suites
                 *   + RSN Capabilities (2 bytes) ← aquí nos interesa */
                int rpos = 0;
                if (rpos + 2 > tag_len) break;  /* version */
                rpos += 2;
                if (rpos + 4 > tag_len) break;  /* group cipher */
                rpos += 4;
                if (rpos + 2 > tag_len) break;  /* pairwise count */
                uint16_t pc = (uint16_t)(tag_data[rpos] | (tag_data[rpos+1] << 8));
                rpos += 2;
                rpos += pc * 4;                  /* saltar pairwise suites */
                if (rpos + 2 > tag_len) break;  /* AKM count */
                uint16_t ac = (uint16_t)(tag_data[rpos] | (tag_data[rpos+1] << 8));
                rpos += 2;
                rpos += ac * 4;                  /* saltar AKM suites */
                if (rpos + 2 > tag_len) break;  /* RSN Capabilities */
                uint16_t caps = (uint16_t)(tag_data[rpos] | (tag_data[rpos+1] << 8));
                ap->pmf_capable  = (caps >> 6) & 1;  /* bit 6: MFPC */
                ap->pmf_required = (caps >> 7) & 1;  /* bit 7: MFPR */
                break;
            }
            case 221: { /* Vendor Specific */
                /* WPS: OUI = 00:50:F2:04 (primeros 4 bytes del tag_data) */
                if (tag_len >= 4 && memcmp(tag_data, WPS_OUI, 4) == 0) {
                    ap->wps_enabled = true;
                }
                break;
            }
            default:
                break;
        }
        pos += 2 + tag_len;
    }
}

/* ── Init ────────────────────────────────────────────────────────────────── */
void beacon_parser_init(void) {
    memset(g_aps, 0, sizeof(g_aps));
    g_ap_count = 0;
    g_mutex = xSemaphoreCreateMutex();
    ESP_LOGI(TAG, "Beacon parser inicializado (max %d APs)", BP_MAX_APS);
}

/* ── Handler de frames de gestión ───────────────────────────────────────── */
void beacon_parser_handle_mgmt(const wifi_promiscuous_pkt_t *frame) {
    if (!frame) return;

    const uint8_t *payload = frame->payload;
    int len = (int)frame->rx_ctrl.sig_len;

    if (len < (int)sizeof(ieee80211_mgmt_hdr_t) + 12) return;

    const ieee80211_mgmt_hdr_t *hdr = (const ieee80211_mgmt_hdr_t *)payload;
    uint8_t type    = (hdr->frame_ctrl >> 2) & 0x03;
    uint8_t subtype = (hdr->frame_ctrl >> 4) & 0x0F;

    /* Solo Management Beacon (8) y Probe Response (5) */
    if (type != 0) return;
    if (subtype != MGMT_SUBTYPE_BEACON && subtype != MGMT_SUBTYPE_PROBE_RESP) return;

    /* addr3 es el BSSID en beacons */
    const uint8_t *bssid = hdr->addr3;

    /* IEs empiezan después del header + 12 bytes fijos del beacon body
     * (Timestamp 8 + Beacon Interval 2 + Capability Info 2) */
    const uint8_t *ies    = payload + sizeof(ieee80211_mgmt_hdr_t) + 12;
    int            ies_len = len - (int)sizeof(ieee80211_mgmt_hdr_t) - 12;
    if (ies_len < 0) return;

    if (g_mutex && xSemaphoreTake(g_mutex, pdMS_TO_TICKS(5)) == pdTRUE) {
        bp_ap_info_t *ap = find_or_create_ap(bssid);
        if (ap) {
            ap->rssi     = frame->rx_ctrl.rssi;
            ap->channel  = frame->rx_ctrl.channel;
            ap->last_seen = (uint32_t)(esp_timer_get_time() / 1000);
            parse_ies(ap, ies, ies_len);
        }
        xSemaphoreGive(g_mutex);
    }
}

/* ── Anotar cliente de data frame ────────────────────────────────────────── */
void beacon_parser_note_client(const uint8_t *ap_bssid, const uint8_t *client_mac) {
    if (!ap_bssid || !client_mac) return;

    /* Ignorar multidifusión / broadcast */
    if (client_mac[0] & 0x01) return;

    if (g_mutex && xSemaphoreTake(g_mutex, pdMS_TO_TICKS(5)) == pdTRUE) {
        bp_ap_info_t *ap = find_or_create_ap(ap_bssid);
        if (ap) {
            /* ¿ya está en la lista? */
            bool found = false;
            for (uint8_t i = 0; i < ap->client_count; i++) {
                if (memcmp(ap->client_macs[i], client_mac, 6) == 0) {
                    found = true; break;
                }
            }
            if (!found && ap->client_count < BP_MAX_CLIENTS) {
                memcpy(ap->client_macs[ap->client_count], client_mac, 6);
                ap->client_count++;
            }
        }
        xSemaphoreGive(g_mutex);
    }
}

/* ── Consultas ───────────────────────────────────────────────────────────── */
uint8_t beacon_parser_ap_count(void) {
    return g_ap_count;
}

const bp_ap_info_t *beacon_parser_get_ap(uint8_t idx) {
    if (idx >= g_ap_count) return NULL;
    return &g_aps[idx];
}

const bp_ap_info_t *beacon_parser_find_ap(const uint8_t *bssid) {
    for (uint8_t i = 0; i < g_ap_count; i++) {
        if (memcmp(g_aps[i].bssid, bssid, 6) == 0) return &g_aps[i];
    }
    return NULL;
}

void beacon_parser_clear(void) {
    if (g_mutex) xSemaphoreTake(g_mutex, portMAX_DELAY);
    memset(g_aps, 0, sizeof(g_aps));
    g_ap_count = 0;
    if (g_mutex) xSemaphoreGive(g_mutex);
}
