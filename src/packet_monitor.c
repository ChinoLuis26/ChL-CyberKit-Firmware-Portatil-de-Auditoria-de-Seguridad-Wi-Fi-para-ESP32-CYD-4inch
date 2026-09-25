/**
 * @file packet_monitor.c
 * @brief Monitor de paquetes en tiempo real.
 *
 * @author Pedro Luis Rezabala Delgado — ChL-CyberKit v1.0 PRO
 * @copyright Copyright (C) 2026 Pedro Luis Rezabala Delgado. GPL v3.
 */
#include "packet_monitor.h"
#include <string.h>
#include <stdint.h>
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

static pmon_stats_t      s_stats;
static uint32_t          s_frame_this_sec = 0;
static SemaphoreHandle_t s_mutex          = NULL;
static int64_t           s_last_tick_us   = 0;

void pmon_init(void) {
    s_mutex = xSemaphoreCreateMutex();
    memset(&s_stats, 0, sizeof(s_stats));
    s_frame_this_sec = 0;
    s_last_tick_us   = esp_timer_get_time();
}

void pmon_handle_frame(const uint8_t *payload, int len) {
    if (!payload || len < 4) return;

    /* Saltar radiotap */
    uint16_t rt_len = (uint16_t)(payload[2] | (payload[3] << 8));
    if ((int)rt_len + 2 > len) return;
    const uint8_t *mhdr = payload + rt_len;

    uint8_t fc0 = mhdr[0];
    uint8_t type    = (fc0 >> 2) & 0x03;  /* 0=mgmt 1=ctl 2=data */
    uint8_t subtype = (fc0 >> 4) & 0x0F;

    if (s_mutex) xSemaphoreTake(s_mutex, pdMS_TO_TICKS(5));

    s_stats.total++;
    s_frame_this_sec++;

    if (type == 0) { /* Management */
        switch (subtype) {
            case 8:  s_stats.beacon++;     break;
            case 4:  s_stats.probe_req++;  break;
            case 5:  s_stats.probe_resp++; break;
            case 0:  /* fall */
            case 1:  s_stats.assoc++;      break;
            case 12: s_stats.deauth++;     break;
            case 10: s_stats.disassoc++;   break;
            default: s_stats.mgmt_other++; break;
        }
    } else if (type == 2) { /* Data */
        s_stats.data++;
    }

    if (s_mutex) xSemaphoreGive(s_mutex);
}

void pmon_tick(void) {
    int64_t now = esp_timer_get_time();
    if ((now - s_last_tick_us) < 900000LL) return; /* < 900ms, esperar */
    s_last_tick_us = now;

    if (s_mutex) xSemaphoreTake(s_mutex, pdMS_TO_TICKS(10));

    s_stats.pps = s_frame_this_sec;
    s_frame_this_sec = 0;

    /* Ring buffer */
    uint16_t val = (s_stats.pps > 0xFFFF) ? 0xFFFF : (uint16_t)s_stats.pps;
    s_stats.pps_history[s_stats.pps_idx] = val;
    s_stats.pps_idx = (s_stats.pps_idx + 1) % PMON_HISTORY_SIZE;

    if (s_mutex) xSemaphoreGive(s_mutex);
}

pmon_stats_t pmon_get_stats(void) {
    pmon_stats_t snap;
    if (s_mutex && xSemaphoreTake(s_mutex, pdMS_TO_TICKS(10))) {
        snap = s_stats;
        xSemaphoreGive(s_mutex);
    } else {
        snap = s_stats;
    }
    return snap;
}

void pmon_reset(void) {
    if (s_mutex) xSemaphoreTake(s_mutex, portMAX_DELAY);
    memset(&s_stats, 0, sizeof(s_stats));
    s_frame_this_sec = 0;
    if (s_mutex) xSemaphoreGive(s_mutex);
}
