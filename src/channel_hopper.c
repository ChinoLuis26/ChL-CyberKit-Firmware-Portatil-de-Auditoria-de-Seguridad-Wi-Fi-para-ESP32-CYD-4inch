/**
 * @file channel_hopper.c
 * @brief Channel Hopper — cicla automáticamente por los canales WiFi 1-13.
 *
 * @author Pedro Luis Rezabala Delgado — ChL-CyberKit v1.0 PRO
 * @copyright Copyright (C) 2026 Pedro Luis Rezabala Delgado. GPL v3.
 */
#include "channel_hopper.h"
#include <string.h>
#include "esp_wifi.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "ch_hop";

#define CHANNEL_MIN  1
#define CHANNEL_MAX 13

static volatile ch_hop_state_t s_state     = CH_HOP_IDLE;
static volatile uint8_t        s_cur_ch    = 1;
static volatile uint16_t       s_dwell_ms  = CH_HOP_DEFAULT_DWELL_MS;
static TaskHandle_t            s_task_h    = NULL;

/* ── Tarea FreeRTOS ─────────────────────────────────────────────────────── */
static void hop_task(void *arg) {
    (void)arg;
    uint8_t ch = CHANNEL_MIN;
    while (s_state == CH_HOP_RUNNING) {
        esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
        s_cur_ch = ch;
        ESP_LOGV(TAG, "CH%u", ch);
        vTaskDelay(pdMS_TO_TICKS(s_dwell_ms));
        ch = (ch >= CHANNEL_MAX) ? CHANNEL_MIN : ch + 1;
    }
    s_task_h = NULL;
    vTaskDelete(NULL);
}

/* ── API pública ─────────────────────────────────────────────────────────── */

void ch_hop_init(void) {
    s_state    = CH_HOP_IDLE;
    s_cur_ch   = 6;
    s_dwell_ms = CH_HOP_DEFAULT_DWELL_MS;
    s_task_h   = NULL;
    ESP_LOGI(TAG, "Inicializado");
}

bool ch_hop_start(uint16_t dwell_ms) {
    if (s_state == CH_HOP_RUNNING) return true;

    if (dwell_ms < CH_HOP_MIN_DWELL_MS) dwell_ms = CH_HOP_MIN_DWELL_MS;
    if (dwell_ms > CH_HOP_MAX_DWELL_MS) dwell_ms = CH_HOP_MAX_DWELL_MS;
    s_dwell_ms = dwell_ms;

    s_state = CH_HOP_RUNNING;
    BaseType_t ret = xTaskCreate(hop_task, "ch_hop", 2048, NULL,
                                  tskIDLE_PRIORITY + 1, &s_task_h);
    if (ret != pdPASS) {
        s_state = CH_HOP_IDLE;
        ESP_LOGE(TAG, "Error creando tarea");
        return false;
    }
    ESP_LOGI(TAG, "Iniciado — dwell=%ums", dwell_ms);
    return true;
}

void ch_hop_stop(void) {
    if (s_state == CH_HOP_IDLE) return;
    s_state = CH_HOP_IDLE;
    /* La tarea se autodestruye al detectar el cambio de estado */
    vTaskDelay(pdMS_TO_TICKS(s_dwell_ms + 50));
    ESP_LOGI(TAG, "Detenido en CH%u", s_cur_ch);
}

ch_hop_state_t ch_hop_get_state(void)  { return s_state; }
uint8_t        ch_hop_current_channel(void) { return s_cur_ch; }
uint16_t       ch_hop_get_dwell(void)  { return s_dwell_ms; }
