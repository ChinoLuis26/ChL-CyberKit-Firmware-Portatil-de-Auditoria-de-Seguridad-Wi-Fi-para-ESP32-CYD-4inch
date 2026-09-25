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
 * @file main.cpp
 * @brief ChL-CyberKit v1.0 — by Pedro Luis Rezabala
 *
 * Ahora puedes hacer desde la CYD TODO lo que hacías en el panel web:
 *   1. Escanear redes           → Pantalla REDES → [SCAN]
 *   2. Seleccionar target       → Tocar una fila de la lista
 *   3. Elegir tipo de ataque    → Botones [Pasivo][HS][PMKID][DoS]
 *   4. Elegir método            → Botones ◄ ►
 *   5. Lanzar ataque            → [LANZAR]
 *   6. Detener ataque           → [STOP] (aparece durante el ataque)
 *   7. Ver estado               → Pantalla ESTADO
 *   8. Ver auditoría defensiva  → Pantalla RIESGO
 *   9. Stealth on/off           → Botón en PANEL o CONFIG
 *  10. Recalibrar touch         → CONFIG → [CALIBRAR TOUCH]
 *
 * Panel web (acceso alternativo): http://10.10.10.26
 *   WiFi: ChL-CyberKit   Pass: CyberKit2026
 *   User: chl            Clave: CyberKit2026
 */

#include <Arduino.h>
#include "esp_log.h"
#include "esp_err.h"
#include "esp_event.h"
#include "esp_wifi.h"

extern "C" {
#include "attack.h"
#include "wifi_controller.h"
#include "ap_scanner.h"
#include "webserver.h"
#include "pcap_serializer.h"
#include "hccapx_serializer.h"
#include "probe_logger.h"
#include "beacon_parser.h"
#include "evil_twin.h"
#include "beacon_flood.h"
#include "auto_audit.h"
#include "report_gen.h"
#include "karma.h"
#include "channel_hopper.h"
#include "packet_monitor.h"
#include "ssid_list.h"
}

#include "cyd_display.h"
#include "sd_storage.h"
#include "wifi_audit.h"
#include "ota_manager.h"
#include "ble_scanner.h"

static const char *TAG = "main";

/* ── Estado global ───────────────────────────────────────────────────────── */
static screen_t          cur_scr    = SCR_DASHBOARD;
static bool              stealth_on = false;
static bool              sd_ok_flag = false;
static uint8_t           last_state = 0xFF;
static uint8_t           last_type  = 0xFF;
static unsigned long     next_info  = 0;
static unsigned long     next_touch = 0;
static unsigned long     next_audit = 0;

/* ── Conversores ─────────────────────────────────────────────────────────── */
static disp_attack_state_t cvt_state(uint8_t s) {
    switch(s){ case 1: return DA_RUNNING;  case 2: return DA_FINISHED;
               case 3: return DA_TIMEOUT;  default: return DA_READY; }
}
static disp_attack_type_t cvt_type(uint8_t t) {
    switch(t){ case 0: return DT_PASSIVE;   case 1: return DT_HANDSHAKE;
               case 2: return DT_PMKID;     case 3: return DT_DOS;
               default: return DT_NONE; }
}

/* ── Guardar captura en SD ────────────────────────────────────────────────── */
static void save_to_sd(uint8_t type, const attack_status_t *st) {
    if (!sd_ok_flag) return;
    const char *type_names[] = {"PASIVO","HANDSHAKE","PMKID","DOS"};
    const char *tn = (type < 4) ? type_names[type] : "?";

    if (type == 1) {
        uint8_t *pcap  = pcap_serializer_get_buffer();
        unsigned pcap_len = pcap_serializer_get_size();
        hccapx_t *hx  = hccapx_serializer_get();
        char ssid[33] = {0};
        if (hx) { uint8_t sl = hx->essid_len < 32 ? hx->essid_len : 32; memcpy(ssid, hx->essid, sl); }
        sd_result_t res = sd_save_handshake(ssid[0]?ssid:"unknown", pcap, pcap_len, (uint8_t*)hx, sizeof(hccapx_t));
        sd_log_event(tn, ssid, "??:??:??:??:??:??", res==SD_OK?"OK":"ERROR");
        ESP_LOGI(TAG, "[SD] Handshake: %s", sd_last_file());
    } else if (type == 2) {
        if (st->content && st->content_size > 13) {
            uint8_t ssid_len = (uint8_t)st->content[12];
            char ssid[33] = {0};
            if (ssid_len > 0 && ssid_len <= 32) memcpy(ssid, st->content+13, ssid_len);
            sd_result_t res = sd_save_pmkid(ssid[0]?ssid:"unknown", (const uint8_t*)st->content, st->content_size);
            sd_log_event(tn, ssid, "??:??:??:??:??:??", res==SD_OK?"OK":"ERROR");
            ESP_LOGI(TAG, "[SD] PMKID: %s", sd_last_file());
        }
    } else {
        sd_log_event(tn, "---", "---", "OK");
    }
}

/* ── Disparar ataque desde la CYD ────────────────────────────────────────── */
static void fire_attack(const cyd_touch_t &t) {
    attack_request_t req;
    req.ap_record_id = t.attack_ap;
    req.type         = t.attack_type;
    req.method       = t.attack_method;
    req.timeout      = t.attack_timeout;
    esp_event_post(WEBSERVER_EVENTS, WEBSERVER_EVENT_ATTACK_REQUEST,
                   &req, sizeof(attack_request_t), portMAX_DELAY);
    ESP_LOGI(TAG, "[CYD] Ataque lanzado: ap=%u type=%u method=%u timeout=%u",
             req.ap_record_id, req.type, req.method, req.timeout);
}

/* ── Resetear ataque ─────────────────────────────────────────────────────── */
static void fire_reset() {
    esp_event_post(WEBSERVER_EVENTS, WEBSERVER_EVENT_ATTACK_RESET, NULL, 0, portMAX_DELAY);
    ESP_LOGI(TAG, "[CYD] Ataque detenido/reseteado");
}

/* ── Redibujar pantalla actual ───────────────────────────────────────────── */
static void redraw() {
    wifi_sta_list_t sl; uint8_t cli = 0;
    if (esp_wifi_ap_get_sta_list(&sl) == ESP_OK) cli = (uint8_t)sl.num;
    cyd_draw_screen(cur_scr, stealth_on, sd_ok_flag,
                    cvt_state(last_state), cvt_type(last_type),
                    millis()/1000, cli, sd_capture_count(), sd_last_file());
}

/* ── setup() ─────────────────────────────────────────────────────────────── */
void setup() {
    Serial.begin(115200);
    delay(100);
    ESP_LOGI(TAG, "ChL-CyberKit v1.0 — by Pedro Luis Rezabala");

    cyd_display_init();

    sd_ok_flag = (sd_init() == SD_OK);
    ESP_LOGI(TAG, "SD: %s", sd_ok_flag ? "OK" : "sin tarjeta");

    esp_err_t ev = esp_event_loop_create_default();
    if (ev != ESP_OK && ev != ESP_ERR_INVALID_STATE) ESP_ERROR_CHECK(ev);

    wifictl_mgmt_ap_start();
    attack_init();
    audit_init();
    probe_logger_init();
    beacon_parser_init();
    auto_audit_init();

    /* ── Nuevos módulos v1.0 PRO ─────────────────────────────────────────── */
    karma_init();
    ch_hop_init();
    pmon_init();
    ssid_list_init();   /* carga SSIDs de SD si está disponible */

    /* OTA: permite actualización vía PlatformIO / esptool por WiFi */
    ota_manager_init("ChL-CyberKit", "CyberKit2026");

    next_audit = millis() + 15000;
    webserver_run();

    cyd_draw_screen(cur_scr, stealth_on, sd_ok_flag,
                    DA_READY, DT_NONE, 0, 0, 0, "");
    cyd_led(DA_READY);
    ESP_LOGI(TAG, "Listo | WiFi: %s | IP: 10.10.10.26", CONFIG_MGMT_AP_SSID);
}

/* ── loop() ──────────────────────────────────────────────────────────────── */

static unsigned long next_pmon_tick = 0;   /* pmon_tick() cada 1000ms */

void loop() {
    unsigned long now = millis();
    bool atk_running = (last_state == 1);

    /* ── 0. OTA y Packet Monitor (fondo) ─────────────────────────────────── */
    ota_manager_handle();   /* procesa eventos ArduinoOTA pendientes  */
    if (now >= next_pmon_tick) {
        next_pmon_tick = now + 1000;
        pmon_tick();        /* actualiza cálculo de pps cada segundo  */
    }

    /* ── 1. Estado del ataque ─────────────────────────────────────────── */
    const attack_status_t *st = attack_get_status();
    if (st->state != last_state || (uint8_t)st->type != last_type) {
        uint8_t prev_state = last_state;
        last_state = st->state;
        last_type  = (uint8_t)st->type;
        disp_attack_state_t ds = cvt_state(last_state);
        disp_attack_type_t  dt = cvt_type(last_type);
        cyd_update_attack(ds, dt, cur_scr);
        cyd_led(ds);
        if (last_state == 2 && prev_state == 1) save_to_sd(last_type, st);
        ESP_LOGI(TAG, "[STATUS] state=%d type=%d caps=%d",
                 last_state, last_type, sd_capture_count());
    }

    /* ── 2. Uptime + clientes ─────────────────────────────────────────── */
    if (now >= next_info) {
        next_info = now + 5000;
        wifi_sta_list_t sl; uint8_t cli = 0;
        if (esp_wifi_ap_get_sta_list(&sl) == ESP_OK) cli = (uint8_t)sl.num;
        cyd_update_info(now/1000, cli, cur_scr, sd_capture_count());
    }

    /* ── 3. Auditoría pasiva (cada 60s, si no hay ataque) ─────────────── */
    if (now >= next_audit && !atk_running) {
        next_audit = now + 60000;
        wifictl_scan_nearby_aps();
        audit_update_from_scan(wifictl_get_ap_records());
        if (cur_scr == SCR_DASHBOARD || cur_scr == SCR_NETWORKS ||
            cur_scr == SCR_AUDIT    || cur_scr == SCR_TOOLS)
            redraw();
    }

    /* ── 4. Touch (anti-rebote 600ms) ────────────────────────────────── */
    if (now >= next_touch) {
        cyd_touch_t t = cyd_handle_touch(cur_scr, stealth_on, atk_running);

        /* Cambio de pantalla */
        if (t.new_scr != cur_scr) {
            next_touch = now + 600;
            cur_scr = t.new_scr;
            redraw();
            return;
        }

        /* Stealth toggle */
        if (t.stealth_tog) {
            next_touch = now + 800;
            stealth_on = !stealth_on;
            wifictl_set_stealth(stealth_on);
            redraw();
            ESP_LOGI(TAG, "Stealth: %s", stealth_on ? "ON" : "OFF");
            return;
        }

        /* Calibrar touch */
        if (t.calib_req) {
            next_touch = now + 2000;
            cyd_run_calibration();
            redraw();
            return;
        }

        /* Escanear redes */
        if (t.scan_req) {
            next_touch = now + 1500;
            wifictl_scan_nearby_aps();
            audit_update_from_scan(wifictl_get_ap_records());
            redraw();
            ESP_LOGI(TAG, "[SCAN] %u redes encontradas", wifictl_get_ap_records()->count);
            return;
        }

        /* LANZAR ataque desde CYD */
        if (t.attack_req) {
            next_touch = now + 1000;
            fire_attack(t);
            return;
        }

        /* STOP/RESET desde CYD */
        if (t.reset_req) {
            next_touch = now + 800;
            fire_reset();
            /* Si el Auto-Audit estaba corriendo, pararlo también */
            if (auto_audit_is_running()) auto_audit_stop();
            /* Si Evil Twin estaba corriendo, pararlo */
            if (evil_twin_get_state() == ET_RUNNING) evil_twin_stop();
            /* Si Beacon Flood estaba corriendo, pararlo */
            if (beacon_flood_get_state() == BF_RUNNING) beacon_flood_stop();
            /* Si Karma estaba corriendo, pararlo */
            if (karma_get_state() == KARMA_RUNNING) karma_stop();
            return;
        }

        /* Guardar reporte HTML en SD */
        if (t.report_req && sd_ok_flag) {
            next_touch = now + 2000;
            char rpath[64] = {0};
            report_result_t rr = report_gen_save(rpath, sizeof(rpath));
            ESP_LOGI(TAG, "[REPORT] %s → %s",
                     rpath[0] ? rpath : "?",
                     rr == RG_OK ? "OK" : "ERROR");
            redraw();
            return;
        }

        /* ── HERRAM: Beacon Flood ─────────────────────────────────────── */
        if (t.bf_start_req) {
            next_touch = now + 800;
            beacon_flood_start(t.bf_channel, t.bf_rate_ms);
            ESP_LOGI(TAG, "[BF] Iniciado CH=%u rate=%ums",
                     t.bf_channel, (unsigned)t.bf_rate_ms);
            if (cur_scr == SCR_TOOLS) redraw();
            return;
        }
        if (t.bf_stop_req) {
            next_touch = now + 800;
            beacon_flood_stop();
            ESP_LOGI(TAG, "[BF] Detenido");
            if (cur_scr == SCR_TOOLS) redraw();
            return;
        }

        /* ── HERRAM: Evil Twin ────────────────────────────────────────── */
        if (t.et_start_req) {
            next_touch = now + 800;
            const wifictl_ap_records_t *recs = wifictl_get_ap_records();
            if (t.attack_ap < recs->count) {
                const wifi_ap_record_t *ap = &recs->records[t.attack_ap];
                evil_twin_cfg_t cfg; memset(&cfg, 0, sizeof(cfg));
                strncpy(cfg.ssid, (const char*)ap->ssid, 32);
                memcpy(cfg.bssid, ap->bssid, 6);
                cfg.channel = ap->primary;
                bool ok = evil_twin_start(&cfg);
                ESP_LOGI(TAG, "[ET] Iniciado: %s CH%u → %s",
                         cfg.ssid, cfg.channel, ok ? "OK" : "ERROR");
            } else {
                ESP_LOGW(TAG, "[ET] Sin target seleccionado");
            }
            if (cur_scr == SCR_TOOLS) redraw();
            return;
        }
        if (t.et_stop_req) {
            next_touch = now + 800;
            evil_twin_stop();
            ESP_LOGI(TAG, "[ET] Detenido");
            if (cur_scr == SCR_TOOLS) redraw();
            return;
        }

        /* ── HERRAM: Karma Attack ────────────────────────────────────── */
        if (t.karma_start_req) {
            next_touch = now + 800;
            uint8_t kch = (t.karma_channel >= 1 && t.karma_channel <= 13) ? t.karma_channel : 6;
            bool ok = karma_start(kch);
            ESP_LOGI(TAG, "[KARMA] Iniciado CH=%u → %s", kch, ok ? "OK" : "ERROR");
            if (cur_scr == SCR_TOOLS) redraw();
            return;
        }
        if (t.karma_stop_req) {
            next_touch = now + 800;
            karma_stop();
            ESP_LOGI(TAG, "[KARMA] Detenido");
            if (cur_scr == SCR_TOOLS) redraw();
            return;
        }

        /* ── HERRAM: Probe Logger ─────────────────────────────────────── */
        if (t.probe_sd_req) {
            next_touch = now + 1000;
            probe_logger_dump_to_sd();
            ESP_LOGI(TAG, "[PROBE] Dump a SD solicitado");
            return;
        }
        if (t.probe_clear_req) {
            next_touch = now + 600;
            probe_logger_clear();
            ESP_LOGI(TAG, "[PROBE] Tabla limpiada");
            if (cur_scr == SCR_TOOLS) redraw();
            return;
        }

        /* ── HERRAM: Auto Audit ───────────────────────────────────────── */
        if (t.audit_run_req) {
            next_touch = now + 800;
            if (auto_audit_is_running()) {
                auto_audit_stop();
                ESP_LOGI(TAG, "[AUDIT] Detenido por usuario");
            } else {
                bool ok = auto_audit_start();
                ESP_LOGI(TAG, "[AUDIT] Iniciado: %s", ok ? "OK" : "ERROR");
            }
            if (cur_scr == SCR_TOOLS) redraw();
            return;
        }
    }

    delay(200);
}
