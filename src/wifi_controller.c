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
 * @file wifi_controller.c
 * @brief WiFi controller — ChL-CyberKit v1.0
 *
 * Cambios vs original:
 *  - Canal del AP aleatorio en cada boot (anti-detección)
 *  - IP del AP: 10.10.10.26 (leet)
 *  - wifictl_set_stealth() para alternar AP oculto/visible
 *  - esp_netif_init() tolerante (ya iniciado por Arduino core)
 */

#include "wifi_controller.h"

#include <stdio.h>
#include <string.h>

#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_err.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_netif.h"
#include "esp_event.h"
#include "esp_random.h"
#include "lwip/ip4_addr.h"

static const char *TAG = "wifi_controller";

static bool  wifi_init       = false;
static bool  stealth_mode    = false;          /* estado actual de stealth */
static uint8_t boot_channel  = 3;             /* canal aleatorio generado al arrancar */
static uint8_t original_mac_ap[6];

static void wifi_event_handler(void *arg, esp_event_base_t base,
                                int32_t id, void *data) {}

/* ── Cambiar IP del AP a 10.10.10.26 ──────────────────────────────────────── */
static void set_ap_ip() {
    esp_netif_t *ap_netif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
    if (!ap_netif) return;

    esp_netif_ip_info_t ip_info;
    IP4_ADDR(&ip_info.ip,      10, 10, 10, 26);
    IP4_ADDR(&ip_info.gw,      10, 10, 10, 26);
    IP4_ADDR(&ip_info.netmask, 255, 255, 255, 0);

    esp_netif_dhcps_stop(ap_netif);
    esp_netif_set_ip_info(ap_netif, &ip_info);
    esp_netif_dhcps_start(ap_netif);
    ESP_LOGI(TAG, "IP del AP: 10.10.10.26");
}

/* ── Inicializar WiFi en modo APSTA ──────────────────────────────────────── */
static void wifi_init_apsta() {
    /* esp_netif puede ya estar inicializado por Arduino core */
    esp_err_t netif_err = esp_netif_init();
    if (netif_err != ESP_OK && netif_err != ESP_ERR_INVALID_STATE) {
        ESP_ERROR_CHECK(netif_err);
    }

    esp_netif_create_default_wifi_ap();
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                               &wifi_event_handler, NULL));
    ESP_ERROR_CHECK(esp_wifi_get_mac(WIFI_IF_AP, original_mac_ap));
    ESP_ERROR_CHECK(esp_wifi_start());

    /* Cambiar IP a 10.10.10.26 */
    set_ap_ip();

    /* Canal aleatorio (1-11) para anti-detección */
    boot_channel = (uint8_t)((esp_random() % 11) + 1);
    ESP_LOGI(TAG, "Canal AP aleatorio: %d", boot_channel);

    wifi_init = true;
}

/* ── API pública ─────────────────────────────────────────────────────────── */

void wifictl_ap_start(wifi_config_t *wifi_config) {
    if (!wifi_init) wifi_init_apsta();
    ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_AP, wifi_config));
    ESP_LOGI(TAG, "AP iniciado: SSID=%s", wifi_config->ap.ssid);
}

void wifictl_ap_stop() {
    wifi_config_t cfg = { .ap = { .max_connection = 0 } };
    ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_AP, &cfg));
}

void wifictl_mgmt_ap_start() {
    wifi_config_t cfg = {
        .ap = {
            .ssid            = CONFIG_MGMT_AP_SSID,
            .ssid_len        = strlen(CONFIG_MGMT_AP_SSID),
            .password        = CONFIG_MGMT_AP_PASSWORD,
            .channel         = boot_channel,
            .max_connection  = CONFIG_MGMT_AP_MAX_CONNECTIONS,
            .authmode        = WIFI_AUTH_WPA2_PSK,
            .ssid_hidden     = 0,   /* visible por defecto */
        },
    };
    wifictl_ap_start(&cfg);
}

/**
 * @brief Alterna el AP entre visible y oculto (stealth mode).
 * @param hidden  true → AP oculto, false → AP visible
 */
void wifictl_set_stealth(bool hidden) {
    stealth_mode = hidden;
    wifi_config_t cfg = {
        .ap = {
            .ssid           = CONFIG_MGMT_AP_SSID,
            .ssid_len       = strlen(CONFIG_MGMT_AP_SSID),
            .password       = CONFIG_MGMT_AP_PASSWORD,
            .channel        = boot_channel,
            .max_connection = CONFIG_MGMT_AP_MAX_CONNECTIONS,
            .authmode       = WIFI_AUTH_WPA2_PSK,
            .ssid_hidden    = hidden ? 1 : 0,
        },
    };
    ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_AP, &cfg));
    ESP_LOGI(TAG, "Stealth mode: %s", hidden ? "ACTIVADO" : "DESACTIVADO");
}

void wifictl_sta_connect_to_ap(const wifi_ap_record_t *ap_record,
                                const char password[]) {
    if (!wifi_init) wifi_init_apsta();
    wifi_config_t cfg = {
        .sta = {
            .channel      = ap_record->primary,
            .scan_method  = WIFI_FAST_SCAN,
            .pmf_cfg.capable  = false,
            .pmf_cfg.required = false,
        },
    };
    memcpy(cfg.sta.ssid, ap_record->ssid, 32);
    if (password && strlen(password) < 64)
        memcpy(cfg.sta.password, password, strlen(password) + 1);
    ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_STA, &cfg));
    ESP_ERROR_CHECK(esp_wifi_connect());
}

void wifictl_sta_disconnect()           { esp_wifi_disconnect(); }
void wifictl_set_ap_mac(const uint8_t *m) { esp_wifi_set_mac(WIFI_IF_AP, m); }
void wifictl_get_ap_mac(uint8_t *m)     { esp_wifi_get_mac(WIFI_IF_AP, m); }
void wifictl_restore_ap_mac()           { esp_wifi_set_mac(WIFI_IF_AP, original_mac_ap); }
void wifictl_get_sta_mac(uint8_t *m)    { esp_wifi_get_mac(WIFI_IF_STA, m); }

void wifictl_set_channel(uint8_t ch) {
    if (ch == 0 || ch > 13) {
        ESP_LOGE(TAG, "Canal inválido: %u", ch);
        return;
    }
    esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
}
