/**
 * @file ota_manager.cpp
 * @brief Actualización de firmware OTA (Over-The-Air).
 *
 * @author Pedro Luis Rezabala Delgado — ChL-CyberKit v1.0 PRO
 * @copyright Copyright (C) 2026 Pedro Luis Rezabala Delgado. GPL v3.
 */
#include "ota_manager.h"
#include <ArduinoOTA.h>
#include "esp_log.h"

static const char *TAG      = "ota";
static kit_ota_state_t s_state  = KIT_OTA_IDLE;
static uint8_t     s_progress = 0;
static bool        s_inited = false;

void ota_manager_init(const char *hostname, const char *password) {
    if (s_inited) return;

    ArduinoOTA.setHostname(hostname ? hostname : "CyberKit");
    if (password && password[0]) {
        ArduinoOTA.setPassword(password);
    }

    ArduinoOTA.onStart([]() {
        s_state    = KIT_OTA_RECEIVING;
        s_progress = 0;
        ESP_LOGI(TAG, "OTA inicio — tipo: %s",
                 ArduinoOTA.getCommand() == U_FLASH ? "firmware" : "filesystem");
    });

    ArduinoOTA.onEnd([]() {
        s_state    = KIT_OTA_DONE;
        s_progress = 100;
        ESP_LOGI(TAG, "OTA completado — reiniciando…");
    });

    ArduinoOTA.onProgress([](unsigned int done, unsigned int total) {
        s_progress = (uint8_t)((done * 100UL) / total);
        ESP_LOGD(TAG, "OTA %u%%", s_progress);
    });

    ArduinoOTA.onError([](ota_error_t err) {
        s_state = KIT_OTA_ERROR;
        const char *reason = "desconocido";
        if      (err == OTA_AUTH_ERROR)    reason = "autenticación";
        else if (err == OTA_BEGIN_ERROR)   reason = "inicio";
        else if (err == OTA_CONNECT_ERROR) reason = "conexión";
        else if (err == OTA_RECEIVE_ERROR) reason = "recepción";
        else if (err == OTA_END_ERROR)     reason = "fin";
        ESP_LOGE(TAG, "Error OTA [%u]: %s", err, reason);
    });

    ArduinoOTA.begin();
    s_inited = true;
    ESP_LOGI(TAG, "OTA listo — host: %s", hostname ? hostname : "CyberKit");
}

void ota_manager_handle(void) {
    if (!s_inited) return;
    ArduinoOTA.handle();
}

kit_ota_state_t ota_get_state(void)    { return s_state;    }
uint8_t     ota_get_progress(void) { return s_progress; }
