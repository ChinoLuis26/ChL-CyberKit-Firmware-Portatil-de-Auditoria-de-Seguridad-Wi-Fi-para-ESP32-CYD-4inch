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
 * @file ble_scanner.cpp
 * @brief Escáner BLE pasivo usando Arduino BLE API (NimBLE backend).
 * @author Pedro Luis Rezabala — ChL-CyberKit v1.0 PRO
 *
 * Coexistencia WiFi+BLE: ESP32 lo maneja por hardware con TDMA.
 * Se usa escaneo pasivo (sin scan request) para no emitir paquetes.
 */

#include "ble_scanner.h"

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#include <BLEDevice.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>

#include <string.h>

static const char *TAG = "ble_scan";

/* ── Estado global ───────────────────────────────────────────────────────── */
static ble_device_t      s_devices[BLE_MAX_DEVICES];
static uint8_t           s_count   = 0;
static volatile ble_state_t s_state = BLE_IDLE;
static SemaphoreHandle_t s_mutex   = NULL;
static BLEScan          *s_scanner = NULL;
static bool              s_inited  = false;

/* ── Callback de dispositivos advertised ─────────────────────────────────── */
class KitBLECallback : public BLEAdvertisedDeviceCallbacks {
public:
    void onResult(BLEAdvertisedDevice dev) override {
        if (s_state != BLE_RUNNING) return;
        if (xSemaphoreTake(s_mutex, pdMS_TO_TICKS(20)) != pdTRUE) return;

        /* getNative() retorna uint8_t(*)[6]; cast a uint8_t* para memcmp/memcpy */
        const uint8_t *raw = (const uint8_t *)dev.getAddress().getNative();

        /* ── Buscar si ya está en la tabla ─── */
        for (int i = 0; i < (int)s_count; i++) {
            if (memcmp(s_devices[i].addr, raw, 6) == 0) {
                s_devices[i].rssi = dev.getRSSI();
                if (s_devices[i].seen_count < 0xFF) s_devices[i].seen_count++;
                /* Actualizar nombre si antes no tenía y ahora sí */
                if (s_devices[i].name[0] == '\0' && dev.haveName()) {
                    strncpy(s_devices[i].name, dev.getName().c_str(), 32);
                }
                xSemaphoreGive(s_mutex);
                return;
            }
        }

        /* ── Dispositivo nuevo ─── */
        if (s_count >= BLE_MAX_DEVICES) {
            xSemaphoreGive(s_mutex);
            return;
        }

        ble_device_t *d = &s_devices[s_count++];
        memset(d, 0, sizeof(*d));

        memcpy(d->addr, raw, 6);
        d->rssi        = dev.getRSSI();
        /* isConnectable() no existe en la BLE API estándar del ESP32 (solo NimBLE).
         * Por defecto true — la mayoría de periféricos BLE son conectables. */
        d->connectable = true;
        d->addr_type   = (uint8_t)dev.getAddressType();
        d->seen_count  = 1;

        if (dev.haveName()) {
            strncpy(d->name, dev.getName().c_str(), 32);
        }
        if (dev.haveAppearance()) {
            d->appearance = dev.getAppearance();
        }

        xSemaphoreGive(s_mutex);

        ESP_LOGI(TAG, "[BLE] %02X:%02X:%02X:%02X:%02X:%02X '%s' %ddBm %s",
                 d->addr[5], d->addr[4], d->addr[3],
                 d->addr[2], d->addr[1], d->addr[0],
                 d->name[0] ? d->name : "?",
                 d->rssi,
                 d->connectable ? "CONN" : "ADVT");
    }
};

static KitBLECallback s_cb;

/* ── API pública ─────────────────────────────────────────────────────────── */

bool ble_scanner_start(void)
{
    if (s_state == BLE_RUNNING) return true;

    if (!s_mutex) {
        s_mutex = xSemaphoreCreateMutex();
        if (!s_mutex) return false;
    }

    if (!s_inited) {
        BLEDevice::init("");   /* nombre vacío — solo escaneo pasivo */
        s_inited = true;
    }

    s_scanner = BLEDevice::getScan();
    s_scanner->setAdvertisedDeviceCallbacks(&s_cb, /*wantDuplicates=*/false);
    s_scanner->setActiveScan(false);  /* pasivo: no envía scan requests */
    s_scanner->setInterval(160);      /* 160 × 0.625ms = 100ms ventana  */
    s_scanner->setWindow(150);        /* 150 × 0.625ms ≈ 94ms activo    */

    s_state = BLE_RUNNING;

    /* Escaneo continuo (duración=0 → infinito) */
    bool ok = s_scanner->start(0, nullptr, false);
    if (!ok) {
        s_state = BLE_IDLE;
        ESP_LOGE(TAG, "Error al iniciar BLE scan");
        return false;
    }

    ESP_LOGI(TAG, "BLE scan iniciado (pasivo)");
    return true;
}

void ble_scanner_stop(void)
{
    if (s_state == BLE_IDLE) return;
    if (s_scanner) s_scanner->stop();
    s_state = BLE_IDLE;
    ESP_LOGI(TAG, "BLE scan detenido | dispositivos=%u", s_count);
}

ble_state_t ble_scanner_get_state(void) { return s_state; }

uint8_t ble_scanner_device_count(void) { return s_count; }

const ble_device_t *ble_scanner_get_device(uint8_t idx)
{
    if (idx >= s_count) return NULL;
    return &s_devices[idx];
}

void ble_scanner_clear(void)
{
    if (!s_mutex) return;
    if (xSemaphoreTake(s_mutex, pdMS_TO_TICKS(200)) == pdTRUE) {
        memset(s_devices, 0, sizeof(s_devices));
        s_count = 0;
        xSemaphoreGive(s_mutex);
        ESP_LOGI(TAG, "Tabla BLE limpiada");
    }
}
