/**
 * @file ble_manager.h
 * @brief Gestor BLE — Scanner de dispositivos + Spam de anuncios de proximidad.
 *
 * BLE Scanner: detecta dispositivos Bluetooth Low Energy en el entorno,
 * extrae MAC, nombre, RSSI y tipo de dispositivo.
 *
 * BLE Spam: inyecta anuncios de proximidad falsos de distintas marcas
 * (Apple AirDrop/AirPods, Android FastPair, Windows Swift Pair, Samsung)
 * similares a lo que hace Bruce Firmware y Flipper Zero.
 *
 * SOLO PARA USO EN LABORATORIO AUTORIZADO.
 *
 * @author Pedro Luis Rezabala Delgado — ChL-CyberKit v1.0 PRO
 * @copyright Copyright (C) 2026 Pedro Luis Rezabala Delgado. GPL v3.
 */
#pragma once
#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

/* ── Configuración ───────────────────────────────────────────────────────── */
#define BLE_SCAN_MAX_DEVICES   24   /**< Máximo de dispositivos en tabla     */
#define BLE_SPAM_INTERVAL_MS  100   /**< Intervalo entre anuncios spam (ms)  */

/* ── Tipo de spam ────────────────────────────────────────────────────────── */
typedef enum {
    BLE_SPAM_APPLE_AIRDROP   = 0,
    BLE_SPAM_APPLE_AIRPODS   = 1,
    BLE_SPAM_ANDROID_PAIR    = 2,
    BLE_SPAM_WINDOWS_SWIFT   = 3,
    BLE_SPAM_SAMSUNG_PAIR    = 4,
    BLE_SPAM_ALL             = 5   /**< Alterna entre todos (modo caos)      */
} ble_spam_type_t;

/* ── Estado ─────────────────────────────────────────────────────────────── */
typedef enum {
    BLE_IDLE       = 0,
    BLE_SCANNING   = 1,
    BLE_SPAMMING   = 2
} ble_state_t;

/* ── Dispositivo BLE ─────────────────────────────────────────────────────── */
typedef struct {
    uint8_t  addr[6];     /**< Dirección MAC BLE                            */
    char     name[32];    /**< Nombre del dispositivo (si anuncia)          */
    int8_t   rssi;        /**< RSSI en dBm                                  */
    uint8_t  addr_type;   /**< 0=public, 1=random                          */
    char     type_str[16];/**< "Apple", "Android", "Windows", "Generic"... */
    uint32_t last_seen;   /**< millis() de la última detección              */
} ble_device_t;

/* ── API pública — Scanner ───────────────────────────────────────────────── */

/** Inicializar módulo BLE (llamar en setup()). */
bool ble_manager_init(void);

/** Iniciar escaneo pasivo de dispositivos BLE. */
bool ble_scan_start(void);

/** Detener escaneo. */
void ble_scan_stop(void);

/** Número de dispositivos detectados. */
uint8_t ble_scan_device_count(void);

/** Obtener dispositivo por índice (NULL si fuera de rango). */
const ble_device_t *ble_scan_get_device(uint8_t idx);

/** Limpiar tabla de dispositivos. */
void ble_scan_clear(void);

/* ── API pública — Spam ──────────────────────────────────────────────────── */

/**
 * Iniciar spam de anuncios BLE.
 * @param type  Tipo de spam (marca o BLE_SPAM_ALL para rotar).
 * @return true si se inició.
 */
bool ble_spam_start(ble_spam_type_t type);

/** Detener spam. */
void ble_spam_stop(void);

/** Número de anuncios enviados en la sesión actual. */
uint32_t ble_spam_count(void);

/* ── Estado unificado ────────────────────────────────────────────────────── */
ble_state_t ble_get_state(void);

#ifdef __cplusplus
}
#endif
