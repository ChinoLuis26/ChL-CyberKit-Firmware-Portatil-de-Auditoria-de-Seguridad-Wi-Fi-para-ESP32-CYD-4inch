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
 * @file ble_scanner.h
 * @brief Escáner BLE pasivo — lista dispositivos Bluetooth Low Energy
 *        cercanos con MAC, nombre, RSSI y tipo de dirección.
 *
 * Implementado en ble_scanner.cpp (Arduino BLE API).
 * El ESP32 soporta coexistencia WiFi + BLE por hardware.
 *
 * @author Pedro Luis Rezabala — ChL-CyberKit v1.0 PRO
 */
#pragma once
#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

/* ── Límites ─────────────────────────────────────────────────────────────── */
#define BLE_MAX_DEVICES  24

/* ── Estado ──────────────────────────────────────────────────────────────── */
typedef enum {
    BLE_IDLE    = 0,
    BLE_RUNNING = 1
} ble_state_t;

/* ── Tipo de dirección BLE ───────────────────────────────────────────────── */
typedef enum {
    BLE_ADDR_PUBLIC  = 0,
    BLE_ADDR_RANDOM  = 1,
} ble_addr_type_t;

/* ── Descriptor de un dispositivo BLE ───────────────────────────────────── */
typedef struct {
    uint8_t  addr[6];           /**< MAC address (little-endian)           */
    int8_t   rssi;              /**< RSSI en dBm                           */
    char     name[33];          /**< Nombre del dispositivo (vacío si N/A) */
    uint8_t  addr_type;         /**< BLE_ADDR_PUBLIC / BLE_ADDR_RANDOM     */
    bool     connectable;       /**< true si el dispositivo es conectable  */
    uint16_t appearance;        /**< BLE Appearance value (0 si no tiene)  */
    uint8_t  seen_count;        /**< Nº de veces detectado                 */
} ble_device_t;

/* ── API pública ─────────────────────────────────────────────────────────── */

/** Iniciar el escaneo BLE pasivo continuo. */
bool ble_scanner_start(void);

/** Detener el escaneo. */
void ble_scanner_stop(void);

/** Estado actual. */
ble_state_t ble_scanner_get_state(void);

/** Número de dispositivos únicos detectados. */
uint8_t ble_scanner_device_count(void);

/** Obtener dispositivo por índice (0 .. count-1). NULL si fuera de rango. */
const ble_device_t* ble_scanner_get_device(uint8_t idx);

/** Limpiar la tabla de dispositivos. */
void ble_scanner_clear(void);

#ifdef __cplusplus
}
#endif
