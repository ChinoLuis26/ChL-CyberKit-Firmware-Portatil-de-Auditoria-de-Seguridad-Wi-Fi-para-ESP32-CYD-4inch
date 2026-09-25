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
 * @file beacon_flood.h
 * @brief Inundación de beacons con SSIDs aleatorios (confusión de entorno).
 *        Utiliza esp_wifi_80211_tx() para inyección de frames raw.
 *        SOLO PARA USO EN LABORATORIO AUTORIZADO.
 *
 * @author Pedro Luis Rezabala — ChL-CyberKit v1.0 PRO
 */
#pragma once
#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

/* ── Configuración por defecto ────────────────────────────────────────────── */
#define BEACON_FLOOD_DEFAULT_RATE_MS   20   /* Intervalo entre beacons (ms) */
#define BEACON_FLOOD_DEFAULT_CHANNEL    1   /* Canal de operación           */

/* ── Estado ─────────────────────────────────────────────────────────────── */
typedef enum {
    BF_IDLE    = 0,
    BF_RUNNING = 1
} beacon_flood_state_t;

/* ── API pública ─────────────────────────────────────────────────────────── */

/**
 * Iniciar el flood de beacons.
 * @param channel   Canal WiFi (1-13)
 * @param rate_ms   Intervalo entre inyecciones en milisegundos
 * @return true si se inició correctamente
 */
bool beacon_flood_start(uint8_t channel, uint32_t rate_ms);

/** Detener el flood y liberar recursos. */
void beacon_flood_stop(void);

/** Estado actual. */
beacon_flood_state_t beacon_flood_get_state(void);

/** Número de beacons inyectados en la sesión actual. */
uint32_t beacon_flood_count(void);

#ifdef __cplusplus
}
#endif
