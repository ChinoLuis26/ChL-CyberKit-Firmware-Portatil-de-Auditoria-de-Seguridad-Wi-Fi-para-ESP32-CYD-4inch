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
 * @file karma_attack.h
 * @brief Karma Attack: responde probe requests con el SSID solicitado
 *        para atraer dispositivos al AP cautivo.
 *        SOLO PARA USO EN LABORATORIO AUTORIZADO.
 *
 * Flujo:
 *   1. karma_attack_start() — activa el listener de probe requests
 *   2. Cada probe directed (SSID != "") recibe una Probe Response
 *      con el SSID solicitado, usando un BSSID aleatorio
 *   3. Si el dispositivo conecta, evil_twin lo redirige al portal
 *   4. karma_attack_stop() — desactiva el listener
 *
 * Requiere que el sniffer esté activo (promiscuous mode).
 * Integración: sniffer.c llama karma_attack_handle_mgmt() en frame_handler.
 *
 * @author Pedro Luis Rezabala — ChL-CyberKit v1.0 PRO
 */
#pragma once
#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

/* ── Estado ──────────────────────────────────────────────────────────────── */
typedef enum {
    KA_IDLE    = 0,
    KA_RUNNING = 1
} karma_state_t;

/* ── Estadísticas ────────────────────────────────────────────────────────── */
typedef struct {
    uint32_t probes_seen;      /**< Probe requests dirigidos vistos       */
    uint32_t responses_sent;   /**< Probe responses enviadas              */
    char     last_ssid[33];    /**< Último SSID solicitado                */
    uint8_t  last_sta[6];      /**< MAC del último dispositivo detectado  */
} karma_stats_t;

/* ── API pública ─────────────────────────────────────────────────────────── */

/** Iniciar el Karma Attack. */
bool karma_attack_start(void);

/** Detener el Karma Attack. */
void karma_attack_stop(void);

/** Estado actual. */
karma_state_t karma_attack_get_state(void);

/** Estadísticas de la sesión actual. */
karma_stats_t karma_attack_get_stats(void);

/**
 * Hook para el sniffer — llamar desde frame_handler() en sniffer.c.
 * Analiza el frame; si es un Probe Request dirigido, envía respuesta.
 * @param payload  Datos del frame 802.11 (sin radiotap)
 * @param len      Longitud en bytes
 */
void karma_attack_handle_mgmt(const uint8_t *payload, uint32_t len);

#ifdef __cplusplus
}
#endif
