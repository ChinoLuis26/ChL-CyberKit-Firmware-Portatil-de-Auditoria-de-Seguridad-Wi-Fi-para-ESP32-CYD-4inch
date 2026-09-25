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
 * @file evil_twin.h
 * @brief Módulo Evil Twin con DNS captive (UDP 53) y portal HTTP.
 *        SOLO PARA USO EN LABORATORIO AUTORIZADO.
 *
 * Flujo:
 *   1. evil_twin_start() → AP falso con SSID/canal del target, red OPEN
 *   2. DNS captive (task lwIP UDP:53): responde TODAS las queries con 10.10.10.26
 *   3. Deauth continuo al AP real (via attack_method_broadcast)
 *   4. Webserver sirve /portal (login falso) y /portal/submit (captura creds)
 *   5. Creds → /CyberKit/captures/creds.csv en SD
 *   6. evil_twin_stop() → restaura AP de gestión original
 *
 * @author Pedro Luis Rezabala — ChL-CyberKit v1.0 PRO
 */
#pragma once
#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

/* ── Estado del Evil Twin ────────────────────────────────────────────────── */
typedef enum {
    ET_IDLE      = 0,
    ET_RUNNING   = 1,
    ET_STOPPING  = 2
} evil_twin_state_t;

/* ── Configuración del target ────────────────────────────────────────────── */
typedef struct {
    char    ssid[33];
    uint8_t bssid[6];
    uint8_t channel;
} evil_twin_cfg_t;

/* ── API pública ─────────────────────────────────────────────────────────── */

/**
 * Iniciar el ataque Evil Twin.
 * @param cfg  Configuración del AP objetivo (SSID, BSSID, canal).
 * @return true si se inició correctamente.
 */
bool evil_twin_start(const evil_twin_cfg_t *cfg);

/** Detener el Evil Twin y restaurar el AP de gestión. */
void evil_twin_stop(void);

/** Estado actual del módulo. */
evil_twin_state_t evil_twin_get_state(void);

/** Número de credenciales capturadas en esta sesión. */
uint8_t evil_twin_cred_count(void);

/**
 * Manejar una petición HTTP al portal cautivo.
 * Llamar desde el webserver al recibir GET /portal.
 * @param req_uri  URI de la petición.
 * @param body     Cuerpo (para POST), puede ser NULL.
 * @param resp_buf Buffer para la respuesta HTML.
 * @param buf_size Tamaño del buffer.
 * @return Número de bytes escritos en resp_buf.
 */
int evil_twin_handle_http(const char *req_uri, const char *body,
                           char *resp_buf, int buf_size);

#ifdef __cplusplus
}
#endif
