/**
 * @file karma.h
 * @brief Karma Attack — responde probe requests con el SSID solicitado.
 *
 * Intercepta frames 802.11 Probe Request del sniffer y responde con un
 * Probe Response (y beacon) usando el mismo SSID buscado por el cliente,
 * forzándolo a asociarse al dispositivo como AP falso.
 *
 * Técnica clásica de "Karma" / MANA — SOLO PARA USO EN LABORATORIO AUTORIZADO.
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

/* ── Estado ─────────────────────────────────────────────────────────────── */
typedef enum {
    KARMA_IDLE    = 0,
    KARMA_RUNNING = 1
} karma_state_t;

/* ── Estadísticas ─────────────────────────────────────────────────────────── */
typedef struct {
    uint32_t probes_seen;     /**< Probe requests interceptados            */
    uint32_t responses_sent;  /**< Probe responses inyectados              */
    uint32_t unique_ssids;    /**< SSIDs distintos respondidos             */
    char     last_ssid[33];   /**< Último SSID respondido                  */
    uint8_t  last_client[6];  /**< MAC del último cliente respondido       */
} karma_stats_t;

/* ── API pública ─────────────────────────────────────────────────────────── */

/** Inicializar módulo (llamar en setup()). */
void karma_init(void);

/**
 * Iniciar Karma Attack.
 * El sniffer debe estar activo para que lleguen los probe requests.
 * @param channel   Canal WiFi en el que operar (1-13)
 * @return true si se inició correctamente.
 */
bool karma_start(uint8_t channel);

/** Detener Karma Attack. */
void karma_stop(void);

/** Estado actual. */
karma_state_t karma_get_state(void);

/** Estadísticas de la sesión (solo lectura). */
karma_stats_t karma_get_stats(void);

/**
 * Llamar desde frame_handler() del sniffer con cada frame de gestión.
 * Filtra internamente los Probe Requests y genera las respuestas.
 */
void karma_handle_mgmt(const uint8_t *payload, int len, uint8_t rssi);

#ifdef __cplusplus
}
#endif
