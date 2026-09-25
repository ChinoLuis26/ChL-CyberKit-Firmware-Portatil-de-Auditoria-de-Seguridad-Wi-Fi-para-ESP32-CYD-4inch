/**
 * @file channel_hopper.h
 * @brief Channel Hopper — cicla automáticamente por los canales WiFi 1-13.
 *
 * Útil para maximizar la cobertura del Probe Logger, Packet Monitor y
 * Karma Attack sin fijar un canal concreto.
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

/* ── Configuración por defecto ────────────────────────────────────────────── */
#define CH_HOP_DEFAULT_DWELL_MS  200   /**< Tiempo en cada canal (ms) */
#define CH_HOP_MIN_DWELL_MS       50
#define CH_HOP_MAX_DWELL_MS     2000

/* ── Estado ─────────────────────────────────────────────────────────────── */
typedef enum {
    CH_HOP_IDLE    = 0,
    CH_HOP_RUNNING = 1
} ch_hop_state_t;

/* ── API pública ─────────────────────────────────────────────────────────── */

/** Inicializar módulo (llamar en setup()). */
void ch_hop_init(void);

/**
 * Iniciar el channel hopper.
 * @param dwell_ms  Tiempo en milisegundos por canal (50-2000).
 * @return true si se inició correctamente.
 */
bool ch_hop_start(uint16_t dwell_ms);

/** Detener el channel hopper. */
void ch_hop_stop(void);

/** Estado actual. */
ch_hop_state_t ch_hop_get_state(void);

/** Canal actualmente configurado en el radio. */
uint8_t ch_hop_current_channel(void);

/** Tiempo de permanencia configurado (ms). */
uint16_t ch_hop_get_dwell(void);

#ifdef __cplusplus
}
#endif
