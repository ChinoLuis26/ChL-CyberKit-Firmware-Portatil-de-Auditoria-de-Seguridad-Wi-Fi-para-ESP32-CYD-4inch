/**
 * @file packet_monitor.h
 * @brief Monitor de paquetes en tiempo real — conteo por tipo y gráfica de pps.
 *
 * Se alimenta desde el frame_handler() del sniffer.
 * Calcula paquetes por segundo (pps) cada segundo y mantiene un ring buffer
 * de 40 muestras para la gráfica de tendencia en la CYD.
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
#define PMON_HISTORY_SIZE  40   /**< Muestras de pps en el ring buffer       */

/* ── Tipos de paquete contabilizados ─────────────────────────────────────── */
typedef struct {
    uint32_t beacon;       /**< Frames Beacon                               */
    uint32_t probe_req;    /**< Probe Requests                              */
    uint32_t probe_resp;   /**< Probe Responses                             */
    uint32_t assoc;        /**< Association Req + Resp                      */
    uint32_t deauth;       /**< Deauthentication                            */
    uint32_t disassoc;     /**< Disassociation                              */
    uint32_t data;         /**< Data frames (todos los subtipos)            */
    uint32_t mgmt_other;   /**< Otros frames de gestión                     */
    uint32_t total;        /**< Total de frames vistos                      */
    uint32_t pps;          /**< Paquetes por segundo (último segundo)       */
    uint16_t pps_history[PMON_HISTORY_SIZE]; /**< Ring buffer pps          */
    uint8_t  pps_idx;      /**< Índice actual del ring buffer               */
} pmon_stats_t;

/* ── API pública ─────────────────────────────────────────────────────────── */

/** Inicializar módulo (llamar en setup()). */
void pmon_init(void);

/** Llamar desde frame_handler() por cada paquete capturado. */
void pmon_handle_frame(const uint8_t *payload, int len);

/** Obtener estadísticas actuales (snapshot). */
pmon_stats_t pmon_get_stats(void);

/** Resetear todos los contadores. */
void pmon_reset(void);

/** Actualizar cálculo de pps (llamar desde loop() cada ~1000ms). */
void pmon_tick(void);

#ifdef __cplusplus
}
#endif
