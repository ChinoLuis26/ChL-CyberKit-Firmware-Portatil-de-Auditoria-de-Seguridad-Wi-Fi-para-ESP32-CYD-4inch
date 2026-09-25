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
 * @file auto_audit.h
 * @brief Modo de auditoría autónomo: escanea, prioriza targets,
 *        lanza ataques y guarda resultados de forma secuencial.
 *        SOLO PARA USO EN LABORATORIO AUTORIZADO.
 *
 * Flujo (estado):
 *   IDLE → SCANNING → ATTACKING → SAVING → (siguiente target) → DONE
 *
 * Prioridad de targets:
 *   1. Sin PMF + WPA2/3 + RSSI >= -85 dBm
 *   Skip automático de redes con PMF required.
 *   Timeout de seguridad: 65s por target.
 *
 * @author Pedro Luis Rezabala — ChL-CyberKit v1.0 PRO
 */
#pragma once
#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

/* ── Timeout de ataque por target ────────────────────────────────────────── */
#define AUTO_AUDIT_TIMEOUT_S   65

/* ── Estados del autómata ────────────────────────────────────────────────── */
typedef enum {
    AA_IDLE      = 0,
    AA_SCANNING  = 1,
    AA_ATTACKING = 2,
    AA_SAVING    = 3,
    AA_DONE      = 4
} auto_audit_state_t;

/* ── Informe de progreso (solo lectura) ───────────────────────────────────── */
typedef struct {
    auto_audit_state_t state;
    uint8_t  targets_total;    /* APs candidatos encontrados     */
    uint8_t  targets_done;     /* APs ya procesados              */
    uint8_t  captures;         /* Capturas exitosas              */
    uint8_t  skipped_pmf;      /* APs skipped por PMF required   */
    char     current_ssid[33]; /* SSID del target actual         */
    int8_t   current_rssi;
} auto_audit_status_t;

/* ── API pública ─────────────────────────────────────────────────────────── */

/** Inicializar módulo. Llamar una vez en setup(). */
void auto_audit_init(void);

/**
 * Iniciar el modo autónomo.
 * Ejecuta todo en una tarea FreeRTOS interna.
 * @return true si arrancó correctamente.
 */
bool auto_audit_start(void);

/** Detener el modo autónomo de forma segura. */
void auto_audit_stop(void);

/** Obtener el estado actual (snapshot). */
auto_audit_status_t auto_audit_get_status(void);

/** ¿Está en ejecución? */
bool auto_audit_is_running(void);

#ifdef __cplusplus
}
#endif
