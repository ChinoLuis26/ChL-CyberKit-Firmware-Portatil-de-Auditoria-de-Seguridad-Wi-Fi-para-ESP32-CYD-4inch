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
 * @file probe_logger.h
 * @brief Captura y registro de Probe Requests 802.11.
 *        Identifica dispositivos por MAC (OUI) y los SSIDs que buscan.
 *
 * @author Pedro Luis Rezabala — ChL-CyberKit v1.0 PRO
 */
#pragma once
#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "esp_wifi_types.h"

/* ── Configuración ───────────────────────────────────────────────────────── */
#define PROBE_MAX_DEVICES   30   /* Máximo de dispositivos distintos en RAM   */
#define PROBE_MAX_SSIDS      8   /* SSIDs distintos por dispositivo           */
#define PROBE_SSID_LEN      33   /* Longitud máxima de SSID + '\0'            */

/* ── Estructura de un dispositivo que hace probe ─────────────────────────── */
typedef struct {
    uint8_t  mac[6];
    char     ssids[PROBE_MAX_SSIDS][PROBE_SSID_LEN]; /* SSIDs solicitados    */
    uint8_t  ssid_count;
    int8_t   rssi_last;
    uint32_t count;          /* Total de probes de este dispositivo           */
    uint32_t last_seen;      /* millis() de la última vez que se vio          */
    char     vendor[24];     /* Nombre del fabricante (OUI lookup)            */
} probe_device_t;

/* ── API pública ─────────────────────────────────────────────────────────── */

/** Inicializa el logger. Llamar una vez en setup(). */
void probe_logger_init(void);

/**
 * Procesar un frame de gestión capturado en modo promiscuo.
 * Filtrar solo los de tipo Probe Request (subtype 0x04).
 * @param frame  Puntero al paquete promiscuo completo
 */
void probe_logger_handle_mgmt(const wifi_promiscuous_pkt_t *frame);

/** Número de dispositivos distintos observados. */
uint8_t probe_logger_device_count(void);

/**
 * Obtener el dispositivo por índice (0 … device_count-1).
 * Devuelve NULL si el índice es inválido.
 */
const probe_device_t *probe_logger_get_device(uint8_t idx);

/** Limpiar todos los registros. */
void probe_logger_clear(void);

/**
 * Volcar todos los registros al log de SD (audit.csv).
 * No hace nada si la SD no está disponible.
 */
void probe_logger_dump_to_sd(void);

#ifdef __cplusplus
}
#endif
