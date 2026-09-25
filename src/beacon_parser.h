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
 * @file beacon_parser.h
 * @brief Parseo de IEs en beacons 802.11:
 *         - WPS (Tag 221, OUI 00:50:F2:04)
 *         - PMF / MFP (RSN Capabilities bits 6-7)
 *         - Clientes asociados (data frames ToDS/FromDS)
 *
 * @author Pedro Luis Rezabala — ChL-CyberKit v1.0 PRO
 */
#pragma once
#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include "esp_wifi_types.h"

/* ── Configuración ───────────────────────────────────────────────────────── */
#define BP_MAX_APS       20    /* Máx. APs en tabla (= CONFIG_SCAN_MAX_AP)   */
#define BP_MAX_CLIENTS    8    /* Máx. clientes por AP (reduce BSS ~13 KB)   */
#define BP_SSID_LEN      33

/* ── Info de AP parseada desde sus beacons ───────────────────────────────── */
typedef struct {
    uint8_t  bssid[6];
    char     ssid[BP_SSID_LEN];
    uint8_t  channel;
    int8_t   rssi;
    bool     wps_enabled;    /* Anunciado vía IE 221 OUI 00:50:F2:04        */
    bool     pmf_capable;    /* RSN Caps bit 6                               */
    bool     pmf_required;   /* RSN Caps bit 7                               */
    uint8_t  client_macs[BP_MAX_CLIENTS][6];
    uint8_t  client_count;
    uint32_t last_seen;      /* ms desde boot                                */
} bp_ap_info_t;

/* ── API pública ─────────────────────────────────────────────────────────── */

/** Inicializar. Llamar una vez en setup(). */
void beacon_parser_init(void);

/**
 * Procesar un frame de gestión (Beacon / Probe Response).
 * @param frame Puntero al paquete promiscuo.
 */
void beacon_parser_handle_mgmt(const wifi_promiscuous_pkt_t *frame);

/**
 * Anotar un cliente asociado a un AP (extraído de data frames).
 * @param ap_bssid  BSSID del AP (ToDS: addr1; FromDS: addr2)
 * @param client_mac MAC del cliente
 */
void beacon_parser_note_client(const uint8_t *ap_bssid, const uint8_t *client_mac);

/** Número de APs en tabla. */
uint8_t beacon_parser_ap_count(void);

/**
 * Obtener AP por índice.
 * @return puntero a bp_ap_info_t (solo lectura) o NULL si fuera de rango.
 */
const bp_ap_info_t *beacon_parser_get_ap(uint8_t idx);

/**
 * Buscar AP por BSSID.
 * @return puntero o NULL si no encontrado.
 */
const bp_ap_info_t *beacon_parser_find_ap(const uint8_t *bssid);

/** Limpiar toda la tabla. */
void beacon_parser_clear(void);

#ifdef __cplusplus
}
#endif
