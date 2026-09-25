/**
 * @file ssid_list.h
 * @brief Gestión de lista de SSIDs personalizados para Beacon Flood.
 *
 * Carga una lista de SSIDs desde /CyberKit/ssids.txt en la SD card
 * (un SSID por línea, máx. 32 chars). Si no existe el archivo, usa
 * SSIDs aleatorios como el comportamiento por defecto de beacon_flood.
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

#define SSID_LIST_MAX      128  /**< Máximo de SSIDs en la lista     */
#define SSID_LIST_PATH     "/CyberKit/ssids.txt"

/* ── API pública ─────────────────────────────────────────────────────────── */

/** Inicializar (carga desde SD si está disponible). */
void ssid_list_init(void);

/**
 * Cargar lista desde la SD card.
 * @return Número de SSIDs cargados (0 si falla o no existe el archivo).
 */
uint16_t ssid_list_load_from_sd(void);

/** Número de SSIDs en la lista. */
uint16_t ssid_list_count(void);

/**
 * Obtener SSID por índice.
 * @param idx  Índice (0-based).
 * @return Puntero a la cadena, o NULL si fuera de rango.
 */
const char *ssid_list_get(uint16_t idx);

/** Añadir un SSID manualmente (hasta SSID_LIST_MAX). */
bool ssid_list_add(const char *ssid);

/** Limpiar la lista. */
void ssid_list_clear(void);

/**
 * Guardar lista actual en la SD card.
 * @return true si se guardó correctamente.
 */
bool ssid_list_save_to_sd(void);

#ifdef __cplusplus
}
#endif
