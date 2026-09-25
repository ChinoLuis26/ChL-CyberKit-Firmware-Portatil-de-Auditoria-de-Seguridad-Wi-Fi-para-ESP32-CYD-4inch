/**
 * @file ota_manager.h
 * @brief Actualización de firmware OTA (Over-The-Air) por WiFi.
 *
 * Usa ArduinoOTA para aceptar actualizaciones via PlatformIO o esptool
 * mientras el dispositivo está en funcionamiento, conectado al AP de gestión.
 *
 * También expone un endpoint HTTP /api/ota para iniciar la actualización
 * desde el panel web.
 *
 * Uso con PlatformIO:
 *   pio run --target upload --upload-port 10.10.10.26
 *
 * @author Pedro Luis Rezabala Delgado — ChL-CyberKit v1.0 PRO
 * @copyright Copyright (C) 2026 Pedro Luis Rezabala Delgado. GPL v3.
 */
#pragma once
#include <Arduino.h>

/* ── Estado OTA ──────────────────────────────────────────────────────────── */
/* Prefijo KIT_ para evitar conflicto con ota_state_t de ArduinoOTA.h       */
typedef enum {
    KIT_OTA_IDLE       = 0,
    KIT_OTA_RECEIVING  = 1,
    KIT_OTA_DONE       = 2,
    KIT_OTA_ERROR      = 3
} kit_ota_state_t;

/* ── API pública ─────────────────────────────────────────────────────────── */

/** Inicializar ArduinoOTA. Llamar en setup() después de WiFi activo. */
void ota_manager_init(const char *hostname, const char *password);

/** Llamar en loop() — procesa eventos OTA pendientes. */
void ota_manager_handle(void);

/** Estado actual del OTA. */
kit_ota_state_t ota_get_state(void);

/** Progreso de la actualización (0-100). */
uint8_t ota_get_progress(void);
