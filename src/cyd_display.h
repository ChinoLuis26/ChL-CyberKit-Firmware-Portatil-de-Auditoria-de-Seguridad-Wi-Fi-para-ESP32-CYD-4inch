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
 * @file cyd_display.h
 * @brief Display TFT multipantalla v2 — ChL-CyberKit v1.0
 *
 * 6 pantallas navegables:
 *   [PANEL] [REDES] [HERRAM] [RIESGO] [ESTADO] [CONFIG]
 *
 * HERRAM (nuevo): control táctil de Beacon Flood, Evil Twin,
 *                 Karma Attack, Probe Sniffer y Auto Audit.
 *
 * @author Pedro Luis Rezabala — ChL-CyberKit v1.0 PRO
 */
#pragma once
#include <Arduino.h>

/* ── Paleta ──────────────────────────────────────────────────────────────── */
#define CL_BG     0x0000
#define CL_PANEL  0x0841
#define CL_PANEL2 0x0021
#define CL_HDR    0x0340
#define CL_GREEN  0x07E0
#define CL_DGRN   0x03E0
#define CL_TEXT   0xFFFF
#define CL_MUTED  0x7BEF
#define CL_YELLOW 0xFFE0
#define CL_RED    0xF800
#define CL_BLUE   0x001F
#define CL_CYAN   0x07FF
#define CL_ORANGE 0xFD20
#define CL_PURPLE 0x780F

/* ── LED RGB ─────────────────────────────────────────────────────────────── */
#define LED_R 22
#define LED_G 16
#define LED_B 17

/* ── Pantallas ───────────────────────────────────────────────────────────── */
typedef enum {
    SCR_DASHBOARD = 0,
    SCR_NETWORKS  = 1,
    SCR_TOOLS     = 2,   /* HERRAM — Beacon Flood / Evil Twin / Probe / Audit */
    SCR_AUDIT     = 3,
    SCR_STATUS    = 4,
    SCR_SETTINGS  = 5
} screen_t;

/* ── Estado ataque WiFi ───────────────────────────────────────────────────── */
typedef enum { DA_READY=0, DA_RUNNING=1, DA_FINISHED=2, DA_TIMEOUT=3 } disp_attack_state_t;
typedef enum { DT_NONE=-1, DT_PASSIVE=0, DT_HANDSHAKE=1, DT_PMKID=2, DT_DOS=3 } disp_attack_type_t;

/* ── Resultado del manejo de toque ──────────────────────────────────────── */
typedef struct {
    screen_t new_scr;

    /* ── Ataques WiFi (pantalla REDES) ── */
    bool stealth_tog;     ///< Stealth on/off
    bool calib_req;       ///< Calibrar touch (Config)
    bool scan_req;        ///< Escanear redes WiFi
    bool attack_req;      ///< Lanzar ataque WiFi
    bool reset_req;       ///< Detener ataque WiFi
    bool report_req;      ///< Guardar reporte HTML en SD
    uint8_t attack_ap;        ///< Índice AP seleccionado
    uint8_t attack_type;      ///< 0=Pasivo 1=HS 2=PMKID 3=DoS
    uint8_t attack_method;    ///< 0=RogueAP 1=Broadcast 2=Pasivo/Combine
    uint8_t attack_timeout;   ///< Timeout en segundos

    /* ── Herramientas (pantalla HERRAM) ── */
    bool bf_start_req;    ///< Iniciar Beacon Flood
    bool bf_stop_req;     ///< Detener Beacon Flood
    bool et_start_req;    ///< Iniciar Evil Twin (usa attack_ap)
    bool et_stop_req;     ///< Detener Evil Twin
    bool karma_start_req; ///< Iniciar Karma Attack
    bool karma_stop_req;  ///< Detener Karma Attack
    bool probe_sd_req;    ///< Volcar Probe Logger a SD
    bool probe_clear_req; ///< Limpiar tabla de Probe Logger
    bool audit_run_req;   ///< Iniciar/Detener Auto Audit
    uint8_t  bf_channel;  ///< Canal Beacon Flood (1-13)
    uint32_t bf_rate_ms;  ///< Intervalo Beacon Flood en ms
    uint8_t  karma_channel; ///< Canal Karma Attack (1-13, 0=auto)
} cyd_touch_t;

/* ── API pública ─────────────────────────────────────────────────────────── */

/** Inicializa TFT + LED. Calibra touch si no hay datos en NVS. */
void cyd_display_init(void);

/** Calibración interactiva de touch, guarda en NVS. */
void cyd_run_calibration(void);

/** Dibuja la pantalla indicada desde cero. */
void cyd_draw_screen(screen_t scr, bool stealth, bool sd_ok,
                     disp_attack_state_t state, disp_attack_type_t type,
                     unsigned long uptime_s, uint8_t clients,
                     uint16_t capture_count, const char *last_file);

/** Actualiza solo el bloque dinámico del estado de ataque. */
void cyd_update_attack(disp_attack_state_t state, disp_attack_type_t type, screen_t scr);

/** Actualiza uptime + clientes + capturas en pantalla activa. */
void cyd_update_info(unsigned long uptime_s, uint8_t clients, screen_t scr,
                     uint16_t capture_count);

/** Procesa toque y devuelve todos los eventos. */
cyd_touch_t cyd_handle_touch(screen_t cur, bool stealth_on, bool atk_running);

/** Ajusta el LED RGB según estado del ataque. */
void cyd_led(disp_attack_state_t state);
