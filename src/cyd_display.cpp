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
 * @file cyd_display.cpp
 * @brief Display TFT multipantalla v2 — ChL-CyberKit v1.0
 *
 * 6 pantallas navegables:
 *   [PANEL] [REDES] [HERRAM] [RIESGO] [ESTADO] [CONFIG]
 *
 * HERRAM (nuevo): control táctil de Beacon Flood, Evil Twin,
 *                 Probe Sniffer y Auto Audit.
 *
 * REDES mejorado: vendor OUI en cada fila de red.
 * PANEL mejorado: fila de estado de herramientas.
 *
 * @author Pedro Luis Rezabala — ChL-CyberKit v1.0 PRO
 */
#include "cyd_display.h"
#include "wifi_audit.h"
#include "ap_scanner.h"
#include "beacon_flood.h"
#include "evil_twin.h"
#include "karma.h"
#include "probe_logger.h"
#include "auto_audit.h"
#include "oui_lookup.h"
#include <TFT_eSPI.h>
#include <Preferences.h>

static TFT_eSPI   tft  = TFT_eSPI();
static Preferences prefs;

/* ─── Layout ─────────────────────────────────────────────────────────────── */
static const int W     = 320;
static const int HDR   = 50;
static const int NAV   = 70;
static const int CY    = HDR;
static const int CH    = 480 - HDR - NAV;   // 360
static const int NAV_Y = 480 - NAV;         // 410
static const int TAB_W = W / 6;             // 53  (6 tabs)

/* ─── Estado pantalla REDES ─────────────────────────────────────────────── */
static int  net_scroll   = 0;
static int  net_selected = -1;
static uint8_t atk_type    = 1;
static uint8_t atk_method  = 0;
static uint8_t atk_timeout = 60;

/* ─── Estado pantalla HERRAM ────────────────────────────────────────────── */
static uint8_t  bf_ch       = 6;
static uint8_t  bf_rate_idx = 2;
static const uint32_t BF_RATES[] = {20, 50, 100, 200, 500};
static const uint8_t  BF_RATE_N  = 5;
static uint8_t  ka_ch       = 6;  ///< Canal Karma (1-13)

/* ─── Constantes REDES ───────────────────────────────────────────────────── */
static const int NET_ROWS  = 5;
static const int NET_ROW_H = 40;
static const int NET_Y     = CY + 26;
static const int NET_H     = NET_ROWS * NET_ROW_H;   // 200

static const int TARGET_Y   = CY + 228;
static const int TARGET_H   = 26;
static const int ATYPE_Y    = CY + 258;
static const int ATYPE_H    = 36;
static const int METHOD_Y   = CY + 298;
static const int METHOD_H   = 22;
static const int CTRL_Y     = CY + 324;
static const int CTRL_H     = 36;

/* ─── Constantes CONFIG ──────────────────────────────────────────────────── */
static const int BTN_ST_X  = 12, BTN_ST_Y  = CY+50,  BTN_ST_W  = 210, BTN_ST_H  = 36;
static const int BTN_CAL_X = 12, BTN_CAL_Y = CY+100, BTN_CAL_W = 210, BTN_CAL_H = 36;
static const int BTN_RPT_X = 12, BTN_RPT_Y = CY+150, BTN_RPT_W = 210, BTN_RPT_H = 36;

/* ─── Constantes HERRAM ──────────────────────────────────────────────────── */
//  5 paneles dentro del área de contenido (360px):
//  BF:    CY+2   h=82  → termina CY+84
//  ET:    CY+88  h=82  → termina CY+170
//  KA:    CY+174 h=60  → termina CY+234
//  Probe: CY+238 h=66  → termina CY+304
//  AA:    CY+308 h=48  → termina CY+356
static const int BF_PY = CY + 2;
static const int ET_PY = CY + 88;
static const int KA_PY = CY + 174;
static const int PR_PY = CY + 238;
static const int AA_PY = CY + 308;

/* ─── Helpers ────────────────────────────────────────────────────────────── */
static void fillContent(uint32_t col = CL_BG) {
    tft.fillRect(0, CY, W, CH, col);
}
static void lbl(int x, int y, const char *t, uint32_t fg, uint8_t font = 1,
                uint32_t bg = TFT_TRANSPARENT) {
    bg == TFT_TRANSPARENT ? tft.setTextColor(fg, TFT_TRANSPARENT)
                          : tft.setTextColor(fg, bg);
    tft.setTextFont(font); tft.setCursor(x, y); tft.print(t);
}
static void lbl_c(int y, const char *t, uint32_t fg, uint8_t font = 1) {
    tft.setTextColor(fg, TFT_TRANSPARENT);
    tft.setTextFont(font);
    tft.setTextDatum(MC_DATUM);
    tft.drawString(t, W/2, y);
    tft.setTextDatum(TL_DATUM);
}
static void pnl(int y, int h, int m = 4, uint32_t c = CL_PANEL) {
    tft.fillRoundRect(m, y, W-2*m, h, 6, c);
}
static void btn(int x, int y, int w, int h, const char *label,
                uint32_t bg, uint32_t fg = 0x0000, uint8_t font = 2) {
    tft.fillRoundRect(x, y, w, h, 6, bg);
    tft.setTextColor(fg, bg);
    tft.setTextFont(font);
    tft.setTextDatum(MC_DATUM);
    tft.drawString(label, x + w/2, y + h/2);
    tft.setTextDatum(TL_DATUM);
}

/* Pastilla de estado coloreada (pill) */
static void pill(int x, int y, int w, int h, const char *txt, uint32_t bg) {
    tft.fillRoundRect(x, y, w, h, 4, bg);
    tft.setTextColor(0x0000, bg);
    tft.setTextFont(1);
    tft.setTextDatum(MC_DATUM);
    tft.drawString(txt, x+w/2, y+h/2);
    tft.setTextDatum(TL_DATUM);
}

/* ─── Helpers de texto ───────────────────────────────────────────────────── */
static const char *atk_state_str(disp_attack_state_t s) {
    switch(s){ case DA_RUNNING:  return "EN CURSO";
               case DA_FINISHED: return "TERMINADO";
               case DA_TIMEOUT:  return "TIMEOUT";
               default:          return "LISTO"; }
}
static uint32_t atk_state_col(disp_attack_state_t s) {
    switch(s){ case DA_RUNNING:  return CL_ORANGE;
               case DA_FINISHED: return CL_BLUE;
               case DA_TIMEOUT:  return CL_RED;
               default:          return CL_GREEN; }
}
static const char *atk_type_str(disp_attack_type_t t) {
    switch(t){ case DT_PASSIVE:   return "Pasivo";
               case DT_HANDSHAKE: return "Handshake";
               case DT_PMKID:     return "PMKID";
               case DT_DOS:       return "DoS";
               default:           return "---"; }
}
static const char *auth_str(uint8_t a) {
    switch(a){ case 0: return "OPEN"; case 1: return "WEP";
               case 2: return "WPA";  case 3: return "WPA2";
               case 4: return "WPA/2";case 6: return "WPA3";
               default: return "?"; }
}
static uint32_t auth_col(uint8_t a) {
    if (a==0||a==1) return CL_RED;
    if (a==2) return CL_YELLOW;
    return CL_GREEN;
}
static const char *method_label(uint8_t m) {
    if (atk_type == 0) return "N/A";
    if (atk_type == 1 || atk_type == 2) {
        switch(m){ case 0: return "Rogue AP"; case 1: return "Broadcast"; default: return "Pasivo"; }
    }
    switch(m){ case 0: return "Rogue AP"; case 1: return "Broadcast"; default: return "Combinar"; }
}
static uint8_t method_max() {
    if (atk_type == 0) return 0;
    return 2;
}
static uint8_t default_timeout(uint8_t type) {
    switch(type){ case 0: return 60; case 1: return 60;
                  case 2: return 10; case 3: return 120; default: return 60; }
}

/* ─── Header y Nav ───────────────────────────────────────────────────────── */
static void draw_header() {
    tft.fillRect(0, 0, W, HDR, CL_HDR);
    lbl(10, 8,  "ChL-CyberKit", CL_GREEN, 4, CL_HDR);
    lbl(10, 36, "v1.0  by Pedro Luis Rezabala", CL_MUTED, 1, CL_HDR);
    tft.fillCircle(W-14, 16, 5, CL_GREEN);
}

static void draw_nav(screen_t active) {
    tft.fillRect(0, NAV_Y, W, NAV, 0x0821);
    const char *lbs[] = {"PANEL","REDES","HERRAM","RIESGO","ESTADO","CONFIG"};
    for (int i = 0; i < 6; i++) {
        int x0 = i * TAB_W;
        int tw = (i == 5) ? W - x0 : TAB_W;   // último tab toma el resto
        bool sel = (i == (int)active);
        uint32_t bg = sel ? CL_GREEN : 0x0821;
        uint32_t fg = sel ? 0x0000   : CL_MUTED;
        tft.fillRect(x0+2, NAV_Y+4, tw-4, NAV-8, bg);
        tft.setTextColor(fg, bg); tft.setTextFont(1);
        tft.setTextDatum(MC_DATUM);
        tft.drawString(lbs[i], x0 + tw/2, NAV_Y + NAV/2);
        tft.setTextDatum(TL_DATUM);
        if (i < 5) tft.drawFastVLine(x0+TAB_W, NAV_Y+8, NAV-16, 0x18C3);
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  PANTALLA 0 — DASHBOARD  (con fila de estado de herramientas)
 * ═════════════════════════════════════════════════════════════════════════ */
static void draw_dashboard(bool stealth, bool sd_ok,
                            disp_attack_state_t state, disp_attack_type_t type,
                            unsigned long uptime_s, uint8_t clients, uint16_t cap_count) {
    fillContent();

    /* ── Panel 1: Red de Gestión (compactado a 90px) ── */
    pnl(CY+2, 90);
    lbl(14, CY+10,  "RED DE GESTION", CL_DGRN, 1, CL_PANEL);
    lbl(14, CY+26,  "SSID :", CL_MUTED, 1, CL_PANEL);
    lbl(72, CY+24,  CONFIG_MGMT_AP_SSID, CL_GREEN, 2, CL_PANEL);
    lbl(14, CY+46,  "PASS :", CL_MUTED, 1, CL_PANEL);
    lbl(72, CY+44,  CONFIG_MGMT_AP_PASSWORD, CL_TEXT, 2, CL_PANEL);
    lbl(14, CY+66,  "IP   :", CL_MUTED, 1, CL_PANEL);
    lbl(72, CY+64,  "10.10.10.26", CL_CYAN, 2, CL_PANEL);
    uint32_t sc = stealth ? CL_RED : CL_DGRN;
    tft.fillRoundRect(216, CY+22, 94, 18, 4, sc);
    tft.setTextColor(0x0000, sc); tft.setTextFont(1); tft.setTextDatum(MC_DATUM);
    tft.drawString(stealth?"STEALTH ON":"STEALTH OFF", 263, CY+31);
    tft.setTextDatum(TL_DATUM);

    /* ── Panel 2: Operación ── */
    pnl(CY+96, 50);
    char ut[16]; unsigned long h=uptime_s/3600,m=(uptime_s%3600)/60,s=uptime_s%60;
    if(uptime_s<86400) snprintf(ut,16,"%02lu:%02lu:%02lu",h,m,s);
    else snprintf(ut,16,"%lud%02lu:%02lu",uptime_s/86400,h%24,m);
    char cb[4]; snprintf(cb,4,"%d",clients);
    char capb[8]; snprintf(capb,8,"%d",cap_count);
    lbl(14, CY+104, "OPERACION",CL_DGRN,1,CL_PANEL);
    lbl(14, CY+118, "Uptime:",CL_MUTED,1,CL_PANEL); lbl(72,CY+116,ut,CL_TEXT,2,CL_PANEL);
    lbl(192,CY+118, "Cli:",CL_MUTED,1,CL_PANEL);    lbl(222,CY+116,cb,clients>0?CL_GREEN:CL_MUTED,2,CL_PANEL);
    lbl(270,CY+118, "Caps:",CL_MUTED,1,CL_PANEL);   lbl(14,CY+136,capb,CL_TEXT,1,CL_PANEL);
    lbl(40, CY+136, "SD:",CL_MUTED,1,CL_PANEL);     lbl(60,CY+136,sd_ok?"OK":"---",sd_ok?CL_GREEN:CL_RED,1,CL_PANEL);
    lbl(90, CY+136, "capturas:",CL_MUTED,1,CL_PANEL); lbl(162,CY+136,capb,CL_TEXT,1,CL_PANEL);

    /* ── Panel 3: Último ataque WiFi ── */
    pnl(CY+150, 52);
    lbl(14,CY+158,"ULTIMO ATAQUE",CL_DGRN,1,CL_PANEL);
    uint32_t col = atk_state_col(state);
    tft.fillRoundRect(14,CY+170,110,24,5,col);
    tft.setTextColor(0x0000,col); tft.setTextFont(2); tft.setTextDatum(MC_DATUM);
    tft.drawString(atk_state_str(state),69,CY+182); tft.setTextDatum(TL_DATUM);
    lbl(136,CY+176,atk_type_str(type),CL_TEXT,2,CL_PANEL);

    /* ── Panel 4: Estado herramientas (NUEVO) ── */
    pnl(CY+206, 52, 4, CL_PANEL2);
    lbl(14,CY+214,"HERRAMIENTAS",CL_CYAN,1,CL_PANEL2);
    // Beacon Flood
    {
        bool bf_on = (beacon_flood_get_state() == BF_RUNNING);
        pill(14, CY+228, 60, 16, bf_on?"BF:ON":"BF:OFF", bf_on?CL_ORANGE:0x4208);
        char bfb[8]; snprintf(bfb,sizeof(bfb),"%lu",(unsigned long)beacon_flood_count());
        lbl(82,CY+232,bfb,bf_on?CL_ORANGE:CL_MUTED,1,CL_PANEL2);
    }
    // Evil Twin
    {
        evil_twin_state_t ets = evil_twin_get_state();
        bool et_on = (ets == ET_RUNNING || ets == ET_STOPPING);
        pill(110, CY+228, 60, 16, et_on?"ET:ON":"ET:OFF", et_on?CL_RED:0x4208);
        char etb[8]; snprintf(etb,sizeof(etb),"c:%u",evil_twin_cred_count());
        lbl(178,CY+232,etb,et_on?CL_RED:CL_MUTED,1,CL_PANEL2);
    }
    // Probe Logger
    {
        uint8_t pdev = probe_logger_device_count();
        char pb[16]; snprintf(pb,sizeof(pb),"Probe:%u",pdev);
        pill(210, CY+228, 70, 16, pb, pdev>0?CL_PURPLE:0x4208);
    }
    // Auto Audit
    {
        bool aa_on = auto_audit_is_running();
        pill(14, CY+248, 80, 14, aa_on?"AUDIT:ACTIVO":"AUDIT:IDLE", aa_on?CL_YELLOW:0x4208);
        if (aa_on) {
            auto_audit_status_t aa = auto_audit_get_status();
            char aab[20]; snprintf(aab,sizeof(aab),"%u/%u caps:%u",aa.targets_done,aa.targets_total,aa.captures);
            lbl(102,CY+250,aab,CL_YELLOW,1,CL_PANEL2);
        }
    }

    /* ── Panel 5: Riesgo WiFi ── */
    const audit_summary_t *audit = audit_get_summary();
    pnl(CY+262,48,4,CL_PANEL2);
    lbl(14,CY+270,"RIESGO WIFI:",CL_CYAN,1,CL_PANEL2);
    char rb[28]; snprintf(rb,sizeof(rb),"%u/100 %s",audit->risk_score,audit->risk_label);
    uint32_t rc = audit->risk_score>=75?CL_RED:(audit->risk_score>=45?CL_YELLOW:CL_GREEN);
    lbl(112,CY+266,rb,rc,2,CL_PANEL2);
    lbl(14,CY+286,audit->top_issue,CL_MUTED,1,CL_PANEL2);

    /* ── Panel 6: Web ── */
    pnl(CY+314,38,4,CL_PANEL2);
    lbl(14,CY+322,"Web: http://10.10.10.26",CL_GREEN,2,CL_PANEL2);
    lbl(14,CY+340,"User: chl  Clave: CyberKit2026",CL_MUTED,1,CL_PANEL2);
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  PANTALLA 1 — REDES + CONTROL DE ATAQUES
 *  Mejora: vendor OUI en línea 2 de cada AP
 * ═════════════════════════════════════════════════════════════════════════ */
static void draw_networks_screen(bool atk_running) {
    fillContent();
    const wifictl_ap_records_t *recs = wifictl_get_ap_records();

    /* Cabecera */
    char head[48];
    snprintf(head, sizeof(head), "Detectadas: %u   Pag: %d",
             recs->count, (net_scroll / NET_ROWS) + 1);
    lbl(12, CY+6, head, CL_MUTED, 1, CL_BG);

    /* Lista de redes */
    if (recs->count == 0) {
        pnl(NET_Y, NET_H);
        lbl_c(NET_Y + NET_H/2 - 14, "Sin redes escaneadas", CL_MUTED, 2);
        lbl_c(NET_Y + NET_H/2 + 8,  "Toca [ESCANEAR]",      CL_GREEN, 2);
    } else {
        for (int row = 0; row < NET_ROWS; row++) {
            int idx = net_scroll + row;
            if (idx >= (int)recs->count) break;
            const wifi_ap_record_t *ap = &recs->records[idx];
            int y = NET_Y + row * NET_ROW_H;

            bool is_sel = (idx == net_selected);
            uint32_t bg_col = is_sel ? 0x01A0 : (row%2 ? CL_PANEL2 : CL_PANEL);
            tft.fillRect(4, y, W-8, NET_ROW_H-2, bg_col);
            if (is_sel) tft.drawRect(4, y, W-8, NET_ROW_H-2, CL_CYAN);

            char ssid[33] = {0};
            memcpy(ssid, ap->ssid, 32);
            if (!ssid[0]) strcpy(ssid, "(oculta)");

            /* Línea 1: índice + SSID */
            char line1[36]; snprintf(line1, sizeof(line1), "%02d %-23.23s", idx+1, ssid);
            lbl(10, y+4, line1, is_sel ? CL_CYAN : CL_TEXT, 1, bg_col);

            /* Línea 2: CH / RSSI / auth / vendor OUI (reemplaza octetos BSSID) */
            const char *vnd = oui_vendor(ap->bssid);
            char line2[48];
            snprintf(line2, sizeof(line2), "CH:%02u %ddBm %-5.5s %-10.10s",
                     ap->primary, ap->rssi,
                     auth_str((uint8_t)ap->authmode),
                     (vnd && vnd[0]) ? vnd : "---");
            lbl(10, y+20, line2, auth_col((uint8_t)ap->authmode), 1, bg_col);
        }
    }

    /* Panel objetivo */
    tft.fillRect(4, TARGET_Y, W-8, TARGET_H, 0x0009);
    if (net_selected >= 0 && net_selected < (int)recs->count) {
        char ssid[33] = {0}; memcpy(ssid, recs->records[net_selected].ssid, 32);
        if (!ssid[0]) strcpy(ssid, "(oculta)");
        char tgt[48]; snprintf(tgt, sizeof(tgt), "TARGET: %-20.20s  CH:%02u",
                               ssid, recs->records[net_selected].primary);
        lbl(8, TARGET_Y+6, tgt, CL_CYAN, 1, 0x0009);
    } else {
        lbl(8, TARGET_Y+6, "TARGET: (toca una red)", CL_MUTED, 1, 0x0009);
    }

    /* Botones tipo de ataque */
    const char *tnames[] = {"Pasivo","HS","PMKID","DoS"};
    int tw = (W - 12) / 4;
    for (int i = 0; i < 4; i++) {
        bool sel = (atk_type == (uint8_t)i);
        btn(6 + i*tw, ATYPE_Y, tw-3, ATYPE_H, tnames[i],
            sel ? CL_CYAN : CL_PANEL,
            sel ? 0x0000 : CL_MUTED);
    }

    /* Selector de método ◄ Método ► */
    tft.fillRect(4, METHOD_Y, W-8, METHOD_H, CL_PANEL);
    lbl(8, METHOD_Y+4, "Metodo:", CL_MUTED, 1, CL_PANEL);
    btn(70, METHOD_Y+1, 20, 20, "<", 0x18C3, CL_TEXT, 1);
    char mname[20]; strncpy(mname, method_label(atk_method), sizeof(mname)-1);
    tft.setTextColor(CL_TEXT, CL_PANEL); tft.setTextFont(1);
    tft.setTextDatum(MC_DATUM);
    tft.drawString(mname, 175, METHOD_Y + 11);
    tft.setTextDatum(TL_DATUM);
    btn(240, METHOD_Y+1, 20, 20, ">", 0x18C3, CL_TEXT, 1);
    char tstr[12]; snprintf(tstr, sizeof(tstr), "%ds", atk_timeout);
    lbl(268, METHOD_Y+4, tstr, CL_MUTED, 1, CL_PANEL);

    /* Botones de control */
    int bw = (W - 12) / 4;
    if (!atk_running) {
        bool can_launch = (net_selected >= 0 && net_selected < (int)recs->count);
        btn(6,        CTRL_Y, bw-3, CTRL_H, "LANZAR",
            can_launch ? CL_GREEN : 0x2104,
            can_launch ? 0x0000 : CL_MUTED);
    } else {
        btn(6, CTRL_Y, bw-3, CTRL_H, "STOP", CL_RED, 0x0000);
    }
    btn(6+bw,   CTRL_Y, bw-3, CTRL_H, "SCAN",   CL_DGRN, 0x0000);
    btn(6+bw*2, CTRL_Y, bw-3, CTRL_H, "ARRIBA",  0x4208,  CL_TEXT);
    btn(6+bw*3, CTRL_Y, bw-3, CTRL_H, "ABAJO",   0x4208,  CL_TEXT);
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  PANTALLA 2 — HERRAMIENTAS
 *  Beacon Flood / Evil Twin / Karma Attack / Probe Sniffer / Auto Audit
 * ═════════════════════════════════════════════════════════════════════════ */
static void draw_tools_screen() {
    fillContent();

    /* ──────────────────────────────────────────
     * Panel 1: BEACON FLOOD  (BF_PY, h=82)
     * ────────────────────────────────────────── */
    bool bf_on = (beacon_flood_get_state() == BF_RUNNING);
    uint32_t bfbg = bf_on ? 0x0021 : CL_PANEL;
    pnl(BF_PY, 82, 4, bfbg);

    lbl(14, BF_PY+6, "BEACON FLOOD", CL_ORANGE, 2, bfbg);
    pill(222, BF_PY+4, 88, 18,
         bf_on ? "● ACTIVO" : "● IDLE",
         bf_on ? CL_ORANGE : 0x4208);

    /* Count + channel selector */
    char bfcount[28];
    snprintf(bfcount, sizeof(bfcount), "Tx:%lu", (unsigned long)beacon_flood_count());
    lbl(14, BF_PY+22, bfcount, bf_on ? CL_ORANGE : CL_MUTED, 1, bfbg);

    lbl(90, BF_PY+24, "CH:", CL_MUTED, 1, bfbg);
    btn(118, BF_PY+20, 20, 18, "<", 0x2965, CL_TEXT, 1);
    char chbuf[4]; snprintf(chbuf, sizeof(chbuf), "%u", bf_ch);
    tft.setTextColor(CL_TEXT, bfbg); tft.setTextFont(2);
    tft.setTextDatum(MC_DATUM); tft.drawString(chbuf, 162, BF_PY+29); tft.setTextDatum(TL_DATUM);
    btn(180, BF_PY+20, 20, 18, ">", 0x2965, CL_TEXT, 1);

    char rtbuf[14]; snprintf(rtbuf, sizeof(rtbuf), "%ums", (unsigned)BF_RATES[bf_rate_idx]);
    lbl(210, BF_PY+24, rtbuf, CL_MUTED, 1, bfbg);

    /* Botón INICIAR / DETENER */
    btn(10, BF_PY+44, W-20, 32,
        bf_on ? "[ DETENER FLOOD ]" : "[ INICIAR FLOOD ]",
        bf_on ? CL_RED : CL_ORANGE, 0x0000, 2);

    /* ──────────────────────────────────────────
     * Panel 2: EVIL TWIN  (ET_PY, h=82)
     * ────────────────────────────────────────── */
    evil_twin_state_t ets = evil_twin_get_state();
    bool et_on = (ets == ET_RUNNING || ets == ET_STOPPING);
    uint32_t etbg = et_on ? 0x1000 : CL_PANEL;
    pnl(ET_PY, 82, 4, etbg);

    lbl(14, ET_PY+6, "EVIL TWIN", CL_RED, 2, etbg);
    const char *etstate = (ets == ET_RUNNING) ? "● ACTIVO"
                        : (ets == ET_STOPPING) ? "● PARAND" : "● IDLE";
    uint32_t etcol = (ets == ET_RUNNING)   ? CL_RED
                   : (ets == ET_STOPPING)  ? CL_YELLOW : 0x4208;
    pill(222, ET_PY+4, 88, 18, etstate, etcol);

    /* Target */
    const wifictl_ap_records_t *recs = wifictl_get_ap_records();
    lbl(14, ET_PY+24, "Target:", CL_MUTED, 1, etbg);
    if (!et_on && net_selected >= 0 && net_selected < (int)recs->count) {
        char ssid[33]={0}; memcpy(ssid, recs->records[net_selected].ssid, 32);
        if (!ssid[0]) strcpy(ssid, "(oculta)");
        char tgt[30]; snprintf(tgt, sizeof(tgt), "%-20.20s %2u", ssid,
                               recs->records[net_selected].primary);
        lbl(70, ET_PY+24, tgt, CL_CYAN, 1, etbg);
    } else if (et_on) {
        char credsbuf[20]; snprintf(credsbuf, sizeof(credsbuf), "Creds:%u", evil_twin_cred_count());
        lbl(70, ET_PY+24, credsbuf, CL_ORANGE, 1, etbg);
    } else {
        lbl(70, ET_PY+24, "--- selec. en REDES ---", CL_MUTED, 1, etbg);
    }

    bool can_et = et_on || (net_selected >= 0 && net_selected < (int)recs->count);
    btn(10, ET_PY+44, W-20, 32,
        et_on ? "[ DETENER EVIL TWIN ]" : "[ INICIAR EVIL TWIN ]",
        et_on ? CL_RED : (can_et ? CL_RED : 0x2104),
        0x0000, 2);

    /* ──────────────────────────────────────────
     * Panel 3: KARMA ATTACK  (KA_PY, h=60)
     * ────────────────────────────────────────── */
    karma_state_t ka_state = karma_get_state();
    bool ka_on = (ka_state == KARMA_RUNNING);
    uint32_t kabg = ka_on ? 0x3008 : CL_PANEL;
    pnl(KA_PY, 60, 4, kabg);

    lbl(14, KA_PY+6, "KARMA", CL_PURPLE, 2, kabg);
    if (ka_on) {
        karma_stats_t ks = karma_get_stats();
        char kainfo[32];
        snprintf(kainfo, sizeof(kainfo), "P:%lu R:%lu U:%lu",
                 (unsigned long)ks.probes_seen,
                 (unsigned long)ks.responses_sent,
                 (unsigned long)ks.unique_ssids);
        lbl(80, KA_PY+8, kainfo, CL_PURPLE, 1, kabg);
        pill(222, KA_PY+4, 88, 18, "● ACTIVO", CL_PURPLE);
    } else {
        pill(222, KA_PY+4, 88, 18, "● IDLE", 0x4208);
        /* Canal selector */
        lbl(80, KA_PY+9, "CH:", CL_MUTED, 1, kabg);
        btn(106, KA_PY+6, 20, 16, "<", 0x2965, CL_TEXT, 1);
        char kachbuf[4]; snprintf(kachbuf, sizeof(kachbuf), "%u", ka_ch);
        tft.setTextColor(CL_TEXT, kabg); tft.setTextFont(1);
        tft.setTextDatum(MC_DATUM); tft.drawString(kachbuf, 148, KA_PY+14); tft.setTextDatum(TL_DATUM);
        btn(162, KA_PY+6, 20, 16, ">", 0x2965, CL_TEXT, 1);
    }

    btn(10, KA_PY+38, W-20, 18,
        ka_on ? "[ DETENER KARMA ]" : "[ INICIAR KARMA ]",
        ka_on ? CL_RED : CL_PURPLE, 0x0000, 1);

    /* ──────────────────────────────────────────
     * Panel 4: PROBE SNIFFER  (PR_PY, h=66)
     * ────────────────────────────────────────── */
    uint8_t pdev = probe_logger_device_count();
    uint32_t prpbg = pdev > 0 ? 0x0011 : CL_PANEL;
    pnl(PR_PY, 66, 4, prpbg);

    lbl(14, PR_PY+6, "PROBE SNIFF", CL_PURPLE, 2, prpbg);
    char pcount[24]; snprintf(pcount, sizeof(pcount), "Dev:%u/64", pdev);
    pill(218, PR_PY+4, 92, 18, pcount, pdev > 0 ? CL_PURPLE : 0x4208);

    if (pdev > 0) {
        const probe_device_t *pd = probe_logger_get_device(pdev-1);
        if (pd) {
            char devline[48];
            snprintf(devline, sizeof(devline), "%02X:%02X:%02X %-10.10s %ddBm",
                     pd->mac[0], pd->mac[1], pd->mac[2],
                     pd->vendor[0] ? pd->vendor : "---",
                     pd->rssi_last);
            lbl(14, PR_PY+24, devline, CL_TEXT, 1, prpbg);
        }
    } else {
        lbl(14, PR_PY+24, "(sin dispositivos aun)", CL_MUTED, 1, prpbg);
    }

    int half = (W-24)/2;
    btn(10,      PR_PY+44, half, 18, "DUMP SD",  0x0340, CL_TEXT, 1);
    btn(14+half, PR_PY+44, half, 18, "LIMPIAR",  0x4208, CL_TEXT, 1);

    /* ──────────────────────────────────────────
     * Panel 5: AUTO AUDIT  (AA_PY, h=48)
     * ────────────────────────────────────────── */
    bool aa_on = auto_audit_is_running();
    uint32_t aapbg = aa_on ? 0x2020 : CL_PANEL;
    pnl(AA_PY, 48, 4, aapbg);

    lbl(14, AA_PY+6, "AUTO AUDIT", CL_YELLOW, 2, aapbg);
    if (aa_on) {
        auto_audit_status_t aa = auto_audit_get_status();
        char aastatus[40];
        snprintf(aastatus, sizeof(aastatus), "%-14.14s %u/%u caps:%u",
                 aa.current_ssid[0] ? aa.current_ssid : "scan...",
                 aa.targets_done, aa.targets_total, aa.captures);
        lbl(14, AA_PY+24, aastatus, CL_YELLOW, 1, aapbg);
        pill(222, AA_PY+4, 88, 18, "● ACTIVO", CL_YELLOW);
    } else {
        pill(222, AA_PY+4, 88, 18, "● IDLE", 0x4208);
        btn(10, AA_PY+24, W-20, 20,
            "INICIAR AUTO AUDIT", CL_YELLOW, 0x0000, 1);
    }
    if (aa_on) {
        btn(10, AA_PY+24, W-20, 20, "DETENER", CL_RED, 0x0000, 1);
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  PANTALLA 3 — AUDITORÍA (RIESGO)
 * ═════════════════════════════════════════════════════════════════════════ */
static void draw_audit_screen() {
    fillContent();
    const audit_summary_t *a = audit_get_summary();
    lbl_c(CY+16, "AUDITORIA WIFI DEFENSIVA", CL_CYAN);
    pnl(CY+30, 72);
    uint32_t rc = a->risk_score>=75?CL_RED:(a->risk_score>=45?CL_YELLOW:CL_GREEN);
    lbl(14,CY+38,"Riesgo:",CL_MUTED,1,CL_PANEL);
    char score[32]; snprintf(score,sizeof(score),"%u/100 %s",a->risk_score,a->risk_label);
    lbl(82,CY+34,score,rc,4,CL_PANEL);
    lbl(14,CY+76,a->top_issue,CL_TEXT,1,CL_PANEL);
    pnl(CY+108,102);
    char b[24];
    lbl(14,CY+116,"RESUMEN",CL_DGRN,1,CL_PANEL);
    snprintf(b,sizeof(b),"%u",a->networks);
    lbl(14,CY+134,"Redes:",CL_MUTED,1,CL_PANEL);     lbl(90,CY+132,b,CL_TEXT,2,CL_PANEL);
    snprintf(b,sizeof(b),"%u",a->open_networks);
    lbl(160,CY+134,"Abiertas:",CL_MUTED,1,CL_PANEL);  lbl(246,CY+132,b,a->open_networks?CL_RED:CL_GREEN,2,CL_PANEL);
    snprintf(b,sizeof(b),"%u",a->weak_networks);
    lbl(14,CY+158,"Debiles:",CL_MUTED,1,CL_PANEL);    lbl(90,CY+156,b,a->weak_networks?CL_YELLOW:CL_GREEN,2,CL_PANEL);
    snprintf(b,sizeof(b),"%u",a->evil_twin_suspects);
    lbl(160,CY+158,"EvilTwin:",CL_MUTED,1,CL_PANEL);  lbl(246,CY+156,b,a->evil_twin_suspects?CL_RED:CL_GREEN,2,CL_PANEL);
    snprintf(b,sizeof(b),"%u",a->deauth_frames);
    lbl(14,CY+182,"Deauth:",CL_MUTED,1,CL_PANEL);     lbl(90,CY+180,b,a->deauth_frames?CL_RED:CL_GREEN,2,CL_PANEL);
    snprintf(b,sizeof(b),"%u",a->crowded_channels);
    lbl(160,CY+182,"Canales:",CL_MUTED,1,CL_PANEL);   lbl(246,CY+180,b,a->crowded_channels?CL_YELLOW:CL_GREEN,2,CL_PANEL);
    pnl(CY+216,136,4,CL_PANEL2);
    lbl(14,CY+224,"EVENTOS RECIENTES",CL_CYAN,1,CL_PANEL2);
    if (!a->event_count) {
        lbl(14,CY+246,"Sin eventos. Ejecuta un escaneo.",CL_MUTED,1,CL_PANEL2);
    } else {
        for (uint8_t i=0; i<a->event_count && i<5; i++) {
            int ey=CY+244+i*20;
            lbl(14,ey,a->events[i].type,a->events[i].risk>=75?CL_RED:CL_YELLOW,1,CL_PANEL2);
            lbl(106,ey,a->events[i].ssid,CL_TEXT,1,CL_PANEL2);
            lbl(14,ey+10,a->events[i].detail,CL_MUTED,1,CL_PANEL2);
        }
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  PANTALLA 4 — ESTADO
 * ═════════════════════════════════════════════════════════════════════════ */
static void draw_status_screen(disp_attack_state_t state, disp_attack_type_t type,
                                unsigned long uptime_s, uint8_t clients,
                                uint16_t cap_count, const char *last_file,
                                bool atk_running) {
    fillContent();
    lbl_c(CY+16, "ESTADO EN TIEMPO REAL", CL_CYAN);

    /* Ataque WiFi */
    pnl(CY+30, 100);
    lbl(14,CY+38,"Ataque WiFi:",CL_MUTED,1,CL_PANEL);
    uint32_t col = atk_state_col(state);
    tft.fillRoundRect(14,CY+52,190,40,8,col);
    tft.setTextColor(0x0000,col); tft.setTextFont(4); tft.setTextDatum(MC_DATUM);
    tft.drawString(atk_state_str(state),109,CY+72); tft.setTextDatum(TL_DATUM);
    lbl(14,CY+100,atk_type_str(type),CL_TEXT,2,CL_PANEL);

    /* Uptime / clientes */
    pnl(CY+136,46);
    char ut[16]; unsigned long h=uptime_s/3600,m2=(uptime_s%3600)/60,s2=uptime_s%60;
    if(uptime_s<86400) snprintf(ut,16,"%02lu:%02lu:%02lu",h,m2,s2);
    else snprintf(ut,16,"%lud%02lu:%02lu",uptime_s/86400,h%24,m2);
    char cb[4]; snprintf(cb,4,"%d",clients);
    char capb[8]; snprintf(capb,8,"%d",cap_count);
    lbl(14,CY+144,"Uptime:",CL_MUTED,1,CL_PANEL);  lbl(72,CY+142,ut,CL_TEXT,2,CL_PANEL);
    lbl(14,CY+164,"Clientes:",CL_MUTED,1,CL_PANEL); lbl(80,CY+162,cb,clients>0?CL_GREEN:CL_MUTED,2,CL_PANEL);
    lbl(160,CY+164,"Caps:",CL_MUTED,1,CL_PANEL);    lbl(210,CY+162,capb,CL_TEXT,2,CL_PANEL);

    /* Herramientas activas */
    pnl(CY+188,62,4,CL_PANEL2);
    lbl(14,CY+196,"HERRAMIENTAS:",CL_CYAN,1,CL_PANEL2);
    {
        bool bf2 = (beacon_flood_get_state() == BF_RUNNING);
        evil_twin_state_t ets2 = evil_twin_get_state();
        bool et2 = (ets2 != ET_IDLE);
        bool aa2 = auto_audit_is_running();
        uint8_t pd2 = probe_logger_device_count();
        char hline[64];
        snprintf(hline,sizeof(hline),"BF:%s  ET:%s  Probe:%u  Audit:%s",
                 bf2?"ON":"OFF", et2?"ON":"OFF", pd2, aa2?"ON":"OFF");
        lbl(14,CY+212,hline,CL_TEXT,1,CL_PANEL2);
        if (aa2) {
            auto_audit_status_t aastat = auto_audit_get_status();
            char aaline[48];
            snprintf(aaline,sizeof(aaline),"Audit: %u/%u  caps:%u  %-12.12s",
                     aastat.targets_done,aastat.targets_total,
                     aastat.captures, aastat.current_ssid[0]?aastat.current_ssid:"");
            lbl(14,CY+228,aaline,CL_YELLOW,1,CL_PANEL2);
        }
    }

    /* Última captura */
    pnl(CY+256,60,4,CL_PANEL2);
    lbl(14,CY+264,"ULTIMA CAPTURA SD:",CL_CYAN,1,CL_PANEL2);
    if (last_file && last_file[0]) {
        const char *fn = strrchr(last_file, '/'); fn = fn ? fn+1 : last_file;
        lbl(14,CY+278,fn,CL_GREEN,1,CL_PANEL2);
    } else {
        lbl(14,CY+278,"(ninguna aun)",CL_MUTED,1,CL_PANEL2);
    }
    lbl(14,CY+296,"/CyberKit/captures/  —  http://10.10.10.26",CL_MUTED,1,CL_PANEL2);

    /* Botón STOP si hay ataque en curso */
    if (atk_running) {
        btn(6, CY+322, 140, 28, "STOP ATAQUE", CL_RED, 0x0000, 2);
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  PANTALLA 5 — CONFIGURACION
 * ═════════════════════════════════════════════════════════════════════════ */
static void draw_settings(bool stealth, bool sd_ok) {
    fillContent();
    lbl_c(CY+16, "CONFIGURACION", CL_CYAN);
    uint32_t sc = stealth ? CL_RED : CL_GREEN;
    tft.fillRoundRect(BTN_ST_X,BTN_ST_Y,BTN_ST_W,BTN_ST_H,7,sc);
    tft.setTextColor(0x0000,sc); tft.setTextFont(2); tft.setTextDatum(ML_DATUM);
    tft.drawString(stealth?" STEALTH ON  [TAP=OFF]":" STEALTH OFF [TAP=ON] ",
                   BTN_ST_X+8, BTN_ST_Y+BTN_ST_H/2); tft.setTextDatum(TL_DATUM);
    tft.fillRoundRect(BTN_CAL_X,BTN_CAL_Y,BTN_CAL_W,BTN_CAL_H,7,0x4208);
    tft.setTextColor(CL_YELLOW,0x4208); tft.setTextFont(2); tft.setTextDatum(ML_DATUM);
    tft.drawString(" CALIBRAR TOUCH [TAP]", BTN_CAL_X+8, BTN_CAL_Y+BTN_CAL_H/2);
    tft.setTextDatum(TL_DATUM);
    tft.fillRoundRect(BTN_RPT_X,BTN_RPT_Y,BTN_RPT_W,BTN_RPT_H,7,0x0210);
    tft.setTextColor(CL_GREEN,0x0210); tft.setTextFont(2); tft.setTextDatum(ML_DATUM);
    tft.drawString(" GUARDAR REPORTE HTML", BTN_RPT_X+8, BTN_RPT_Y+BTN_RPT_H/2);
    tft.setTextDatum(TL_DATUM);
    pnl(CY+196, 176);
    lbl(14,CY+204,"INFO DEL DISPOSITIVO",CL_DGRN,1,CL_PANEL);
    struct { const char *k, *v; } info[] = {
        {"Firmware :", "ChL-CyberKit v1.0"},
        {"Creador  :", "Pedro Luis Rezabala"},
        {"Placa    :", "ESP32-32E  (CYD 4.0\")"},
        {"Pantalla :", "ST7796S  320x480  SPI"},
        {"Touch    :", "XPT2046 resistivo"},
        {"Flash    :", "4 MB"},
        {"WiFi     :", "802.11 b/g/n"},
        {"SD card  :", sd_ok ? "OK — /CyberKit/" : "Sin tarjeta"},
        {"Framework:", "Arduino-ESP32 2.x"},
        {"IP AP    :", "10.10.10.26"},
    };
    int ny = CY+220;
    for (auto &row : info) {
        lbl(14, ny, row.k, CL_MUTED, 1, CL_PANEL);
        lbl(102,ny, row.v, CL_TEXT,  1, CL_PANEL);
        ny += 16;
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  CALIBRACIÓN
 * ═════════════════════════════════════════════════════════════════════════ */
void cyd_run_calibration() {
    tft.fillScreen(CL_BG);
    tft.setTextColor(CL_GREEN,CL_BG); tft.setTextFont(2); tft.setTextDatum(MC_DATUM);
    tft.drawString("CALIBRACION DE TOUCH",W/2,60);
    tft.setTextColor(CL_MUTED,CL_BG);
    tft.drawString("Toca cada punto cuando aparezca",W/2,90);
    tft.setTextFont(1);
    tft.drawString("Los datos se guardan en NVS (flash interna)",W/2,115);
    tft.setTextDatum(TL_DATUM); delay(1200);
    uint16_t calData[5];
    tft.calibrateTouch(calData, TFT_WHITE, TFT_BLACK, 15);
    prefs.begin("chl_cal",false);
    prefs.putBytes("touch",calData,sizeof(calData));
    prefs.end();
    tft.fillScreen(CL_BG);
    tft.setTextColor(CL_GREEN,CL_BG); tft.setTextFont(2); tft.setTextDatum(MC_DATUM);
    tft.drawString("Calibracion guardada OK",W/2,200);
    tft.drawString("Continua en 2 segundos...",W/2,225);
    tft.setTextDatum(TL_DATUM); delay(2000);
}

static bool touch_calibration_valid(const uint16_t calData[5]) {
    bool all_zero=true, all_ffff=true;
    for(int i=0;i<5;i++){if(calData[i]!=0)all_zero=false;if(calData[i]!=0xFFFF)all_ffff=false;}
    if(all_zero||all_ffff)return false;
    if(calData[1]<50||calData[3]<50)return false;
    if(calData[4]>7)return false;
    return true;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  API PÚBLICA
 * ═════════════════════════════════════════════════════════════════════════ */
void cyd_display_init() {
    bool force_cal = (digitalRead(0) == LOW);
    pinMode(LED_R,OUTPUT); digitalWrite(LED_R,HIGH);
    pinMode(LED_G,OUTPUT); digitalWrite(LED_G,LOW);
    pinMode(LED_B,OUTPUT); digitalWrite(LED_B,HIGH);
    pinMode(TFT_BL,OUTPUT); digitalWrite(TFT_BL,HIGH);
    tft.init(); tft.setRotation(0); tft.fillScreen(CL_BG);

    prefs.begin("chl_cal",false);
    if(force_cal){ prefs.remove("touch"); Serial.println("[TOUCH] BOOT: calibracion borrada"); }
    bool has_cal = prefs.isKey("touch");
    uint16_t calData[5]={0};
    if(has_cal) prefs.getBytes("touch",calData,sizeof(calData));
    if(has_cal && !touch_calibration_valid(calData)){ prefs.remove("touch"); has_cal=false; }
    prefs.end();

    if(has_cal){
        tft.setTouch(calData);
        Serial.printf("[TOUCH] Calibracion cargada: %u,%u,%u,%u,%u\n",
                      calData[0],calData[1],calData[2],calData[3],calData[4]);
    } else {
        tft.setTextColor(CL_YELLOW,CL_BG); tft.setTextFont(2); tft.setTextDatum(MC_DATUM);
        tft.drawString(force_cal?"BOOT: calibrando...":"Primera vez: calibrando...",W/2,240);
        tft.setTextDatum(TL_DATUM); delay(1500);
        cyd_run_calibration();
        prefs.begin("chl_cal",true);
        prefs.getBytes("touch",calData,sizeof(calData));
        prefs.end();
        tft.setTouch(calData);
    }

    tft.fillScreen(CL_BG);
    tft.setTextDatum(MC_DATUM);
    tft.setTextColor(CL_GREEN,CL_BG); tft.setTextFont(4); tft.drawString("ChL-CyberKit",W/2,140);
    tft.setTextFont(2); tft.setTextColor(CL_MUTED,CL_BG); tft.drawString("v1.0  |  CYD 4.0\"",W/2,172);
    tft.setTextFont(1); tft.drawString("by Pedro Luis Rezabala",W/2,194);
    tft.drawRect(30,240,260,12,CL_DGRN);
    for(int i=0;i<=260;i+=13){tft.fillRect(31,241,i,10,CL_GREEN);delay(18);}
    tft.setTextColor(CL_MUTED,CL_BG); tft.drawString("Iniciando WiFi stack...",W/2,264);
    tft.setTextDatum(TL_DATUM); delay(300);
}

/* ─────────────────────────────────────────────────────────────────────────── */
void cyd_draw_screen(screen_t scr, bool stealth, bool sd_ok,
                     disp_attack_state_t state, disp_attack_type_t type,
                     unsigned long uptime_s, uint8_t clients,
                     uint16_t cap_count, const char *last_file) {
    bool atk_running = (state == DA_RUNNING);
    tft.fillScreen(CL_BG);
    draw_header();
    draw_nav(scr);
    switch(scr){
        case SCR_DASHBOARD: draw_dashboard(stealth,sd_ok,state,type,uptime_s,clients,cap_count); break;
        case SCR_NETWORKS:  draw_networks_screen(atk_running); break;
        case SCR_TOOLS:     draw_tools_screen(); break;
        case SCR_AUDIT:     draw_audit_screen(); break;
        case SCR_STATUS:    draw_status_screen(state,type,uptime_s,clients,cap_count,last_file,atk_running); break;
        case SCR_SETTINGS:  draw_settings(stealth,sd_ok); break;
    }
}

/* ─────────────────────────────────────────────────────────────────────────── */
void cyd_update_attack(disp_attack_state_t state, disp_attack_type_t type, screen_t scr) {
    uint32_t col=atk_state_col(state);
    if(scr==SCR_DASHBOARD){
        tft.fillRect(6,CY+162,W-12,40,CL_PANEL);
        tft.fillRoundRect(14,CY+170,110,24,5,col);
        tft.setTextColor(0x0000,col); tft.setTextFont(2); tft.setTextDatum(MC_DATUM);
        tft.drawString(atk_state_str(state),69,CY+182); tft.setTextDatum(TL_DATUM);
        lbl(136,CY+176,atk_type_str(type),CL_TEXT,2,CL_PANEL);
    } else if(scr==SCR_STATUS){
        tft.fillRect(6,CY+42,W-12,84,CL_PANEL);
        tft.fillRoundRect(14,CY+52,190,40,8,col);
        tft.setTextColor(0x0000,col); tft.setTextFont(4); tft.setTextDatum(MC_DATUM);
        tft.drawString(atk_state_str(state),109,CY+72); tft.setTextDatum(TL_DATUM);
        tft.fillRect(6,CY+100,W-12,30,CL_PANEL);
        lbl(14,CY+100,atk_type_str(type),CL_TEXT,2,CL_PANEL);
    }
}

/* ─────────────────────────────────────────────────────────────────────────── */
void cyd_update_info(unsigned long uptime_s, uint8_t clients, screen_t scr,
                     uint16_t cap_count) {
    char ut[16]; unsigned long h=uptime_s/3600,m2=(uptime_s%3600)/60,s2=uptime_s%60;
    if(uptime_s<86400) snprintf(ut,16,"%02lu:%02lu:%02lu",h,m2,s2);
    else snprintf(ut,16,"%lud%02lu:%02lu",uptime_s/86400,h%24,m2);
    char cb[4]; snprintf(cb,4,"%d",clients);
    char capb[8]; snprintf(capb,8,"%d",cap_count);
    if(scr==SCR_DASHBOARD){
        tft.fillRect(70,CY+114,240,26,CL_PANEL);
        lbl(72,CY+116,ut,CL_TEXT,2,CL_PANEL);
        lbl(222,CY+116,cb,clients>0?CL_GREEN:CL_MUTED,2,CL_PANEL);
        tft.fillRect(40,CY+134,200,14,CL_PANEL);
        lbl(162,CY+136,capb,CL_TEXT,1,CL_PANEL);
    } else if(scr==SCR_STATUS){
        tft.fillRect(72,CY+140,240,30,CL_PANEL);
        lbl(72,CY+142,ut,CL_TEXT,2,CL_PANEL);
        lbl(80,CY+162,cb,clients>0?CL_GREEN:CL_MUTED,2,CL_PANEL);
        lbl(210,CY+162,capb,CL_TEXT,2,CL_PANEL);
    }
}

/* ─────────────────────────────────────────────────────────────────────────── */
cyd_touch_t cyd_handle_touch(screen_t cur, bool stealth_on, bool atk_running) {
    cyd_touch_t r = {};
    r.new_scr       = cur;
    r.attack_ap     = (uint8_t)(net_selected >= 0 ? net_selected : 0);
    r.attack_type   = atk_type;
    r.attack_method = atk_method;
    r.attack_timeout= atk_timeout;
    r.bf_channel    = bf_ch;
    r.bf_rate_ms    = BF_RATES[bf_rate_idx];

    uint16_t tx, ty;
    if (!tft.getTouch(&tx, &ty, 40)) return r;

    /* ── Tab de navegación (6 tabs) ─────────────────────── */
    if (ty >= (uint16_t)NAV_Y) {
        int tab = (int)tx / TAB_W;
        if (tab < 0) tab = 0;
        if (tab > 5) tab = 5;
        r.new_scr = (screen_t)tab;
        return r;
    }

    /* ══════════════════════════════════════════════════════
     * REDES
     * ══════════════════════════════════════════════════════ */
    if (cur == SCR_NETWORKS) {
        const wifictl_ap_records_t *recs = wifictl_get_ap_records();
        int bw = (W-12)/4;

        /* Lista de redes → seleccionar */
        if (ty >= (uint16_t)NET_Y && ty < (uint16_t)(NET_Y + NET_H)) {
            int row = (ty - NET_Y) / NET_ROW_H;
            int idx = net_scroll + row;
            if (idx < (int)recs->count) {
                net_selected = idx;
                draw_networks_screen(atk_running);
            }
            return r;
        }

        /* Botones tipo de ataque */
        if (ty >= (uint16_t)ATYPE_Y && ty < (uint16_t)(ATYPE_Y + ATYPE_H)) {
            int ti = (tx - 6) / ((W-12)/4);
            if (ti >= 0 && ti < 4) {
                atk_type    = (uint8_t)ti;
                atk_method  = 0;
                atk_timeout = default_timeout(atk_type);
                draw_networks_screen(atk_running);
            }
            return r;
        }

        /* Selector de método ◄ ► */
        if (ty >= (uint16_t)METHOD_Y && ty < (uint16_t)(METHOD_Y + METHOD_H)) {
            if (tx >= 70 && tx <= 90) {
                if (atk_method > 0) atk_method--;
                else atk_method = method_max();
                draw_networks_screen(atk_running);
            } else if (tx >= 240 && tx <= 260) {
                atk_method = (atk_method + 1) % (method_max() + 1);
                draw_networks_screen(atk_running);
            }
            return r;
        }

        /* Botones de control */
        if (ty >= (uint16_t)CTRL_Y && ty < (uint16_t)(CTRL_Y + CTRL_H)) {
            if (tx >= 6 && tx < (uint16_t)(6+bw)) {
                if (atk_running) {
                    r.reset_req = true;
                } else if (net_selected >= 0 && net_selected < (int)recs->count) {
                    r.attack_req     = true;
                    r.attack_ap      = (uint8_t)net_selected;
                    r.attack_type    = atk_type;
                    r.attack_method  = atk_method;
                    r.attack_timeout = atk_timeout;
                }
            } else if (tx >= (uint16_t)(6+bw) && tx < (uint16_t)(6+bw*2)) {
                r.scan_req = true;
            } else if (tx >= (uint16_t)(6+bw*2) && tx < (uint16_t)(6+bw*3)) {
                net_scroll -= NET_ROWS;
                if (net_scroll < 0) net_scroll = 0;
                draw_networks_screen(atk_running);
            } else {
                if (recs->count > NET_ROWS && net_scroll + NET_ROWS < (int)recs->count)
                    net_scroll += NET_ROWS;
                draw_networks_screen(atk_running);
            }
            return r;
        }
    }

    /* ══════════════════════════════════════════════════════
     * HERRAM
     * ══════════════════════════════════════════════════════ */
    if (cur == SCR_TOOLS) {

        /* ── BEACON FLOOD ─────────────────── */
        /* CH ◄  (x=118..138, y=BF_PY+20..BF_PY+38) */
        if (tx >= 118 && tx <= 138 && ty >= (uint16_t)(BF_PY+20) && ty <= (uint16_t)(BF_PY+38)) {
            if (bf_ch > 1) bf_ch--; else bf_ch = 13;
            r.bf_channel = bf_ch; r.bf_rate_ms = BF_RATES[bf_rate_idx];
            draw_tools_screen(); return r;
        }
        /* CH ►  (x=180..200, y=BF_PY+20..BF_PY+38) */
        if (tx >= 180 && tx <= 200 && ty >= (uint16_t)(BF_PY+20) && ty <= (uint16_t)(BF_PY+38)) {
            if (bf_ch < 13) bf_ch++; else bf_ch = 1;
            r.bf_channel = bf_ch; r.bf_rate_ms = BF_RATES[bf_rate_idx];
            draw_tools_screen(); return r;
        }
        /* BF INICIAR/DETENER btn (y=BF_PY+44..BF_PY+76) */
        if (tx >= 10 && tx <= W-10 && ty >= (uint16_t)(BF_PY+44) && ty <= (uint16_t)(BF_PY+76)) {
            r.bf_channel = bf_ch; r.bf_rate_ms = BF_RATES[bf_rate_idx];
            if (beacon_flood_get_state() == BF_RUNNING) r.bf_stop_req  = true;
            else                                         r.bf_start_req = true;
            return r;
        }

        /* ── EVIL TWIN ────────────────────── */
        /* ET INICIAR/DETENER btn (y=ET_PY+44..ET_PY+76) */
        if (tx >= 10 && tx <= W-10 && ty >= (uint16_t)(ET_PY+44) && ty <= (uint16_t)(ET_PY+76)) {
            evil_twin_state_t ets2 = evil_twin_get_state();
            if (ets2 != ET_IDLE) {
                r.et_stop_req = true;
            } else {
                r.et_start_req = true;
                r.attack_ap = (uint8_t)(net_selected >= 0 ? net_selected : 0);
            }
            return r;
        }

        /* ── KARMA ATTACK ─────────────────── */
        /* KA CH ◄  (x=106..126, y=KA_PY+6..KA_PY+22) - only when IDLE */
        if (karma_get_state() == KARMA_IDLE &&
            tx >= 106 && tx <= 126 && ty >= (uint16_t)(KA_PY+6) && ty <= (uint16_t)(KA_PY+22)) {
            if (ka_ch > 1) ka_ch--; else ka_ch = 13;
            r.karma_channel = ka_ch;
            draw_tools_screen(); return r;
        }
        /* KA CH ►  (x=162..182, y=KA_PY+6..KA_PY+22) */
        if (karma_get_state() == KARMA_IDLE &&
            tx >= 162 && tx <= 182 && ty >= (uint16_t)(KA_PY+6) && ty <= (uint16_t)(KA_PY+22)) {
            if (ka_ch < 13) ka_ch++; else ka_ch = 1;
            r.karma_channel = ka_ch;
            draw_tools_screen(); return r;
        }
        /* KA INICIAR/DETENER btn (y=KA_PY+38..KA_PY+56) */
        if (tx >= 10 && tx <= W-10 && ty >= (uint16_t)(KA_PY+38) && ty <= (uint16_t)(KA_PY+56)) {
            if (karma_get_state() == KARMA_RUNNING) {
                r.karma_stop_req = true;
            } else {
                r.karma_start_req = true;
                r.karma_channel   = ka_ch;
            }
            return r;
        }

        /* ── PROBE SNIFFER ────────────────── */
        int half2 = (W-24)/2;
        /* DUMP SD btn (x=10..10+half2, y=PR_PY+44..PR_PY+62) */
        if (tx >= 10 && tx <= (uint16_t)(10+half2) &&
            ty >= (uint16_t)(PR_PY+44) && ty <= (uint16_t)(PR_PY+62)) {
            r.probe_sd_req = true; return r;
        }
        /* LIMPIAR btn (x=14+half2.., y=PR_PY+44..PR_PY+62) */
        if (tx >= (uint16_t)(14+half2) && tx <= W-10 &&
            ty >= (uint16_t)(PR_PY+44) && ty <= (uint16_t)(PR_PY+62)) {
            r.probe_clear_req = true; return r;
        }

        /* ── AUTO AUDIT ───────────────────── */
        /* AA INICIAR/DETENER btn (y=AA_PY+24..AA_PY+44) */
        if (tx >= 10 && tx <= W-10 && ty >= (uint16_t)(AA_PY+24) && ty <= (uint16_t)(AA_PY+44)) {
            r.audit_run_req = true; return r;
        }
    }

    /* ── STATUS — botón STOP ataque ─────────────────────── */
    if (cur == SCR_STATUS && atk_running) {
        if (ty >= (uint16_t)(CY+322) && ty < (uint16_t)(CY+350) && tx >= 6 && tx < 146) {
            r.reset_req = true; return r;
        }
    }

    /* ── SETTINGS ──────────────────────────────────────────── */
    if (cur == SCR_SETTINGS) {
        if (tx>=(uint16_t)BTN_ST_X && tx<=(uint16_t)(BTN_ST_X+BTN_ST_W) &&
            ty>=(uint16_t)BTN_ST_Y && ty<=(uint16_t)(BTN_ST_Y+BTN_ST_H)) {
            r.stealth_tog = true; return r;
        }
        if (tx>=(uint16_t)BTN_CAL_X && tx<=(uint16_t)(BTN_CAL_X+BTN_CAL_W) &&
            ty>=(uint16_t)BTN_CAL_Y && ty<=(uint16_t)(BTN_CAL_Y+BTN_CAL_H)) {
            r.calib_req = true; return r;
        }
        if (tx>=(uint16_t)BTN_RPT_X && tx<=(uint16_t)(BTN_RPT_X+BTN_RPT_W) &&
            ty>=(uint16_t)BTN_RPT_Y && ty<=(uint16_t)(BTN_RPT_Y+BTN_RPT_H)) {
            r.report_req = true; return r;
        }
    }

    /* ── DASHBOARD — stealth toggle ────────────────────────── */
    if (cur == SCR_DASHBOARD) {
        if (tx >= 216 && tx <= 310 && ty >= (uint16_t)(CY+22) && ty <= (uint16_t)(CY+40)) {
            r.stealth_tog = true;
        }
    }

    return r;
}

/* ─────────────────────────────────────────────────────────────────────────── */
void cyd_led(disp_attack_state_t state) {
    switch(state){
        case DA_READY:    digitalWrite(LED_R,HIGH);digitalWrite(LED_G,LOW); digitalWrite(LED_B,HIGH);break;
        case DA_RUNNING:  digitalWrite(LED_R,LOW); digitalWrite(LED_G,LOW); digitalWrite(LED_B,HIGH);break;
        case DA_FINISHED: digitalWrite(LED_R,HIGH);digitalWrite(LED_G,HIGH);digitalWrite(LED_B,LOW); break;
        case DA_TIMEOUT:  digitalWrite(LED_R,LOW); digitalWrite(LED_G,HIGH);digitalWrite(LED_B,HIGH);break;
        default:          digitalWrite(LED_R,HIGH);digitalWrite(LED_G,HIGH);digitalWrite(LED_B,HIGH);break;
    }
}
