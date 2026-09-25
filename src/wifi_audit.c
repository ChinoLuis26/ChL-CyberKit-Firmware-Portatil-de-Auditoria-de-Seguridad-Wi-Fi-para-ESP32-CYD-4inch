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
 * @file wifi_audit.c
 * @brief Evaluacion defensiva de redes WiFi cercanas.
 */
#include "wifi_audit.h"

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include "esp_timer.h"
#include "esp_wifi_types.h"

static audit_summary_t summary;

static uint32_t now_s(void) {
    return (uint32_t)(esp_timer_get_time() / 1000000ULL);
}

static void copy_ssid(char out[33], const uint8_t ssid[33]) {
    memset(out, 0, 33);
    memcpy(out, ssid, 32);
    out[32] = '\0';
}

static void bssid_to_str(const uint8_t bssid[6], char out[18]) {
    snprintf(out, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
}

static const char *auth_label(wifi_auth_mode_t auth) {
    switch (auth) {
        case WIFI_AUTH_OPEN: return "OPEN";
        case WIFI_AUTH_WEP: return "WEP";
        case WIFI_AUTH_WPA_PSK: return "WPA";
        case WIFI_AUTH_WPA2_PSK: return "WPA2";
        case WIFI_AUTH_WPA_WPA2_PSK: return "WPA/WPA2";
        case WIFI_AUTH_WPA2_ENTERPRISE: return "WPA2-ENT";
        case WIFI_AUTH_WPA3_PSK: return "WPA3";
        case WIFI_AUTH_WPA2_WPA3_PSK: return "WPA2/WPA3";
        default: return "OTRO";
    }
}

static bool is_weak_auth(wifi_auth_mode_t auth) {
    return auth == WIFI_AUTH_OPEN || auth == WIFI_AUTH_WEP || auth == WIFI_AUTH_WPA_PSK;
}

static void risk_label(uint8_t risk, char out[12]) {
    if (risk >= 75) strcpy(out, "ALTO");
    else if (risk >= 45) strcpy(out, "MEDIO");
    else strcpy(out, "BAJO");
}

static void push_event(const char *type, const char *ssid, const char *bssid,
                       const char *detail, uint8_t risk) {
    memmove(&summary.events[1], &summary.events[0],
            sizeof(audit_event_t) * (AUDIT_MAX_EVENTS - 1));
    audit_event_t *ev = &summary.events[0];
    memset(ev, 0, sizeof(*ev));
    ev->uptime_s = now_s();
    snprintf(ev->type, sizeof(ev->type), "%s", type);
    snprintf(ev->ssid, sizeof(ev->ssid), "%s", ssid && ssid[0] ? ssid : "(oculto)");
    snprintf(ev->bssid, sizeof(ev->bssid), "%s", bssid);
    snprintf(ev->detail, sizeof(ev->detail), "%s", detail);
    ev->risk = risk;
    if (summary.event_count < AUDIT_MAX_EVENTS) summary.event_count++;
}

static void json_escape(char *out, int outlen, const char *in) {
    int pos = 0;
    for (int i = 0; in && in[i] && pos < outlen - 1; i++) {
        char c = in[i];
        if ((c == '"' || c == '\\') && pos < outlen - 2) {
            out[pos++] = '\\';
            out[pos++] = c;
        } else if ((unsigned char)c >= 32) {
            out[pos++] = c;
        }
    }
    out[pos] = '\0';
}

void audit_init(void) {
    memset(&summary, 0, sizeof(summary));
    strcpy(summary.risk_label, "BAJO");
    strcpy(summary.top_issue, "Sin escaneo aun");
}

void audit_update_from_scan(const wifictl_ap_records_t *records) {
    if (!records) return;

    uint16_t channel_count[15] = {0};
    uint16_t open_count = 0;
    uint16_t weak_count = 0;
    uint16_t twin_count = 0;
    uint8_t risk = 0;
    char top_issue[64] = "Sin riesgos criticos";

    for (unsigned i = 0; i < records->count; i++) {
        const wifi_ap_record_t *ap = &records->records[i];
        char ssid[33], bssid[18], detail[64];
        copy_ssid(ssid, ap->ssid);
        bssid_to_str(ap->bssid, bssid);

        if (ap->primary < 15) channel_count[ap->primary]++;

        if (ap->authmode == WIFI_AUTH_OPEN) {
            open_count++;
            if (risk < 70) {
                risk = 70;
                snprintf(top_issue, sizeof(top_issue), "Red abierta: %s", ssid[0] ? ssid : "(oculta)");
            }
            snprintf(detail, sizeof(detail), "%s canal %u RSSI %d", auth_label(ap->authmode), ap->primary, ap->rssi);
            push_event("RED_ABIERTA", ssid, bssid, detail, 70);
        } else if (is_weak_auth(ap->authmode)) {
            weak_count++;
            if (risk < 55) {
                risk = 55;
                snprintf(top_issue, sizeof(top_issue), "Cifrado debil: %s", ssid[0] ? ssid : "(oculta)");
            }
            snprintf(detail, sizeof(detail), "%s canal %u RSSI %d", auth_label(ap->authmode), ap->primary, ap->rssi);
            push_event("CIFRADO_DEBIL", ssid, bssid, detail, 55);
        }
    }

    for (unsigned i = 0; i < records->count; i++) {
        const wifi_ap_record_t *a = &records->records[i];
        char ssid_a[33], bssid_a[18], detail[64];
        copy_ssid(ssid_a, a->ssid);
        if (!ssid_a[0]) continue;

        for (unsigned j = i + 1; j < records->count; j++) {
            const wifi_ap_record_t *b = &records->records[j];
            char ssid_b[33];
            copy_ssid(ssid_b, b->ssid);
            if (strcmp(ssid_a, ssid_b) != 0) continue;
            if (memcmp(a->bssid, b->bssid, 6) == 0) continue;
            if (a->authmode != b->authmode || a->primary != b->primary || abs(a->rssi - b->rssi) > 25) {
                twin_count++;
                bssid_to_str(b->bssid, bssid_a);
                snprintf(detail, sizeof(detail), "Mismo SSID canal %u/%u RSSI %d/%d",
                         a->primary, b->primary, a->rssi, b->rssi);
                push_event("EVIL_TWIN?", ssid_a, bssid_a, detail, 80);
                if (risk < 80) {
                    risk = 80;
                    snprintf(top_issue, sizeof(top_issue), "Evil Twin sospechoso: %s", ssid_a);
                }
            }
        }
    }

    uint16_t crowded = 0;
    for (int ch = 1; ch <= 14; ch++) {
        if (channel_count[ch] >= 4) crowded++;
    }
    if (crowded && risk < 40) {
        risk = 40;
        snprintf(top_issue, sizeof(top_issue), "Canales saturados detectados");
    }

    if (summary.deauth_frames >= 10 && risk < 85) {
        risk = 85;
        snprintf(top_issue, sizeof(top_issue), "Posible deauth/disassoc detectado");
    }

    summary.last_scan_s = now_s();
    summary.networks = records->count;
    summary.open_networks = open_count;
    summary.weak_networks = weak_count;
    summary.evil_twin_suspects = twin_count;
    summary.crowded_channels = crowded;
    summary.risk_score = risk;
    risk_label(risk, summary.risk_label);
    snprintf(summary.top_issue, sizeof(summary.top_issue), "%s", top_issue);
}

void audit_note_deauth_frame(const uint8_t *frame, unsigned len, int8_t rssi, uint8_t channel) {
    if (!frame || len < 24) return;
    uint8_t type = (frame[0] & 0x0C) >> 2;
    uint8_t subtype = (frame[0] & 0xF0) >> 4;
    if (type != 0 || (subtype != 10 && subtype != 12)) return;

    summary.deauth_frames++;
    if ((summary.deauth_frames == 1) || (summary.deauth_frames % 10 == 0)) {
        char bssid[18], detail[64];
        bssid_to_str(&frame[10], bssid);
        snprintf(detail, sizeof(detail), "subtipo %u canal %u RSSI %d total %u",
                 subtype, channel, rssi, summary.deauth_frames);
        push_event("DEAUTH", "(gestion)", bssid, detail, 85);
        if (summary.risk_score < 85) {
            summary.risk_score = 85;
            risk_label(summary.risk_score, summary.risk_label);
            snprintf(summary.top_issue, sizeof(summary.top_issue), "Posible deauth/disassoc detectado");
        }
    }
}

const audit_summary_t *audit_get_summary(void) {
    return &summary;
}

int audit_write_json(char *out, int outlen) {
    char issue[80];
    json_escape(issue, sizeof(issue), summary.top_issue);
    int pos = snprintf(out, outlen,
        "{\"last_scan_s\":%lu,\"networks\":%u,\"open\":%u,\"weak\":%u,"
        "\"evil_twin\":%u,\"crowded_channels\":%u,\"deauth\":%u,"
        "\"risk_score\":%u,\"risk_label\":\"%s\",\"top_issue\":\"%s\",\"events\":[",
        (unsigned long)summary.last_scan_s, summary.networks, summary.open_networks,
        summary.weak_networks, summary.evil_twin_suspects, summary.crowded_channels,
        summary.deauth_frames, summary.risk_score, summary.risk_label, issue);

    for (uint8_t i = 0; i < summary.event_count && pos < outlen - 8; i++) {
        char ssid[40], detail[80];
        json_escape(ssid, sizeof(ssid), summary.events[i].ssid);
        json_escape(detail, sizeof(detail), summary.events[i].detail);
        pos += snprintf(out + pos, outlen - pos,
            "%s{\"uptime_s\":%lu,\"type\":\"%s\",\"ssid\":\"%s\",\"bssid\":\"%s\",\"detail\":\"%s\",\"risk\":%u}",
            i ? "," : "", (unsigned long)summary.events[i].uptime_s, summary.events[i].type,
            ssid, summary.events[i].bssid, detail, summary.events[i].risk);
    }
    pos += snprintf(out + pos, outlen - pos, "]}");
    return pos;
}

int audit_write_csv(char *out, int outlen) {
    int pos = snprintf(out, outlen, "uptime_s,type,ssid,bssid,detail,risk\n");
    for (uint8_t i = 0; i < summary.event_count && pos < outlen - 96; i++) {
        pos += snprintf(out + pos, outlen - pos, "%lu,%s,\"%s\",%s,\"%s\",%u\n",
            (unsigned long)summary.events[i].uptime_s, summary.events[i].type,
            summary.events[i].ssid, summary.events[i].bssid,
            summary.events[i].detail, summary.events[i].risk);
    }
    return pos;
}

int audit_write_report(char *out, int outlen) {
    int pos = snprintf(out, outlen,
        "ChL-CyberKit - Reporte defensivo WiFi\n"
        "Ultimo escaneo: %lu s\n"
        "Redes: %u\n"
        "Riesgo: %u/100 %s\n"
        "Principal hallazgo: %s\n"
        "Redes abiertas: %u\n"
        "Cifrados debiles: %u\n"
        "Evil Twin sospechosos: %u\n"
        "Canales saturados: %u\n"
        "Tramas deauth/disassoc vistas: %u\n\n"
        "Eventos recientes\n",
        (unsigned long)summary.last_scan_s, summary.networks, summary.risk_score,
        summary.risk_label, summary.top_issue, summary.open_networks,
        summary.weak_networks, summary.evil_twin_suspects, summary.crowded_channels,
        summary.deauth_frames);

    for (uint8_t i = 0; i < summary.event_count && pos < outlen - 100; i++) {
        pos += snprintf(out + pos, outlen - pos, "- %lu %s %s %s %s riesgo=%u\n",
            (unsigned long)summary.events[i].uptime_s, summary.events[i].type,
            summary.events[i].ssid, summary.events[i].bssid,
            summary.events[i].detail, summary.events[i].risk);
    }
    return pos;
}
