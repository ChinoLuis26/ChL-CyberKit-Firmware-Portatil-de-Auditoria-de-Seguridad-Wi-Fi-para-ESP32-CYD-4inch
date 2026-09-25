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
 * @file wifi_audit.h
 * @brief Auditoria pasiva defensiva para redes WiFi cercanas.
 */
#ifndef WIFI_AUDIT_H
#define WIFI_AUDIT_H

#include <stdint.h>
#include "ap_scanner.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AUDIT_MAX_EVENTS 12

typedef struct {
    uint32_t uptime_s;
    char type[20];
    char ssid[33];
    char bssid[18];
    char detail[64];
    uint8_t risk;
} audit_event_t;

typedef struct {
    uint32_t last_scan_s;
    uint16_t networks;
    uint16_t open_networks;
    uint16_t weak_networks;
    uint16_t evil_twin_suspects;
    uint16_t crowded_channels;
    uint16_t deauth_frames;
    uint8_t risk_score;
    char risk_label[12];
    char top_issue[64];
    audit_event_t events[AUDIT_MAX_EVENTS];
    uint8_t event_count;
} audit_summary_t;

void audit_init(void);
void audit_update_from_scan(const wifictl_ap_records_t *records);
void audit_note_deauth_frame(const uint8_t *frame, unsigned len, int8_t rssi, uint8_t channel);
const audit_summary_t *audit_get_summary(void);

int audit_write_json(char *out, int outlen);
int audit_write_csv(char *out, int outlen);
int audit_write_report(char *out, int outlen);

#ifdef __cplusplus
}
#endif

#endif
