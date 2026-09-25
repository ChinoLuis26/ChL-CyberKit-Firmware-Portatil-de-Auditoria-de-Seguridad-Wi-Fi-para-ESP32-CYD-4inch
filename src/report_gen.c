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
 * @file report_gen.c
 * @brief Implementación del generador de reportes HTML.
 *
 * @author Pedro Luis Rezabala — ChL-CyberKit v1.0 PRO
 */
#include "report_gen.h"
#include "beacon_parser.h"
#include "probe_logger.h"
#include "wifi_audit.h"
#include "sd_storage.h"

#include <stdio.h>
#include <string.h>
#include "esp_log.h"
#include "esp_timer.h"

static const char *TAG = "report_gen";

/* Contador de reportes */
static uint8_t g_report_count = 0;

/* ── Helper: escribir una línea al archivo y al buffer interno ──────────── */
/* Para no consumir todo el heap con un string gigante, escribimos directamente
 * al archivo de SD en bloques pequeños mediante sd_append_line().            */

/* ── Cabecera HTML ──────────────────────────────────────────────────────── */
static void write_head(const char *path) {
    sd_append_line(path,
        "<!DOCTYPE html><html lang='es'><head>"
        "<meta charset='UTF-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>ChL-CyberKit — Reporte de Auditoría</title>"
        "<style>"
        "body{font-family:Arial,sans-serif;background:#0d1117;color:#c9d1d9;margin:0;padding:16px}"
        "h1{color:#58a6ff;border-bottom:1px solid #30363d;padding-bottom:8px}"
        "h2{color:#79c0ff;margin-top:32px}"
        "table{border-collapse:collapse;width:100%;margin-bottom:24px;font-size:13px}"
        "th{background:#161b22;color:#58a6ff;padding:8px;text-align:left;border:1px solid #30363d}"
        "td{padding:6px 8px;border:1px solid #21262d}"
        "tr:nth-child(even){background:#161b22}"
        ".ok{color:#3fb950}.warn{color:#d29922}.bad{color:#f85149}"
        ".tag{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold}"
        ".tag-wps{background:#d29922;color:#000}"
        ".tag-pmf{background:#3fb950;color:#000}"
        ".tag-pmfr{background:#238636;color:#fff}"
        ".tag-open{background:#f85149;color:#fff}"
        "footer{margin-top:48px;font-size:11px;color:#484f58;text-align:center}"
        "</style></head><body>"
        "<h1>&#128737; ChL-CyberKit v1.0 PRO — Reporte de Auditoría WiFi</h1>"
    );
}

/* ── Sección: resumen de auditoría ──────────────────────────────────────── */
static void write_audit_section(const char *path) {
    const audit_summary_t *sum = audit_get_summary();
    if (!sum) {
        sd_append_line(path, "<h2>&#128202; Resumen de Auditoría</h2><p>Sin datos.</p>");
        return;
    }

    char line[256];
    snprintf(line, sizeof(line),
             "<h2>&#128202; Resumen de Auditoría</h2>"
             "<table><tr><th>Parámetro</th><th>Valor</th></tr>"
             "<tr><td>Riesgo Global</td><td class='%s'>%s (%d/100)</td></tr>"
             "<tr><td>Total APs</td><td>%d</td></tr>"
             "<tr><td>Redes Abiertas</td><td class='%s'>%d</td></tr>"
             "<tr><td>WEP/WPA Débil</td><td class='%s'>%d</td></tr>"
             "<tr><td>Canales Saturados</td><td>%d</td></tr>"
             "</table>",
             sum->risk_score >= 60 ? "bad" : sum->risk_score >= 30 ? "warn" : "ok",
             sum->risk_label, (int)sum->risk_score,
             (int)sum->networks,
             sum->open_networks > 0 ? "bad" : "ok", (int)sum->open_networks,
             sum->weak_networks > 0 ? "warn" : "ok", (int)sum->weak_networks,
             (int)sum->crowded_channels);
    sd_append_line(path, line);
}

/* ── Sección: tabla de redes detectadas ─────────────────────────────────── */
static void write_networks_section(const char *path) {
    uint8_t ap_count = beacon_parser_ap_count();

    sd_append_line(path,
        "<h2>&#128225; Redes Detectadas (Beacon Parser)</h2>"
        "<table>"
        "<tr><th>#</th><th>SSID</th><th>BSSID</th>"
        "<th>Ch</th><th>RSSI</th><th>WPS</th><th>PMF</th><th>Clientes</th></tr>"
    );

    char line[256];
    for (uint8_t i = 0; i < ap_count; i++) {
        const bp_ap_info_t *ap = beacon_parser_get_ap(i);
        if (!ap) continue;

        const char *wps_tag  = ap->wps_enabled
            ? "<span class='tag tag-wps'>WPS</span>" : "—";
        const char *pmf_tag;
        if (ap->pmf_required)
            pmf_tag = "<span class='tag tag-pmfr'>REQ</span>";
        else if (ap->pmf_capable)
            pmf_tag = "<span class='tag tag-pmf'>CAP</span>";
        else
            pmf_tag = "—";

        snprintf(line, sizeof(line),
                 "<tr><td>%d</td>"
                 "<td>%s</td>"
                 "<td>%02X:%02X:%02X:%02X:%02X:%02X</td>"
                 "<td>%d</td>"
                 "<td class='%s'>%d</td>"
                 "<td>%s</td>"
                 "<td>%s</td>"
                 "<td>%d</td></tr>",
                 (int)(i + 1),
                 ap->ssid[0] ? ap->ssid : "(oculto)",
                 ap->bssid[0], ap->bssid[1], ap->bssid[2],
                 ap->bssid[3], ap->bssid[4], ap->bssid[5],
                 (int)ap->channel,
                 ap->rssi >= -60 ? "ok" : ap->rssi >= -80 ? "warn" : "bad",
                 (int)ap->rssi,
                 wps_tag, pmf_tag,
                 (int)ap->client_count);
        sd_append_line(path, line);
    }
    sd_append_line(path, "</table>");
}

/* ── Sección: probe requests ─────────────────────────────────────────────── */
static void write_probes_section(const char *path) {
    uint8_t dev_count = probe_logger_device_count();

    sd_append_line(path,
        "<h2>&#128270; Dispositivos Probe (Probe Logger)</h2>"
        "<table>"
        "<tr><th>#</th><th>MAC</th><th>Fabricante</th>"
        "<th>RSSI</th><th>Probes</th><th>SSIDs Buscados</th></tr>"
    );

    char line[512];
    for (uint8_t i = 0; i < dev_count; i++) {
        const probe_device_t *d = probe_logger_get_device(i);
        if (!d) continue;

        /* Construir lista de SSIDs */
        char ssid_list[256] = {0};
        for (uint8_t j = 0; j < d->ssid_count; j++) {
            if (j > 0) strncat(ssid_list, ", ", sizeof(ssid_list) - strlen(ssid_list) - 1);
            strncat(ssid_list, d->ssids[j], sizeof(ssid_list) - strlen(ssid_list) - 1);
        }
        if (d->ssid_count == 0) strncpy(ssid_list, "(wildcard)", sizeof(ssid_list) - 1);

        snprintf(line, sizeof(line),
                 "<tr><td>%d</td>"
                 "<td>%02X:%02X:%02X:%02X:%02X:%02X</td>"
                 "<td>%s</td>"
                 "<td class='%s'>%d</td>"
                 "<td>%lu</td>"
                 "<td>%s</td></tr>",
                 (int)(i + 1),
                 d->mac[0], d->mac[1], d->mac[2],
                 d->mac[3], d->mac[4], d->mac[5],
                 d->vendor,
                 d->rssi_last >= -60 ? "ok" : d->rssi_last >= -80 ? "warn" : "bad",
                 (int)d->rssi_last,
                 (unsigned long)d->count,
                 ssid_list);
        sd_append_line(path, line);
    }
    sd_append_line(path, "</table>");
}

/* ── Sección: footer ────────────────────────────────────────────────────── */
static void write_footer(const char *path) {
    char line[256];
    uint32_t uptime_s = (uint32_t)(esp_timer_get_time() / 1000000ULL);
    snprintf(line, sizeof(line),
             "<footer>"
             "ChL-CyberKit v1.0 PRO &mdash; Autor: Pedro Luis Rezabala &mdash; "
             "Uptime: %lus &mdash; SOLO USO EN LABORATORIO AUTORIZADO"
             "</footer></body></html>",
             (unsigned long)uptime_s);
    sd_append_line(path, line);
}

/* ── report_gen_save() ──────────────────────────────────────────────────── */
report_result_t report_gen_save(char *out_path, int path_len) {
    if (!sd_storage_available()) {
        ESP_LOGW(TAG, "SD no disponible");
        return RG_ERR_SD;
    }

    /* Encontrar nombre libre */
    char path[64];
    snprintf(path, sizeof(path), "/CyberKit/report_%04d.html",
             (int)(g_report_count + 1));

    ESP_LOGI(TAG, "Generando reporte: %s", path);

    /* Inicializar archivo (crear vacío) */
    sd_append_line(path, "");  /* Crear/truncar */

    write_head(path);
    write_audit_section(path);
    write_networks_section(path);
    write_probes_section(path);
    write_footer(path);

    g_report_count++;

    if (out_path && path_len > 0) {
        strncpy(out_path, path, (size_t)(path_len - 1));
        out_path[path_len - 1] = '\0';
    }

    ESP_LOGI(TAG, "Reporte guardado: %s", path);
    return RG_OK;
}

uint8_t report_gen_count(void) { return g_report_count; }
