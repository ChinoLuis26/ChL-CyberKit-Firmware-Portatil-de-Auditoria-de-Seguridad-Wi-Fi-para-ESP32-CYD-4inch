/**
 * @file webserver.c
 * @brief Servidor HTTP con REST API completa — ChL-CyberKit v1.0 PRO
 *
 * Expone el panel web de control y una REST API JSON para todos los módulos:
 *   Beacon Flood, Evil Twin, Karma Attack, BLE Scanner, Probe Logger,
 *   Auto Audit, Channel Hopper, captura de handshakes/PMKID y archivos SD.
 *
 * Autenticación: HTTP Basic Auth (usuario: chl, contraseña: CyberKit2026)
 *
 * @author Pedro Luis Rezabala Delgado — ChL-CyberKit v1.0 PRO
 * @copyright Copyright (C) 2026 Pedro Luis Rezabala Delgado. GPL v3.
 *
 * This file is part of ChL-CyberKit.
 * ChL-CyberKit is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License v3 as published by the
 * Free Software Foundation.
 */
#include "webserver.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_err.h"
#include "esp_event.h"
#include "esp_http_server.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "wifi_controller.h"
#include "wifi_audit.h"
#include "attack.h"
#include "pcap_serializer.h"
#include "hccapx_serializer.h"
#include "beacon_flood.h"
#include "evil_twin.h"
#include "karma.h"
#include "probe_logger.h"
#include "auto_audit.h"
#include "ble_scanner.h"
#include "sd_storage.h"
#include "pages/page_index.h"

static const char *TAG = "webserver";
ESP_EVENT_DEFINE_BASE(WEBSERVER_EVENTS);

/* ─── HTTP Basic Auth ────────────────────────────────────────────────────────
 * Usuario: chl   Contraseña: CyberKit2026
 * Base64("chl:CyberKit2026") = Y2hsOkN5YmVyS2l0MjAyNg==
 * ─────────────────────────────────────────────────────────────────────────── */
#define AUTH_HEADER "Basic Y2hsOkN5YmVyS2l0MjAyNg=="

/* ─── Helpers internos ───────────────────────────────────────────────────── */

static bool check_auth(httpd_req_t *req) {
    char auth[96] = {0};
    if (httpd_req_get_hdr_value_str(req, "Authorization", auth, sizeof(auth)) == ESP_OK) {
        if (strncmp(auth, AUTH_HEADER, strlen(AUTH_HEADER)) == 0) return true;
    }
    httpd_resp_set_status(req, "401 Unauthorized");
    httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"ChL-CyberKit\"");
    httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
    httpd_resp_send(req, "No autorizado", HTTPD_RESP_USE_STRLEN);
    return false;
}

static void set_json_headers(httpd_req_t *req) {
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
    httpd_resp_set_hdr(req, "Cache-Control", "no-cache");
}

/** Leer cuerpo de POST en buf (max bytes). Retorna bytes leídos. */
static int read_body(httpd_req_t *req, char *buf, int max) {
    int total = req->content_len < (max - 1) ? req->content_len : (max - 1);
    if (total <= 0) { buf[0] = '\0'; return 0; }
    int got = httpd_req_recv(req, buf, total);
    buf[got > 0 ? got : 0] = '\0';
    return got;
}

/** Extraer campo entero de JSON minimalista. */
static int json_get_int(const char *json, const char *key, int def) {
    char k[48];
    snprintf(k, sizeof(k), "\"%s\"", key);
    const char *p = strstr(json, k);
    if (!p) return def;
    p = strchr(p + strlen(k), ':');
    if (!p) return def;
    while (*(++p) == ' ');
    return atoi(p);
}

/** Formatear MAC como "AA:BB:CC:DD:EE:FF" en buf (18 bytes mínimo). */
static void fmt_mac(const uint8_t *m, char *buf) {
    snprintf(buf, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             m[0], m[1], m[2], m[3], m[4], m[5]);
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  GET /
 * ═══════════════════════════════════════════════════════════════════════════ */
static esp_err_t uri_root_get_handler(httpd_req_t *req) {
    if (!check_auth(req)) return ESP_OK;
    httpd_resp_set_type(req, "text/html");
    httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
    /* NOTA: PAGE_INDEX_HTML es HTML crudo — NO usar Content-Encoding: gzip */
    return httpd_resp_send(req, PAGE_INDEX_HTML, sizeof(PAGE_INDEX_HTML) - 1);
}
static httpd_uri_t uri_root_get = {
    .uri = "/", .method = HTTP_GET, .handler = uri_root_get_handler
};

/* ═══════════════════════════════════════════════════════════════════════════
 *  HEAD /reset — detenerse/resetear ataque
 * ═══════════════════════════════════════════════════════════════════════════ */
static esp_err_t uri_reset_head_handler(httpd_req_t *req) {
    ESP_ERROR_CHECK(esp_event_post(WEBSERVER_EVENTS, WEBSERVER_EVENT_ATTACK_RESET,
                                   NULL, 0, portMAX_DELAY));
    return httpd_resp_send(req, NULL, 0);
}
static httpd_uri_t uri_reset_head = {
    .uri = "/reset", .method = HTTP_HEAD, .handler = uri_reset_head_handler
};

/* ═══════════════════════════════════════════════════════════════════════════
 *  GET /ap-list — lista binaria de APs (42 bytes × N)
 *
 *  Formato por registro (42 bytes):
 *    [0-31]  SSID (32 bytes, null-padded)
 *    [32]    Canal primario (uint8)
 *    [33]    RSSI (int8 como uint8 — JS hace value-256)
 *    [34]    Modo de autenticación (uint8)
 *    [35-40] BSSID (6 bytes)
 *    [41]    Padding (0)
 * ═══════════════════════════════════════════════════════════════════════════ */
static esp_err_t uri_ap_list_get_handler(httpd_req_t *req) {
    if (!check_auth(req)) return ESP_OK;
    wifictl_scan_nearby_aps();
    audit_update_from_scan(wifictl_get_ap_records());

    const wifictl_ap_records_t *recs = wifictl_get_ap_records();
    uint8_t chunk[42];

    ESP_ERROR_CHECK(httpd_resp_set_type(req, HTTPD_TYPE_OCTET));
    httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");

    for (unsigned i = 0; i < recs->count; i++) {
        memset(chunk, 0, sizeof(chunk));
        /* SSID en bytes 0-31 (max 32 chars, null-padded) */
        uint8_t sl = (uint8_t)strlen((const char *)recs->records[i].ssid);
        if (sl > 32) sl = 32;
        memcpy(&chunk[0], recs->records[i].ssid, sl);
        chunk[32] = recs->records[i].primary;             /* canal    */
        chunk[33] = (uint8_t)(int8_t)recs->records[i].rssi; /* RSSI  */
        chunk[34] = (uint8_t)recs->records[i].authmode;  /* auth     */
        memcpy(&chunk[35], recs->records[i].bssid, 6);   /* BSSID    */
        ESP_ERROR_CHECK(httpd_resp_send_chunk(req, (char *)chunk, 42));
    }
    return httpd_resp_send_chunk(req, NULL, 0);
}
static httpd_uri_t uri_ap_list_get = {
    .uri = "/ap-list", .method = HTTP_GET, .handler = uri_ap_list_get_handler
};

/* ═══════════════════════════════════════════════════════════════════════════
 *  POST /run-attack — lanzar ataque (binario attack_request_t)
 * ═══════════════════════════════════════════════════════════════════════════ */
static esp_err_t uri_run_attack_post_handler(httpd_req_t *req) {
    if (!check_auth(req)) return ESP_OK;
    attack_request_t attack_request;
    memset(&attack_request, 0, sizeof(attack_request));
    httpd_req_recv(req, (char *)&attack_request, sizeof(attack_request_t));
    esp_err_t res = httpd_resp_send(req, NULL, 0);
    ESP_ERROR_CHECK(esp_event_post(WEBSERVER_EVENTS, WEBSERVER_EVENT_ATTACK_REQUEST,
                                   &attack_request, sizeof(attack_request_t), portMAX_DELAY));
    return res;
}
static httpd_uri_t uri_run_attack_post = {
    .uri = "/run-attack", .method = HTTP_POST, .handler = uri_run_attack_post_handler
};

/* ═══════════════════════════════════════════════════════════════════════════
 *  GET /status — estado binario del ataque (legacy)
 * ═══════════════════════════════════════════════════════════════════════════ */
static esp_err_t uri_status_get_handler(httpd_req_t *req) {
    if (!check_auth(req)) return ESP_OK;
    const attack_status_t *st = attack_get_status();
    ESP_ERROR_CHECK(httpd_resp_set_type(req, HTTPD_TYPE_OCTET));
    httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
    ESP_ERROR_CHECK(httpd_resp_send_chunk(req, (char *)st, 4));
    if ((st->state == FINISHED || st->state == TIMEOUT) && st->content_size > 0)
        ESP_ERROR_CHECK(httpd_resp_send_chunk(req, st->content, st->content_size));
    return httpd_resp_send_chunk(req, NULL, 0);
}
static httpd_uri_t uri_status_get = {
    .uri = "/status", .method = HTTP_GET, .handler = uri_status_get_handler
};

/* ═══════════════════════════════════════════════════════════════════════════
 *  GET /capture.pcap
 * ═══════════════════════════════════════════════════════════════════════════ */
static esp_err_t uri_pcap_get_handler(httpd_req_t *req) {
    httpd_resp_set_type(req, HTTPD_TYPE_OCTET);
    httpd_resp_set_hdr(req, "Content-Disposition",
                       "attachment; filename=\"capture.pcap\"");
    return httpd_resp_send(req, (char *)pcap_serializer_get_buffer(),
                           pcap_serializer_get_size());
}
static httpd_uri_t uri_pcap_get = {
    .uri = "/capture.pcap", .method = HTTP_GET, .handler = uri_pcap_get_handler
};

/* ═══════════════════════════════════════════════════════════════════════════
 *  GET /capture.hccapx
 * ═══════════════════════════════════════════════════════════════════════════ */
static esp_err_t uri_hccapx_get_handler(httpd_req_t *req) {
    httpd_resp_set_type(req, HTTPD_TYPE_OCTET);
    httpd_resp_set_hdr(req, "Content-Disposition",
                       "attachment; filename=\"capture.hccapx\"");
    return httpd_resp_send(req, (char *)hccapx_serializer_get(), sizeof(hccapx_t));
}
static httpd_uri_t uri_hccapx_get = {
    .uri = "/capture.hccapx", .method = HTTP_GET, .handler = uri_hccapx_get_handler
};

/* ═══════════════════════════════════════════════════════════════════════════
 *  GET /capture.hc22000 — formato hashcat WPA*02
 * ═══════════════════════════════════════════════════════════════════════════ */
static esp_err_t uri_hc22000_get_handler(httpd_req_t *req) {
    hccapx_t *hx = hccapx_serializer_get();
    if (!hx) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Sin datos");

    char line[1100]; int pos = 0;
    pos += snprintf(line + pos, sizeof(line) - pos, "WPA*02*");
    for (int i = 0; i < 16; i++)
        pos += snprintf(line + pos, sizeof(line) - pos, "%02x", hx->keymic[i]);
    pos += snprintf(line + pos, sizeof(line) - pos, "*");
    for (int i = 0; i < 6; i++)
        pos += snprintf(line + pos, sizeof(line) - pos, "%02x", hx->mac_ap[i]);
    pos += snprintf(line + pos, sizeof(line) - pos, "*");
    for (int i = 0; i < 6; i++)
        pos += snprintf(line + pos, sizeof(line) - pos, "%02x", hx->mac_sta[i]);
    pos += snprintf(line + pos, sizeof(line) - pos, "*");
    uint8_t sl = hx->essid_len < 32 ? hx->essid_len : 32;
    for (int i = 0; i < sl; i++)
        pos += snprintf(line + pos, sizeof(line) - pos, "%02x", hx->essid[i]);
    pos += snprintf(line + pos, sizeof(line) - pos, "*");
    for (int i = 0; i < 32; i++)
        pos += snprintf(line + pos, sizeof(line) - pos, "%02x", hx->nonce_ap[i]);
    pos += snprintf(line + pos, sizeof(line) - pos, "*");
    uint16_t el = hx->eapol_len < 256 ? hx->eapol_len : 256;
    for (int i = 0; i < el; i++)
        pos += snprintf(line + pos, sizeof(line) - pos, "%02x", hx->eapol[i]);
    pos += snprintf(line + pos, sizeof(line) - pos, "*\n");

    httpd_resp_set_type(req, "text/plain");
    httpd_resp_set_hdr(req, "Content-Disposition",
                       "attachment; filename=\"capture.hc22000\"");
    httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
    return httpd_resp_send(req, line, pos);
}
static httpd_uri_t uri_hc22000_get = {
    .uri = "/capture.hc22000", .method = HTTP_GET, .handler = uri_hc22000_get_handler
};

/* ═══════════════════════════════════════════════════════════════════════════
 *  GET /audit.json
 * ═══════════════════════════════════════════════════════════════════════════ */
static esp_err_t uri_audit_json_get_handler(httpd_req_t *req) {
    if (!check_auth(req)) return ESP_OK;
    static char json[3072];
    int len = audit_write_json(json, sizeof(json));
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
    return httpd_resp_send(req, json, len);
}
static httpd_uri_t uri_audit_json_get = {
    .uri = "/audit.json", .method = HTTP_GET, .handler = uri_audit_json_get_handler
};

/* ═══════════════════════════════════════════════════════════════════════════
 *  GET /audit.csv
 * ═══════════════════════════════════════════════════════════════════════════ */
static esp_err_t uri_audit_csv_get_handler(httpd_req_t *req) {
    if (!check_auth(req)) return ESP_OK;
    static char csv[3072];
    int len = audit_write_csv(csv, sizeof(csv));
    httpd_resp_set_type(req, "text/csv");
    httpd_resp_set_hdr(req, "Content-Disposition",
                       "attachment; filename=\"wifi_audit.csv\"");
    httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
    return httpd_resp_send(req, csv, len);
}
static httpd_uri_t uri_audit_csv_get = {
    .uri = "/audit.csv", .method = HTTP_GET, .handler = uri_audit_csv_get_handler
};

/* ═══════════════════════════════════════════════════════════════════════════
 *  GET /audit-report.txt
 * ═══════════════════════════════════════════════════════════════════════════ */
static esp_err_t uri_audit_report_get_handler(httpd_req_t *req) {
    if (!check_auth(req)) return ESP_OK;
    static char report[4096];
    int len = audit_write_report(report, sizeof(report));
    httpd_resp_set_type(req, "text/plain");
    httpd_resp_set_hdr(req, "Content-Disposition",
                       "attachment; filename=\"wifi_audit_report.txt\"");
    httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
    return httpd_resp_send(req, report, len);
}
static httpd_uri_t uri_audit_report_get = {
    .uri = "/audit-report.txt", .method = HTTP_GET, .handler = uri_audit_report_get_handler
};

/* ═══════════════════════════════════════════════════════════════════════════
 *  HEAD /audit-scan — disparar escaneo pasivo
 * ═══════════════════════════════════════════════════════════════════════════ */
static esp_err_t uri_audit_scan_head_handler(httpd_req_t *req) {
    if (!check_auth(req)) return ESP_OK;
    wifictl_scan_nearby_aps();
    audit_update_from_scan(wifictl_get_ap_records());
    return httpd_resp_send(req, NULL, 0);
}
static httpd_uri_t uri_audit_scan_head = {
    .uri = "/audit-scan", .method = HTTP_HEAD, .handler = uri_audit_scan_head_handler
};

/* ═══════════════════════════════════════════════════════════════════════════
 *  GET /api/status — estado JSON completo de todos los módulos
 *
 *  Llamado cada 3 segundos por el panel web.
 * ═══════════════════════════════════════════════════════════════════════════ */
static esp_err_t uri_api_status_handler(httpd_req_t *req) {
    if (!check_auth(req)) return ESP_OK;

    const attack_status_t   *atk = attack_get_status();
    auto_audit_status_t      aa  = auto_audit_get_status();
    karma_stats_t            ks  = karma_get_stats();
    beacon_flood_state_t     bfs = beacon_flood_get_state();
    evil_twin_state_t        ets = evil_twin_get_state();
    karma_state_t            kas = karma_get_state();
    ble_state_t              bles = ble_scanner_get_state();

    wifi_sta_list_t sta_list;
    uint8_t cli = 0;
    if (esp_wifi_ap_get_sta_list(&sta_list) == ESP_OK) cli = (uint8_t)sta_list.num;

    char ka_mac[18] = "00:00:00:00:00:00";
    fmt_mac(ks.last_client, ka_mac);

    /* Mapear estados a strings */
    const char *aa_states[] = {"IDLE","SCANNING","ATTACKING","SAVING","DONE"};
    const char *aa_str = aa_states[aa.state < 5 ? aa.state : 0];
    const char *atk_states[] = {"READY","RUNNING","FINISHED","TIMEOUT"};
    const char *atk_str = atk_states[atk->state < 4 ? atk->state : 0];

    static char json[1024];
    int pos = snprintf(json, sizeof(json),
        "{"
        "\"uptime_s\":%lu,"
        "\"clients\":%u,"
        "\"captures\":%u,"
        "\"net_count\":%u,"
        "\"probe_count\":%u,"
        "\"ble_count\":%u,"
        "\"bf_state\":\"%s\","
        "\"bf_count\":%lu,"
        "\"et_state\":\"%s\","
        "\"et_creds\":%u,"
        "\"ka_state\":\"%s\","
        "\"ka_probes\":%lu,"
        "\"ka_responses\":%lu,"
        "\"ka_unique\":%lu,"
        "\"ka_last_ssid\":\"%s\","
        "\"ka_last_sta\":\"%s\","
        "\"aa_state\":\"%s\","
        "\"aa_total\":%u,"
        "\"aa_done\":%u,"
        "\"aa_caps\":%u,"
        "\"aa_pmf\":%u,"
        "\"aa_ssid\":\"%s\","
        "\"ble_state\":\"%s\","
        "\"atk_state\":\"%s\""
        "}",
        (unsigned long)(xTaskGetTickCount() * portTICK_PERIOD_MS / 1000),
        cli,
        sd_capture_count(),
        (unsigned)wifictl_get_ap_records()->count,
        (unsigned)probe_logger_device_count(),
        (unsigned)ble_scanner_device_count(),
        bfs == BF_RUNNING ? "RUNNING" : "IDLE",
        (unsigned long)beacon_flood_count(),
        ets == ET_RUNNING ? "RUNNING" : (ets == ET_STOPPING ? "STOPPING" : "IDLE"),
        (unsigned)evil_twin_cred_count(),
        kas == KARMA_RUNNING ? "RUNNING" : "IDLE",
        (unsigned long)ks.probes_seen,
        (unsigned long)ks.responses_sent,
        (unsigned long)ks.unique_ssids,
        ks.last_ssid[0] ? ks.last_ssid : "-",
        ka_mac,
        aa_str,
        aa.targets_total,
        aa.targets_done,
        aa.captures,
        aa.skipped_pmf,
        aa.current_ssid[0] ? aa.current_ssid : "-",
        bles == BLE_RUNNING ? "RUNNING" : "IDLE",
        atk_str
    );
    (void)pos;

    set_json_headers(req);
    return httpd_resp_send(req, json, HTTPD_RESP_USE_STRLEN);
}
static httpd_uri_t uri_api_status = {
    .uri = "/api/status", .method = HTTP_GET, .handler = uri_api_status_handler
};

/* ═══════════════════════════════════════════════════════════════════════════
 *  POST /api/bf/start   {"channel":6,"rate_ms":20}
 * ═══════════════════════════════════════════════════════════════════════════ */
static esp_err_t uri_api_bf_start_handler(httpd_req_t *req) {
    if (!check_auth(req)) return ESP_OK;
    char body[128];
    read_body(req, body, sizeof(body));
    int ch      = json_get_int(body, "channel",  1);
    int rate_ms = json_get_int(body, "rate_ms",  20);
    if (ch < 1 || ch > 13) ch = 1;
    if (rate_ms < 5 || rate_ms > 5000) rate_ms = 20;
    bool ok = beacon_flood_start((uint8_t)ch, (uint32_t)rate_ms);
    set_json_headers(req);
    char resp[64];
    snprintf(resp, sizeof(resp), "{\"ok\":%s,\"channel\":%d,\"rate_ms\":%d}",
             ok ? "true" : "false", ch, rate_ms);
    return httpd_resp_send(req, resp, HTTPD_RESP_USE_STRLEN);
}
static httpd_uri_t uri_api_bf_start = {
    .uri = "/api/bf/start", .method = HTTP_POST, .handler = uri_api_bf_start_handler
};

/* ═══════════════════════════════════════════════════════════════════════════
 *  POST /api/bf/stop
 * ═══════════════════════════════════════════════════════════════════════════ */
static esp_err_t uri_api_bf_stop_handler(httpd_req_t *req) {
    if (!check_auth(req)) return ESP_OK;
    beacon_flood_stop();
    set_json_headers(req);
    return httpd_resp_send(req, "{\"ok\":true}", HTTPD_RESP_USE_STRLEN);
}
static httpd_uri_t uri_api_bf_stop = {
    .uri = "/api/bf/stop", .method = HTTP_POST, .handler = uri_api_bf_stop_handler
};

/* ═══════════════════════════════════════════════════════════════════════════
 *  POST /api/et/start   {"ap_id":0}
 * ═══════════════════════════════════════════════════════════════════════════ */
static esp_err_t uri_api_et_start_handler(httpd_req_t *req) {
    if (!check_auth(req)) return ESP_OK;
    char body[128];
    read_body(req, body, sizeof(body));
    int ap_id = json_get_int(body, "ap_id", -1);

    const wifictl_ap_records_t *recs = wifictl_get_ap_records();
    set_json_headers(req);

    if (ap_id < 0 || (unsigned)ap_id >= recs->count) {
        return httpd_resp_send(req, "{\"ok\":false,\"err\":\"ap_id invalido\"}",
                               HTTPD_RESP_USE_STRLEN);
    }

    const wifi_ap_record_t *ap = &recs->records[ap_id];
    evil_twin_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    strncpy(cfg.ssid, (const char *)ap->ssid, 32);
    memcpy(cfg.bssid, ap->bssid, 6);
    cfg.channel = ap->primary;

    bool ok = evil_twin_start(&cfg);
    char resp[128];
    snprintf(resp, sizeof(resp), "{\"ok\":%s,\"ssid\":\"%s\",\"channel\":%u}",
             ok ? "true" : "false", cfg.ssid, cfg.channel);
    return httpd_resp_send(req, resp, HTTPD_RESP_USE_STRLEN);
}
static httpd_uri_t uri_api_et_start = {
    .uri = "/api/et/start", .method = HTTP_POST, .handler = uri_api_et_start_handler
};

/* ═══════════════════════════════════════════════════════════════════════════
 *  POST /api/et/stop
 * ═══════════════════════════════════════════════════════════════════════════ */
static esp_err_t uri_api_et_stop_handler(httpd_req_t *req) {
    if (!check_auth(req)) return ESP_OK;
    evil_twin_stop();
    set_json_headers(req);
    return httpd_resp_send(req, "{\"ok\":true}", HTTPD_RESP_USE_STRLEN);
}
static httpd_uri_t uri_api_et_stop = {
    .uri = "/api/et/stop", .method = HTTP_POST, .handler = uri_api_et_stop_handler
};

/* ═══════════════════════════════════════════════════════════════════════════
 *  POST /api/karma/start   {"channel":6}
 * ═══════════════════════════════════════════════════════════════════════════ */
static esp_err_t uri_api_karma_start_handler(httpd_req_t *req) {
    if (!check_auth(req)) return ESP_OK;
    char body[128];
    read_body(req, body, sizeof(body));
    int ch = json_get_int(body, "channel", 6);
    if (ch < 1 || ch > 13) ch = 6;
    bool ok = karma_start((uint8_t)ch);
    set_json_headers(req);
    char resp[64];
    snprintf(resp, sizeof(resp), "{\"ok\":%s,\"channel\":%d}", ok ? "true" : "false", ch);
    return httpd_resp_send(req, resp, HTTPD_RESP_USE_STRLEN);
}
static httpd_uri_t uri_api_karma_start = {
    .uri = "/api/karma/start", .method = HTTP_POST, .handler = uri_api_karma_start_handler
};

/* ═══════════════════════════════════════════════════════════════════════════
 *  POST /api/karma/stop
 * ═══════════════════════════════════════════════════════════════════════════ */
static esp_err_t uri_api_karma_stop_handler(httpd_req_t *req) {
    if (!check_auth(req)) return ESP_OK;
    karma_stop();
    set_json_headers(req);
    return httpd_resp_send(req, "{\"ok\":true}", HTTPD_RESP_USE_STRLEN);
}
static httpd_uri_t uri_api_karma_stop = {
    .uri = "/api/karma/stop", .method = HTTP_POST, .handler = uri_api_karma_stop_handler
};

/* ═══════════════════════════════════════════════════════════════════════════
 *  POST /api/ble/start
 * ═══════════════════════════════════════════════════════════════════════════ */
static esp_err_t uri_api_ble_start_handler(httpd_req_t *req) {
    if (!check_auth(req)) return ESP_OK;
    bool ok = ble_scanner_start();
    set_json_headers(req);
    char resp[32];
    snprintf(resp, sizeof(resp), "{\"ok\":%s}", ok ? "true" : "false");
    return httpd_resp_send(req, resp, HTTPD_RESP_USE_STRLEN);
}
static httpd_uri_t uri_api_ble_start = {
    .uri = "/api/ble/start", .method = HTTP_POST, .handler = uri_api_ble_start_handler
};

/* ═══════════════════════════════════════════════════════════════════════════
 *  POST /api/ble/stop
 * ═══════════════════════════════════════════════════════════════════════════ */
static esp_err_t uri_api_ble_stop_handler(httpd_req_t *req) {
    if (!check_auth(req)) return ESP_OK;
    ble_scanner_stop();
    set_json_headers(req);
    return httpd_resp_send(req, "{\"ok\":true}", HTTPD_RESP_USE_STRLEN);
}
static httpd_uri_t uri_api_ble_stop = {
    .uri = "/api/ble/stop", .method = HTTP_POST, .handler = uri_api_ble_stop_handler
};

/* ═══════════════════════════════════════════════════════════════════════════
 *  POST /api/ble/clear
 * ═══════════════════════════════════════════════════════════════════════════ */
static esp_err_t uri_api_ble_clear_handler(httpd_req_t *req) {
    if (!check_auth(req)) return ESP_OK;
    ble_scanner_clear();
    set_json_headers(req);
    return httpd_resp_send(req, "{\"ok\":true}", HTTPD_RESP_USE_STRLEN);
}
static httpd_uri_t uri_api_ble_clear = {
    .uri = "/api/ble/clear", .method = HTTP_POST, .handler = uri_api_ble_clear_handler
};

/* ═══════════════════════════════════════════════════════════════════════════
 *  GET /api/ble/list — {"devices":[{mac,name,rssi,addr_type,seen},...]}
 * ═══════════════════════════════════════════════════════════════════════════ */
static esp_err_t uri_api_ble_list_handler(httpd_req_t *req) {
    if (!check_auth(req)) return ESP_OK;
    set_json_headers(req);

    httpd_resp_sendstr_chunk(req, "{\"devices\":[");
    uint8_t count = ble_scanner_device_count();
    for (uint8_t i = 0; i < count; i++) {
        const ble_device_t *d = ble_scanner_get_device(i);
        if (!d) continue;
        char mac[18];
        fmt_mac(d->addr, mac);
        char entry[128];
        int len = snprintf(entry, sizeof(entry),
            "%s{\"mac\":\"%s\",\"name\":\"%s\",\"rssi\":%d,"
            "\"addr_type\":%u,\"seen\":%u}",
            i > 0 ? "," : "", mac,
            d->name[0] ? d->name : "?",
            (int)d->rssi, d->addr_type, d->seen_count);
        httpd_resp_send_chunk(req, entry, len);
    }
    httpd_resp_sendstr_chunk(req, "]}");
    return httpd_resp_send_chunk(req, NULL, 0);
}
static httpd_uri_t uri_api_ble_list = {
    .uri = "/api/ble/list", .method = HTTP_GET, .handler = uri_api_ble_list_handler
};

/* ═══════════════════════════════════════════════════════════════════════════
 *  GET /api/probe/list — {"devices":[{mac,vendor,ssids[],rssi,count},...]}
 * ═══════════════════════════════════════════════════════════════════════════ */
static esp_err_t uri_api_probe_list_handler(httpd_req_t *req) {
    if (!check_auth(req)) return ESP_OK;
    set_json_headers(req);

    httpd_resp_sendstr_chunk(req, "{\"devices\":[");
    uint8_t count = probe_logger_device_count();
    for (uint8_t i = 0; i < count; i++) {
        const probe_device_t *d = probe_logger_get_device(i);
        if (!d) continue;
        char mac[18];
        fmt_mac(d->mac, mac);

        char entry[256]; int pos = 0;
        pos += snprintf(entry + pos, sizeof(entry) - pos,
            "%s{\"mac\":\"%s\",\"vendor\":\"%s\","
            "\"rssi\":%d,\"count\":%lu,\"ssids\":[",
            i > 0 ? "," : "", mac,
            d->vendor[0] ? d->vendor : "?",
            (int)d->rssi_last, (unsigned long)d->count);

        for (uint8_t s = 0; s < d->ssid_count && s < PROBE_MAX_SSIDS; s++) {
            if (pos < (int)sizeof(entry) - 40)
                pos += snprintf(entry + pos, sizeof(entry) - pos,
                    "%s\"%s\"", s > 0 ? "," : "", d->ssids[s]);
        }
        if (pos < (int)sizeof(entry) - 4)
            pos += snprintf(entry + pos, sizeof(entry) - pos, "]}");
        httpd_resp_send_chunk(req, entry, pos);
    }
    httpd_resp_sendstr_chunk(req, "]}");
    return httpd_resp_send_chunk(req, NULL, 0);
}
static httpd_uri_t uri_api_probe_list = {
    .uri = "/api/probe/list", .method = HTTP_GET, .handler = uri_api_probe_list_handler
};

/* ═══════════════════════════════════════════════════════════════════════════
 *  POST /api/probe/dump — volcar probes a SD
 * ═══════════════════════════════════════════════════════════════════════════ */
static esp_err_t uri_api_probe_dump_handler(httpd_req_t *req) {
    if (!check_auth(req)) return ESP_OK;
    probe_logger_dump_to_sd();
    set_json_headers(req);
    return httpd_resp_send(req, "{\"ok\":true}", HTTPD_RESP_USE_STRLEN);
}
static httpd_uri_t uri_api_probe_dump = {
    .uri = "/api/probe/dump", .method = HTTP_POST, .handler = uri_api_probe_dump_handler
};

/* ═══════════════════════════════════════════════════════════════════════════
 *  POST /api/probe/clear
 * ═══════════════════════════════════════════════════════════════════════════ */
static esp_err_t uri_api_probe_clear_handler(httpd_req_t *req) {
    if (!check_auth(req)) return ESP_OK;
    probe_logger_clear();
    set_json_headers(req);
    return httpd_resp_send(req, "{\"ok\":true}", HTTPD_RESP_USE_STRLEN);
}
static httpd_uri_t uri_api_probe_clear = {
    .uri = "/api/probe/clear", .method = HTTP_POST, .handler = uri_api_probe_clear_handler
};

/* ═══════════════════════════════════════════════════════════════════════════
 *  POST /api/audit/toggle — iniciar o detener Auto Audit
 * ═══════════════════════════════════════════════════════════════════════════ */
static esp_err_t uri_api_audit_toggle_handler(httpd_req_t *req) {
    if (!check_auth(req)) return ESP_OK;
    bool running;
    if (auto_audit_is_running()) {
        auto_audit_stop();
        running = false;
    } else {
        running = auto_audit_start();
    }
    set_json_headers(req);
    char resp[32];
    snprintf(resp, sizeof(resp), "{\"running\":%s}", running ? "true" : "false");
    return httpd_resp_send(req, resp, HTTPD_RESP_USE_STRLEN);
}
static httpd_uri_t uri_api_audit_toggle = {
    .uri = "/api/audit/toggle", .method = HTTP_POST,
    .handler = uri_api_audit_toggle_handler
};

/* ═══════════════════════════════════════════════════════════════════════════
 *  GET /api/credentials — credenciales capturadas por Evil Twin
 *  Lee /CyberKit/captures/creds.csv (formato: timestamp,user,pass,ip)
 * ═══════════════════════════════════════════════════════════════════════════ */
static esp_err_t uri_api_credentials_handler(httpd_req_t *req) {
    if (!check_auth(req)) return ESP_OK;
    set_json_headers(req);

    /* Usar sd_read_file para obtener el contenido del CSV */
    static char csv_buf[2048];
    int bytes = sd_read_file("/CyberKit/captures/creds.csv", csv_buf, sizeof(csv_buf) - 1);

    httpd_resp_sendstr_chunk(req, "{\"creds\":[");
    bool first = true;

    if (bytes > 0) {
        csv_buf[bytes] = '\0';
        char *line = strtok(csv_buf, "\n");
        while (line) {
            /* Saltar línea de cabecera */
            if (strncmp(line, "timestamp", 9) != 0 && strlen(line) > 4) {
                char ts[32]="",usr[64]="",pass[64]="",ip[20]="";
                /* Parsear CSV: timestamp,user,pass,ip */
                char *p = line;
                char *c1 = strchr(p, ',');
                if (c1) {
                    int l = c1 - p; if (l > 31) l = 31;
                    strncpy(ts, p, l); ts[l] = 0;
                    p = c1 + 1;
                    char *c2 = strchr(p, ',');
                    if (c2) {
                        l = c2 - p; if (l > 63) l = 63;
                        strncpy(usr, p, l); usr[l] = 0;
                        p = c2 + 1;
                        char *c3 = strchr(p, ',');
                        if (c3) {
                            l = c3 - p; if (l > 63) l = 63;
                            strncpy(pass, p, l); pass[l] = 0;
                            strncpy(ip, c3 + 1, 19); ip[19] = 0;
                            /* Quitar \r si lo hay */
                            char *cr = strchr(ip, '\r'); if(cr) *cr=0;
                        }
                    }
                }
                char entry[256];
                int elen = snprintf(entry, sizeof(entry),
                    "%s{\"ts\":\"%s\",\"user\":\"%s\",\"pass\":\"%s\",\"ip\":\"%s\"}",
                    first ? "" : ",", ts, usr, pass, ip);
                httpd_resp_send_chunk(req, entry, elen);
                first = false;
            }
            line = strtok(NULL, "\n");
        }
    }

    httpd_resp_sendstr_chunk(req, "]}");
    return httpd_resp_send_chunk(req, NULL, 0);
}
static httpd_uri_t uri_api_credentials = {
    .uri = "/api/credentials", .method = HTTP_GET,
    .handler = uri_api_credentials_handler
};

/* ═══════════════════════════════════════════════════════════════════════════
 *  GET /api/files — lista de archivos en la SD
 * ═══════════════════════════════════════════════════════════════════════════ */
static esp_err_t uri_api_files_handler(httpd_req_t *req) {
    if (!check_auth(req)) return ESP_OK;
    set_json_headers(req);

    static char json[4096];
    int len = sd_list_files_json(json, sizeof(json));
    if (len <= 0) {
        return httpd_resp_send(req, "{\"files\":[]}", HTTPD_RESP_USE_STRLEN);
    }
    return httpd_resp_send(req, json, len);
}
static httpd_uri_t uri_api_files = {
    .uri = "/api/files", .method = HTTP_GET, .handler = uri_api_files_handler
};

/* ═══════════════════════════════════════════════════════════════════════════
 *  GET /api/files/dl?path=/CyberKit/captures/hs_MyWifi_001.pcap
 *  Descarga de archivos desde la SD
 * ═══════════════════════════════════════════════════════════════════════════ */
static esp_err_t uri_api_files_dl_handler(httpd_req_t *req) {
    if (!check_auth(req)) return ESP_OK;

    /* Extraer parámetro ?path= */
    char query[128] = {0};
    char path[96]   = {0};
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK) {
        httpd_query_key_value(query, "path", path, sizeof(path));
    }

    if (path[0] == '\0') {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Falta ?path=");
    }

    /* Seguridad: sólo archivos bajo /CyberKit/ */
    if (strncmp(path, "/CyberKit/", 10) != 0) {
        return httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "Ruta no permitida");
    }

    /* Leer y enviar el archivo */
    static char file_buf[8192];
    int bytes = sd_read_file(path, file_buf, sizeof(file_buf));
    if (bytes <= 0) {
        return httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "Archivo no encontrado");
    }

    /* Tipo MIME por extensión */
    const char *ext = strrchr(path, '.');
    const char *mime = HTTPD_TYPE_OCTET;
    if (ext) {
        if (strcmp(ext, ".txt") == 0 || strcmp(ext, ".csv") == 0 ||
            strcmp(ext, ".hc22000") == 0) mime = "text/plain";
        else if (strcmp(ext, ".json") == 0) mime = "application/json";
        else if (strcmp(ext, ".html") == 0) mime = "text/html";
    }

    /* Nombre de archivo para Content-Disposition */
    const char *fname = strrchr(path, '/');
    fname = fname ? fname + 1 : path;
    char disp[128];
    snprintf(disp, sizeof(disp), "attachment; filename=\"%s\"", fname);

    httpd_resp_set_type(req, mime);
    httpd_resp_set_hdr(req, "Content-Disposition", disp);
    httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
    return httpd_resp_send(req, file_buf, bytes);
}
static httpd_uri_t uri_api_files_dl = {
    .uri = "/api/files/dl", .method = HTTP_GET, .handler = uri_api_files_dl_handler
};

/* ═══════════════════════════════════════════════════════════════════════════
 *  webserver_run() — iniciar servidor HTTP
 * ═══════════════════════════════════════════════════════════════════════════ */
void webserver_run() {
    httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
    cfg.max_uri_handlers = 36;      /* 12 legacy + ~20 /api/* = 32 mínimo    */
    cfg.stack_size       = 8192;    /* stack extra para JSON serialización    */
    httpd_handle_t server = NULL;
    ESP_ERROR_CHECK(httpd_start(&server, &cfg));

    /* ── Endpoints legacy ───────────────────────────────────────────────── */
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_root_get));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_reset_head));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_ap_list_get));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_run_attack_post));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_status_get));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_pcap_get));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_hccapx_get));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_hc22000_get));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_audit_json_get));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_audit_csv_get));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_audit_report_get));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_audit_scan_head));

    /* ── REST API /api/* ────────────────────────────────────────────────── */
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_api_status));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_api_bf_start));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_api_bf_stop));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_api_et_start));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_api_et_stop));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_api_karma_start));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_api_karma_stop));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_api_ble_start));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_api_ble_stop));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_api_ble_clear));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_api_ble_list));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_api_probe_list));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_api_probe_dump));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_api_probe_clear));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_api_audit_toggle));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_api_credentials));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_api_files));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &uri_api_files_dl));

    ESP_LOGI(TAG, "Webserver activo — http://10.10.10.26  (30 endpoints)");
}
