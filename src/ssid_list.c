/**
 * @file ssid_list.c
 * @brief Gestión de lista de SSIDs personalizados.
 *
 * @author Pedro Luis Rezabala Delgado — ChL-CyberKit v1.0 PRO
 * @copyright Copyright (C) 2026 Pedro Luis Rezabala Delgado. GPL v3.
 */
#include "ssid_list.h"
#include <string.h>
#include <stdio.h>
#include "esp_log.h"

static const char *TAG = "ssid_list";

static char  s_ssids[SSID_LIST_MAX][33];
static uint16_t s_count = 0;

void ssid_list_init(void) {
    s_count = 0;
    memset(s_ssids, 0, sizeof(s_ssids));
}

uint16_t ssid_list_load_from_sd(void) {
    FILE *f = fopen(SSID_LIST_PATH, "r");
    if (!f) {
        ESP_LOGW(TAG, "No se encontró %s", SSID_LIST_PATH);
        return 0;
    }

    s_count = 0;
    char line[64];
    while (fgets(line, sizeof(line), f) && s_count < SSID_LIST_MAX) {
        /* Eliminar \r\n */
        size_t l = strlen(line);
        while (l > 0 && (line[l-1] == '\n' || line[l-1] == '\r')) {
            line[--l] = '\0';
        }
        if (l == 0) continue;
        if (l > 32) line[32] = '\0';
        strncpy(s_ssids[s_count], line, 32);
        s_count++;
    }
    fclose(f);
    ESP_LOGI(TAG, "Cargados %u SSIDs desde SD", s_count);
    return s_count;
}

uint16_t    ssid_list_count(void)           { return s_count; }
const char *ssid_list_get(uint16_t idx) {
    if (idx >= s_count) return NULL;
    return s_ssids[idx];
}

bool ssid_list_add(const char *ssid) {
    if (!ssid || s_count >= SSID_LIST_MAX) return false;
    strncpy(s_ssids[s_count], ssid, 32);
    s_ssids[s_count][32] = '\0';
    s_count++;
    return true;
}

void ssid_list_clear(void) {
    s_count = 0;
    memset(s_ssids, 0, sizeof(s_ssids));
}

bool ssid_list_save_to_sd(void) {
    FILE *f = fopen(SSID_LIST_PATH, "w");
    if (!f) return false;
    for (uint16_t i = 0; i < s_count; i++) {
        fprintf(f, "%s\n", s_ssids[i]);
    }
    fclose(f);
    ESP_LOGI(TAG, "Guardados %u SSIDs en SD", s_count);
    return true;
}
