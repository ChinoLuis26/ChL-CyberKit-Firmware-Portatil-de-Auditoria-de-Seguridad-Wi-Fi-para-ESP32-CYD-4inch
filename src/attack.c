/**
 * @file attack.c
 * @author risinek (risinek@gmail.com)
 * @date 2021-04-02
 * @copyright Copyright (c) 2021
 * 
 * @brief Implements common attack wrapper.
 */

#include "attack.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_err.h"
#include "esp_event.h"
#include "esp_timer.h"

#include "attack_pmkid.h"
#include "attack_handshake.h"
#include "attack_dos.h"
#include "webserver.h"
#include "wifi_controller.h"

static const char* TAG = "attack";
static attack_status_t attack_status = { .state = READY, .type = -1, .content_size = 0, .content = NULL };
static esp_timer_handle_t attack_timeout_handle;

static void attack_set_error(uint8_t type, const char *message) {
    if (attack_status.content) {
        free(attack_status.content);
        attack_status.content = NULL;
    }
    attack_status.state = TIMEOUT;
    attack_status.type = type;
    attack_status.content_size = strlen(message);
    attack_status.content = (char *)malloc(attack_status.content_size + 1);
    if (attack_status.content) {
        memcpy(attack_status.content, message, attack_status.content_size + 1);
    } else {
        attack_status.content_size = 0;
    }
    ESP_LOGW(TAG, "[LAB] Operacion no iniciada: %s", message);
}

const attack_status_t *attack_get_status() {
    return &attack_status;
}

void attack_update_status(attack_state_t state) {
    attack_status.state = state;
    if(state == FINISHED) {
        ESP_LOGD(TAG, "Stopping attack timeout timer");
        /* Usar sin ESP_ERROR_CHECK: si el timer ya expiro (TIMEOUT),
         * esp_timer_stop devuelve ESP_ERR_INVALID_STATE y no es fatal */
        esp_timer_stop(attack_timeout_handle);
    }
}

void attack_append_status_content(uint8_t *buffer, unsigned size){
    if(size == 0){
        ESP_LOGE(TAG, "Size can't be 0 if you want to reallocate");
        return;
    }
    // temporarily save new location in case of realloc failure to preserve current content
    char *reallocated_content = realloc(attack_status.content, attack_status.content_size + size);
    if(reallocated_content == NULL){
        ESP_LOGE(TAG, "Error reallocating status content! Status content may not be complete.");
        return;
    }
    // copy new data after current content
    memcpy(&reallocated_content[attack_status.content_size], buffer, size);
    attack_status.content = reallocated_content;
    attack_status.content_size += size;
}

char *attack_alloc_result_content(unsigned size) {
    attack_status.content_size = size;
    attack_status.content = (char *) malloc(size);
    return attack_status.content;
}

/**
 * @brief Callback function for attack timeout timer.
 * 
 * This function is called when attack times out. 
 * It updates attack status state to TIMEOUT.
 * It calls appropriate abort functions based on current attack type.
 * @param arg not used.
 */
static void attack_timeout(void* arg){
    ESP_LOGD(TAG, "Attack timed out");
    ESP_LOGW(TAG, "[AUDIT] ATAQUE FINALIZADO POR TIMEOUT — tipo=%d", attack_status.type);
    attack_update_status(TIMEOUT);

    switch(attack_status.type) {
        case ATTACK_TYPE_PMKID:
            ESP_LOGI(TAG, "Aborting PMKID attack...");
            attack_pmkid_stop();
            break;
        case ATTACK_TYPE_HANDSHAKE:
            ESP_LOGI(TAG, "Abort HANDSHAKE attack...");
            attack_handshake_stop();
            break;
        case ATTACK_TYPE_PASSIVE:
            ESP_LOGI(TAG, "Abort PASSIVE attack...");
            break;
        case ATTACK_TYPE_DOS:
            ESP_LOGI(TAG, "Abort DOS attack...");
            attack_dos_stop();
            break;
        default:
            ESP_LOGE(TAG, "Unknown attack type. Not aborting anything");
    }
}

/**
 * @brief Callback for WEBSERVER_EVENT_ATTACK_REQUEST event.
 * 
 * This function handles WEBSERVER_EVENT_ATTACK_REQUEST event from event loop.
 * It parses attack_request_t structure and set initial values to attack_status.
 * It sets attack state to RUNNING.
 * It starts attack timeout timer.
 * It starts attack based on chosen type.
 * 
 * @param args not used
 * @param event_base expects WEBSERVER_EVENTS
 * @param event_id expects WEBSERVER_EVENT_ATTACK_REQUEST
 * @param event_data expects attack_request_t
 */
static void attack_request_handler(void *args, esp_event_base_t event_base, int32_t event_id, void *event_data) {
    attack_request_t *attack_request = (attack_request_t *) event_data;
    if (!attack_request) {
        attack_set_error(ATTACK_TYPE_PASSIVE, "Solicitud vacia");
        return;
    }

    if (attack_status.state == RUNNING) {
        attack_set_error(attack_status.type, "Ya hay una operacion en curso");
        return;
    }

    if (attack_request->type > ATTACK_TYPE_DOS) {
        attack_set_error(ATTACK_TYPE_PASSIVE, "Tipo de operacion invalido");
        return;
    }

    if (attack_request->timeout == 0) {
        attack_set_error(attack_request->type, "Timeout invalido");
        return;
    }

    /* ── LOG DE AUDITORÍA — ChL-CyberKit ────────────────────────────────── */
    const char *type_names[] = {"PASIVO", "HANDSHAKE", "PMKID", "DOS"};
    const char *method_names[] = {"Broadcast", "RogueAP", "Pasivo/Combine"};
    const wifi_ap_record_t *ap_tmp = wifictl_get_ap_record(attack_request->ap_record_id);
    if (!ap_tmp) {
        attack_set_error(attack_request->type, "Selecciona una red valida o escanea de nuevo");
        return;
    }

    if (attack_request->type == ATTACK_TYPE_PASSIVE) {
        attack_set_error(attack_request->type, "Modo pasivo no implementado en este firmware");
        return;
    }

    if (ap_tmp) {
        ESP_LOGI(TAG, "╔══════════════════════════════════════════════════");
        ESP_LOGI(TAG, "║ [AUDIT] INICIO DE ATAQUE");
        ESP_LOGI(TAG, "║ Tipo   : %s", type_names[attack_request->type & 3]);
        ESP_LOGI(TAG, "║ Método : %s", method_names[attack_request->method & 2]);
        ESP_LOGI(TAG, "║ Target : %s", ap_tmp->ssid);
        ESP_LOGI(TAG, "║ BSSID  : %02X:%02X:%02X:%02X:%02X:%02X",
                 ap_tmp->bssid[0], ap_tmp->bssid[1], ap_tmp->bssid[2],
                 ap_tmp->bssid[3], ap_tmp->bssid[4], ap_tmp->bssid[5]);
        ESP_LOGI(TAG, "║ Canal  : %d  |  RSSI: %d dBm", ap_tmp->primary, ap_tmp->rssi);
        ESP_LOGI(TAG, "║ Timeout: %d s", attack_request->timeout);
        ESP_LOGI(TAG, "╚══════════════════════════════════════════════════");
    }
    /* ────────────────────────────────────────────────────────────────────── */
    ESP_LOGI(TAG, "Starting attack...");
    attack_config_t attack_config = { .type = attack_request->type, .method = attack_request->method, .timeout = attack_request->timeout };
    attack_config.ap_record = ap_tmp;
    
    attack_status.state = RUNNING;
    attack_status.type = attack_config.type;

    // set timeout
    esp_err_t timer_err = esp_timer_start_once(attack_timeout_handle, attack_config.timeout * 1000000);
    if (timer_err != ESP_OK) {
        attack_set_error(attack_config.type, esp_err_to_name(timer_err));
        return;
    }
    // start attack based on it's type
    switch(attack_config.type) {
        case ATTACK_TYPE_PMKID:
            attack_pmkid_start(&attack_config);
            break;
        case ATTACK_TYPE_HANDSHAKE:
            attack_handshake_start(&attack_config);
            break;
        case ATTACK_TYPE_PASSIVE:
            ESP_LOGW(TAG, "ATTACK_TYPE_PASSIVE not implemented yet!");
            break;
        case ATTACK_TYPE_DOS:
            attack_dos_start(&attack_config);
            break;
        default:
            ESP_LOGE(TAG, "Unknown attack type!");
    }
}

/**
 * @brief Callback for WEBSERVER_EVENT_ATTACK_RESET event.
 * 
 * This callback resets attack status by freeing previously allocated status content and putting attack to READY state.
 * 
 * @param args not used
 * @param event_base expects WEBSERVER_EVENTS
 * @param event_id expects WEBSERVER_EVENT_ATTACK_RESET
 * @param event_data not used
 */
static void attack_reset_handler(void *args, esp_event_base_t event_base, int32_t event_id, void *event_data) {
    ESP_LOGD(TAG, "Resetting attack status...");
    if(attack_status.content){
        free(attack_status.content);
        attack_status.content = NULL;
    }
    attack_status.content_size = 0;
    attack_status.type = -1;
    attack_status.state = READY;
}

/**
 * @brief Initialises common attack resources.
 * 
 * Creates attack timeout timer.
 * Registers event loop event handlers.
 */
void attack_init(){
    const esp_timer_create_args_t attack_timeout_args = {
        .callback = &attack_timeout
    };
    ESP_ERROR_CHECK(esp_timer_create(&attack_timeout_args, &attack_timeout_handle));

    ESP_ERROR_CHECK(esp_event_handler_register(WEBSERVER_EVENTS, WEBSERVER_EVENT_ATTACK_REQUEST, &attack_request_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(WEBSERVER_EVENTS, WEBSERVER_EVENT_ATTACK_RESET, &attack_reset_handler, NULL));
}
