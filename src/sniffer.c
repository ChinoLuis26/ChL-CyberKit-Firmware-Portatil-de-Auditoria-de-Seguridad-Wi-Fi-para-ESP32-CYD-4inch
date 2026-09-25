/**
 * @file sniffer.c
 * @author risinek (risinek@gmail.com)
 * @date 2021-04-05
 * @copyright Copyright (c) 2021
 * 
 * @brief Implements sniffer logic.
 */
#include "sniffer.h"

#define LOG_LOCAL_LEVEL ESP_LOG_DEBUG
#include "esp_log.h"
#include "esp_err.h"
#include "esp_event.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "wifi_audit.h"
#include "probe_logger.h"
#include "beacon_parser.h"

static const char *TAG = "sniffer"; 

ESP_EVENT_DEFINE_BASE(SNIFFER_EVENTS);

/**
 * @brief Callback for promiscuous reciever. 
 * 
 * It forwards captured frames into event pool and sorts them based on their type
 * - Data
 * - Management
 * - Control
 * 
 * @param buf 
 * @param type 
 */
/* ── Offsets de cabecera 802.11 ──────────────────────────────────────────── */
#define FC_OFFSET       0       /* Frame Control (2 bytes)  */
#define ADDR1_OFFSET    4       /* DA  (6 bytes)            */
#define ADDR2_OFFSET   10       /* SA  (6 bytes)            */
#define ADDR3_OFFSET   16       /* BSSID (6 bytes)          */

static void frame_handler(void *buf, wifi_promiscuous_pkt_type_t type) {
    ESP_LOGV(TAG, "Captured frame %d.", (int) type);

    wifi_promiscuous_pkt_t *frame = (wifi_promiscuous_pkt_t *) buf;
    const uint8_t *payload = frame->payload;
    uint16_t       len     = (uint16_t)frame->rx_ctrl.sig_len;

    /* ── 1. wifi_audit siempre recibe el frame ───────────────────────────── */
    audit_note_deauth_frame(payload, len,
                            frame->rx_ctrl.rssi, frame->rx_ctrl.channel);

    /* ── 2. Despacho por tipo de frame ──────────────────────────────────── */
    if (type == WIFI_PKT_MGMT && len >= 24) {
        /* probe_logger y beacon_parser reciben todos los frames de gestión */
        probe_logger_handle_mgmt(frame);
        beacon_parser_handle_mgmt(frame);
    }
    else if (type == WIFI_PKT_DATA && len >= 26) {
        /*
         * Extraer MACs de clientes de frames de datos:
         *   FC bits [9:8] → DS bits:
         *     ToDS=1 / FromDS=0 → BSSID=ADDR1, SA=ADDR2, DA=ADDR3
         *     ToDS=0 / FromDS=1 → BSSID=ADDR2, SA=ADDR3, DA=ADDR1
         * En ambos casos el cliente es la STA (no el AP/BSSID).
         */
        uint8_t fc1   = payload[1];  /* byte alto del Frame Control */
        uint8_t to_ds   = (fc1 >> 0) & 0x01;
        uint8_t from_ds = (fc1 >> 1) & 0x01;

        const uint8_t *bssid = NULL;
        const uint8_t *sta   = NULL;

        if (to_ds && !from_ds) {
            bssid = payload + ADDR1_OFFSET;  /* RA = AP */
            sta   = payload + ADDR2_OFFSET;  /* TA = STA */
        } else if (!to_ds && from_ds) {
            bssid = payload + ADDR2_OFFSET;  /* TA = AP */
            sta   = payload + ADDR3_OFFSET;  /* DA = STA */
        }
        /* Notificar al beacon_parser (para rellenar client_macs del AP) */
        if (bssid && sta) {
            beacon_parser_note_client(bssid, sta);
        }
    }

    /* ── 3. Reenvío al event loop (para el resto del firmware) ──────────── */
    int32_t event_id;
    switch (type) {
        case WIFI_PKT_DATA: event_id = SNIFFER_EVENT_CAPTURED_DATA; break;
        case WIFI_PKT_MGMT: event_id = SNIFFER_EVENT_CAPTURED_MGMT; break;
        case WIFI_PKT_CTRL: event_id = SNIFFER_EVENT_CAPTURED_CTRL; break;
        default: return;
    }

    ESP_ERROR_CHECK(esp_event_post(SNIFFER_EVENTS, event_id, frame,
                                   frame->rx_ctrl.sig_len + sizeof(wifi_promiscuous_pkt_t),
                                   portMAX_DELAY));
}

/**
 * @see https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/network/esp_wifi.html#_CPPv425wifi_promiscuous_filter_t
 */
void wifictl_sniffer_filter_frame_types(bool data, bool mgmt, bool ctrl) {
    wifi_promiscuous_filter_t filter = { .filter_mask = 0 };
    if(data) {
        filter.filter_mask |= WIFI_PROMIS_FILTER_MASK_DATA;
    }
    else if(mgmt) {
        filter.filter_mask |= WIFI_PROMIS_FILTER_MASK_MGMT;
    }
    else if(ctrl) {
        filter.filter_mask |= WIFI_PROMIS_FILTER_MASK_CTRL;
    }
    esp_wifi_set_promiscuous_filter(&filter);
}

void wifictl_sniffer_start(uint8_t channel) {
    ESP_LOGI(TAG, "Starting promiscuous mode...");
    // ESP32 cannot switch port, if there is some STA connected to AP
    ESP_LOGD(TAG, "Kicking all connected STAs from AP");
    ESP_ERROR_CHECK(esp_wifi_deauth_sta(0));
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(&frame_handler);
}

void wifictl_sniffer_stop() {
    ESP_LOGI(TAG, "Stopping promiscuous mode...");
    esp_wifi_set_promiscuous(false);
}
