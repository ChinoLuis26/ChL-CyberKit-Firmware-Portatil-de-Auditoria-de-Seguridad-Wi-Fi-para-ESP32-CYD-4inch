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
 * @file wifi_controller.h
 * @brief WiFi controller — ChL-CyberKit v1.0
 */
#ifndef WIFI_CONTROLLER_H
#define WIFI_CONTROLLER_H

#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>

#include "ap_scanner.h"
#include "sniffer.h"
#include "esp_wifi_types.h"

void wifictl_ap_start(wifi_config_t *wifi_config);
void wifictl_ap_stop();
void wifictl_mgmt_ap_start();
void wifictl_set_stealth(bool hidden);          /* Nuevo: ocultar/mostrar AP */
void wifictl_sta_connect_to_ap(const wifi_ap_record_t *ap_record, const char password[]);
void wifictl_sta_disconnect();
void wifictl_set_ap_mac(const uint8_t *mac_ap);
void wifictl_get_ap_mac(uint8_t *mac_ap);
void wifictl_restore_ap_mac();
void wifictl_get_sta_mac(uint8_t *mac_sta);
void wifictl_set_channel(uint8_t channel);

#endif
