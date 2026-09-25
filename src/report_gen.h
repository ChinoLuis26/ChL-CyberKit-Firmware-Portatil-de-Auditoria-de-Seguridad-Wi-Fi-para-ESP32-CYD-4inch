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
 * @file report_gen.h
 * @brief Generador de reporte HTML profesional en SD.
 *        Incluye tabla de redes (WPS/PMF/clientes), probes, creds, auditoría.
 *
 * El archivo se guarda como /CyberKit/report_NNNN.html (numerado).
 *
 * @author Pedro Luis Rezabala — ChL-CyberKit v1.0 PRO
 */
#pragma once
#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

/* ── Resultado de generación ─────────────────────────────────────────────── */
typedef enum {
    RG_OK         = 0,
    RG_ERR_SD     = 1,   /* SD no disponible o error de escritura  */
    RG_ERR_NODATA = 2    /* No hay datos que reportar              */
} report_result_t;

/* ── API pública ─────────────────────────────────────────────────────────── */

/**
 * Generar y guardar el reporte HTML completo.
 * @param out_path  Buffer donde se copia la ruta del archivo creado (puede ser NULL).
 * @param path_len  Tamaño del buffer out_path.
 * @return          RG_OK en éxito.
 */
report_result_t report_gen_save(char *out_path, int path_len);

/** Número de reportes generados en esta sesión. */
uint8_t report_gen_count(void);

#ifdef __cplusplus
}
#endif
