/* hacktv - Analogue video transmitter for the HackRF                    */
/*=======================================================================*/
/* Copyright 2017 Philip Heron <phil@sanslogic.co.uk>                    */
/* Copyright 2026 Katy Coe - https://github.com/djkaty/                  */
/*                                                                       */
/* This program is free software: you can redistribute it and/or modify  */
/* it under the terms of the GNU General Public License as published by  */
/* the Free Software Foundation, either version 3 of the License, or     */
/* (at your option) any later version.                                   */
/*                                                                       */
/* This program is distributed in the hope that it will be useful,       */
/* but WITHOUT ANY WARRANTY; without even the implied warranty of        */
/* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         */
/* GNU General Public License for more details.                          */
/*                                                                       */
/* You should have received a copy of the GNU General Public License     */
/* along with this program.  If not, see <http://www.gnu.org/licenses/>. */

/*=======================================================================*/
/* All of the code in this file belongs to Katy Coe who has worked for   */
/* 999 days (no, really!) to reverse engineer the ASIC used in these     */
/* cards. Without her, this functionality would not have been possible   */
/*=======================================================================*/

#ifndef VIDEOCRYPT10_H
#define VIDEOCRYPT10_H

#define ENCRYPT_OK   1
#define ENCRYPT_FAIL 0

#include <stdint.h>
#include <stdbool.h>
#include "videocrypt-ca.h"

/* ASIC structure */
typedef struct {
    bool shift_register[105];
    bool fifo_buffer[64];
    int iterations;
    bool crypto_enabled;
    bool decoder_capture;
    int read_pointer;
    bool has_pending_response;
    uint8_t pending_response_byte;
} asic10_t;

/* Kernel structure */
typedef struct {
    uint8_t buf[12];
    int bptr5;
    int bptr7;
    uint8_t b;
} kernel10_t;

/* Card structure */
typedef struct card10_t {
    asic10_t asic_instance;
    asic10_t *asic;
    kernel10_t kernel;
    uint8_t **rainbow_table;      /* 64MB rainbow table (optional) */
    int rainbow_table_loaded;     /* Flag for 64MB table */
} card10_t;

extern void vc_seed_sky_p10(_vc_block_t *s, int mode);

#endif /* VIDEOCRYPT10_H */