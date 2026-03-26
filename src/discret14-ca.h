/* hacktv - Analogue video transmitter for the HackRF                    */
/*=======================================================================*/
/* Copyright 2026 Philip Heron <phil@sanslogic.co.uk>                    */
/* Copyright 2026 Alex James                                             */
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

#ifndef DISCRET14_CA_H
#define DISCRET14_CA_H
 
#include <stdint.h>
 
#define D14_CA_SUPERFRAME_BYTES  24
 
typedef struct
{
    /* Superframe state */
    uint8_t superframe[D14_CA_SUPERFRAME_BYTES];
    int     ready;
 
    /* VBI packet cycling */
    uint8_t msg0_cycle;           /* 1..5                       */
    uint8_t frame_phase5;         /* 0x00 or 0x20               */
    int     packets_until_toggle;
    int     phase5_toggle_pending;
    int     cw_phase;             /* 0/1: which target pair      */
 
    /* ASIC seed output */
    uint8_t asic_seed[16];        /* seed0[0..7] + seed1[8..15]  */
} discret14_ca_t;
 
/* Initialise CA state.  First superframe is built and logged. */
extern void discret14_ca_init(discret14_ca_t *ca);
 
/* Build superframe for current msg0/phase.
 * If log != 0, prints superframe details and ASIC seeds. */
extern void discret14_ca_build_superframe(discret14_ca_t *ca, int log);
 
/* Advance msg0 cycle (call at end of each packet). */
extern void discret14_ca_advance_packet(discret14_ca_t *ca);
 
/* Fire the phase5 toggle (call at the toggle row).
 * Rebuilds superframe and logs. Returns new cw_phase. */
extern int discret14_ca_toggle(discret14_ca_t *ca);
 
/* Return the VBI byte for a given row/col. */
extern uint8_t discret14_ca_vbi_byte(discret14_ca_t *ca, int row, int col);
 
#endif /* DISCRET14_CA_H */
 