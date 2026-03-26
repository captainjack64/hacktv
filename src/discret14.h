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

#ifndef _DISCRET14_H
#define _DISCRET14_H

#include <stdint.h>
#include "vbidata.h"

#define D14_FIELDS                 48
#define D14_LINES_PER_FIELD        288
#define D14_WORDS_PER_FIELD        9
#define D14_VISIBLE_LINES          287
#define D14_FIELD_1_START          23
#define D14_FIELD_2_START          335
#define D14_VBI_BYTES              (24 * 4)

/* Fields after toggle before LUT switches */
#define D14_LUT_SWITCH_DELAY       83

/* Row within transition packet where phase5 toggles */
#define D14_TOGGLE_ROW             7

typedef struct {
    vbidata_lut_t *lut;
    int vbi_seq;
} discret14_t;

extern int discret14_init(discret14_t *s, vid_t *vs);
extern void discret14_free(discret14_t *s);
extern int discret14_render_line(vid_t *s, void *arg, int nlines, vid_line_t **lines);

#endif