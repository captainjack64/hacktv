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

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "video.h"
#include "discret14.h"
#include "discret14-ca.h"
#include "discret14-sequences.h"

/*
 * Discret 14 scrambler/encoder
 *
 * The superframe (24 bytes) carries:
 *   bytes  0..7:  programme data (msg0 cycles 1-5, bit 6 = phase)
 *   bytes  8..15: CW_A = DES_decrypt(current_target, mixed_key)
 *   bytes 16..23: CW_B = DES_decrypt(next_target, next_key)
 *
 * Two validation targets with different equal halves produce different
 * ASIC seeds, alternating the scrambling pattern at each toggle.
 * 
 * Scrambling uses two packed 48-field delay LUTs that alternate every 240 fields.
 */

static const uint64_t (*lut_table[2])[D14_WORDS_PER_FIELD] =
{
    d14_lut_a,
    d14_lut_b,
};

static inline int lut_lookup(int phase, int field, int line)
{
    return (int)((lut_table[phase][field][line >> 5] >> ((line & 31) * 2)) & 3);
}

static discret14_ca_t ca;
static int lut_phase;
static int lut_delay_counter = -1;

static uint8_t generated_vbi_byte(int row, int col)
{
    if (col == 1 && ca.phase5_toggle_pending && row == D14_TOGGLE_ROW)
    {
        discret14_ca_toggle(&ca);

        if (D14_LUT_SWITCH_DELAY <= 0)
            lut_phase ^= 1;
        else
            lut_delay_counter = D14_LUT_SWITCH_DELAY;
    }

    return discret14_ca_vbi_byte(&ca, row, col);
}

static vbidata_lut_t *_render_data_symbols(vid_t *s)
{
    int i, l;
    vbidata_lut_t *lut, *lptr;

    for (l = i = 0; i < 8; i++)
    {
        l += vbidata_update_step(NULL,
            (double)s->width * 0.22731 + (double)s->width * 0.09229 * i,
            (double)s->width * 0.09229, (double)s->width * 0.009229,
            s->white_level - s->black_level);
    }

    l += vbidata_update_step(NULL,
        (double)s->width * 0.22731 - (double)s->width * 0.09229 * 0.226415094,
        (double)s->width * 0.09229 * 0.226415094, (double)s->width * 0.009229,
        (s->white_level - s->black_level) * 0.5);
    l += 1;

    lut = malloc(l * sizeof(int16_t));
    if (!lut)
        return NULL;

    lptr = lut;
    for (i = 0; i < 8; i++, lptr = (vbidata_lut_t *)&lptr->value[lptr->length])
    {
        vbidata_update_step(lptr,
            (double)s->width * 0.22731 + (double)s->width * 0.09229 * i,
            (double)s->width * 0.09229, (double)s->width * 0.009229,
            s->white_level - s->black_level);
    }

    vbidata_update_step(lptr,
        (double)s->width * 0.22731 - (double)s->width * 0.09229 * 0.226415094,
        (double)s->width * 0.09229 * 0.226415094, (double)s->width * 0.009229,
        (s->white_level - s->black_level) * 0.5);

    lptr = (vbidata_lut_t *)&lptr->value[lptr->length];
    lptr->length = -1;

    return lut;
}

int discret14_init(discret14_t *s, vid_t *vid)
{
    memset(s, 0, sizeof(discret14_t));
    s->lut = _render_data_symbols(vid);
    if (!s->lut)
        return VID_OUT_OF_MEMORY;
    discret14_ca_init(&ca);
    return VID_OK;
}

void discret14_free(discret14_t *s)
{
    free(s->lut);
}

int discret14_render_line(vid_t *s, void *arg, int nlines, vid_line_t **lines)
{
    discret14_t *n = arg;
    vid_line_t *l = lines[0];
    int x;

    (void)nlines;

    /* VBI data on lines 24, 310, 336, 622 */
    if (l->line == 24 || l->line == 310 || l->line == 336 || l->line == 622)
    {
        uint8_t data[2];
        int row = n->vbi_seq / 4;
        int col = n->vbi_seq % 4;

        for (x = s->active_left; x < s->active_left + s->active_width; x++)
            l->output[x * 2] = s->black_level;

        data[0] = generated_vbi_byte(row, col);
        data[1] = 0x01;
        vbidata_render(n->lut, data, 0, 9, VBIDATA_LSB_FIRST, l);
        l->vbialloc = 1;

        if (++n->vbi_seq == D14_VBI_BYTES)
        {
            n->vbi_seq = 0;
            discret14_ca_advance_packet(&ca);
        }
    }

    /* Line-delay scrambling */
    {
        int field = (l->line < D14_FIELD_2_START) ? 0 : 1;
        int lif = l->line - (field ? D14_FIELD_2_START : D14_FIELD_1_START);

        if (lif >= 0 && lif < D14_VISIBLE_LINES)
        {
            int fi, ll, dsel, dp, shift;

            if (lif == 0 && lut_delay_counter > 0)
            {
                if (--lut_delay_counter == 0)
                {
                    lut_phase ^= 1;
                    lut_delay_counter = -1;
                }
            }

            fi = ((((l->frame - 1) * 2) + field) % D14_FIELDS + D14_FIELDS - 1) % D14_FIELDS;
            ll = (lif +  D14_LINES_PER_FIELD) % D14_LINES_PER_FIELD;
            dsel = lut_lookup(lut_phase, fi, ll);
            dp = (int)(((1.0 / 4433618.75) * 4.0 * s->pixel_rate) + 0.5);
            shift = (2 - dsel) * dp;

            for (x = s->active_left + s->active_width - 1; x >= s->active_left; x--)
            {
                int sx = x - shift;
                l->output[x * 2] = (sx >= s->active_left) ? l->output[sx * 2] : s->black_level;
            }
        }
    }

    return 1;
}