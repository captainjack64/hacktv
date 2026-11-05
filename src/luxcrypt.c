/* hacktv - Analogue video transmitter for the HackRF                    */
/*=======================================================================*/
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

/* Luxcrypt (RTL4 / RTL5) - EXPERIMENTAL-ish
 *
 * Sync suppressed. Each line starts with a band (replacing sync and back
 * porch) carrying a 24-bit data packet, which the decoder's PLL locks to,
 * and the colour burst. Line 4 carries the frame pattern the decoder's
 * 24-bit detector resets its counter on, clocked at the decoder's 5.75 MHz
 * (368 x fH). Lines 24/336 carry the luma and chroma flags and line 335 the
 * decode enable, at the sample points of the decoder ROMs. Levels are
 * fractions of blanking->white.
 *
 * The burst is sent inverted with the chroma flag set. rtl5 also sends the
 * picture inverted with the luma flag set. The decoder clears its flags on
 * lines 4/317 and samples them on lines 24/336.
 */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include "video.h"
#include "common.h"
#include "vbidata.h"
#include "luxcrypt.h"

#define LX_US       (1.0 / (368.0 * 15625.0))

#define DATA_BITS   24
#define A_END       (40 * LX_US)
#define A_LEVEL     0.70
#define B_END       (65 * LX_US)
#define B_LEVEL     0.40
#define KEY_START   (36 * LX_US)
#define KEY_END     (38 * LX_US)
#define KEY_LEVEL   0.54
#define ACTIVE      (67 * LX_US)
#define VBI_START   (56 * LX_US)
#define RISE        0.072e-6
#define BIT_RISE    0.024e-6

#define BAR_START   (102 * LX_US)
#define BAR_END     (339 * LX_US)
#define BAR_LEVEL   0.78

#define PAT_BITS    40
#define PAT_END     48.56e-6

#define FLAG_END    23.65e-6
#define FLAG_BLANK  24.0e-6
#define WHITE_START 12.86e-6
#define WHITE_END   21.90e-6
#define LUMA_START  17.05e-6
#define LUMA_END    19.05e-6

#define L335_END    54.90e-6

static const uint8_t _ones[8] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
static const uint8_t _data[3] = { 0x55, 0x55, 0x55 };
static const uint8_t _pat[5] = { 0xCC, 0xCC, 0x32, 0x33, 0xAB };

static double _lvl(vid_t *v, double f)
{
	return((v->white_level - v->blanking_level) * f);
}

static int16_t _clip(double v)
{
	return(lround(v > INT16_MAX ? INT16_MAX : (v < INT16_MIN ? INT16_MIN : v)));
}

void luxcrypt_free(luxcrypt_t *s)
{
	free(s->data);
	free(s->pat);
	free(s->patbase);
	free(s->band);
	free(s->band_vbi);
	free(s->bar);
	free(s->flags);
	free(s->l335);
	memset(s, 0, sizeof(luxcrypt_t));
}

int luxcrypt_init(luxcrypt_t *s, vid_t *vid)
{
	double bit = LX_US * vid->pixel_rate;
	double t0 = PAT_END - PAT_BITS * LX_US;
	double sync = vid->sync_level - vid->blanking_level;
	double white = vid->white_level - vid->sync_level;
	double a = _lvl(vid, A_LEVEL), b = _lvl(vid, B_LEVEL);

	memset(s, 0, sizeof(luxcrypt_t));

	s->active_x = round(ACTIVE * vid->pixel_rate);
	s->vbi_x = round(VBI_START * vid->pixel_rate);
	s->flag_blank = round(FLAG_BLANK * vid->pixel_rate);
	s->burst_l = vid->burst_left;
	s->burst_r = vid->burst_left + vid->burst_width;
	s->key_l = round(KEY_START * vid->pixel_rate);
	s->key_r = round(KEY_END * vid->pixel_rate);
	s->invert = vid->conf.luxcrypt == 2;

	s->data = vbidata_init_step(DATA_BITS, vid->width, _lvl(vid, 1.0), bit, BIT_RISE * IRT1090 * vid->pixel_rate, 0);
	s->pat = vbidata_init_step(PAT_BITS, vid->width, 2 * sync, bit, BIT_RISE * IRT1090 * vid->pixel_rate, t0 * vid->pixel_rate);

	s->patbase = _render_sync_pulses(vid, (const double[][4]) {
		{ t0, PAT_BITS * LX_US, BIT_RISE, -sync },
	}, 1);

	s->band = _render_sync_pulses(vid, (const double[][4]) {
		{ DATA_BITS * LX_US, A_END - DATA_BITS * LX_US, RISE, a },
		{ A_END, B_END - A_END, RISE, b },
		{ KEY_START, KEY_END - KEY_START, RISE, _lvl(vid, KEY_LEVEL) - a },
	}, 3);

	s->band_vbi = _render_sync_pulses(vid, (const double[][4]) {
		{ DATA_BITS * LX_US, A_END - DATA_BITS * LX_US, RISE, a },
		{ A_END, VBI_START - A_END, RISE, b },
		{ KEY_START, KEY_END - KEY_START, RISE, _lvl(vid, KEY_LEVEL) - a },
	}, 3);

	s->bar = _render_sync_pulses(vid, (const double[][4]) {
		{ BAR_START, BAR_END - BAR_START, RISE, _lvl(vid, BAR_LEVEL) },
	}, 1);

	if(s->invert)
	{
		s->flags = _render_sync_pulses(vid, (const double[][4]) {
			{ ACTIVE, FLAG_END - ACTIVE, RISE, sync },
			{ ACTIVE, WHITE_END - ACTIVE, RISE, white },
		}, 2);
		s->nflags = 2;
	}
	else
	{
		s->flags = _render_sync_pulses(vid, (const double[][4]) {
			{ ACTIVE, FLAG_END - ACTIVE, RISE, sync },
			{ WHITE_START, LUMA_START - WHITE_START, RISE, white },
			{ LUMA_END, WHITE_END - LUMA_END, RISE, white },
		}, 3);
		s->nflags = 3;
	}

	s->l335 = _render_sync_pulses(vid, (const double[][4]) {
		{ ACTIVE, L335_END - ACTIVE, RISE, vid->white_level - vid->blanking_level },
	}, 1);

	if(!s->data || !s->pat || !s->patbase || !s->band || !s->band_vbi || !s->bar || !s->flags || !s->l335)
	{
		luxcrypt_free(s);
		return(VID_OUT_OF_MEMORY);
	}

	return(VID_OK);
}

int luxcrypt_reserve_line(vid_t *s, void *arg, int nlines, vid_line_t **lines)
{
	int line = lines[0]->line;

	if(line == 22 || line == 24 || line == 335 || line == 336)
	{
		lines[0]->vbialloc = 1;
	}

	return(1);
}

int luxcrypt_render_line(vid_t *s, void *arg, int nlines, vid_line_t **lines)
{
	luxcrypt_t *lx = arg;
	vid_line_t *l = lines[0];
	int16_t *o = l->output;
	int line = l->line, x;
	int vbi = (line >= 6 && line <= 23) || (line >= 318 && line <= 334);
	int pic_x = vbi ? lx->vbi_x : lx->active_x;
	int pic_inv = lx->invert && !((line >= 5 && line <= 23) || (line >= 318 && line <= 335));
	int burst = ((line >= 5 && line <= 24) || (line >= 318 && line <= 336)) ? 1 : -1;

	if(line >= 624 || line <= 5 || (line >= 311 && line <= 317))
	{
		for(x = 0; x < l->width; x++) o[x * 2] = s->blanking_level;

		vbidata_render(lx->data, _data, 0, DATA_BITS, VBIDATA_LSB_FIRST, l);

		if(line == 624 || line == 2 || line == 311 || line == 314 || line == 315)
		{
			vbidata_render(lx->bar, _ones, 0, 1, VBIDATA_LSB_FIRST, l);
		}

		if(line == 4)
		{
			vbidata_render(lx->patbase, _ones, 0, 1, VBIDATA_LSB_FIRST, l);
			vbidata_render(lx->pat, _pat, 0, PAT_BITS, VBIDATA_LSB_FIRST, l);
		}

		l->vbialloc = 1;
		return(1);
	}

	if(line == 623 || line == 318)
	{
		for(x = lx->active_x; x < l->width; x++)
		{
			if(o[x * 2] < s->blanking_level) o[x * 2] = s->blanking_level;
		}
	}

	if(pic_inv)
	{
		int k = s->black_level + s->white_level;

		for(x = pic_x; x < l->width; x++) o[x * 2] = _clip(k - o[x * 2]);
	}

	for(x = 0; x < pic_x && x < l->width; x++)
	{
		int v = (x >= lx->burst_l && x < lx->burst_r && (x < lx->key_l || x >= lx->key_r)) ? (o[x * 2] - s->blanking_level) * burst : 0;
		o[x * 2] = _clip(s->blanking_level + v);
	}

	vbidata_render(lx->data, _data, 0, DATA_BITS, VBIDATA_LSB_FIRST, l);
	vbidata_render(vbi ? lx->band_vbi : lx->band, _ones, 0, 3, VBIDATA_LSB_FIRST, l);

	if(line == 24 || line == 336)
	{
		for(x = lx->active_x; x < lx->flag_blank && x < l->width; x++) o[x * 2] = s->blanking_level;
		vbidata_render(lx->flags, _ones, 0, lx->nflags, VBIDATA_LSB_FIRST, l);
	}

	if(line == 335)
	{
		for(x = lx->active_x; x < l->width; x++) o[x * 2] = s->blanking_level;
		vbidata_render(lx->l335, _ones, 0, 1, VBIDATA_LSB_FIRST, l);
	}

	return(1);
}
