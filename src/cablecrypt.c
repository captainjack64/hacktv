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

/* Cablecrypt
 *
 * Data lines (66 bits: edge bit, 8 bytes MSB first, edge bit, at 82 x fH):
 *   Sync line  frame marker: one of 8 codewords + 4 random bytes
 *   Auth line  key byte + luma and chroma flags + constant tail,
 *              one before each field
 *   EMM line   subscriber data - sent blank here
 *
 * Line layout (625-line numbering), as measured in the recordings and as
 * read by the decoders:
 *   field 2:  311 dark, 312-317 EMM, 318 Auth (= Sync - 1), 319 Sync,
 *             320-331 white, 332 grey, 333-335 white, 336-337 marker,
 *             picture 338-622
 *   field 1:  623-624 dark, 625 + 1-5 EMM, 6 Auth (= Sync + 312),
 *             7-18 white, 19 grey, 20-22 white, 23 dark, 24 white, 25 dark,
 *             picture 26-310
 *
 * This reproduces the TV Cabo broadcasts analysed from off-air
 * recordings (--cablecrypt-tvcabo) - thanks Afonso!
 *
 * Luma inversion flips at scene changes: after a random hold of 1-4 secs it
 * flips at the next frame that differs strongly from the one before (a cut),
 * or after 10 s without one. Chroma changes in runs of 5-12 fields. hsync is
 * displaced 2.34 us early in random blocks of 18 or 27 lines.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "video.h"
#include "cablecrypt.h"

/* Auth line constant bytes 3-7 (plaintext) */
static const uint8_t cc_auth_tail[5] = { 0xCA, 0xCA, 0xB0, 0xB0, 0x00 };

/* Sync line codewords (bytes 0-3) */
static const uint8_t cc_sync_cw[8][4] = {
	{ 0x76, 0x41, 0x29, 0x40 }, { 0xDA, 0xD3, 0xB2, 0x00 }, { 0x25, 0x2E, 0xD6, 0x80 }, { 0xDA, 0xD6, 0xD6, 0x80 },
	{ 0x25, 0x2B, 0xB2, 0x00 }, { 0xDA, 0xD1, 0x29, 0x40 }, { 0x25, 0x29, 0x29, 0x40 }, { 0x76, 0x46, 0xD6, 0x80 },
};

#define CC_DISP_US    2.34      /* hsync displacement */
#define CC_INV_LEVEL  11.0      /* luma inversion level offset, % of black-white */
#define CC_CUT_THR    0.25      /* scene change (1 - |correlation|) that counts as a cut */
#define CC_HOLD_MIN   25        /* min/max frames to hold luma after a flip */
#define CC_HOLD_MAX   100
#define CC_FORCE      250       /* flip anyway after this many frames without a cut */

#define CC_AUTH1_LINE 5
#define CC_AUTH2_LINE 317
#define CC_SYNC_LINE  318

static uint32_t _rand(cablecrypt_t *c)
{
	uint32_t x = c->rng;
	x ^= x << 13; x ^= x >> 17; x ^= x << 5;
	return(c->rng = x);
}

static void _fill(vid_line_t *l, int x0, int x1, int16_t level)
{
	int x;
	if(x0 < 0) x0 = 0;
	if(x1 > l->width) x1 = l->width;
	for(x = x0; x < x1; x++) l->output[x * 2] = level;
}

/* Blank line with a normal hsync */
static void _blank(vid_t *s, vid_line_t *l)
{
	uint8_t sc = 1;
	int x;
	for(x = 0; x < l->width; x++) { l->output[x * 2] = s->blanking_level; l->output[x * 2 + 1] = 0; }
	vbidata_render(s->syncs, &sc, 0, 5, VBIDATA_LSB_FIRST, l);
	l->vbialloc = 1;
}

/* Data line: 66 bits = edge bit, 8 bytes MSB first, edge bit */
static void _data(vid_t *s, cablecrypt_t *c, vid_line_t *l, const uint8_t *by)
{
	uint8_t bits[9] = { 0 };
	int i, b;

	for(i = 0; i < 66; i++)
	{
		if(i == 0 || i == 65) b = _rand(c) & 1;
		else b = (by[(i - 1) / 8] >> (7 - (i - 1) % 8)) & 1;
		if(b) bits[i >> 3] |= 0x80 >> (i & 7);
	}

	_blank(s, l);
	_fill(l, c->x0, c->x1 + 1, s->black_level);
	vbidata_render(c->lut, bits, 0, 66, VBIDATA_MSB_FIRST, l);
}

/* Sync line: a random codeword and payload every frame */
static void _sync_line(vid_t *s, cablecrypt_t *c, vid_line_t *l)
{
	uint8_t by[8];
	uint32_t r = _rand(c);

	memcpy(by, cc_sync_cw[r & 7], 4);
	r = _rand(c);
	by[4] = r; by[5] = r >> 8; by[6] = r >> 16; by[7] = r >> 24;
	_data(s, c, l, by);
}

static uint8_t _rot3d(int k)
{
	k &= 7;
	return((uint8_t) ((0x3D << k) | (0x3D >> (8 - k))));
}

/* Auth line for field f (0 = field 1, 1 = field 2); sets that field's flags.
 * Luma inversion changes by frame (decided before field 1), chroma by field. */
static void _auth_line(vid_t *s, cablecrypt_t *c, vid_line_t *l, int f)
{
	uint8_t plain[7], by[8];
	uint32_t k = c->key;
	int i;

	/* luma: once per frame (before field 1). Hold, then flip at the next cut,
	 * or after CC_FORCE frames without one */
	if(f == 0)
	{
		if(c->hold > 0) c->hold--;
		else if(c->scene > CC_CUT_THR || ++c->armed >= CC_FORCE)
		{
			c->luma_set ^= 1;
			c->hold = CC_HOLD_MIN + _rand(c) % (CC_HOLD_MAX - CC_HOLD_MIN + 1);
			c->armed = 0;
		}
	}

	if(--c->chroma_run <= 0)
	{
		c->chroma_set ^= 1;
		c->chroma_run = 5 + _rand(c) % 8;               /* 5 - 12 fields */
	}

	/* clear flags carry a rotation of 0x3D from a 3-bit shift register,
	 * one new bit per Auth line */
	for(i = 0; i < 2; i++) c->sym[i] = ((c->sym[i] << 1) | (_rand(c) & 1)) & 7;
	plain[0] = c->luma_set ? 0x00 : _rot3d((1 - c->sym[0]) & 7);
	plain[1] = c->chroma_set ? 0x00 : _rot3d((1 - c->sym[1]) & 7);
	memcpy(&plain[2], cc_auth_tail, 5);

	/* key byte: 8-bit window on a 32-bit LFSR, one new bit per Auth line,
	 * b(n) = b(n-1) ^ b(n-18) ^ b(n-19) ^ b(n-31) ^ b(n-32)
	 * this could technically be random but it wouldn't follow the official
	 * implementation */
	k = (k << 1) | (((k >> 0) ^ (k >> 17) ^ (k >> 18) ^ (k >> 30) ^ (k >> 31)) & 1);
	c->key = k;
	by[0] = k & 0xFF;
	for(i = 0; i < 7; i++) by[1 + i] = plain[i] ^ by[0];
	_data(s, c, l, by);

	c->luma[f] = c->luma_set;
	c->chroma[f] = c->chroma_set;
}

int cablecrypt_init(cablecrypt_t *s, vid_t *vid)
{
	double cell = (double) vid->width / 82;                  /* bit rate 82 x fH */
	double offset = vid->pixel_rate * 10.34e-6;              /* first data bit */
	double rise = vid->pixel_rate * 200e-9;
	double hsw = vid->pixel_rate * vid->conf.hsync_width;
	double srise = vid->pixel_rate * vid->conf.sync_rise;

	memset(s, 0, sizeof(cablecrypt_t));
	s->rng = 0x2545F491;

	s->jump = (int) ceil(vid->pixel_rate * CC_DISP_US * 1e-6);
	s->hsync_end = (int) ceil(hsw + srise) + 2;
	s->x0 = (int) floor(offset - rise);
	s->x1 = (int) ceil(offset + cell * 66 + rise);

	s->lut = vbidata_init_step(66, vid->width, vid->white_level - vid->black_level, cell, rise, offset);
	s->bsync = vbidata_init_step(1, vid->width, vid->sync_level - vid->blanking_level, hsw, srise,
		-vid->pixel_rate * CC_DISP_US * 1e-6);
	if(!s->lut || !s->bsync)
	{
		cablecrypt_free(s);
		return(VID_OUT_OF_MEMORY);
	}

	s->luma[0] = s->luma[1] = 0;
	s->chroma[0] = s->chroma[1] = 1;
	s->luma_set = 0;
	s->chroma_set = 1;
	s->chroma_run = 7;
	s->key = 0xB853C6F8;
	s->hold = CC_HOLD_MIN + _rand(s) % (CC_HOLD_MAX - CC_HOLD_MIN + 1);

	return(VID_OK);
}

void cablecrypt_free(cablecrypt_t *s)
{
	free(s->lut);
	free(s->bsync);
	memset(s, 0, sizeof(cablecrypt_t));
}

/* Field of a picture line: 0, 1, or -1 if not a picture line */
static int _field(int line)
{
	if(line >= 26 && line <= 310) return(0);
	if(line >= 338 && line <= 622) return(1);
	return(-1);
}

/* The raster inverts the chroma on the chroma flag; the luma inversion flips
 * it again, giving chroma inverted = chroma flag XOR luma */
int cablecrypt_chroma_invert(cablecrypt_t *s, int frame, int line)
{
	int f = _field(line);
	(void) frame;
	return(f < 0 ? 0 : s->chroma[f]);
}

/* Vertical interval: 1 = white, 2 = black, 3 = grey */
static int _vi(int line)
{
	if((line >= 7 && line <= 18) || (line >= 20 && line <= 22) || line == 24) return(1);
	if((line >= 320 && line <= 331) || (line >= 333 && line <= 335)) return(1);
	if(line == 23 || line == 25) return(2);
	if(line == 19 || line == 332) return(3);
	return(0);
}

int cablecrypt_render_line(vid_t *s, void *arg, int nlines, vid_line_t **lines)
{
	cablecrypt_t *c = arg;
	vid_line_t *prev = lines[0];
	vid_line_t *l = lines[1];
	int line = l->line, f, vi, x, ar;

	(void) nlines;

	if(line == CC_AUTH1_LINE)
	{
		/* the frame just finished: block averages, compared with the frame
		 * before by 1 - |correlation| (inversion only changes the sign) */
		double cur[CC_GRID_R * CC_GRID_C], mc = 0, mp = 0, sxy = 0, sxx = 0, syy = 0;
		int i, j, n = CC_GRID_R * CC_GRID_C;
		for(i = 0; i < CC_GRID_R; i++)
			for(j = 0; j < CC_GRID_C; j++)
			{
				cur[i * CC_GRID_C + j] = c->gridn[i][j] ? c->grid[i][j] / c->gridn[i][j] : 0;
				c->grid[i][j] = 0; c->gridn[i][j] = 0;
			}
		if(c->prev_ok)
		{
			for(i = 0; i < n; i++) { mc += cur[i]; mp += c->prev[i]; }
			mc /= n; mp /= n;
			for(i = 0; i < n; i++)
			{
				double a = cur[i] - mc, b = c->prev[i] - mp;
				sxy += a * b; sxx += a * a; syy += b * b;
			}
			c->scene = (sxx > 0 && syy > 0) ? 1.0 - fabs(sxy / sqrt(sxx * syy)) : 0.0;
			{
				double dm = fabs(fabs(mc - mp) - 0.0) / (s->white_level - s->black_level) * 2.0;
				if(dm > c->scene) c->scene = dm;
			}
		}
		memcpy(c->prev, cur, sizeof(cur));
		c->prev_ok = 1;
	}
	if(line == CC_AUTH1_LINE || line == CC_AUTH2_LINE)
	{
		_auth_line(s, c, l, line == CC_AUTH2_LINE);
		return(1);
	}
	if(line == CC_SYNC_LINE)
	{
		_sync_line(s, c, l);
		return(1);
	}

	/* Blank: EMM slots, the old vsync lines and the dark lines
	*  may be implemented in the future */
	if(line <= 5 || (line >= 311 && line <= 317) || line >= 623)
	{
		_blank(s, l);
		return(1);
	}

	ar = s->active_left + s->active_width;

	/* Marker lines after field 2's interval: at sync level for ~47 us in
	 * alternate frames, black in the others */
	if(line == 336 || line == 337)
	{
		_blank(s, l);
		if(l->frame & 1)
			_fill(l, (int) (s->pixel_rate * 11.4e-6), (int) (s->pixel_rate * 58.4e-6), s->sync_level);
		return(1);
	}

	vi = _vi(line);
	if(vi)
	{
		_fill(l, s->active_left, ar,
			vi == 1 ? s->white_level :
			vi == 2 ? s->black_level :
			(s->black_level + s->white_level) / 2);
		l->vbialloc = 1;
		return(1);
	}

	f = _field(line);
	if(f < 0) return(1);

	/* scene signature: block sums of this frame's picture, before inversion */
	{
		int row = (line - (f ? 338 : 26)) * CC_GRID_R / 285, col, w = (ar - s->active_left) / CC_GRID_C;
		if(row >= CC_GRID_R) row = CC_GRID_R - 1;
		for(col = 0; col < CC_GRID_C; col++)
		{
			long sum = 0;
			for(x = s->active_left + col * w; x < s->active_left + (col + 1) * w; x++) sum += l->output[x * 2];
			c->grid[row][col] += (double) sum / w;
			c->gridn[row][col]++;
		}
	}

	/* Luma inversion: mirror the composite (this also flips the chroma)
	 * around black + white, offset by the inversion level */
	if(c->luma[f])
	{
		int k = s->black_level + s->white_level + (int) (CC_INV_LEVEL * 0.01 * (s->white_level - s->black_level));
		for(x = s->active_left; x < ar; x++)
		{
			int v = k - l->output[x * 2];
			l->output[x * 2] = v > INT16_MAX ? INT16_MAX : (v < INT16_MIN ? INT16_MIN : v);
		}
	}

	/* hsync displacement: random blocks of 18 or 27 lines, alternating
	 * normal and 2.34 us early */
	if(c->blk_left-- <= 0)
	{
		c->blk_disp ^= 1;
		c->blk_left = 9 * ((_rand(c) & 1) ? 2 : 3) - 1;
	}
	if(c->blk_disp)
	{
		uint8_t sc = 1;
		_fill(l, 0, c->hsync_end, s->blanking_level);
		if(prev->width > 0) _fill(prev, prev->width - c->jump - 4, prev->width, s->blanking_level);
		vbidata_render(c->bsync, &sc, 0, 1, VBIDATA_LSB_FIRST, l);
	}

	return(1);
}