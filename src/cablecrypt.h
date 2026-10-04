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

#ifndef _CABLECRYPT_H
#define _CABLECRYPT_H

#include <stdint.h>
#include "vbidata.h"

#define CC_GRID_R 8             /* scene signature: block grid rows */
#define CC_GRID_C 16            /* and columns */

typedef struct {
	vbidata_lut_t *lut;         /* data line bits */
	vbidata_lut_t *bsync;       /* displaced hsync pulse */
	int x0, x1;                 /* data area */
	int jump;                   /* hsync displacement, samples */
	int hsync_end;

	int luma[2];                /* per field: luma inverted */
	int chroma[2];              /* per field: chroma flag set */

	/* Auth line state */
	int luma_set, chroma_set;
	int chroma_run;             /* fields left until the chroma flag changes */
	uint8_t sym[2];             /* 3-bit symbol shift registers (luma, chroma) */
	uint32_t key;               /* key byte generator (32-bit LFSR) */
	double grid[CC_GRID_R][CC_GRID_C];      /* block sums of the frame being rendered */
	int gridn[CC_GRID_R][CC_GRID_C];
	double prev[CC_GRID_R * CC_GRID_C];     /* previous frame's block averages */
	int prev_ok;
	double scene;               /* scene change of the last frame: 1 - |correlation| */
	int hold;                   /* frames left before luma may flip */
	int armed;                  /* frames since the hold expired */

	uint32_t rng;
	int blk_left, blk_disp;     /* hsync displacement blocks */
} cablecrypt_t;

extern int cablecrypt_init(cablecrypt_t *s, vid_t *vid);
extern void cablecrypt_free(cablecrypt_t *s);
extern int cablecrypt_render_line(vid_t *s, void *arg, int nlines, vid_line_t **lines);
extern int cablecrypt_chroma_invert(cablecrypt_t *s, int frame, int line);

#endif
