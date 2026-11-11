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

#ifndef _LUXCRYPT_H
#define _LUXCRYPT_H

#include <stdint.h>
#include "vbidata.h"

typedef struct {
	int active_x;
	int vbi_x;
	int flag_blank;
	int burst_l, burst_r;
	int key_l, key_r;
	int invert;
	int nflags;
	vbidata_lut_t *data;
	vbidata_lut_t *pat;
	vbidata_lut_t *patbase;
	vbidata_lut_t *band;
	vbidata_lut_t *band_vbi;
	vbidata_lut_t *bar;
	vbidata_lut_t *flags;
	vbidata_lut_t *l335;
} luxcrypt_t;

extern int luxcrypt_init(luxcrypt_t *s, vid_t *vid);
extern void luxcrypt_free(luxcrypt_t *s);
extern int luxcrypt_reserve_line(vid_t *s, void *arg, int nlines, vid_line_t **lines);
extern int luxcrypt_render_line(vid_t *s, void *arg, int nlines, vid_line_t **lines);

#endif
