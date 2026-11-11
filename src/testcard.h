/* hacktv - Analogue video transmitter for the HackRF                    */
/*=======================================================================*/
/* Copyright 2017 Philip Heron <phil@sanslogic.co.uk>                    */
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


#ifndef _TESTCARD_H
#define _TESTCARD_H

#include <stdint.h>

typedef struct {
	const uint32_t *data;   /* 0xAARRGGBB, top row first */
	int width;
	int height;
} testcard_image_t;

typedef struct {
	int width;              /* Active width in pixels */
	int height;             /* Active lines */
	double pixel_rate;      /* Pixels per second */
	double pixel_left;      /* Time of pixel 0 relative to 0H, in seconds */
	double active_left;     /* Nominal start of active video, in seconds */
	double active_width;    /* Nominal active line width, in seconds */
	const testcard_image_t *logo; /* HACK TV logo, or NULL */
} testcard_geometry_t;

/* Returns 1 if name is a known generated test card */
extern int testcard_exists(const char *name);

/* Returns the picture aspect ratio of the card (4/3 or 16/9) */
extern float testcard_ratio(const char *name);

extern int testcard_render(const char *name, const testcard_geometry_t *g, uint32_t *fb);

/* As above, but outputs Y, U and V planes as floats (for testing) */
extern int testcard_render_yuv(const char *name, const testcard_geometry_t *g, float *y, float *u, float *v);

/* Print the list of available cards */
extern void testcard_list(void);

#endif
