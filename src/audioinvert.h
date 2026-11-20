/* hacktv - Analogue video transmitter for the HackRF                    */
/*=======================================================================*/
/* Copyright 2018 Philip Heron <phil@sanslogic.co.uk>                    */
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

#ifndef _AUDIOINVERT_H
#define _AUDIOINVERT_H

#include <stdint.h>
#include <stddef.h>

/* Audio spectrum inversion, as used by Syster / Discret 11 (12.8 kHz)
 * and Videocrypt S / BBC Select (12.51 kHz) */

#define AUDIOINVERT_NTAPS 771

typedef struct {
	
	/* Complex FIR filter passing 0 Hz - carrier */
	int16_t *tapsi, *tapsq;
	
	/* Filter windows, I + Q, per channel */
	int16_t *firi[2], *firq[2];
	int firx;
	
	/* Carrier oscillator */
	double phase;
	double delta;
	
	/* Mix stereo to mono before inverting */
	int mono;
	
	/* Output buffer */
	int16_t *buf;
	size_t buf_samples;
	
} audioinvert_t;

/* carrier: inversion frequency in Hz
 * level:   overall gain applied to the inverted audio
 * mono:    1 to average the two channels before inverting */
extern int audioinvert_init(audioinvert_t *s, double carrier, double level, int mono);
extern void audioinvert_free(audioinvert_t *s);

/* Inverts stereo samples into the internal buffer, returns a pointer to it.
 * The input is left unmodified. Returns NULL if audio is NULL. */
extern int16_t *audioinvert_process(audioinvert_t *s, const int16_t *audio, size_t samples);

#endif

