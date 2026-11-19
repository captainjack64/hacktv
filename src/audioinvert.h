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

/* Audio spectrum inversion around 12.8 kHz, as used by
 * Syster / Discret 11 and Videocrypt S (BBC Select) */

typedef struct {
	int16_t *firli, *firlq; /* Left channel, I + Q */
	int16_t *firri, *firrq; /* Right channel, I + Q */
	int mixx;
	int firx;
} audioinvert_t;

extern int audioinvert_init(audioinvert_t *s);
extern void audioinvert_free(audioinvert_t *s);
extern void audioinvert_process(audioinvert_t *s, int16_t *audio, size_t samples);

#endif

