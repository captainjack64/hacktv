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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "audioinvert.h"
#include "hacktv.h"
#include "video.h"
#include "fir.h"

#define NTAPS AUDIOINVERT_NTAPS

int audioinvert_init(audioinvert_t *s, double carrier, double level, int mono)
{
	double taps[NTAPS];
	double w;
	int i, c;
	
	memset(s, 0, sizeof(audioinvert_t));
	
	s->mono = mono;
	s->phase = 0;
	s->delta = 2.0 * M_PI * carrier / HACKTV_AUDIO_SAMPLE_RATE;
	
	s->tapsi = calloc(NTAPS, sizeof(int16_t));
	s->tapsq = calloc(NTAPS, sizeof(int16_t));
	
	for(c = 0; c < 2; c++)
	{
		s->firi[c] = calloc(NTAPS * 2, sizeof(int16_t));
		s->firq[c] = calloc(NTAPS * 2, sizeof(int16_t));
	}
	
	if(s->tapsi == NULL || s->tapsq == NULL ||
	   s->firi[0] == NULL || s->firq[0] == NULL ||
	   s->firi[1] == NULL || s->firq[1] == NULL)
	{
		audioinvert_free(s);
		return(VID_OUT_OF_MEMORY);
	}
	
	/* Design the 0 Hz - carrier complex filter: a low-pass filter with
	 * a cutoff of half the carrier frequency, shifted up by the same.
	 * The gain is doubled as taking the real part of the output halves it.
	 * The taps are stored time-reversed, in the order they are applied */
	fir_low_pass(taps, NTAPS, HACKTV_AUDIO_SAMPLE_RATE, carrier / 2, 0, 2.0 * level);
	w = 2.0 * M_PI * (carrier / 2) / HACKTV_AUDIO_SAMPLE_RATE;
	
	for(i = 0; i < NTAPS; i++)
	{
		double t = i - (NTAPS - 1) / 2;
		s->tapsi[i] = lround(taps[i] * cos(-w * t) * INT16_MAX);
		s->tapsq[i] = lround(taps[i] * sin(-w * t) * INT16_MAX);
	}
	
	return(VID_OK);
}

void audioinvert_free(audioinvert_t *s)
{
	int c;
	
	free(s->tapsi);
	free(s->tapsq);
	
	for(c = 0; c < 2; c++)
	{
		free(s->firi[c]);
		free(s->firq[c]);
	}
	
	free(s->buf);
	
	memset(s, 0, sizeof(audioinvert_t));
}

int16_t *audioinvert_process(audioinvert_t *s, const int16_t *audio, size_t samples)
{
	size_t i;
	int c, x, nc;
	int16_t mi, mq;
	int64_t a;
	
	/* Invert the audio spectrum below the carrier frequency.
	 * 
	 * Each audio channel is mixed with a complex sine wave to create a
	 * DSB-SC signal at +carrier. A sharp complex FIR filter is then used
	 * to remove everything but the lower sideband, with the real part of
	 * the result being the inverted audio.
	 * 
	 * The mixing and filtering use complex operations to avoid the
	 * upper sideband interfering after mixing.
	 */
	
	if(audio == NULL) return(NULL);
	
	/* Grow the output buffer if needed */
	if(samples > s->buf_samples)
	{
		int16_t *buf = realloc(s->buf, samples * 2 * sizeof(int16_t));
		if(buf == NULL) return(NULL);
		s->buf = buf;
		s->buf_samples = samples;
	}
	
	nc = s->mono ? 1 : 2;
	
	for(i = 0; i < samples; i++)
	{
		/* Next carrier sample */
		mi = lround(cos(s->phase) * INT16_MAX);
		mq = lround(sin(s->phase) * INT16_MAX);
		
		s->phase += s->delta;
		if(s->phase >= 2.0 * M_PI) s->phase -= 2.0 * M_PI;
		
		for(c = 0; c < nc; c++)
		{
			int32_t in = s->mono
				? ((int32_t) audio[i * 2 + 0] + audio[i * 2 + 1]) / 2
				: audio[i * 2 + c];
			
			s->firi[c][s->firx + NTAPS] = s->firi[c][s->firx] = (in * mi) >> 15;
			s->firq[c][s->firx + NTAPS] = s->firq[c][s->firx] = (in * mq) >> 15;
		}
		
		if(++s->firx == NTAPS) s->firx = 0;
		
		for(c = 0; c < nc; c++)
		{
			const int16_t *fi = &s->firi[c][s->firx];
			const int16_t *fq = &s->firq[c][s->firx];
			
			for(a = x = 0; x < NTAPS; x++)
			{
				a += (int32_t) fi[x] * s->tapsi[x] -
				     (int32_t) fq[x] * s->tapsq[x];
			}
			
			a >>= 15;
			s->buf[i * 2 + c] = a > INT16_MAX ? INT16_MAX : (a < INT16_MIN ? INT16_MIN : a);
		}
		
		if(s->mono)
		{
			s->buf[i * 2 + 1] = s->buf[i * 2 + 0];
		}
	}
	
	return(s->buf);
}

