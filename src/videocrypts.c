/* hacktv - Analogue video transmitter for the HackRF                    */
/*=======================================================================*/
/* Copyright 2019 Philip Heron <phil@sanslogic.co.uk>                    */
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

/* -=== Videocrypt S encoder ===-
 * 
 * The line shuffle is generated from the CW and the frame count (see
 * "Line shuffle generator" below), matching a real BBC Select decoder.
 * Free access uses a CW of all ones. Conditional access sends a random
 * CW in bytes 19-26 of the F9 messages, for use with a card that returns
 * those bytes to the decoder.
*/

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <inttypes.h>
#include <time.h>
#include "video.h"
#include "vbidata.h"


/* The first line of each block */
static const int _block_start[12] = {
	 28,  75, 122, 169, 216, 263,
	340, 387, 434, 481, 528, 575,
};

/* Header synchronisation sequence */
static const uint8_t _sequence[8] = {
	0x81,0x92,0xA3,0xB4,0xC5,0xD6,0xE7,0xF0,
};

/* Hamming codes */
static const uint8_t _hamming[16] = {
	0x15,0x02,0x49,0x5E,0x64,0x73,0x38,0x2F,
	0xD0,0xC7,0x8C,0x9B,0xA1,0xB6,0xFD,0xEA,
};

/* The mode byte:
 * 
 * 0x01 = Clear
 * 0x11 = Free access, scrambled
 * 0x21 = Conditional access, scrambled
 *
 * The LSB of the channel byte controls audio inversion.
 *
 * 0 = No inversion
 * 1 = Inversion
*/

/* Blocks for VCS free-access decoding */
static const _vcs_block_t _fa_blocks[] = { { 0x11, 0x00, 0x0000000000000000 }};

/* Blocks for VCS conditional-access decoding, sampled from BBC Select */
static const _vcs_block_t _bbc_blocks[] = {
	{
		0x21, 0x05, 0x0000000000000000,
		{
			{ 0x00 },{ 0x00 },{ 0x00 },{ 0x00 },
			{ 0xF9,0x3A,0xA1,0x25,0x07,0x20,0x20,0x02,0x4C,0x7A,0x8E,0xCA,0x7D,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x80,0x97,0x39,0xDB },
			{ 0x00 },{ 0x00 },
			{ 0x21,0x00,0x78,0x07,0x18,0x06,0xC6,0x42,0x42,0x43,0x20,0x53,0x45,0x4C,0x45,0x43,0x54,0x0D,0xC6,0x42,0x59,0x20,0x48,0x41,0x43,0x4B,0x54,0x56,0x03,0x00,0x00 },
		}
	},
	{
		0x21, 0x05, 0x0000000000000000,
		{
			{ 0x00 },{ 0x00 },{ 0x00 },{ 0x00 },
			{ 0xF9,0x3A,0xA1,0x25,0x07,0x20,0x20,0x02,0x4C,0x7A,0x8E,0xCA,0x7D,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x80,0x97,0x39,0xDB },
			{ 0x00 },{ 0x00 },
			{ 0x21,0x00,0x18,0x01,0x01,0x04,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },
		}
	},
	{
		0x21, 0x05, 0x0000000000000000,
		{
			{ 0x00 },{ 0x00 },{ 0x00 },{ 0x00 },
			{ 0xF9,0x3A,0xA1,0x25,0x07,0x20,0x20,0x02,0x4C,0x7A,0x8E,0xCA,0x7D,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x80,0x97,0x39,0xDB },
			{ 0x00 },{ 0x00 },
			{ 0x21,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },
		}
	},
};

/* -=== Line shuffle generator ===-
 *
 * Derived from captures of a BBC Select decoder.
 * Reproduces every measured block and the full free-access sequence.
 *
 * 1. Picture seed (20 bits): CW bits 8*(fcnt % 8) .. +19 (wrapping round at
 *    bit 59), XOR the frame count spread over 20 bits, XOR 0x6FF00.
 * 2. Block word: the seed rotated left by the block number (0-11).
 * 3. For each block, a 6-bit counter c = k * d (k = 1..64, d odd, from 5
 *    word bits) goes through a mixing stage, a 4-bit adder and an output
 *    stage. Addresses 47-63 are skipped. The 47 remaining values give the
 *    output position of each transmitted line of the block.
 *
 * fcnt is the frame count byte sent in the VBI for the frame.
*/

#define VCS_MASK20      0xFFFFFu
#define VCS_SEED_CONST  0x6FF00u
#define VCS_CW_FA       ((((uint64_t) 1) << 60) - 1)

static uint32_t _rotl20(uint32_t x, int n)
{
	n %= 20;
	return(n ? ((x << n) | (x >> (20 - n))) & VCS_MASK20 : x);
}

static uint32_t _shuffle_seed(uint64_t cw, uint8_t fcnt)
{
	int m = fcnt & 7;
	uint32_t window, e;
	
	cw &= VCS_CW_FA;
	
	/* CW bits 8m .. 8m+19, wrapping round at bit 59 */
	window = (uint32_t) (((cw >> (8 * m)) | (cw << (60 - 8 * m))) & VCS_MASK20);
	e = fcnt | (fcnt << 8) | ((uint32_t) (fcnt & 0x0F) << 16);
	
	return(window ^ e ^ VCS_SEED_CONST);
}

/* Bit n of a block word */
static inline int _wb(uint32_t w, int n)
{
	return((w >> n) & 1);
}

static void _shuffle_block(uint32_t w, uint8_t q[47])
{
	/* Counter step (always odd) and adder constant */
	int d  = 1 | _wb(w, 0) << 1 | _wb(w, 7) << 2 | (_wb(w, 17) ^ 1) << 3 | _wb(w, 12) << 4 | _wb(w, 3) << 5;
	int k  = _wb(w, 10) | _wb(w, 19) << 1 | _wb(w, 5) << 2 | _wb(w, 14) << 3;
	
	/* Mixing stage controls. x3 = c5 ^ (m3 & c1) ^ v3 */
	int b2 = _wb(w, 2), b6 = _wb(w, 6), b8 = _wb(w, 8), b13 = _wb(w, 13);
	int m3 = _wb(w, 4) ^ b6;
	int v3 = _wb(w, 15) ^ (_wb(w, 4) & b6);
	
	/* Output stage: bit swaps (b9: 2/3, b18: 4/5) as bit positions,
	 * then the XORs (b1, b11, b16) as one mask */
	int s2 = _wb(w, 9) ? 3 : 2, s3 = _wb(w, 9) ? 2 : 3;
	int s4 = _wb(w, 18) ? 5 : 4, s5 = _wb(w, 18) ? 4 : 5;
	int xm = _wb(w, 1) << 1 | _wb(w, 11) << s3 | _wb(w, 16) << s2;
	int c = 0, i = 0;
	
	/* d is odd, so the counter visits all 64 addresses and
	 * exactly 47 of them are below 47 */
	while(i < 47)
	{
		int c0, c1, c2, c3, c4, c5, l4, n, x;
		
		c  = (c + d) & 63;
		c0 = c & 1;
		c1 = (c >> 1) & 1;
		c2 = (c >> 2) & 1;
		c3 = (c >> 3) & 1;
		c4 = (c >> 4) & 1;
		c5 = c >> 5;
		l4 = c4 ^ (b8 & c0);
		
		/* 4-bit adder on x3, x1, x4, x0 (LSB..MSB) */
		n  = (c5 ^ (m3 & c1) ^ v3)
		   | (c1 ^ b6) << 1
		   | (b2 ? c2 : c3) << 2
		   | (b2 ? c3 : c2) << 3;
		n  = (n + k) & 15;
		
		/* Place each bit at its output position */
		x  = (n & 1) << s3
		   | ((n >> 1) & 1) << 1
		   | ((n >> 2) & 1) << s4
		   | (n >> 3)
		   | (b13 ? l4 : c0) << s2
		   | (b13 ? c0 : l4) << s5;
		x ^= xm;
		
		/* Addresses 47-63 are skipped */
		if(x < 47) q[i++] = x;
	}
}

/* q[b][i] = output position (within output block b + 1) of transmitted
 * line i of transmitted block b */
static void _shuffle_frame(uint64_t cw, uint8_t fcnt, uint8_t q[12][47])
{
	uint32_t s = _shuffle_seed(cw, fcnt);
	int b;
	
	for(b = 0; b < 12; b++)
	{
		_shuffle_block(_rotl20(s, b), q[b]);
	}
}

/* A random 60-bit CW */
static uint64_t _random_cw(void)
{
	uint64_t cw = 0;
	int i;
	
	for(i = 0; i < 4; i++)
	{
		cw = (cw << 16) | (rand() & 0xFFFF);
	}
	
	return(cw & VCS_CW_FA);
}

/* Reverse bits in an 8-bit value */
static uint8_t _reverse(uint8_t b)
{
	b = (b & 0xF0) >> 4 | (b & 0x0F) << 4;
	b = (b & 0xCC) >> 2 | (b & 0x33) << 2;
	b = (b & 0xAA) >> 1 | (b & 0x55) << 1;
	return(b);
}

/* Reverse nibbles in a byte */
static inline uint8_t _rnibble(uint8_t a)
{
	return((a >> 4) | (a << 4));
}

/* Apply VBI frame interleaving */
static void _interleave(uint8_t *frame)
{
	int b, i, j;
	int offset[6] = { 0, 6, 12, 20, 26, 32 };
	uint8_t r[8];
	uint8_t m;
	
	for(b = 0; b < 6; b++)
	{
		uint8_t *s = frame + offset[b];
		
		s[0] = _reverse(s[0]);
		s[7] = _reverse(s[7]);
		
		for(i = 0, m = 0x80; i < 8; i++, m >>= 1)
		{
			r[i] = 0x00;
			for(j = 0; j < 8; j++)
			{
				r[i] |= ((m & s[j]) ? 1 : 0) << j;
			}
		}
		
		memcpy(s, r, 8);
	}
}

/* Encode VBI data */
static void _encode_vbi(uint8_t vbi[40], const uint8_t data[16], uint8_t a, uint8_t b)
{
	int x;
	
	/* Set the information (a, b) and initial check bytes for each field */
	vbi[ 9] = vbi[ 0] = a;
	vbi[19] = vbi[10] = b;
	
	/* Copy the eight security bytes for each field,
	 * while updating the check byte */
	for(x = 0; x < 8; x++)
	{
		vbi[ 9] += vbi[ 1 + x] = data[0 + x];
		vbi[19] += vbi[11 + x] = data[8 + x];
	}
	
	/* Hamming code the VBI data */
	for(x = 19; x >= 0; x--)
	{
		vbi[x * 2 + 1] = _hamming[vbi[x] & 0x0F];
		vbi[x * 2 + 0] = _hamming[vbi[x] >> 4];
	}
	
	/* Interleave the VBI data */
	_interleave(vbi);
}

int vcs_init(vcs_t *s, vid_t *vid, const char *mode)
{
	memset(s, 0, sizeof(vcs_t));
	
	/* Generate the VBI data symbols */
	s->lut = vbidata_init_step(
		40,
		vid->width,
		round((vid->white_level - vid->black_level) * 1.00),
		(double) vid->pixel_rate / VCS_SAMPLE_RATE * VCS_VBI_SAMPLES_PER_BIT,
		vid->pixel_rate * 125e-9 * IRT1090,
		vid->pixel_rate * 11.90e-6
	);
	
	if(!s->lut)
	{
		return(VID_OUT_OF_MEMORY);
	}
	
	s->counter  = 0;
	
	if(strcmp(mode, "free") == 0)
	{
		/* Free access: the decoder uses a CW of all ones */
		s->blocks    = _fa_blocks;
		s->block_len = sizeof(_fa_blocks) / sizeof(_vcs_block_t);
		s->cw        = VCS_CW_FA;
	}
	else if(strcmp(mode, "conditional") == 0)
	{
		/* Conditional access: a new random CW every 32-frame block,
		 * sent in bytes 19-26 of that block's F9 messages and used
		 * by the scrambler from the start of the following block */
		time_t t;
		
		srand((unsigned) time(&t));
		
		s->blocks    = _bbc_blocks;
		s->block_len = sizeof(_bbc_blocks) / sizeof(_vcs_block_t);
		s->random_cw = 1;
		s->cw        = _random_cw();
		s->next_cw   = _random_cw();
		s->showecm   = vid->conf.showecm;
	}
	else
	{
		fprintf(stderr, "Unrecognised Videocrypt S mode '%s'.\n", mode);
		return(VID_ERROR);
	}
	
	s->block_num = 0;
	
	return(VID_OK);
}

void vcs_free(vcs_t *s)
{
	free(s->lut);
}

/* -=== Line resampling to get to 4FSC ===- */
#define VCS_4FSC  17734475.0
#define VCS_TAPS  16

/* Shift in pixels to apply to a line moved j lines, starting at line n */
static double _move_shift(vid_t *s, int n, int j)
{
	int c = 0;
	int k;
	
	/* Count the 1137-clock lines passed (312 and 624) */
	for(k = 0; k < j; k++)
	{
		int m = (n - 1 + k) % s->conf.lines + 1;
		if(m == 312 || m == 624) c++;
	}
	
	return((double) (j * 1135 + 2 * c) * s->pixel_rate / VCS_4FSC - (double) j * s->width);
}

/* Copy samples x0 .. x1 - 1 of src to dst, reading src at x + delta */
static void _shift_copy(int16_t *dst, const int16_t *src, int x0, int x1, int width, double delta)
{
	double h[VCS_TAPS];
	int32_t hq[VCS_TAPS];
	double f, sum = 0;
	int n, k, x;
	
	n = (int) floor(delta);
	f = delta - n;
	
	if(f < 1e-6 || f > 1 - 1e-6)
	{
		/* Whole-sample shift */
		if(f > 0.5) n++;
		
		for(x = x0; x < x1; x++)
		{
			int i = x + n;
			if(i < 0) i = 0;
			if(i >= width) i = width - 1;
			dst[x * 2] = src[i * 2];
		}
		
		return;
	}
	
	/* Blackman-windowed sinc, taps at n - 7 .. n + 8 */
	for(k = 0; k < VCS_TAPS; k++)
	{
		double t = (k - (VCS_TAPS / 2 - 1)) - f;
		double sinc = sin(M_PI * t) / (M_PI * t);
		double w = 0.42 + 0.5 * cos(2 * M_PI * t / VCS_TAPS) + 0.08 * cos(4 * M_PI * t / VCS_TAPS);
		h[k] = sinc * w;
		sum += h[k];
	}
	
	/* Q15 coefficients */
	for(k = 0; k < VCS_TAPS; k++)
	{
		hq[k] = lrint(h[k] / sum * 32768.0);
	}
	
	for(x = x0; x < x1; x++)
	{
		int64_t a = 1 << 14;
		int i = x + n - (VCS_TAPS / 2 - 1);
		
		if(i >= 0 && i + VCS_TAPS <= width)
		{
			const int16_t *p = &src[i * 2];
			for(k = 0; k < VCS_TAPS; k++)
			{
				a += (int32_t) hq[k] * p[k * 2];
			}
		}
		else
		{
			/* Near the line ends, repeat the end samples */
			for(k = 0; k < VCS_TAPS; k++)
			{
				int m = i + k;
				if(m < 0) m = 0;
				if(m >= width) m = width - 1;
				a += (int32_t) hq[k] * src[m * 2];
			}
		}
		
		a >>= 15;
		dst[x * 2] = a > INT16_MAX ? INT16_MAX : (a < INT16_MIN ? INT16_MIN : a);
	}
}

int vcs_render_line(vid_t *s, void *arg, int nlines, vid_line_t **lines)
{
	vcs_t *v = arg;
	int x, j;
	uint8_t *bline = NULL;
	vid_line_t *l = lines[0];
	
	/* Swap the active line with the oldest line in the delay buffer,
	 * with active video offset in j if necessary. */
	j = 0;
	
	if((l->line >=  28 && l->line <= 309) ||
	   (l->line >= 340 && l->line <= 621))
	{
		int block;
		int bline;
		
		/* Calculate the line number,
		 *   0 - 281 top field,
		 * 282 - 563 bottom field
		*/
		x = l->line - (l->line < 340 ? 28 : 340 - 282);
		
		/* Calculate block number and block line */
		block = x / 47;
		bline = x % 47;
		
		if(bline == 0)
		{
			int i;
			
			for(i = 0; i < 47; i++)
			{
				v->block[i] = v->shuffle[block][i];
			}
		}
		
		/* Calculate target block/line */
		block = (block + 1) % 12;
		bline = v->block[bline];
		
		/* Calculate position in delay buffer */
		j = (_block_start[block] + bline) - l->line;
		if(j < 0) j += s->conf.lines;
	}
	
	if(j > 0)
	{
		_shift_copy(
			l->output, lines[j]->output,
			s->active_left, s->width, s->width,
			_move_shift(s, l->line, j)
		);
	}
	
	/* On the first line of each frame, generate the VBI data */
	if(l->line == 1)
	{
		uint8_t crc;
		
		/* The line shuffle for this frame, from the CW in use and the
		 * frame count byte sent in this frame */
		_shuffle_frame(v->cw, v->counter, v->shuffle);
		
		if((v->counter & 3) == 0)
		{
			/* The active message is updated every 4th frame */
			for(x = 0; x < 31; x++)
			{
				v->message[x] = v->blocks[v->block_num].messages[(v->counter >> 2) & 7][x];
			}
			
			/* Conditional access: the next CW goes in F9 bytes 19-26
			 * (only the low nibble of byte 26 is used) */
			if(v->random_cw && v->message[0] == 0xF9)
			{
				for(x = 0; x < 8; x++)
				{
					v->message[19 + x] = (v->next_cw >> (8 * x)) & 0xFF;
				}
				
				v->message[26] &= 0x0F;
			}
			
			for(crc = x = 0; x < 31; x++)
			{
				crc += v->message[x];
			}
			
			v->message[x] = ~crc + 1;
			
			/* Print the ECM (once per block, the F9 is sent twice) */
			if(v->showecm && v->message[0] == 0xF9 && ((v->counter >> 2) & 7) == 4)
			{
				fprintf(stderr, "\n\nVCS ECM In:  ");
				for(x = 0; x < 32; x++) fprintf(stderr, "%02X ", v->message[x]);
				fprintf(stderr, "\nVCS ECM Out: ");
				for(x = 0; x < 8; x++) fprintf(stderr, "%02" PRIX64 " ", (v->next_cw >> (8 * x)) & 0xFF);
			}
		}
		
		if((v->counter & 2) == 0)
		{
			/* The first half of the message */
			_encode_vbi(
				v->vbi, v->message,
				_sequence[(v->counter >> 2) & 0x07],
				v->counter & 0xFF
			);
		}
		else
		{
			/* The second half of the message */
			_encode_vbi(
				v->vbi, v->message + 16,
				_rnibble(_sequence[(v->counter >> 2) & 0x07]),
				(v->counter & 0x08 ? v->blocks[v->block_num].channel : v->blocks[v->block_num].mode)
			);
		}
		
		v->counter++;
		
		/* After 32 frames, advance to the next VCS block and codeword */
		if((v->counter & 0x1F) == 0)
		{
			/* Apply the CW sent in this block, and pick the next one */
			if(v->random_cw)
			{
				v->cw = v->next_cw;
				v->next_cw = _random_cw();
			}
			
			/* Move to the next block */
			if(++v->block_num == v->block_len)
			{
				v->block_num = 0;
			}
		}
	}
	
	/* Set a pointer to the VBI data to render on this line, or NULL if none */
	if(l->line >= VCS_VBI_FIELD_1_START &&
	   l->line <  VCS_VBI_FIELD_1_START + VCS_VBI_LINES_PER_FIELD)
	{
		/* Top field VBI */
		bline = &v->vbi[(l->line - VCS_VBI_FIELD_1_START) * VCS_VBI_BYTES_PER_LINE];
	}
	else if(l->line >= VCS_VBI_FIELD_2_START &&
	        l->line <  VCS_VBI_FIELD_2_START + VCS_VBI_LINES_PER_FIELD)
	{
		/* Bottom field VBI */
		bline = &v->vbi[(l->line - VCS_VBI_FIELD_2_START + VCS_VBI_LINES_PER_FIELD) * VCS_VBI_BYTES_PER_LINE];
	}
	
	if(bline)
	{
		/* Videocrypt S's VBI data sits in the active video area. Clear it first */
		for(x = s->active_left; x < s->active_left + s->active_width; x++)
		{
			l->output[x * 2] = s->black_level;
		}
		
		vbidata_render(v->lut, bline, 0, 40, VBIDATA_LSB_FIRST, l);
		
		l->vbialloc = 1;
	}
	
	return(1);
}