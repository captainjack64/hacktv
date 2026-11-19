/* Nagravision Syster encoder for hacktv                                 */
/*=======================================================================*/
/* Copyright 2018 Alex L. James                                          */
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

/* -=== Nagravision Syster encoder ===-
 * 
 * These functions implement the image scrambler for Nagravision Syster.
 * This system uses line shuffling to obscure the image.
 * 
 * There is some limited support for real hardware decoders.
*/

/* -=== Discret 11 encoder ===-
 *
 * This system uses one of three line delays. 
 * Implementation here uses free access mode (audience 7),
 * which works with real D11 decoders as well as Syster decoders
 * when used with a valid card (or PIC file provided).
*/

/* Syster VBI data
 * 
 * Some or all of the notes here might be wrong. They're based on
 * data recovered from VHS recordings of Premere (Germany).
 * 
 * Data is transmitted on two VBI lines per field, 224 bits / 28 bytes
 * each encoded as NRZ. The clock rate is 284 * fH. Bytes are transmitted
 * LSB first.
 * 
 * -----------------------------------------------
 * | sync (32) | seq (8) | data (168) | crc (16) |
 * -----------------------------------------------
 * 
 * sync: 10101010 00001011 00011000 00110110 / 55 D0 18 6C
 *  seq: Hamming code sync sequence: 15 FD 73 9B 5E B6 49 A1 02 EA
 * data: Payload data (21 bytes)
 *  crc: 16-bit CRC of the 22 bytes between sync and crc
 * 
 * Blocks (packets, frames?) of 210 bytes are transmitted in 10 parts,
 * each 21 bytes long. The seq field indicates which part is currently
 * being transmitted. A block begins with seq code 15 and ends with
 * code EA, and are always transmitted in this order without interruption.
 * 
 * The decoder never activates without a key inserted. There does not appear
 * to be an equivilent to the free-access mode in Videocrypt, which works
 * with or without a card inserted.
*/

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <inttypes.h>
#include "video.h"
#include "vbidata.h"
#include "syster-ca.h"
#include "systercnr-sequence.h"

/* ECM data table */
static ng_mode_t _ng_modes[] = {
	{ "premiere-fa", { 0xC4, 0xA5, 0xA8, 0x18, 0x74, 0x93, 0xC7, 0x65 }, { 0xFF, 0x01, 0x11, 0x00, 0xFF, 0xFF, 0x00, 0x00 }, "01/01/1999",  0, 1 },
	{ "premiere-ca", { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34 }, { 0x7F, 0x01, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00 }, "01/01/1999",  0, 1 },
	{ "cplfa",       { 0xC4, 0xA5, 0xA8, 0x18, 0x74, 0x93, 0xC7, 0x65 }, { 0xFF, 0x05, 0x11, 0x00, 0x88, 0x15, 0x00, 0x00 }, "01/01/1997", -4, 1 },
	{ "cfrca",       { 0x00, 0xAE, 0x52, 0x90, 0x49, 0xF1, 0xF1, 0xBB }, { 0xFF, 0x01, 0x01, 0x00, 0x7B, 0x0A, 0x00, 0x00 }, "01/01/1997", -1, 2 }, /* VBI offset: -1 = old Canal+ France keys (white), -3 = new Canal+ France keys (grey) */
	{ "cfrfa",       { 0xC4, 0xA5, 0xA8, 0x18, 0x74, 0x93, 0xC7, 0x65 }, { 0xFF, 0x01, 0x11, 0x00, 0x7B, 0x0A, 0x00, 0x00 }, "01/01/1997", -1, 2 }, /* VBI offset: -1 = old Canal+ France keys (white), -3 = new Canal+ France keys (grey) */
	{ "cesfa",       { 0xC4, 0xA5, 0xA8, 0x18, 0x74, 0x93, 0xC7, 0x65 }, { 0x80, 0x01, 0x11, 0x00, 0x7B, 0x0A, 0x00, 0x00 }, "01/01/1997", -4, 1 },
	{ "ntvfa",       { 0xC4, 0xA5, 0xA8, 0x18, 0x74, 0x93, 0xC7, 0x65 }, { 0x80, 0x08, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00 }, "01/01/1997",  1, 2 }, /* HTB+ Russia */
	{ "chorfa",      { 0xC4, 0xA5, 0xA8, 0x18, 0x74, 0x93, 0xC7, 0x65 }, { 0xFF, 0x01, 0x11, 0x00, 0x7B, 0x0A, 0x00, 0x00 }, "01/01/1997", -5, 1 }, /* Canal+ Horizons */
	{ NULL }
};

/* Masks for the PRBS */
#define _PRBS_SR1_MASK (((uint32_t) 1 << 31) - 1)
#define _PRBS_SR2_MASK (((uint32_t) 1 << 29) - 1)

/* The standard syster substitution table */
static const uint8_t _key_table1[0x100] = {
	10, 11, 12, 13, 16, 17, 18, 19, 13, 14, 15, 16,  0,  1,  2,  3,
	21, 22, 23, 24, 18, 19, 20, 21, 23, 24, 25, 26, 26, 27, 28, 29,
	19, 20, 21, 22, 11, 12, 13, 14, 28, 29, 30, 31,  4,  5,  6,  7,
	22, 23, 24, 25,  5,  6,  7,  8, 31,  0,  1,  2, 27, 28, 29, 30,
	 3,  4,  5,  6,  8,  9, 10, 11, 14, 15, 16, 17, 25, 26, 27, 28,
	15, 16, 17, 18,  7,  8,  9, 10, 17, 18, 19, 20, 29, 30, 31,  0,
	24, 25, 26, 27, 20, 21, 22, 23,  1,  2,  3,  4,  6,  7,  8,  9,
	12, 13, 14, 15,  9, 10, 11, 12,  2,  3,  4,  5, 30, 31,  0,  1,
	24, 25, 26, 27,  2,  3,  4,  5, 31,  0,  1,  2,  7,  8,  9, 10,
	13, 14, 15, 16, 26, 27, 28, 29, 14, 15, 16, 17, 18, 19, 20, 21,
	22, 23, 24, 25,  5,  6,  7,  8, 19, 20, 21, 22, 12, 13, 14, 15,
	17, 18, 19, 20, 27, 28, 29, 30, 10, 11, 12, 13, 11, 12, 13, 14,
	 6,  7,  8,  9,  1,  2,  3,  4,  0,  1,  2,  3,  4,  5,  6,  7,
	 3,  4,  5,  6,  8,  9, 10, 11, 15, 16, 17, 18, 23, 24, 25, 26,
	29, 30, 31,  0, 25, 26, 27, 28,  9, 10, 11, 12, 21, 22, 23, 24,
	20, 21, 22, 23, 30, 31,  0,  1, 16, 17, 18, 19, 28, 29, 30, 31
};

/* Canal+ FR (Oct 1997) */
static const uint8_t _key_table2[0x100] = {
	10, 11, 12, 13, 16, 17, 18, 19, 12, 15, 14, 17,  0,  1,  2,  3,
	20, 23, 22, 25, 18, 19, 20, 21, 22, 25, 24, 27, 26, 27, 28, 29,
	18, 21, 20, 23, 10, 13, 12, 15, 28, 29, 30, 31,  4,  5,  6,  7,
	22, 23, 24, 25,  4,  7,  6,  9, 30,  1,  0,  3, 26, 29, 28, 31,
	 2,  5,  4,  7,  8,  9, 10, 11, 14, 15, 16, 17, 24, 27, 26, 29,
	14, 17, 16, 19,  6,  9,  8, 11, 16, 19, 18, 21, 28, 31, 30,  1,
	24, 25, 26, 27, 20, 21, 22, 23,  0,  3,  2,  5,  6,  7,  8,  9,
	12, 13, 14, 15,  8, 11, 10, 13,  2,  3,  4,  5, 30, 31,  0,  1,
	24, 25, 26, 27,  2,  3,  4,  5, 30,  1,  0,  3,  6,  9,  8, 11,
	12, 15, 14, 17, 26, 27, 28, 29, 14, 15, 16, 17, 18, 19, 20, 21,
	22, 23, 24, 25,  4,  7,  6,  9, 18, 21, 20, 23, 12, 13, 14, 15,
	16, 19, 18, 21, 26, 29, 28, 31, 10, 11, 12, 13, 10, 13, 12, 15,
	 6,  7,  8,  9,  0,  3,  2,  5,  0,  1,  2,  3,  4,  5,  6,  7,
	 2,  5,  4,  7,  8,  9, 10, 11, 14, 17, 16, 19, 22, 25, 24, 27,
	28, 31, 30,  1, 24, 27, 26, 29,  8, 11, 10, 13, 20, 23, 22, 25,
	20, 21, 22, 23, 30, 31,  0,  1, 16, 17, 18, 19, 28, 29, 30, 31
};

static const uint8_t _vbi_sequence[10] = {
	0x73, 0x9B, 0x5E, 0xB6, 0x49, 0xA1, 0x02, 0xEA, 0x15, 0xFD
};

/* Blank ECM table for random control words */
static ng_ecm_t _ecm_table_rand[0x40];

static const uint8_t *_dummy_emm = (const uint8_t *) "\xFF\xFF\xFF\xFF" "DUMMYEMMDUMMYEMMDUMMYEMMDUMMYEMMDUMMYEMMDUMMYEMMDUMMYEMMDUMMYEMM" "\x9E\x4D\xDC\xF0";
static const uint8_t _ppua_emm[] = { 0x00,0x40,0x00,0x00,0x43,0x43,0x41,0x80,0x69,0x4A,0x10,0x22,0xE3,0xA9,0x9A,0xF8,0xB9,0x0F,0xD4,0xEF,0x6E,0x8A,0x30,0xCF,0xA4,0xCD,0xAD,0x83,0x4D,0xA3,0x1C,0xB0,0x2F,0x78,0xCE,0xE9,0xA8,0xDE,0xBB,0x4A,0x06,0xF0,0x27,0x4C,0xA6,0xBD,0xAD,0x67,0x9C,0xEB,0xAD,0xAE,0xD2,0xA5,0x31,0xC9,0x51,0x58,0x0D,0x72,0xF5,0x7B,0xF4,0x74,0x2D,0x45,0x3D,0xB1,0x87,0x78,0x21,0x69 };

static void _prbs_reset(ng_t *s, uint64_t cw)
{
	s->sr1 = cw & _PRBS_SR1_MASK;
	s->sr2 = (cw >> 32) & _PRBS_SR2_MASK;
}

static uint16_t _prbs_update(ng_t *s)
{
	uint16_t code = 0;
	int a, i;
	
	for(i = 0; i < 16; i++)
	{
		/* Shift the registers */
		s->sr1 = (s->sr1 >> 1) ^ (s->sr1 & 1 ? 0x7BB88888UL : 0);
		s->sr2 = (s->sr2 >> 1) ^ (s->sr2 & 1 ? 0x17A2C100UL : 0);
		
		/* Load the multiplexer address */
		a = (s->sr2 >> 24) & 0x1F;
		if(a == 31) a = 30;
		
		/* Shift into result register */
		code = (code << 1) | ((s->sr1 >> a) & 1);
	}
	
	/* Code is: rrrrrrrrsssssssx
	 * x = spare bit
	 * r = 8-bit r value
	 * s = 7-bit s value */
	
	return(code >> 1);
}

static uint16_t _crc(const uint8_t *data, size_t length)
{
	uint16_t crc = 0x0000;
	const uint16_t poly = 0xC003;
	int b;
	
	while(length--)
	{
		crc ^= *(data++);
		
		for(b = 0; b < 8; b++)
		{
			crc = (crc & 1 ? (crc >> 1) ^ poly : crc >> 1);
		}
	}
	
	return(crc);
}

static void _pack_vbi_block(uint8_t vbi[10][NG_VBI_BYTES], const uint8_t msg1[NG_MSG_BYTES], const uint8_t msg2[NG_MSG_BYTES])
{
	int i, x;
	
	/* A block covers 10 VBI lines and contains various control bytes, two
	 * EMM messages, a PRBS codeword, some unknown data and two methods of
	 * error detection. */
	
	/* Copy the message data */
	memcpy(&vbi[4][5], &msg2[0], 21);
	memcpy(&vbi[5][5], &msg2[21], 21);
	memcpy(&vbi[2][5], &msg2[42], 21);
	memcpy(&vbi[3][5], &msg2[63], 21);
	
	memcpy(&vbi[8][5], &msg1[0], 21);
	memcpy(&vbi[9][5], &msg1[21], 21);
	memcpy(&vbi[6][5], &msg1[42], 21);
	memcpy(&vbi[7][5], &msg1[63], 21);
	
	/* Calculate the XOR packet data */
	for(x = 5; x < 26; x++)
	{
		vbi[0][x] = vbi[1][x] = 0x00;
		
		for(i = 2; i < 10; i++)
		{
			vbi[i & 1][x] ^= vbi[i][x];
		}
	}
	
	/* Generate the VBI header and CRC for each line */
	for(i = 0; i < 10; i++)
	{
		uint16_t crc;
		
		vbi[i][0] = 0x55;
		vbi[i][1] = 0xD0;
		vbi[i][2] = 0x18;
		vbi[i][3] = 0x6C;
		vbi[i][4] = _vbi_sequence[i];
		
		/* Calculate and apply the CRC */
		crc = _crc(&vbi[i][4], 22);
		vbi[i][26] = (crc & 0x00FF) >> 0;
		vbi[i][27] = (crc & 0xFF00) >> 8;
	}
}

void _ecm_part(ng_t *s, vid_t *vid, uint8_t *dst)
{
	const uint8_t il[20] = {
		0x00, 0x01, 0x30, 0x31, 0x40, 0x41, 0x20, 0x21, 0x60, 0x61,
		0x00, 0x01, 0x7E, 0x7F, 0x50, 0x51, 0x70, 0x71, 0x10, 0x11,
	};
	const uint8_t ap[20] = {
		0x01, 0x0F, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
		0x01, 0x00, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
	};
	
	const ng_ecm_t *ecm;
	const uint8_t *d;
	uint16_t c;
	int i;
	
	/* Calculate ECM table offset for this block */
	c = (s->block_seq / 20 * 2 + il[s->block_seq % 20]) & 0x7F;
	
	ecm = &s->blocks[c / 2];
	
	/* Get a pointer to the 8 ECM bytes to send */
	d = &ecm->ecm[c & 1 ? 8 : 0];
	
	/* Encode the result into the VBI line */
	c = (c << 4) | ap[s->block_seq % 20];
	dst[0] = c >> 8;
	dst[1] = c & 0xFF;
	memcpy(&dst[2], d, 8);
	
	if(ap[s->block_seq % 20] == 0x00)
	{
		s->cw = ecm->cw;
	}
	else if(s->block_seq % 20 == 13)
	{
		/* Print ECM */
		if(vid->conf.showecm)
		{
			fprintf(stderr, "\n\nECM In:  ");
			for(i = 0; i < 16; i++) fprintf(stderr, "%02X ", ecm->ecm[i]);
			fprintf(stderr, "\nECM Out: ");
			for(i = 0; i < 8; i++) fprintf(stderr, "%02X ", (uint8_t) (ecm->cw >> (8 * i) & 0xFF));
		}
	}
}

static void _update_field_order(ng_t *s)
{
	int i, j;
	int b[32];
	
	/* This function generates the scrambled line order for the
	 * next field based on _key_table, s->s and s->r parameters.
	 *
	 * Based on work by Markus G. Kuhn from his publication
	 * 'Analysis of the Nagravision Video Scrambling Method', 1998-07-09
	*/
	
	for(i = 0; i < 32; i++)
	{
		b[i] = -32 + i;
	}
	
	for(i = 0; i < 287; i++)
	{
		j = i <= 254 ? s->table[(s->r + (2 * s->s + 1) * i) & 0xFF] : i - 255;
		b[j] = s->order[b[j] + 32] = i;
	}
}

int _ng_vbi_init(ng_t *s, vid_t *vid)
{
	int i;
	
	/* Calculate the high level for the VBI data, 66% of the white level */
	i = round((vid->white_level - vid->black_level) * 0.66);
	s->lut = vbidata_init(
		NG_VBI_WIDTH, vid->width,
		i,
		VBIDATA_FILTER_RC, (double) vid->width / NG_VBI_WIDTH, 0.7,
		0
	);
	
	if(!s->lut)
	{
		return(VID_OUT_OF_MEMORY);
	}
	
	s->vbi_seq = 0;
	s->block_seq = 0;
	
	return(VID_OK);
}

void _render_ng_vbi(ng_t *s, vid_t *vid, vid_line_t *l)
{
	int x;
	ng_mode_t n = _ng_modes[s->id];
	
	/* Render the VBI data */
	/* French C+ key lines: 13, 14, 326, 327 (ATR 18381200FF148083) (offset 1) */
	/* Premiere  key lines: 14, 15, 327, 328 (ATR 1C381405FF14E1E5) (offset 0) */
	/* Polish C+ key lines: 10, 11, 323, 324 (ATR 1CE00C01FF14E1E5) (offset 4) */
	
	if(l->line == 14 + n.vbioffset|| l->line == 15 + n.vbioffset||
	   l->line == 327 + n.vbioffset || l->line == 328 + n.vbioffset)
	{
		if(s->vbi_seq == 0)
		{
			const uint8_t *emm1 = _dummy_emm;
			const uint8_t *emm2 = _dummy_emm;
			uint8_t msg1[NG_MSG_BYTES];
			uint8_t msg2[NG_MSG_BYTES];
			
			/* Transmit the PPUA EMM every 1000 frames */
			if(l->frame > s->next_ppua)
			{
				emm1 = _ppua_emm;
				s->next_ppua = l->frame + 1000;
			}
			
			/* Build part 1 of the VBI block */
			msg1[ 0] = s->flags | ((n.data[2] >> 5) & 1);    /* Decoder parameters + audience */
			_ecm_part(s, vid, &msg1[1]);
			msg1[ 1] |= n.data[2] << 3;                  /* Audience uses 5 top bits of msg1[1] */
			msg1[11] = 0xFF;	/* Simple checksum -- the Premiere VBI sample only has 0x00/0xFF here */
			for(x = 0; x < 11; x++)
			{
				msg1[11] ^= msg1[x];
			}
			memcpy(&msg1[12], emm1, 72);
			
			/* Build part 2 of the VBI block */
			msg2[ 0] = 0xFE;                             /* ??? Premiere DE: 0xFE, Canal+ PL: 0x00, HTB+: 0x01 */
			msg2[ 1] = 0x28 | ((s->flags >> 2) & 1);     /* ??? Premiere DE: 0x28 (cut and rotate: 0x29), Canal+ PL: 0x2A, HTB+: 0x3A */
			msg2[ 2] = 0xB1;                             /* ??? Premiere DE: 0xB1, Canal+ PL: 0xE4, HTB+: 0x16 */
			msg2[ 3] = emm1 == _ppua_emm ? 0x01 : 0x00;  /* 0x00, or 0x01 when a broadcast EMM is present */
			msg2[ 4] = emm2 == _ppua_emm ? 0x01 : 0x00;
			msg2[ 5] = 0x00;                             /* The following bytes are always 0x00 */
			msg2[ 6] = 0x00;
			msg2[ 7] = 0x00;
			msg2[ 8] = 0x00;
			msg2[ 9] = 0x00;
			msg2[10] = 0x00;
			msg2[11] = 0x00;
			memcpy(&msg2[12], emm2, 72);
			
			/* Pack the messages into the next 10 VBI lines */
			_pack_vbi_block(s->vbi, msg1, msg2);
			
			/* Advance the block sequence counter */
			s->block_seq++;
		}
		
		/* Render the line */
		vbidata_render(s->lut, s->vbi[s->vbi_seq++], 45, NG_VBI_BYTES * 8, VBIDATA_LSB_FIRST, l);
		l->vbialloc = 1;
		
		if(s->vbi_seq == 10)
		{
			s->vbi_seq = 0;
		}
	}
}

void _rand_seed(ng_t *s, unsigned char data[8], unsigned char key[8], int ecm_type)
{
	int i, j;
	
	/* Generate 64 random control words */
	for(j =0 ; j < 0x40; j++)
	{
		for(i = 0; i < 16; i++)
		{
			s->blocks[j].ecm[i] = i < 4 || i > 11 ? (ecm_type == STATIC_ECM ? i : rand() + 0xFF) : data[i-4];
		}
		
		/* Encrypt plain control word to send to card */
		s->blocks[j].cw = encrypt_syster_cw(s->blocks[j].ecm, key, NG_ENCRYPT);
	}
}

uint16_t _get_date(char *dtm)
{
	int day, mon, year;
	sscanf(dtm, "%d/%d/%d", &day, &mon, &year);
	return (uint16_t) ((0x8000 | (year - 1990) << 9 | (mon > 6 ? 1:0) << 8 | ((mon > 6 ? 1:0) + mon % 7) << 5 | day));
}

int _init_common(ng_t *s, vid_t *vid, char *mode, int ecm_type)
{
	memset(s, 0, sizeof(ng_t));
	
	ng_mode_t *n = s->mode;
	s->id = 0;
	
	/* Find the mode */
	for(n = _ng_modes; n->id != NULL; n++, s->id++)
	{
		if(strcmp(mode, n->id) == 0) break;
	}
	
	if(n->id == NULL)
	{
		fprintf(stderr, "Unrecognised Syster mode.\n");
		return(VID_ERROR);
	}
	
	/* D11/CNR delay */
	s->ng_delay = (1 / 4433618.75) * 4 * vid->pixel_rate;
	
	/* Date of broadcast */
	uint16_t d = _get_date(n->date);
	
	/* Premiere uses PPV dates in different locations */
	if((n->id = "premiere-ca") || (n->id = "premiere-fa"))
	{
		n->data[6] = d & 0xFF;
		n->data[7] = d >> 8;
	}
	else
	{
		n->data[4] = d & 0xFF;
		n->data[5] = d >> 8;
	}
	
	n->data[4] = d & 0xFF;
	n->data[5] = d >> 8;

	s->blocks = _ecm_table_rand;
	
	if(vid->conf.scramble_video == 0)
	{
		vid->conf.scramble_video = n->t;
	}
	
	s->table = (vid->conf.scramble_video == 1 ? _key_table1 : _key_table2);
	
	/* Generate random seeds */
	_rand_seed(s, n->data, n->key, ecm_type);
	
	return(VID_OK);
}

int ng_init(ng_t *s, vid_t *vid)
{
	time_t t;
	int x;
	
	srand((unsigned) time(&t));
	char *mode = vid->conf.syster ? vid->conf.syster : vid->conf.systercnr;
	
	if(vid->conf.syster && vid->conf.systercnr)
	{
		if(strcmp(vid->conf.syster, vid->conf.systercnr) != 0)
		{
			fprintf(stderr,"Warning: different modes specified for syster and systercnr. Using mode %s.\n", vid->conf.syster);
		}
	}
	
	if(_init_common(s, vid, mode, vid->conf.systercnr ? STATIC_ECM : RANDOM_ECM) == VID_ERROR)
	{
		return VID_ERROR;
	};
	
	s->flags  = 0 << 7; /* ?? Unused */
	s->flags |= 1 << 6; /* ?? Unused */
	s->flags |= 1 << 5; /* 0: clear, 1: scrambled */
	s->flags |= 1 << 4; /* Audio inversion frequency: 1: 12.8kHz, 0: ?kHz */
	s->flags |= (vid->conf.scramble_video == 1 ? 0 : 1) << 3; /* 0: key table 1, 1: key table 2 */
	s->flags |= (vid->conf.systercnr ? 1 : 0) << 2; /* Seems to enable cut-and-rotate on some decoders */
	s->flags |= (vid->conf.syster ? 1 : 0) << 1; /* Scrambling type: 0: Discret 11, 1: Syster */
	s->flags |= 0 << 0; /* 6th high bit of audience level */
	
	_ng_vbi_init(s, vid);
	
	s->vbi_seq = 0;
	s->block_seq = 0;
	
	/* Initial seeds. Updated every field. */
	s->s = 0;
	s->r = 0;
	_update_field_order(s);
	
	/* Quick and dirty sample rate conversion array */
	for(x = 0; x < NG_VBI_WIDTH; x++)
	{
		s->video_scale[x] = round((double) x * vid->width / NG_VBI_WIDTH);
	}
	
	return(VID_OK);
}

void ng_free(ng_t *s)
{
	free(s->delay);
	free(s->lut);
}

/* Function courtesy of fsphil */
static void _rotate_syster(int16_t *li, vid_line_t *lo, ng_t *n, int frame, const uint8_t sequence[25][576])
{
	int shift;
	int x, y;

	y = lo->line < 336 ? lo->line - 23 : lo->line - 336 + 288;
	shift = sequence[frame % 25][y];

	y = n->video_scale[SCNR_LEFT + SCNR_TOTAL_CUTS - shift];
	for(x = n->video_scale[SCNR_LEFT]; x < n->video_scale[SCNR_LEFT + SCNR_TOTAL_CUTS]; x++, y++)
	{
		lo->output[x * 2 + 1] =  li[(y - n->ng_delay) * 2];
		if(y >= n->video_scale[SCNR_LEFT + SCNR_TOTAL_CUTS])
		{
			y = n->video_scale[SCNR_LEFT + 5];
		}
	}

	for(x = n->video_scale[SCNR_LEFT]; x < n->video_scale[SCNR_LEFT + SCNR_TOTAL_CUTS]; x++)
	{
		/* Blank last line of each field - to stop interfering with D11 data */
		lo->output[x * 2] = lo->line == 310 || lo->line == 622 ? 16056 : lo->output[x * 2 + 1];
		lo->output[x * 2 + 1] = 0;
	}
}

int ng_render_line(vid_t *s, void *arg, int nlines, vid_line_t **lines)
{
	ng_t *n = arg;
	int j = 0;
	int x, f, i;
	vid_line_t *l = lines[0];
	
	/* Calculate the field and field line */
	f = (l->line < NG_FIELD_2_START ? 1 : 2);
	i = l->line - (f == 1 ? NG_FIELD_1_START : NG_FIELD_2_START);
	
	if(s->conf.syster)
	{
		/* Cut and rotate line if enabled with shuffle mode */
		if(s->conf.systercnr)
		{
			vid_line_t *lin = lines[nlines - 1];
			int16_t *dline = lines[nlines - 1]->output;
			
			if((lin->line >=  23 && lin->line <= 310) || (lin->line >= 336 && lin->line <= 623))
			{
				_rotate_syster(dline, lin, n, s->frame, _systercnrshuffle);
			}
		}
		
		if(i >= 0 && i < NG_LINES_PER_FIELD)
		{
			/* Adjust for the decoder's 32 line delay */
			i += 32;
			if(i >= NG_LINES_PER_FIELD)
			{
				i -= NG_LINES_PER_FIELD;
				f = (f == 1 ? 2 : 1);
			}
			
			/* Reinitialise the seeds if this is a new field */
			if(i == 0)
			{
				int sf = l->frame % 50;
				
				if((sf == 6 || sf == 31) && f == 1)
				{
					_prbs_reset(n, n->cw);
				}
				
				x = _prbs_update(n);
				
				n->s = x & 0x7F;
				n->r = x >> 7;
				
				_update_field_order(n);
			}
			
			/* Calculate which line in the delay buffer to copy image data from */
			j = (f == 1 ? NG_FIELD_1_START : NG_FIELD_2_START) + n->order[i];
			if(j < l->line) j += s->conf.lines;
			j -= l->line;
			
			if(j < 0 || j >= nlines)
			{
				/* We should never get to this point */
				fprintf(stderr, "*** Nagravision Syster scrambler is trying to read an invalid line ***\n");
				j = 0;
			}
		}
	}
	
	/* Swap the active line with the oldest line in the delay buffer,
	 * with active video offset in j if necessary. */
	if(j > 0)
	{
		int16_t *dline = lines[j]->output;
		
		/* For PAL the colour burst is not moved, just the active
		 * video. For SECAM the entire line is moved. */
		x = s->active_left * 2;
		
		if(s->conf.colour_mode == VID_SECAM) x = 0;
		
		for(; x < s->width * 2; x += 2)
		{
			l->output[x] = dline[x];
		}
	}
	
	/* Rotate line without shuffling */
	if(!s->conf.syster)
	{
		if((l->line >=  23 && l->line <= 310) || (l->line >= 336 && l->line <= 623))
		{
			int16_t *dline = lines[1]->output;
			_rotate_syster(dline, l, n, s->frame, _systercnr);
		}
	}
	
	_render_ng_vbi(n, s, l);
	
	return(1);
}

/* D11 */

/* 
 * This function generates the line delays for each of the 6 frames
 * within a D11 cycle period in audience 7 mode (free access).
 *
 * Most of the information has been obtained from author of CryptImage
 * http://cryptimage.vot.pl/cryptimage.php
 *
 * Additional info here:
 * https://web.archive.org/web/20180726143048/http://wintzx.fr/blog/2014/01/codage-et-decodage-des-chaines-analogiques-en-1984-partie-1/
*/

static const int d11_lookup_table[8] = {
	 0x00, 0x01, 0x02, 0x02, 0x02, 0x00, 0x00, 0x01 
 };
 
void _create_d11_delay_table(ng_t *n)
{
	/* Magic starting seed = 1337d shifted 177 times */
	int seed = 0x672;
	int b10, b8, d11_delay_index;
	int d11_field = -1;

	for(int line = 0; line < D11_LINES_PER_FIELD * D11_FIELDS ; line++)
	{
		if(line % D11_LINES_PER_FIELD == 0) d11_field++;

		/* Get bit 10 */
		b10 = ((seed & 0x400) >> 10) & 0x01;

		/* Get bit 8 */
		b8  = ((seed & 0x100) >> 8) & 0x01;

		/* Get z bit */
		d11_delay_index  = ((d11_field / 3) & 0x1) << 2;

		/* Bit y b0 poly */
		d11_delay_index |= (seed & 0x01) << 1;

		/* Bit x b10 poly */
		d11_delay_index |= b10 ;

		/* Build delay array */
		n->d11_line_delay[line] = d11_lookup_table[d11_delay_index];

		/* Shift along */
		seed <<= 1;
		seed |= b10 ^ b8;
		seed &= 0x7FF;
	}
}

int d11_init(ng_t *s, vid_t *vid, char *mode)
{
	memset(s, 0, sizeof(ng_t));
	
	if(_init_common(s, vid, mode, STATIC_ECM) == VID_ERROR)
	{
		return VID_ERROR;
	};
	
	s->flags  = 0 << 7; /* ?? Unused */
	s->flags |= 0 << 6; /* ?? Unused */
	s->flags |= 1 << 5; /* 0: clear, 1: scrambled */
	s->flags |= 1 << 4; /* Audio inversion frequency: 1: 12.8kHz, 0: ?kHz */
	s->flags |= 0 << 3; /* 0: key table 1, 1: key table 2 */
	s->flags |= 0 << 2; /* Seems to enable cut-and-rotate on some decoders */
	s->flags |= 0 << 1; /* Scrambling type: 0: Discret 11, 1: Syster */
	s->flags |= 0 << 0; /* 6th high bit of audience level */
	
	/* Initialise VBI sequences - this is still necessary for D11 */
	_ng_vbi_init(s, vid);
	
	_create_d11_delay_table(s);

	return(VID_OK);
}

int d11_render_line(vid_t *s, void *arg, int nlines, vid_line_t **lines)
{
	int x, f, i, d11_field, index, delay, max_delay;
	
	ng_t *d = arg;
	vid_line_t *l = lines[0];
	
	/* Calculate the field and field line */
	f = (l->line < D11_FIELD_2_START ? 0 : 1);
	i = l->line - (f == 0 ? D11_FIELD_1_START : D11_FIELD_2_START);
	d11_field = (l->frame % 3) + (l->frame % 3) + f;
	
	if(i > 0 && i < D11_LINES_PER_FIELD)
	{
		 /* Calculate index for delay values - sequence starts on last field of the last frame */
		index = ((d11_field == 5 ? 0 : d11_field + 1) * D11_LINES_PER_FIELD) + i ;
		
		/* Calculate delay for this line */
		delay = d->d11_line_delay[index] * d->ng_delay;
		
		/* Calculate max delay in order to 'centre' the frame */
		max_delay = d->ng_delay * 2;
		
		/* Delay line */
		for(x = s->active_left + max_delay; x < s->active_left + s->active_width + max_delay; x++)
		{
			/* Adjust end-of-line delay */
			delay = x - d->ng_delay < (s->active_left + s->active_width) ? delay : max_delay;
			
			l->output[(x - max_delay) * 2 + 1] = l->output[(x - delay) * 2];
		}
		
		/* Copy delayed line to output buffer */
		for(x = s->active_left; x < s->active_left + s->active_width; x++)
		{
			l->output[x * 2] = l->output[x * 2 + 1];
			l->output[x * 2 + 1] = 0;
		}
	}
	
	/* D11 sequence sync line 622 - always white level for audience 7 mode */
	if(l->line == 622)
	{
		for(x = s->active_left; x < s->active_left + s->active_width; x++)
		{
			l->output[x * 2] = s->white_level;
		}
	}
	
	/* D11 sequence sync line 310 - triggers white level on the last field of the last frame  */
	if(l->line == 310)
	{
		for(x = s->active_left; x < s->active_left + s->active_width; x++)
		{
			l->output[x * 2] = (l->frame % 3 == 2 ? s->white_level : s->black_level);
		}
	}
	
	_render_ng_vbi(d, s, l);
	
	return(1);
}