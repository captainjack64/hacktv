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

/* -=== Videocrypt encoder ===-
 * 
 * This is a Videocrypt I/II encoder. It scrambles the image using a technique
 * called "line cut-and-rotate", and inserts the necessary data into the
 * VBI area of the image to activate the Videocrypt hardware unscrambler.
 * 
 * THANKS
 * 
 * Markus Kuhn and William Andrew Steer for their detailed descriptions
 * and examples of how Videocrypt works:
 * 
 * https://www.cl.cam.ac.uk/~mgk25/tv-crypt/
 * http://www.techmind.org/vdc/
 * 
 * Ralph Metzler for the details of how the VBI data is encoded:
 * 
 * http://src.gnu-darwin.org/ports/misc/vbidecode/work/bttv/apps/vbidecode/vbidecode.cc
 * 
 * Alex L. James for providing an active Sky subscriber card, VBI samples,
 * Videocrypt 2 information and testing.
 *
 * Marco Wabbel for xtea algo and Funcard (ATMEL based) hex files - needed for xtea.
*/

#include <inttypes.h>
#include <string.h>
#include <math.h>
#include "video.h"
#include "vbidata.h"
#include "videocrypt-ca.h"
#include "videocrypt-data.h"

/*
 * Name of Videocrypt mode (used on command line)
 * Static or dynamic control word
 * Mode
 * Pointer to VC1 block
 * Pointer to VC2 block
 * Block length
 * EMM enabled?
 * Channel/display name
 * Channel ID
 * Broadcast month byte 
 * EMM card prefix byte 
 * Key to use for dynamic CW generation mode
 * Key table offset
*/

static _vc_mode_t _vc_modes[] = {
	/* VC1 modes */
	{ "free",        VC_VER1,   VC_CW_STATIC,  VC_FREE,        _fa_blocks,  1, 0,      "                        ", 0x00, 0x20, 0x00,       0x00, 0x00, VC_FREE,     VC_FREE  },
	{ "ppv",         VC_VER1,   VC_CW_DYNAMIC, VC_PPV,        _ppv_blocks,  1, 0,      "                        ", 0x00, 0x20, 0x00,       0x00, 0x00, VC_KERNEL_2, VC_SIG_2 },
	{ "jstv",        VC_VER1,   VC_CW_DYNAMIC, VC_JSTV,       _vc1_blocks,  2, 0,      "   HACKTV    JSTV  MODE ", 0x00, 0x20, 0x00,  _jstv_key, 0x00, VC_KERNEL_2, VC_SIG_2 },
	{ "sky02",       VC_VER1,   VC_CW_DYNAMIC, VC_SKY02,      _vc1_blocks,  2, 0,      "   HACKTV    SKY02 MODE ", 0x01, 0x0E, 0xA2,   _sky_key, 0x00, VC_KERNEL_1, VC_SIG_1 },
	{ "sky03",       VC_VER1,   VC_CW_DYNAMIC, VC_SKY03,      _vc1_blocks,  2, 0,      "   HACKTV    SKY03 MODE ", 0x01, 0x12, 0xA3,   _sky_key, 0x00, VC_KERNEL_2, VC_SIG_1 },
	{ "sky04",       VC_VER1,   VC_CW_DYNAMIC, VC_SKY04,      _vc1_blocks,  2, 0,      "   HACKTV    SKY04 MODE ", 0x01, 0x14, 0xA4,   _sky_key, 0x20, VC_KERNEL_2, VC_SIG_1 },
	{ "sky05",       VC_VER1,   VC_CW_DYNAMIC, VC_SKY05,      _vc1_blocks,  2, 0,      "   HACKTV    SKY05 MODE ", 0x0C, 0x1C, 0xA5,   _sky_key, 0x40, VC_KERNEL_2, VC_SIG_1 },
	{ "sky06",       VC_VER1,   VC_CW_DYNAMIC, VC_SKY06,      _vc1_blocks,  2, VC_EMM, "   HACKTV    SKY06 MODE ", 0x05, 0x1C, 0xA6,   _sky_key, 0x40, VC_KERNEL_2, VC_SIG_1 },
	{ "sky07",       VC_VER1,   VC_CW_DYNAMIC, VC_SKY07,      _vc1_blocks,  2, VC_EMM, "   HACKTV    SKY07 MODE ", 0x0C, 0x3A, 0xA7,   _sky_key, 0x58, VC_KERNEL_2, VC_SIG_2 },
	{ "sky09",       VC_VER1,   VC_CW_DYNAMIC, VC_SKY09,      _vc1_blocks,  2, VC_EMM, "   HACKTV    SKY09 MODE ", 0x0C, 0x43, 0xA9, _sky09_key, 0x00, VC_KERNEL_2, VC_SIG_2 },
	{ "sky09nano",   VC_VER1,   VC_CW_DYNAMIC, VC_SKY09_NANO, _vc1_blocks,  2, VC_EMM, "   SKY 09    NANO  MODE ", 0x0C, 0x43, 0xA9, _sky09_key, 0x00, VC_KERNEL_2, VC_SIG_2 },
	{ "sky10",       VC_VER1,   VC_CW_DYNAMIC, VC_SKY10,      _vc1_blocks,  2, 0,      "   HACKTV    SKY10 MODE ", 0x00, 0x00, 0x00,       0x00, 0x00, VC_KERNEL_2, VC_SIG_2 },
	{ "sky10ppv",    VC_VER1,   VC_CW_DYNAMIC, VC_SKY10_PPV,  _vc1_blocks,  2, 0,      "HACKTV SKY10  PPV MODE  ", 0x00, 0x00, 0x00,       0x00, 0x00, VC_KERNEL_2, VC_SIG_2 },
	{ "sky11",       VC_VER1,   VC_CW_STATIC,  VC_SKY11,    _sky11_blocks,  2, 0,      "   HACKTV    SKY11 MODE ", 0x00, 0x00, 0x00,       0x00, 0x00, VC_KERNEL_2, VC_SIG_2 },
	{ "sky12",       VC_VER1,   VC_CW_STATIC,  VC_SKY12,    _sky12_blocks,  2, 0,      "   HACKTV    SKY12 MODE ", 0x00, 0x00, 0x00,       0x00, 0x00, VC_KERNEL_2, VC_SIG_2 },
	{ "skynz01",     VC_VER1,   VC_CW_DYNAMIC, VC_SKYNZ01,    _vc1_blocks,  2, VC_EMM, "   HACKTV   SKYNZ01 MODE", 0x02, 0x0e, 0x21, _skynz_key, 0x00, VC_KERNEL_1, VC_SIG_2 },
	{ "skynz02",     VC_VER1,   VC_CW_DYNAMIC, VC_SKYNZ02,    _vc1_blocks,  2, VC_EMM, "   HACKTV   SKYNZ02 MODE", 0x02, 0x0e, 0x22, _skynz_key, 0x00, VC_KERNEL_1, VC_SIG_2 },
	{ "tac1",        VC_VER1,   VC_CW_DYNAMIC, VC_TAC1,       _vc1_blocks,  2, VC_EMM, "   HACKTV    TAC1  MODE ", 0x00, 0x29, 0x00,   _tac_key, 0x00, VC_KERNEL_2, VC_SIG_2 },
	{ "tac2",        VC_VER1,   VC_CW_DYNAMIC, VC_TAC2,       _vc1_blocks,  2, VC_EMM, "   HACKTV    TAC2  MODE ", 0x00, 0x49, 0x00,   _tac_key, 0x40, VC_KERNEL_2, VC_SIG_2 },
	{ "xtea",        VC_VER1,   VC_CW_DYNAMIC, VC_XTEA,      _xtea_blocks,  2, 0,      "   HACKTV    XTEA  MODE ", 0x00, 0x20, 0x00,       0x00, 0x00, VC_KERNEL_2, VC_SIG_2 },
	{ "dmx",         VC_VER1,   VC_CW_DYNAMIC, VC_DMX,        _vc1_blocks,  2, 0,      "   HACKTV    DMX   MODE ", 0x00, 0x12, 0x00,   _dmx_key, 0x00, VC_KERNEL_2, VC_SIG_2 },
	{ "scast",       VC_VER1,   VC_CW_DYNAMIC, VC_SCAST,      _vc1_blocks,  2, 0,      "   HACKTV   SPTSCST MODE", 0x01, 0x14, 0x00, _scast_key, 0x00, VC_KERNEL_1, VC_SIG_2 },
	/* VC2 modes */
	{ "free",        VC_VER2,   VC_CW_STATIC,  VC_FREE,       _fa2_blocks,  1, 0,      "           ",              0x00, 0x52, 0x00,       0x00, 0x00, VC_FREE,     VC_FREE  },
	{ "conditional", VC_VER2,   VC_CW_DYNAMIC, VC_MC,         _vc2_blocks,  2, VC_EMM, "MULTICHOICE",              0x82, 0x53, 0x81,   _vc2_key, 0x00, VC_KERNEL_2, VC_SIG_2 },
	{ NULL }
};

/* PPV card data */
/*                                   |--------CARD SERIAL-------|    Ka    Kb */
static uint8_t _ppv_card_data[7] = { 0x6D, 0xC1, 0x08, 0x44, 0x02, 0x28, 0x3D };


/* Packet header sequences */
static const uint8_t _sequence[8] = {
	0x87,0x96,0xA5,0xB4,0xC3,0xD2,0xE1,0x87,
};

static const uint8_t _sequence2[8] = {
 	0x80,0x91,0xA2,0xB3,0xC4,0xD5,0xE6,0xF7,
};

/* Hamming codes */
static const uint8_t _hamming[16] = {
	0x15,0x02,0x49,0x5E,0x64,0x73,0x38,0x2F,
	0xD0,0xC7,0x8C,0x9B,0xA1,0xB6,0xFD,0xEA,
};

/* Reverse bits in an 8-bit value */
static uint8_t _reverse(uint8_t b)
{
	b = (b & 0xF0) >> 4 | (b & 0x0F) << 4;
	b = (b & 0xCC) >> 2 | (b & 0x33) << 2;
	b = (b & 0xAA) >> 1 | (b & 0x55) << 1;
	return(b);
}

/* Reverse bits in an x-bit value */
static uint64_t _rev(uint64_t b, int x)
{
	uint64_t r = 0;
	
	while(x--)
	{
		r = (r << 1) | (b & 1);
		b >>= 1;
	}
	
	return(r);
}

/* Reverse nibbles in a byte */
static inline uint8_t _rnibble(uint8_t a)
{
	return((a >> 4) | (a << 4));
}

/* Generate IW for PRBS */
static uint64_t _generate_iw(uint64_t cw, uint8_t fcnt)
{
	uint64_t iw;
	
	/* FCNT is repeated 8 times, each time inverted */
	iw  = ((fcnt ^ 0xFF) << 8) | fcnt;
	iw |= (iw << 16) | (iw << 32) | (iw << 48);
	
	return((iw ^ cw) & VC_PRBS_CW_MASK);
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
	uint8_t crc;
	
	crc = vbi[0] = a;
	for(x = 0; x < 8; x++)
	{
		crc += vbi[1 + x] = data[0 + x];
	}
	vbi[9] = crc;
	
	crc = vbi[10] = b;
	for(x = 0; x < 8; x++)
	{
		crc += vbi[11 + x] = data[8 + x];
	}
	vbi[19] = crc;
	
	/* Hamming code the VBI data */
	for(x = 19; x >= 0; x--)
	{
		vbi[x * 2 + 1] = _hamming[vbi[x] & 0x0F];
		vbi[x * 2 + 0] = _hamming[vbi[x] >> 4];
	}
	
	/* Interleave the VBI data */
	_interleave(vbi);
}
 

int vc_init(vc_t *s, vid_t *vid, const char *mode, const char *mode2)
{
	double f, l;
	int i, x;
	time_t t;
	srand((unsigned) time(&t));
	
	memset(s, 0, sizeof(vc_t));
	
	for(i = 0; i < 7; i++) s->ppv_card_data[i] = _ppv_card_data[i];
	
	/* Generate the VBI data symbols */
	s->lut = vbidata_init_step(
		40,
		vid->width,
		round((vid->white_level - vid->black_level) * 1.00),
		(double) vid->pixel_rate / VC_SAMPLE_RATE * VC_VBI_SAMPLES_PER_BIT,
		vid->pixel_rate * 375e-9,
		vid->pixel_rate * 10.86e-6
	);
	
	if(!s->lut)
	{
		return(VID_OUT_OF_MEMORY);
	}
	
	s->counter  = 0;
	s->cw       = rand();
	s->vcmode1  = mode;
	s->vcmode2  = mode2;
	
	/* Find Videocrypt mode to use */
	if(mode != NULL)
	{
		for(s->mode = _vc_modes; s->mode->id != NULL; s->mode++)
		{
			if(strcmp(mode, s->mode->id) == 0 && s->mode->version == VC_VER1) break;
		}
		
		if(s->mode->id == NULL)
		{
			fprintf(stderr, "Unrecognised Videocrypt I mode '%s'.\n", mode);
			return(VID_ERROR);
		}
		
		s->blocks = s->mode->blocks;
		s->block_len = s->mode->len;
		
		/* Set showecm flag for all blocks */
		for(i = 0; i < s->block_len; i++)
		{
			s->blocks[i].showecm = vid->conf.showecm;
		}
		
		/* For dynamic modes, we need to allocate copies of message_data
		 * since the seed functions will modify them. For static modes,
		 * message_data already points to const static data. */
		if(s->mode->cwtype == VC_CW_DYNAMIC || strcmp(mode, "ppv") == 0)
		{
			/* Dynamic mode - allocate and copy from template */
			for(i = 0; i < s->block_len; i++)
			{
				message_data_t *template = s->blocks[i].message_data;
				s->blocks[i].message_data = (message_data_t*)calloc(1, sizeof(message_data_t));
				if(!s->blocks[i].message_data)
				{
					/* Free any previously allocated blocks */
					for(int j = 0; j < i; j++)
					{
						free(s->blocks[j].message_data);
					}
					return(VID_OUT_OF_MEMORY);
				}
				/* Copy template data to dynamic allocation */
				*s->blocks[i].message_data = *template;
			}
		}
		/* else: Static mode - message_data already points to const static data, no allocation needed */
		
		if(strcmp(mode, "ppv") == 0)
		{
			if(vid->conf.findkey)
			{
				/* Starting keys */
				s->ppv_card_data[5] = 0x00; /* Key a */
				s->ppv_card_data[6] = 0x00; /* Key b */
			}
			
			vc_seed_ppv(&s->blocks[0], s->ppv_card_data);
			vc_seed_ppv(&s->blocks[1], s->ppv_card_data);
		}
		else if(s->mode->cwtype == VC_CW_DYNAMIC)
		{
			/* Set channel date */
			s->blocks[0].message_data->messages[5][1] = s->mode->date;
			s->blocks[1].message_data->messages[5][1] = s->mode->date;

			/* Set channel ID */
			s->blocks[0].message_data->messages[5][6] = s->mode->channelid;
			s->blocks[1].message_data->messages[5][6] = s->mode->channelid;

			vc_seed(&s->blocks[0], s->mode);
			vc_seed(&s->blocks[1], s->mode);
		}
		
		/* Process EMM if enabled for the mode */
		if(vid->conf.enableemm || vid->conf.disableemm)
		{
			if(s->mode->emm)
			{
				uint32_t cardserial;
				int b;
				cardserial = vid->conf.enableemm ? vid->conf.enableemm : vid->conf.disableemm;
				b = vid->conf.enableemm ? 1 : 0;
				vc_emm(&s->blocks[0], s->mode, cardserial, b, 0);
				vc_emm(&s->blocks[1], s->mode, cardserial, b, 1);
			}
			else
			{
				fprintf(stderr,"EMMs are not supported in this Videocrypt mode.");
				return(VID_ERROR);
			}
		}

		if(strcmp(mode, "free") != 0)
		{
			/* Set channel name */
			s->blocks[1].message_data->messages[0][0] = 0x20;
			s->blocks[1].message_data->messages[0][1] = 0x00;
			s->blocks[1].message_data->messages[0][2] = 0x60 + strlen(s->mode->channelname);

			for(i = 0; i < strlen(s->mode->channelname); i++)
			{
				s->blocks[1].message_data->messages[0][i + 3] = s->mode->channelname[i];
			}
		} 
	}
	
	/* Find Videocrypt II mode to use */
	if(mode2 != NULL)
	{
		for(s->mode = _vc_modes; s->mode->id != NULL; s->mode++)
		{
			if(strcmp(mode2, s->mode->id) == 0 && s->mode->version == VC_VER2) break;
		}
		
		if(s->mode->id == NULL)
		{
			fprintf(stderr, "Unrecognised Videocrypt II mode '%s'.\n", mode2);
			return(VID_ERROR);
		}
		
		s->blocks2 = s->mode->blocks;
		s->block2_len = s->mode->len;
		
		/* Set showecm flag for all blocks */
		for(i = 0; i < s->block2_len; i++)
		{
			s->blocks2[i].showecm = vid->conf.showecm;
		}
		
		/* For dynamic modes, allocate copies. For static modes, use existing pointers. */
		if(s->mode->cwtype == VC_CW_DYNAMIC)
		{
			/* Dynamic mode - allocate and copy from template */
			for(i = 0; i < s->block2_len; i++)
			{
				message_data_t *template = s->blocks2[i].message_data;
				s->blocks2[i].message_data = (message_data_t*)calloc(1, sizeof(message_data_t));
				if(!s->blocks2[i].message_data)
				{
					/* Free any previously allocated VC2 blocks */
					for(int j = 0; j < i; j++)
					{
						free(s->blocks2[j].message_data);
					}
					return(VID_OUT_OF_MEMORY);
				}
				/* Copy template data to dynamic allocation */
				*s->blocks2[i].message_data = *template;
			}
		}
		/* else: Static mode - message_data already points to const static data */

		if(s->mode->cwtype == VC_CW_DYNAMIC)
		{
			/* Set ECM mode */
			s->blocks2[0].message_data->messages[5][0] = 0xF9;
			s->blocks2[1].message_data->messages[5][0] = 0xF9;

			/* Set channel date */
			s->blocks2[0].message_data->messages[5][1] = s->mode->date;
			s->blocks2[1].message_data->messages[5][1] = s->mode->date;

			/* Set channel ID */
			s->blocks2[0].message_data->messages[5][2] = s->mode->channelid;
			s->blocks2[1].message_data->messages[5][2] = s->mode->channelid;

			vc_seed_vc2(&s->blocks2[0], s->mode);
			vc_seed_vc2(&s->blocks2[1], s->mode);
		
			/* If in simulcrypt mode, do the initial CW sync here */
			if(mode)
			{
				for(i = 0; i < 8; i++)
				{
					s->blocks2[1].message_data->messages[0][i + 17] = (s->blocks[0].message_data->answer ^ s->blocks2[1].message_data->answer) >> (8 * i) & 0xFF;
				}
			}
		}
	
		/* Set channel name */
		/* Both blocks require 'OSD' headers in VC2 */
		if(strcmp(mode2, "free") != 0)
		{
			for(i = 0; i < 2; i++)
			{
				s->blocks2[i].message_data->messages[0][0] = 0x21;
				s->blocks2[i].message_data->messages[0][1] = 0x02;
			}

			s->blocks2[0].message_data->messages[0][2] = 0x60 + strlen(s->mode->channelname);

			for(i = 0; i < strlen(s->mode->channelname); i++)
			{
				s->blocks2[0].message_data->messages[0][i + 3] = s->mode->channelname[i];
			}
		}
		
		if(vid->conf.enableemm)
		{
			/*
			 * 0x1B: Enable card
			 */
			vc2_emm(&s->blocks2[0], s->mode, 0x1B, vid->conf.enableemm);
		}
		
		if(vid->conf.disableemm)
		{
			/*  
			 * 0x1A: Disable card
			 */
			vc2_emm(&s->blocks2[0], s->mode, 0x1A, vid->conf.disableemm);
		}
	}
	
	s->block = 0;
	s->block2 = 0;
	
	/* Sample rate ratio */
	f = (double) vid->width / VC_WIDTH;
	
	/* Videocrypt timings appear to be calculated against the centre of the hsync pulse */
	l = (double) VC_SAMPLE_RATE * vid->conf.hsync_width / 2;
	
	/* Quick and dirty sample rate conversion array */
	for(x = 0; x < VC_WIDTH; x++)
	{
		s->video_scale[x] = round((l + x) * f);
	}
	
	return(VID_OK);
}

void vc_free(vc_t *s)
{
	int i;
	
	/* Safety check */
	if(!s) return;
	
	/* Only free message_data if it was dynamically allocated (VC_CW_DYNAMIC or PPV modes) */
	/* For static modes (free-access), message_data points to const static data */
	if(s->mode && (s->mode->cwtype == VC_CW_DYNAMIC || (s->vcmode1 && strcmp(s->vcmode1, "ppv") == 0)))
	{
		/* Free message_data for VC1 blocks (only if dynamically allocated) */
		if(s->blocks && s->block_len > 0)
		{
			for(i = 0; i < s->block_len; i++)
			{
				if(s->blocks[i].message_data)
				{
					free(s->blocks[i].message_data);
					s->blocks[i].message_data = NULL;
				}
			}
		}
		
		/* Free message_data for VC2 blocks (only if dynamically allocated) */
		if(s->blocks2 && s->block2_len > 0)
		{
			for(i = 0; i < s->block2_len; i++)
			{
				if(s->blocks2[i].message_data)
				{
					free(s->blocks2[i].message_data);
					s->blocks2[i].message_data = NULL;
				}
			}
		}
	}
	/* else: Static mode - message_data points to const static data, don't free */
	
	if(s->lut)
	{
		free(s->lut);
		s->lut = NULL;
	}
}

int vc_render_line(vid_t *s, void *arg, int nlines, vid_line_t **lines)
{
	vc_t *v = arg;
	int i, x;
	const uint8_t *bline = NULL;
	vid_line_t *l = lines[0];
	uint64_t cw;
	const char *mode = v->vcmode1;
	const char *mode2 = v->vcmode2;
	
	/* On the first line of each frame, generate the VBI data */
	if(l->line == 1)
	{
		uint64_t iw;
		uint8_t crc;
		
		/* Videocrypt I */
		if(v->blocks)
		{
			if((v->counter & 7) == 0)
			{
				/* The active message is updated every 8th frame. The last
				 * message in the block is a duplicate of the first. */
				for(crc = x = 0; x < 31; x++)
				{
					crc += v->blocks[v->block].message_data->message[x] = v->blocks[v->block].message_data->messages[((v->counter >> 3) & 7) % 7][x];
				}
				
				v->blocks[v->block].message_data->message[x] = ~crc + 1;
			}
			
			if((v->counter & 4) == 0)
			{
				/* The first half of the message. Transmitted for 4 frames */
				_encode_vbi(
					v->vbi, v->blocks[v->block].message_data->message,
					_sequence[(v->counter >> 4) & 7],
					v->counter & 0xFF
				);
			}
			else
			{
				/* The second half of the message. Transmitted for 4 frames */
				_encode_vbi(
					v->vbi, v->blocks[v->block].message_data->message + 16,
					_rnibble(_sequence[(v->counter >> 4) & 7]),
					v->blocks[v->block].mode
				);
			}
		}
		
		/* Videocrypt II */
		if(v->blocks2)
		{
			if((v->counter & 1) == 0)
			{
				/* The active message is updated every 2nd frame */
				for(crc = x = 0; x < 31; x++)
				{
					crc += v->blocks2[v->block2].message_data->message[x] = v->blocks2[v->block2].message_data->messages[(v->counter >> 1) & 7][x];
				}
				
				v->blocks2[v->block2].message_data->message[x] = ~crc + 1;
			}
			
			if((v->counter & 1) == 0)
			{
				/* The first half of the message */
				_encode_vbi(
					v->vbi2, v->blocks2[v->block2].message_data->message,
					_sequence2[(v->counter >> 1) & 7],
					v->counter & 0xFF
				);
			}
			else
			{
				/* The second half of the message */
				_encode_vbi(
					v->vbi2, v->blocks2[v->block2].message_data->message + 16,
					_rnibble(_sequence2[(v->counter >> 1) & 7]),
					(v->counter & 0x08 ? 0x00 : v->blocks2[v->block2].mode)
				);
			}
		}
		
		/* Reset the PRBS */
		iw = _generate_iw(v->cw, v->counter);
		v->sr1 = iw & VC_PRBS_SR1_MASK;
		v->sr2 = (iw >> 31) & VC_PRBS_SR2_MASK;
		
		v->counter++;
		
		/* After 64 frames, advance to the next VC1 block and codeword */
		if((v->counter & 0x3F) == 0)
		{
			/* Apply the current block codeword */
			if(v->blocks)
			{
				v->cw = v->blocks[v->block].message_data->answer;
			}
			
			/* Generate new seeds */
			if(mode)
			{
				if(v->mode->cwtype == VC_CW_DYNAMIC)
				{
					vc_seed(&v->blocks[v->block], v->mode);
				}
				
				if(strcmp(mode,"ppv") == 0)
				{
					if(s->conf.findkey)
					{
						if(v->ppv_card_data[5] == 0xFF) v->ppv_card_data[6]++;
						v->ppv_card_data[5]++;
						
						fprintf(stderr, "\n\nTesting keys 0x%02X and 0x%02X...", (uint8_t) v->ppv_card_data[5], (uint8_t) v->ppv_card_data[6]);
						
						char fmt[24];
						sprintf(fmt,"KA - 0X%02X   KB - 0X%02X", (uint8_t) v->ppv_card_data[5], (uint8_t) v->ppv_card_data[6]);
						v->blocks[v->block].message_data->messages[strcmp(mode,"ppv") == 0 ? 1 : 0][0] = 0x20;
						v->blocks[v->block].message_data->messages[strcmp(mode,"ppv") == 0 ? 1 : 0][1] = 0x00;
						v->blocks[v->block].message_data->messages[strcmp(mode,"ppv") == 0 ? 1 : 0][2] = 0xF5;
						for(i = 0; i < 22; i++) v->blocks[v->block].message_data->messages[strcmp(mode,"ppv") == 0 ? 1 : 0][i + 3] = fmt[i];
						
					}
					
					vc_seed_ppv(&v->blocks[v->block], v->ppv_card_data);
				}
				
				if(s->conf.showserial) v->blocks[v->block].message_data->messages[strcmp(mode,"ppv") == 0 ? 1 : 0][0] = 0x24;
				
			}
			
			/* Print ECM */
			if(s->conf.showecm && mode)
			{
				fprintf(stderr, "\nVC1 ECM In:         ");
				for(i = 0; i < 32; i++) fprintf(stderr, "%02X ", v->blocks[v->block].message_data->messages[strcmp(mode,"ppv") == 0 ? 0 : 5][i]);
				fprintf(stderr,"\nVC1 ECM Out:        ");
				for(i = 0; i < 8; i++) fprintf(stderr, "%02" PRIX64 " ", v->blocks[v->block].message_data->answer >> (8 * i) & 0xFF);
				
				if(s->conf.enableemm || s->conf.disableemm)
				{
					fprintf(stderr, "\nVC1 EMM In:  ");
					for(i = 0; i < 32; i++) fprintf(stderr, "%02X ", v->blocks[v->block].message_data->messages[2][i]);
				}
			}

			/* Move to the next block */
			if(++v->block == v->block_len)
			{
				v->block = 0;
			}
		}
		
		/* After 16 frames, advance to the next VC2 block and codeword */
		if((v->counter & 0x0F) == 0)
		{
			/* Apply the current block codeword */
			if(v->blocks2 && !mode)
			{
				v->cw = v->blocks2[v->block2].message_data->answer;
			}

			if(mode2)
			{
				if(strcmp(mode2,"conditional") == 0 && (v->counter & 0x3F) == 0x20 ) vc_seed_vc2(&v->blocks2[v->block2], v->mode);
				
				/* OSD bytes 17 - 24 in OSD message 0x21 are used in seed generation in Videocrypt II. */
				/* XOR with VC1 seed for simulcrypt. */
				if(mode)
				{
					/* Sync seeds with Videocrypt I */
					cw = (v->counter % 0x3F < 0x0F || v->counter % 0x3F > 0x2F ? v->blocks[v->block].message_data->answer : v->cw) ^ v->blocks2[v->block2].message_data->answer;
					for(i = 0; i < 8; i++)
					{
						v->blocks2[v->block2].message_data->messages[0][i + 17] = cw >> (8 * i) & 0xFF;
					}
				}
			}
			
			/* Print ECM */
			if(s->conf.showecm && mode2)
			{
				fprintf(stderr, "\n\nVC2 ECM In:  ");
				for(i = 0; i < 32; i++) fprintf(stderr, "%02X ", v->blocks2[v->block2].message_data->messages[5][i]);
				fprintf(stderr,"\nVC2 ECM Out: ");
				for(i = 0; i < 8; i++) fprintf(stderr, "%02" PRIX64 " ", v->blocks2[v->block2].message_data->answer >> (8 * i) & 0xFF);
				
				if(s->conf.enableemm || s->conf.disableemm)
				{
					fprintf(stderr, "\nVC2 EMM In:  ");
					for(i = 0; i < 31; i++) fprintf(stderr, "%02X ", v->blocks2[v->block2].message_data->messages[2][i]);
				}
			}
			
			/* Move to the next block after 64 frames */
			if(((v->counter & 0x3F) == 0) && (++v->block2 == v->block2_len))
			{
				v->block2 = 0;
			}
		}
	}
	
	/* Calculate VBI line, or < 0 if not */
	if(v->blocks &&
	   l->line >= VC_VBI_FIELD_1_START &&
	   l->line < VC_VBI_FIELD_1_START + VC_VBI_LINES_PER_FIELD)
	{
		/* Top VBI field */
		bline = &v->vbi[(l->line - VC_VBI_FIELD_1_START) * VC_VBI_BYTES_PER_LINE];
	}
	else if(v->blocks &&
	        l->line >= VC_VBI_FIELD_2_START &&
	        l->line < VC_VBI_FIELD_2_START + VC_VBI_LINES_PER_FIELD)
	{
		/* Bottom VBI field */
		bline = &v->vbi[(l->line - VC_VBI_FIELD_2_START + VC_VBI_LINES_PER_FIELD) * VC_VBI_BYTES_PER_LINE];
	}
	else if(v->blocks2 &&
	        l->line >= VC2_VBI_FIELD_1_START &&
	        l->line < VC2_VBI_FIELD_1_START + VC_VBI_LINES_PER_FIELD)
	{
		/* Top VBI field VC2 */
		bline = &v->vbi2[(l->line - VC2_VBI_FIELD_1_START) * VC_VBI_BYTES_PER_LINE];
	}
	else if(v->blocks2 &&
	        l->line >= VC2_VBI_FIELD_2_START &&
	        l->line < VC2_VBI_FIELD_2_START + VC_VBI_LINES_PER_FIELD)
	{
		/* Bottom VBI field VC2 */
		bline = &v->vbi2[(l->line - VC2_VBI_FIELD_2_START + VC_VBI_LINES_PER_FIELD) * VC_VBI_BYTES_PER_LINE];
	}
	
	/* Render the VBI line if necessary */
	if(bline)
	{
		vbidata_render(v->lut, bline, 0, 40, VBIDATA_LSB_FIRST, l);
		l->vbialloc = 1;
	}
	
	/* Scramble the line if necessary */
	x = -1;
	
	if((l->line >= VC_FIELD_1_START && l->line < VC_FIELD_1_START + VC_LINES_PER_FIELD) ||
	   (l->line >= VC_FIELD_2_START && l->line < VC_FIELD_2_START + VC_LINES_PER_FIELD))
	{
		int i;
		
		x = (v->c >> 8) & 0xFF;
		
		for(i = 0; i < 16; i++)
		{
			int a;
			
			/* Update shift registers */
			v->sr1 = (v->sr1 >> 1) ^ (v->sr1 & 1 ? 0x7BB88888UL : 0);
			v->sr2 = (v->sr2 >> 1) ^ (v->sr2 & 1 ? 0x17A2C100UL : 0);
			
			/* Load the multiplexer address */
			a = _rev(v->sr2, 29) & 0x1F;
			if(a == 31) a = 30;
			
			/* Shift into result register */
			v->c = (v->c >> 1) | (((_rev(v->sr1, 31) >> a) & 1) << 15);
		}
		
		/* Line 336 is scrambled into line 335, a VBI line. Mark it
		 * as allocated to prevent teletext data appearing there */
		if(l->line == 335)
		{
			l->vbialloc = 1;
		}
	}
	
	/* Hack to preserve WSS signal data */
	if(l->line == 23) x = -1;
	
	if(x != -1)
	{
		int cut;
		int lshift;
		int y;
		int16_t *delay = lines[1]->output;
		
		cut = 105 + (0xFF - x) * 2;
		lshift = 710 - cut;
		
		y = v->video_scale[VC_LEFT + lshift];
		for(x = v->video_scale[VC_LEFT]; x < v->video_scale[VC_LEFT + cut]; x++, y++)
		{
			l->output[x * 2] = delay[y * 2];
		}
		
		y = v->video_scale[VC_LEFT];
		for(; x < v->video_scale[VC_RIGHT + VC_OVERLAP]; x++, y++)
		{
			l->output[x * 2] = delay[y * 2];
		}
	}
	
	return(1);
}

