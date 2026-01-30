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

#ifndef _VIDEOCRYPT_CA_H
#define _VIDEOCRYPT_CA_H

#include <stdint.h>

static inline uint8_t _vc_rotate_left(uint8_t x)
{
	return (x << 1) | (x >> 7);
}

static inline uint8_t _vc_crc(const uint8_t *data)
{
	uint8_t crc = 0;
	for (int i = 0; i < 31; i++)
	{
		crc += data[i];
	}
	return (~crc + 1);
}

/* Reverse calculated control word */
static inline uint64_t _rev_cw(uint8_t in[8])
{
	int i;
	uint64_t cw;
	
	/* Mask high nibble of last byte as it's not used */
	in[7] &= 0x0F;
	
	for(i = 0, cw = 0; i < 8; i++)
	{
		cw |= (uint64_t) in[i] << (i * 8);
	}
	
	return(cw);
}

typedef struct {
	const uint8_t key[256];
} _vc_key_t;

/* Message data structure */
typedef struct {
    uint8_t messages[8][32];  /* Message array - VC1 uses [0-6], VC2 uses [0-7] */
    uint8_t message[32];      /* Current/working message */
    uint8_t hash[4];
    uint64_t answer;
    int has_hash;             /* Only used for Sky10 */
    int has_answer;           /* Only used for Sky10 */
} message_data_t;

typedef struct {
	uint8_t mode;
	message_data_t *message_data;     /* Primary data structure */
	int showecm;                      /* Debug flag for ECM printing */
} _vc_block_t;

/* Note: _vc2_block_t removed - it was identical to _vc_block_t */


typedef struct {
	const char          *id;   /* Name of Videocrypt mode */
	const int       version;   /* VC version: 1 or 2 */
	const int        cwtype;   /* Static or dynamic CW */
	const int          mode;   /* Mode */
	_vc_block_t     *blocks;   /* Block array (VC1 or VC2) */
	const int           len;   /* Block length */
	const int           emm;   /* EMM mode? */
	const char *channelname;   /* Channel/display name */
	const int     channelid;   /* Channel ID */
	const int          date;   /* Broadcast date byte */
	const int      emm_byte;   /* Card issue byte used in EMMs */
	const _vc_key_t    *key;   /* Key used by the card */
	const int    key_offset;   /* Key offset for P03-P07 era of VC cards */
	const int   kernel_type;   /* Kernel type used for this mode */
	const int      sig_type;   /* Signature calculation method used for this mode */
} _vc_mode_t;

enum {
	VC_VER1 = 1,
	VC_VER2 = 2,
	VC_CW_STATIC = 100,
	VC_CW_DYNAMIC,
	VC_EMM,
	VC_FREE,
	VC_SKYNZ01,
	VC_SKYNZ02,
	VC_SCAST,
	VC_SKY02,
	VC_SKY03,
	VC_SKY04,
	VC_SKY05,
	VC_SKY06,
	VC_SKY07,
	VC_SKY09,
	VC_SKY09_NANO,
	VC_SKY10,
	VC_SKY10_PPV,
	VC_SKY11,
	VC_SKY12,
	VC_JSTV,
	VC_TAC1,
	VC_TAC2,
	VC_XTEA,
	VC_MC,
	VC_DMX,
	VC_PPV,
	VC_KERNEL_1,
	VC_KERNEL_2,
	VC_SIG_1,
	VC_SIG_2
};

/* Videocrypt 1 */
extern void vc_seed(_vc_block_t *s, _vc_mode_t *m);
extern void vc_emm(_vc_block_t *s, _vc_mode_t *m, uint32_t cardserial, int b, int i);
extern void vc_seed_ppv(_vc_block_t *s, uint8_t _ppv_card_data[7]);

/* Videocrypt 2 */
extern void vc_seed_vc2(_vc_block_t *s, _vc_mode_t *m);
extern void vc2_emm(_vc_block_t *s, _vc_mode_t *m, int cmd, uint32_t cardserial);
#endif