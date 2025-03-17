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

typedef struct {
	const uint8_t key[256];
} _vc_key_t;

typedef struct {
	uint8_t mode;
	uint64_t codeword;
	uint8_t messages[7][32];
} _vc_block_t;

typedef struct {
	uint8_t mode;
	uint64_t codeword;
	uint8_t messages[8][32];
} _vc2_block_t;


typedef struct {
	const char          *id;   /* Name of Videocrypt mode */
	const int        cwtype;   /* Static or dynamic CW */
	const int          mode;   /* Mode */
	_vc_block_t     *blocks;   /* VC1 blocks */
	_vc2_block_t   *blocks2;   /* VC2 blocks */
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
extern void vc_seed_vc2(_vc2_block_t *s, _vc_mode_t *m);
extern void vc2_emm(_vc2_block_t *s, _vc_mode_t *m, int cmd, uint32_t cardserial);
#endif