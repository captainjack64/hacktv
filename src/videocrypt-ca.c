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

/* 
  * Videocrypt key used for Eurotica and The Adult Channel 
  * Sky 07 card used a 56-byte key with three possible key offsets 
  * depending on msg[1] byte value (month). TAC key has five 
  * different offsets. We only ever use one here.
  *
  * If this key is changed, wrong signature will be generated
  * and you will receive "THIS CHANNEL IS BLOCKED" message. You can 
  * update the key in hex file at address 0000 in EEPROM data.
*/

#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "videocrypt-ca.h"

/* Small section of EEPROM data used in Sky 09 cards. Required for nanocommand processing */
static const uint8_t ext_ee[] =
{
/* 1100 */ 0x3F, 0x87, 0x4B, 0x10, 0xFE, 0x93, 0x05, 0x13,
/* 1108 */ 0x99, 0x49, 0x17, 0xAF, 0x3B, 0x87, 0x04, 0x1B,
/* 1110 */ 0x76, 0x3C, 0xEA, 0x5C, 0x7F, 0x37, 0xEA, 0xDF,
/* 1118 */ 0x7F, 0xEA, 0x93, 0xF7, 0x04, 0x29, 0x1D, 0xEF,
/* 1120 */ 0x13, 0x04, 0x37, 0x8C, 0x2E, 0x4D, 0x11, 0x00,
/* 1128 */ 0x43, 0x10, 0xD5, 0xC8, 0x9A, 0x02, 0xAA, 0x82,
/* 1130 */ 0x4D, 0x1E, 0x65, 0xA0, 0x00, 0xA0, 0x04, 0x43,
/* 1138 */ 0x10, 0xDD, 0x37, 0x92, 0x4D, 0x13, 0x01, 0x43,
/* 1140 */ 0x10, 0xDE, 0x15, 0x02, 0x93, 0x60, 0x15, 0x01,
/* 1148 */ 0x93, 0x64, 0x90, 0x5F, 0x13, 0x3F, 0x1D, 0x62,
/* 1150 */ 0x13, 0x7E, 0x1D, 0x5E, 0x13, 0x10, 0x1B, 0xD6,
/* 1158 */ 0x4D, 0x1D, 0x10, 0x33, 0x8D, 0x93, 0x02, 0x13,
/* 1160 */ 0x11, 0x1D, 0x4F, 0x13, 0x25, 0x1D, 0x4B, 0x33,
/* 1168 */ 0x8E, 0x1D, 0x47, 0x13, 0x21, 0x1D, 0x43, 0x13,
/* 1170 */ 0xB0, 0x1D, 0x3F, 0x13, 0x12, 0x1D, 0x3B, 0x43,
/* 1178 */ 0x10, 0xDE, 0x15, 0x04, 0x93, 0x4A, 0x13, 0x05
};

static const uint32_t xtea_key[4] = {
	0x00112233, 0x44556677, 0x8899AABB, 0xCCDDEEFF
};

/* Calculate Videocrypt message CRC */
static uint8_t _crc(uint8_t *data)
{
	int x;
	uint8_t crc;

	for(crc = x = 0; x < 31; x++)
	{
		crc += data[x];
	}

	return (~crc + 1);
}

static uint8_t _rotate_left(uint8_t x)
{
	return (((x) << 1) | ((x) >> 7)) & 0xFF;
}

/* Reverse nibbles in a byte */
static inline uint8_t _swap_nibbles(uint8_t a)
{
	return((a >> 4) | (a << 4));
}

void _rand_vc_seed(uint8_t *message)
{
	for(int i = 12; i < 27; i++) message[i] = rand() + 0xFF;
}

/* Reverse calculated control word */
uint64_t _rev_cw(uint8_t in[8])
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

/* XOR "round" function to obfuscate card serial number */
void _xor_serial(uint8_t *message, int card_cmd, uint32_t cardserial, int prefix_byte)
{
	int i;
	uint8_t a, b, xor[4];
	
	/* XOR round function */
	switch(prefix_byte)
	{
		/* Videocrypt 2 uses message bytes 5 and 6 */
		case 0x81:
			a = message[5] ^ message[6];
			b = message[6];
			break;
		
		/* Videocrypt 1 uses message bytes 1 and 2 */
		default:
			a = message[1] ^ message[2];
			b = message[2];
			break;
	}

	a = _swap_nibbles(a);

	for (i=0; i < 4;i++)
	{
		b = _rotate_left(b);
		b += a;
		xor[i] = b;
	}

	message[3] =  card_cmd  ^ xor[0];
	message[7] =  prefix_byte ^ xor[0];
	message[8] =  ((cardserial >> 24) & 0xFF) ^ xor[1];
	message[9] =  ((cardserial >> 16) & 0xFF) ^ xor[2];
	message[10] = ((cardserial >> 8)  & 0xFF) ^ xor[3];
	message[11] = ((cardserial >> 0)  & 0xFF);
	for(i = 12; i < 27; i++) message[i] = message[11];
}

void _vc_kernel07(uint8_t *out, int *oi, const uint8_t in, _vc_mode_t *m)
{
	uint8_t b, c, key[32];

	memcpy(key, m->key->key + m->key_offset, 0x20);
	
	out[*oi] ^= in;
	b = key[(out[*oi] >> 4)];
	c = key[(out[*oi] & 0x0F) + 16];
	c = m->mode <= VC_SKY02 ? c + b : ~(c + b);
	c = m->mode <= VC_SKY02 ? c + in : _rotate_left(c) + in;
	c = _rotate_left(c);
	c = _swap_nibbles(c);
	*oi = (*oi + 1) & 7;
	out[*oi] ^= c;
}

uint64_t _vc_process_p07_msg(uint8_t *message, _vc_mode_t *m)
{
	int i;
	int oi = 0;	
	uint8_t b, cw[8];
	
	/* Reset answers */
	memset(cw, 0, 8);
	
	/* Run through kernel */
	for (i = 0; i < 27; i++) _vc_kernel07(cw, &oi, message[i], m);
	
	/* Calculate signature */
	if(m->mode < VC_SKY07)
	{
		for (i = 27, b = 0; i < 31; i++)
		{
			_vc_kernel07(cw, &oi, b, m);
			_vc_kernel07(cw, &oi, b, m);
			_vc_kernel07(cw, &oi, b, m);
			message[i] = cw[oi];
		}
	}
	else
	{	
		for (i = 27, b = 0; i < 31; i++)
		{
			_vc_kernel07(cw, &oi, b, m);
			_vc_kernel07(cw, &oi, b, m);
			b = message[i] = cw[oi];
			oi = (oi + 1) & 7;
		}
	}

	/* Generate checksum */
	message[31] = _crc(message);
	
	/* Iterate through _vc_kernel07 64 more times (99 in total) */
	for (i = 0; i < 64; i++) _vc_kernel07(cw, &oi, message[31], m);

	return _rev_cw(cw);
}

void vc_seed_sky(_vc_block_t *s, _vc_mode_t *m)
{
	/* Random seed for bytes 12 to 26 */
	_rand_vc_seed(s->messages[5]);
	
	/* Process Videocrypt message */
	s->codeword = _vc_process_p07_msg(s->messages[5], m);
}

void vc_emm_nz(_vc_block_t *s, _vc_mode_t *m, int cmd, uint32_t cardserial)
{
	int i;
	
	int emmdata[7] = { 0xF0, 0x0e, 0x1f, 0x20, 0x00, 0x00, 0x02 };
	
	/* Copy EMM data into message block */
	for(i = 0; i < 7; i++) s->messages[2][i] = emmdata[i];

	/* Additional 08 prefix for Sky New Zealand cards */
	cardserial |= 0x08 << 24;
	
	/* Obfuscate card serial */
	_xor_serial(s->messages[2], cmd, cardserial, m->emm_byte);
	
	/* Process Videocrypt message */
	_vc_process_p07_msg(s->messages[2], m);
}

void vc_emm_p07(_vc_block_t *s, _vc_mode_t *m, int cmd, uint32_t cardserial)
{
	int i;
	
	int emmdata[7] = { 0xE0, 0x3F, 0x3E, 0xEC, 0x1C, 0x60, 0x0F };
	
	/* Copy EMM data into message block */
	for(i = 0; i < 7; i++) s->messages[2][i] = emmdata[i];
	
	/* Obfuscate card serial */
	_xor_serial(s->messages[2], cmd, cardserial, m->emm_byte);
	
	/* Process Videocrypt message */
	_vc_process_p07_msg(s->messages[2], m);
}

void vc_seed_vc2(_vc2_block_t *s, _vc_mode_t *m)
{
	/* Random seed for bytes 12 to 26 */
	_rand_vc_seed(s->messages[5]);
	
	/* Process Videocrypt message */
	s->codeword = _vc_process_p07_msg(s->messages[5], m);
}

void vc2_emm(_vc2_block_t *s, _vc_mode_t *m, int cmd, uint32_t cardserial)
{
	int i;
	
	int emmdata[7] = { 0xE1,0x81,0x36,0x00,0xFF,0xFF,0xB4 };
	
	/* Copy EMM data into message block */
	for(i = 0; i < 7; i++) s->messages[2][i] = emmdata[i];
	
	/* Obfuscate card serial */
	_xor_serial(s->messages[2], cmd, cardserial, m->emm_byte);
	
	/* Process Videocrypt message */
	_vc_process_p07_msg(s->messages[2], m);
}

void _vc_kernel09(const _vc_key_t *k, const uint8_t in, uint8_t *out)
{
	uint8_t a, b, c;
	uint8_t temp[8];
	uint16_t m;
	int i;
	
	memcpy(temp, out, 8);
	
	a = in;
	for (i = 0; i <= 4; i += 2)
	{
		b = (a + k->key[temp[i] & 0x3F] - temp[i + 1]);
		c = ((temp[i] - temp[i + 1])) ^ a;
		m = b * c;
		temp[i + 2] ^= (m & 0xFF);
		temp[i + 3] += m >> 8;
		a = _rotate_left(a) + 0x49;
	}
	
	m = temp[6] * temp[7];
	a = (m & 0xFF) + temp[0];
	a = a < temp[0] ? a + 1 : a;
	temp[0] = a + 0x39;
	a = (m >> 8) + temp[1];
	a = a < temp[1] ? a + 1 : a;
	temp[1] = a + 0x8F;
	
	memcpy(out, temp, 8);
}

uint64_t _vc_process_p09_msg(uint8_t *message, _vc_mode_t *m)
{
	int i;
	uint8_t a, b, bb, xor[4], nanobuffer[0x0F], cw[8];
	
	bb = 0;
	i = 0;
	
	if(m->mode == VC_SKY09_NANO)
	{
		int x;
		
		/* XOR round function */
		a = message[1] ^ message[2];
		a = _swap_nibbles(a);
		b = message[2];
		
		for (i = 0; i < 4; i++)
		{
			b = _rotate_left(b);
			b += a;
			xor[i] = b;
		}
		
		/* Set card command to nano - 0x80 */
		message[3] = xor[0] ^ 0x80;
		
		/* Set EEPROM address */
		nanobuffer[0] = 0x09;
		nanobuffer[1] = 0x11;
		nanobuffer[2] = rand() % (0x7F - 0x3F + 1);
		
		/* Set EEPROM offset/number of bytes to read */
		nanobuffer[3] = 0x30;
		nanobuffer[4] = rand() % 0x3F;
		
		/* End session */
		nanobuffer[5] = 0x03;
		
		/* Make nanos */
		x = xor[2];
		for (i = 0; i < 6; i++)
		{
			message[i + 12] = x ^ nanobuffer[i];
		}
	}
	
	/* Reset CW */
	memset(cw, 0, 8);
	
	for (i = 0; i < 27; i++) _vc_kernel09(m->key, message[i], cw);
	
	/* Calculate signature */
	for (i = 27, b = 0; i < 31; i++)
	{
		_vc_kernel09(m->key, b, cw);
		_vc_kernel09(m->key, b, cw);
		b = message[i] = cw[7];
	}
	
	/* Nanos */
	if(m->mode == VC_SKY09_NANO && (message[3] ^ xor[0]) == 0x80)
	{
		int x, ee_address, ee_data, ee_offset;
		
		ee_address = 0;
		
		/* Process nanos */
		for(i = 0; i < 0x0F; i++)
		{
			switch(nanobuffer[i])
			{
				case 0x03:
					bb = i;
					i += 0x0F; /* Done */
					break;
					
				case 0x09:
					ee_address = (nanobuffer[i + 1]) * 0x100 + nanobuffer[i+ 2];
					_vc_kernel09(m->key, 0x63, cw);
					_vc_kernel09(m->key, 0x00, cw);
					i += 2;
					break;
				
				case 0x30:
					ee_offset = nanobuffer[i + 1] & 0x7F;
					for(x = ee_offset; x >= 0; x--)
					{
						ee_data = ext_ee[ee_address + x - 0x1100];
						_vc_kernel09(m->key, ee_data, cw);
					}
					_vc_kernel09(m->key, ee_data, cw);
					_vc_kernel09(m->key, 0xFF, cw);
					i++;
					break;
				
				case 0x46:
					i += 0x0F; /* Done */
					break;
				
				default:
					fprintf(stderr, "\nUnknown nano %02X at index %d!", nanobuffer[i], i);
					break;
			}
		}
	}
	
	/* Generate checksum */
	message[31] = _crc(message);
	
	/* Iterate through _vc_kernel09 64 more times (99 in total)*/
	for (i = 0; i < 64; i++) _vc_kernel09(m->key, (bb ? bb : message[31]), cw);
	
	return _rev_cw(cw);
}

void vc_seed_sky_p09(_vc_block_t *s, _vc_mode_t *m)
{
	/* Random seed for bytes 12 to 26 */
	_rand_vc_seed(s->messages[5]);

	/* Process Videocrypt message */
	s->codeword =  _vc_process_p09_msg(s->messages[5], m);
}

void vc_emm_p09(_vc_block_t *s, int cmd, uint32_t cardserial, _vc_mode_t *m)
{
	int i;
	
	int emmdata[7] = { 0xE1, 0x52, 0x01, 0x25, 0x80, 0xFF, 0x20 };
	
	/* Copy EMM data into message block */
	for(i = 0; i < 7; i++) s->messages[2][i] = emmdata[i];
	
	/* Obfuscate card serial */
	_xor_serial(s->messages[2], cmd, cardserial, 0xA9);

	/* Process Videocrypt message */
	_vc_process_p09_msg(s->messages[2], m);
}

void vc_seed_xtea(_vc_block_t *s)
{
	/* Random seed for bytes 11 to 31 */
	for(int i=11; i < 32; i++) s->messages[5][i] = rand() + 0xFF;
	
	int i;
	uint32_t v0, v1, sum = 0;
	uint32_t delta = 0x9E3779B9;
	
	s->messages[5][6] = 0x63;
	
	memcpy(&v1, &s->messages[5][11], 4);
	memcpy(&v0, &s->messages[5][15], 4);
	
	for (i = 0; i < 32;i++)
	{
		v0  += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + xtea_key[sum & 3]);
		sum += delta;
		v1  += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + xtea_key[(sum >> 11) & 3]);
	
		if(i == 7)
		{
			memcpy(&s->messages[5][19], &v1, 4);
			memcpy(&s->messages[5][23], &v0, 4);
		}
	}
	
	/* Reverse calculated control word */
	s->codeword = ((uint64_t) v0 << 32 | v1) & 0x0FFFFFFFFFFFFFFFUL;
}

/* Code below is to support seed generation for "dumb"/memory card */
/* Thanks to Phil Pemberton for providing the required information */
/* https://github.com/philpem/hacktv */

/* Code table at address 0x1421 from verifier */
const uint8_t tab_1421[8] = {
	0x59, 0x2B, 0x71, 0x22, 0xCF, 0xB7, 0x33, 0x4F	
};

/* The four moduli and also a 256-byte data table */
const uint8_t moduli[256] = {
	0xB1, 0xFD, 0x91, 0x2C, 0x6D, 0xB8, 0xB6, 0xBE,
	0x15, 0x08, 0x0D, 0xE2, 0x83, 0xB1, 0xE8, 0x0B,
	0x36, 0xB0, 0x47, 0xEA, 0xA1, 0x10, 0xA7, 0x8E,
	0xAA, 0x2E, 0x94, 0xC8, 0x47, 0x41, 0xFE, 0x87,
	0x7E, 0xEC, 0x67, 0x45, 0xAB, 0x89, 0x84, 0xA5,
	0xEF, 0xCD, 0x23, 0x01, 0x67, 0x45, 0x2D, 0x46,
	0xAB, 0xA9, 0xEF, 0xCD, 0x24, 0x93, 0x02, 0x67,
	0x1B, 0x4F, 0x81, 0x95, 0xA7, 0x01, 0x00, 0x01,
	
	0x29, 0x9F, 0xC9, 0x85, 0x19, 0xB9, 0x53, 0x53,
	0x92, 0x52, 0x90, 0x5A, 0x44, 0x2D, 0xCA, 0xD4,
	0x90, 0x8D, 0x3A, 0xAD, 0xFB, 0x2B, 0x00, 0x9D,
	0xE4, 0x0C, 0xB8, 0x81, 0x28, 0xBF, 0xE9, 0x0B,
	0x85, 0x7C, 0xAD, 0x90, 0x41, 0xE7, 0x7A, 0xBA,
	0x9D, 0xEF, 0x7E, 0x83, 0x82, 0x0D, 0x0A, 0xCE,
	0x64, 0x77, 0x83, 0x1E, 0x1D, 0x80, 0x26, 0xF5,
	0x48, 0xA4, 0x39, 0x6E, 0xC3, 0x01, 0x00, 0x01,
	
	0x0D, 0x2D, 0xC9, 0x25, 0x51, 0x4A, 0xA3, 0x85,
	0x8B, 0xDC, 0xC7, 0x25, 0x40, 0x0C, 0xB8, 0x61,
	0x0C, 0xF9, 0xC1, 0x21, 0xBD, 0x3D, 0x57, 0x6D,
	0x6C, 0x71, 0x2F, 0xA4, 0xCC, 0x93, 0x40, 0x37,
	0xDE, 0x32, 0x39, 0x65, 0xC1, 0x8D, 0x63, 0x6A,
	0x49, 0xB6, 0xE1, 0xD0, 0x73, 0x5E, 0xDE, 0x9C,
	0x12, 0xA7, 0xC3, 0x34, 0x5E, 0x38, 0x8C, 0x73,
	0x05, 0x4E, 0x63, 0x41, 0x0A, 0x01, 0x00, 0x01,
	
	0xE5, 0x20, 0x5B, 0xD5, 0x56, 0xD1, 0x9B, 0xA9,
	0xA5, 0x54, 0xB7, 0x83, 0x16, 0xDE, 0x36, 0x0B,
	0xD6, 0x03, 0x58, 0x1B, 0xE0, 0x0D, 0x36, 0x72,
	0xAD, 0x6B, 0x69, 0xDA, 0xD9, 0x99, 0x16, 0xBC,
	0xCB, 0x24, 0xF6, 0x65, 0xB4, 0x45, 0xA6, 0xBB,
	0xED, 0x53, 0x3E, 0xB0, 0xF7, 0xB8, 0xF5, 0xEA,
	0xA6, 0xB7, 0xAF, 0x64, 0xED, 0xA2, 0xE7, 0xFE,
	0xC2, 0x57, 0xC4, 0xD1, 0x0B, 0x01, 0x00, 0x01
};

void _hash_ppv(uint64_t *answ, size_t len)
{
	int i, j, m;
	/* Generate seed */	
	for (i = 0; i < 8; i++) 
	{
		for (j = 1; j != len; j++) 
		{
			m = (tab_1421[i] + answ[j - 1]) & 0xFF;
			answ[j] = _rotate_left(answ[j] ^ moduli[m]);
		}
		answ[0] ^= answ[len-1];
	}
}

void vc_seed_ppv(_vc_block_t *s, uint8_t ppv_card_data[7])
{
	int i;
	
	/* Temporary buffers */
	uint64_t   msg[32];
	uint64_t serial[5];
	
	/* Random bytes */
	s->messages[0][21] = rand() + 0xFF;
	s->messages[0][22] = rand() + 0xFF;
	
	/* Copy data into buffers */
	for(i = 0; i < 31; i++)    msg[i] = s->messages[0][i];
	for(i = 0; i <  5; i++) serial[i] = ppv_card_data[i];
	
	_hash_ppv(serial, 5);
	
	msg[1] ^= serial[0] ^ ppv_card_data[5];
	msg[2] ^= serial[1] ^ ppv_card_data[6];
	
	_hash_ppv(&msg[1], 22);
	
	/* Mask high nibble of last byte as it's not used */
	msg[8] &= 0x0F;
	
	/* Reverse calculated control word */
	for(i = 0, s->codeword = 0; i < 8; i++)	s->codeword = msg[i + 1] << (i * 8) | s->codeword;
}

void vc_seed(_vc_block_t *s, _vc_mode_t *m)
{
	switch(m->mode)
	{
		case(VC_DMX):
		case(VC_TAC1):
		case(VC_TAC2):
		case(VC_SKYNZ01):
		case(VC_SKYNZ02):
		case(VC_SKY02):
		case(VC_SKY03):
		case(VC_SKY04):
		case(VC_SKY05):
		case(VC_SKY06):
		case(VC_SKY07):
		case(VC_JSTV):
			vc_seed_sky(s, m);
			break;
			
		case(VC_SKY09):
		case(VC_SKY09_NANO):
			vc_seed_sky_p09(s, m);
			break;
			
		case(VC_XTEA):
			vc_seed_xtea(s);
			break;
			
		default:
			break;
	}
}

void vc_emm(_vc_block_t *s, _vc_mode_t *m, uint32_t cardserial, int b, int i)
{
	uint8_t cmd_tac[]   = { 0x08, 0x09, 0x28, 0x29 };
	uint8_t cmd_sky06[] = { 0x20, 0x21, 0x03, 0x01 };
	uint8_t cmd_sky07[] = { 0x2C, 0x20, 0x0C, 0x00 };
	uint8_t cmd_skynz[] = { 0x03, 0x23 };

	switch(m->mode)
	{
		case(VC_SKYNZ01):
		case(VC_SKYNZ02):
			/*
			 * 0x03: Disable card
			 * 0x23: Enable card
			 */
			vc_emm_nz(s, m, (b ? cmd_skynz[1] : cmd_skynz[0]) , cardserial);
			break;

		case(VC_TAC1):
		case(VC_TAC2):
			/*
			 * 0x08: Unblock channel
			 * 0x09: Enable card
			 * 0x81: Set EXP date
			 * 0x28: Block channel
			 * 0x29: Disable card
			 */
			vc_emm_p07(s, m, (b ? cmd_tac[i] : cmd_tac[i + 2]), cardserial);
			break;

		case(VC_SKY06):
			/*
			 * 0x02: allow Sky Movies
			 * 0x21: Enable card
			 * 0x22: switch off Sky Movies
			 * 0x01: Disable card
			 */
			vc_emm_p07(s, m, (b ? cmd_sky06[i] : cmd_sky06[i + 2]), cardserial);
			break;
		
		case(VC_SKY07):
			/*  
			 * 0x2C: allow Sky Multichannels
			 * 0x20: Enable card
			 * 0x0C: switch off Sky Multichannels
			 * 0x00: Disable card 
			 */
			vc_emm_p07(s, m, (b ? cmd_sky07[i] : cmd_sky07[i + 2]), cardserial);
			break;
		
		case(VC_SKY09):
		case(VC_SKY09_NANO):
			vc_emm_p09(s, (b ? cmd_sky07[i] : cmd_sky07[i + 2]), cardserial, m);
			break;
	}
}