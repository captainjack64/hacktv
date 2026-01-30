/* hacktv - Analogue video transmitter for the HackRF                    */
/*=======================================================================*/
/* Copyright 2017 Philip Heron <phil@sanslogic.co.uk>                    */
/* Copyright 2026 Katy Coe - https://github.com/djkaty/                  */
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

/*=======================================================================*/
/* All of the code in this file belongs to Katy Coe who has worked for   */
/* 999 days (no, really!) to reverse engineer the ASIC used in these     */
/* cards. Without her, this functionality would not have been possible   */
/*=======================================================================*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "videocrypt10-asic.h"

/* Tap selectors for bits 64-79 */
static const int tap_selectors[16][2][4] = 
{
    {{37, 49, 11, 61}, {61, 37, 49, 11}},  /* 64 */
    {{35, 14, 24, 39}, {14, 39, 35, 24}},  /* 65 */
    {{59, 63, 33, 43}, {43, 59, 63, 33}},  /* 66 */
    {{48, 20,  2, 38}, {38, 48, 20,  2}},  /* 67 */
    {{22, 46,  5, 40}, {40, 22, 46,  5}},  /* 68 */
    {{47, 54, 16, 57}, {57, 47, 54, 16}},  /* 69 */
    {{29,  3, 34, 42}, {34, 42,  3, 29}},  /* 70 */
    {{51, 45, 18, 58}, {45, 58, 51, 18}},  /* 71 */
    {{25, 52, 36, 10}, {36, 10, 52, 25}},  /* 72 */
    {{21, 15, 30, 41}, {30, 41, 15, 21}},  /* 73 */
    {{17, 60,  8, 28}, {60, 28, 17,  8}},  /* 74 */
    {{ 4, 32, 13, 53}, {53, 13,  4, 32}},  /* 75 */
    {{12,  7, 23,  9}, { 7,  9, 12, 23}},  /* 76 */
    {{50, 27, 31, 19}, {31, 19, 27, 50}},  /* 77 */
    {{ 0,  6, 55, 62}, { 6, 62,  0, 55}},  /* 78 */
    {{44, 26, 56,  1}, { 1, 56, 44, 26}}   /* 79 */
};

/* P-boxes for bits 80-95 */
typedef struct 
{
    int bit;
    int idx;
} pbox_t;

static const pbox_t p_boxes[16][2][4] = 
{
    {{{76,2}, {68,1}, {69,0}, {69,0}}, {{68,1}, {75,1}, {76,2}, {69,2}}},  /* 80 */
    {{{79,3}, {71,0}, {68,3}, {73,0}}, {{71,2}, {73,0}, {79,3}, {68,3}}},  /* 81 */
    {{{78,3}, {65,0}, {65,3}, {74,1}}, {{74,1}, {78,3}, {65,0}, {72,1}}},  /* 82 */
    {{{66,2}, {64,3}, {78,2}, {75,2}}, {{64,3}, {75,2}, {64,2}, {78,2}}},  /* 83 */
    {{{79,1}, {79,1}, {67,3}, {77,0}}, {{75,1}, {77,0}, {69,2}, {67,3}}},  /* 84 */
    {{{66,2}, {66,1}, {75,0}, {73,1}}, {{75,0}, {64,2}, {79,2}, {66,1}}},  /* 85 */
    {{{65,2}, {66,3}, {67,2}, {75,3}}, {{75,3}, {67,2}, {65,2}, {66,3}}},  /* 86 */
    {{{64,0}, {70,2}, {74,2}, {77,1}}, {{70,2}, {74,2}, {77,1}, {64,0}}},  /* 87 */
    {{{77,3}, {78,0}, {79,2}, {76,3}}, {{73,1}, {65,1}, {76,3}, {78,0}}},  /* 88 */
    {{{72,2}, {76,1}, {77,2}, {66,0}}, {{76,1}, {77,2}, {66,0}, {72,2}}},  /* 89 */
    {{{71,3}, {69,1}, {65,3}, {73,2}}, {{69,1}, {72,1}, {73,2}, {71,3}}},  /* 90 */
    {{{74,3}, {67,0}, {71,1}, {79,0}}, {{67,0}, {73,3}, {72,0}, {73,3}}},  /* 91 */
    {{{69,3}, {72,3}, {65,1}, {67,1}}, {{77,3}, {67,1}, {72,3}, {69,3}}},  /* 92 */
    {{{76,0}, {70,3}, {68,2}, {78,1}}, {{78,1}, {68,2}, {76,0}, {70,3}}},  /* 93 */
    {{{70,0}, {71,2}, {70,0}, {74,3}}, {{72,0}, {79,0}, {71,1}, {71,0}}},  /* 94 */
    {{{74,0}, {70,1}, {64,1}, {68,0}}, {{68,0}, {74,0}, {70,1}, {64,1}}}   /* 95 */
};

/* Linear taps for bits 96-103 */
static const int linear_taps[8][2] = 
{
    {5, 2}, {9, 8}, {17, 10}, {29, 18}, {38, 33}, {46, 44}, {53, 49}, {62, 57}
};

static void byte_to_bools(uint8_t byte, bool *bools) 
{
    for (int i = 0; i < 8; i++) 
    {
        bools[i] = (byte >> i) & 1;
    }
}

static uint8_t bools_to_byte(const bool *bools) 
{
    uint8_t value = 0;
    for (int i = 0; i < 8; i++) 
    {
        if (bools[i]) value |= (1 << i);
    }
    return value;
}

static bool feedback_function(const bool *input) 
{
    /* Get bits from 0-63 based on mask in 64-79 */
    bool sel[16][4];
    for (int b = 0; b < 16; b++) 
    {
        int bit_idx = b + 64;
        int selector = input[bit_idx] ? 1 : 0;
        for (int i = 0; i < 4; i++) 
        {
            sel[b][i] = input[tap_selectors[b][selector][i]];
        }
    }

    /* Permute selected bits based on mask in 80-95 */
    bool s[16][4];
    for (int bit = 0; bit < 16; bit++) 
    {
        int bit_idx = bit + 80;
        int selector = input[bit_idx] ? 0 : 1;  /* Inverted! */
        for (int i = 0; i < 4; i++) 
        {
            pbox_t entry = p_boxes[bit][selector][i];
            s[bit][i] = !sel[entry.bit - 64][entry.idx];
        }
    }

    /* Special cases */
    s[2][2]   = (input[82]   || !sel[1][0])  && (input[90]   || !sel[1][3]);
    s[10][1]  = (!input[82]  || !sel[8][1])  && (!input[90]  || !sel[5][1]);

    s[0][3]   = (input[84]   && !sel[5][2])  || (!input[80]  && !sel[5][0]);
    s[4][0]   = (input[80]   && !sel[11][1]) || (!input[84]  && !sel[15][1]);

    s[1][0]   = (!input[81]  || !sel[15][3]) && (input[94]   || !sel[7][2]);
    s[14][3]  = (input[81]   || !sel[7][0])  && (!input[94]  || !sel[10][3]);

    s[3][2]   = (!input[83]  || !sel[14][2]) && (!input[85]  || !sel[0][2]);
    s[5][0]   = (input[83]   || !sel[2][2])  && (input[85]   || !sel[11][0]);

    s[8][0]   = (!input[88]  || !sel[13][3]) && (input[85]   || !sel[9][1]);
    s[5][2]   = (!input[85]  || !sel[11][0]) && (input[88]   || !sel[15][2]);

    s[8][1]   = (!input[88]  || !sel[14][0]) && (input[92]   || !sel[1][1]);
    s[12][0]  = (!input[92]  || !sel[5][3])  && (input[88]   || !sel[13][3]);

    s[11][3]  = (input[91]   && !sel[9][3])  || (input[94]   && !sel[15][0]);
    s[14][2]  = (!input[91]  && !sel[7][1])  || (!input[94]  && !sel[6][0]);

    s[11][0]  = (input[94]   || !sel[10][3]) && (input[91]   || !sel[3][0]);
    s[14][0]  = (!input[91]  || !sel[8][0])  && (!input[94]  || !sel[6][0]);

    s[15][0]  = !s[15][0];

    /* Complex logic */
    bool a     = ((s[13][1] || s[9][3])  == (s[3][0]  && s[10][2]));
    bool b     = (s[5][3]   || s[7][3])  && (s[4][2]  == s[13][0]);
    bool i1    = a || b;

    bool r1    = (s[15][0]  != s[11][1]) || (s[10][1] && s[2][2]);
    bool r2_1  = (s[0][3]   || s[4][0])  != (s[1][0]  && s[14][3]);
    bool r2    = r2_1 || !r1;

    bool r5    = (s[1][3]   == s[6][2])  || (s[3][2]  && s[5][0]);
    bool r5_1  = (s[2][1]   || s[9][0])  == (s[6][3]  && s[12][3]);
    bool r6    = r5 && r5_1;

    bool r9    = (s[7][0]   == s[10][0]) || (s[8][1]  && s[12][0]);
    bool r12_1 = (s[11][3]  || s[14][2]) != (s[12][2] && s[13][2]);
    bool r12   = r12_1 || !r9;

    bool r10   = (s[1][2]   == s[9][2])  && (s[14][1] || s[15][2]);
    bool r11   = (s[0][1]   || s[10][3]) == (s[3][1]  && s[15][1]);
    bool c     = !r10 && !r11;

    bool r7    = ((s[7][2]  == s[9][1])  || (s[8][0]  && s[5][2]))  ^ (s[8][2]  != s[12][1] || !(s[2][0]  || s[1][1]));
    bool r8    = ((s[7][1]  == s[13][3]) || (s[11][2] && s[8][3]))  ^ (s[3][3]  != s[6][0]  || !(s[5][1]  || s[4][1]));
    bool r13   = ((s[2][3]  == s[0][0])  || (s[14][0] && s[11][0])) ^ (s[4][3]  != s[0][2]  || !(s[6][1]  || s[15][3]));

    bool i2    = (r2 != i1) && (r6 || r7);
    a          = (c || !r13) == (r8 || !r12);

    bool p     = a && !i2;

    /* Handle bits 96-103 */
    int xor_count = 0;
    for (int bit = 96; bit < 104; bit++) 
    {
        int tap_idx = input[bit] ? 1 : 0;
        if (input[linear_taps[bit - 96][tap_idx]]) 
        {
            xor_count++;
        }
    }
    bool xors = (xor_count & 1) == 1;
    xors ^= input[104];

    return p ^ xors;
}

static void asic_shift(asic10_t *asic) 
{
    bool new_bit = feedback_function(asic->shift_register);
    memmove(&asic->shift_register[1], &asic->shift_register[0], 104 * sizeof(bool));
    asic->shift_register[0] = new_bit;
}

void asic_iterate(asic10_t *asic, int rounds) 
{
    if (rounds == -1) 
    {
        rounds = asic->iterations;
    }
    for (int i = 0; i < rounds; i++) 
    {
        asic_shift(asic);
    }
}

static uint8_t asic_read_next(asic10_t *asic) 
{
    uint8_t value = bools_to_byte(&asic->shift_register[asic->read_pointer * 8]);
    asic->read_pointer = (asic->read_pointer + 1) % 8;
    return value;
}

static void asic_push_onto_fifo_queue(asic10_t *asic, uint8_t byte) 
{
    bool value[8];
    byte_to_bools(byte, value);
    
    memmove(&asic->fifo_buffer[8], &asic->fifo_buffer[0], 56 * sizeof(bool));
    memcpy(&asic->fifo_buffer[0], value, 8 * sizeof(bool));

    if (asic->crypto_enabled) 
    {
        for (int i = 0; i < 64; i++) 
        {
            asic->shift_register[i] ^= asic->fifo_buffer[i];
        }
        asic_iterate(asic, -1);
    }
}

void asic_send(asic10_t *asic, const uint8_t *data, int len) 
{
    int pos = 0;
    while (pos < len) 
    {
        uint8_t cmd = data[pos];
        
        switch (cmd) 
        {
            case 0x01:
                if (pos + 1 >= len) 
                {
                    fprintf(stderr, "Missing data for command 0x%02x\n", cmd);
                    return;
                }
                asic_push_onto_fifo_queue(asic, data[pos + 1]);
                break;
                
            case 0x21:
                if (pos + 1 >= len) 
                {
                    fprintf(stderr, "Missing data for command 0x%02x\n", cmd);
                    return;
                }
                asic->crypto_enabled = (data[pos + 1] & 0b00000010) >> 1;
                asic->decoder_capture = (data[pos + 1] & 0b00000100) >> 2;
                if ((data[pos + 1] & 0b00000001) == 1) 
                {
                    asic->shift_register[104] = false;
                    memset(asic->shift_register, 0, 64 * sizeof(bool));
                    asic->read_pointer = 0;
                }
                break;
                
            case 0x31:
                if (pos + 1 >= len) 
                {
                    fprintf(stderr, "Missing data for command 0x%02x\n", cmd);
                    return;
                }
                asic->iterations = (data[pos + 1] > 0) ? (data[pos + 1] * 1024 + 1) : 0;
                break;
                
            case 0x51:
                if (pos + 1 >= len) 
                {
                    fprintf(stderr, "Missing data for command 0x%02x\n", cmd);
                    return;
                }
                byte_to_bools(data[pos + 1], &asic->shift_register[96]);
                break;
            case 0x61:
                if (pos + 1 >= len) 
                {
                    fprintf(stderr, "Missing data for command 0x%02x\n", cmd);
                    return;
                }
                byte_to_bools(data[pos + 1], &asic->shift_register[64]);
                break;
            case 0x71:
                if (pos + 1 >= len) 
                {
                    fprintf(stderr, "Missing data for command 0x%02x\n", cmd);
                    return;
                }
                byte_to_bools(data[pos + 1], &asic->shift_register[72]);
                break;
            case 0x81:
                if (pos + 1 >= len) 
                {
                    fprintf(stderr, "Missing data for command 0x%02x\n", cmd);
                    return;
                }
                byte_to_bools(data[pos + 1], &asic->shift_register[80]);
                break;
            case 0x91:
                if (pos + 1 >= len) 
                {
                    fprintf(stderr, "Missing data for command 0x%02x\n", cmd);
                    return;
                }
                byte_to_bools(data[pos + 1], &asic->shift_register[88]);
                break;
                
            case 0x13:
                asic->pending_response_byte = asic_read_next(asic);
                asic->has_pending_response = true;
                if (len - pos > 1) 
                {
                    fprintf(stderr, "Additional data sent when ASIC is providing a response\n");
                    return;
                }
                break;
                
            default:
                fprintf(stderr, "Unknown command 0x%02x received by ASIC\n", cmd);
                return;
        }
        
        pos += 2;
    }
}

void asic_send_from_decoder(asic10_t *asic, const uint8_t *data, int len) 
{
    if (!asic->decoder_capture) return;
    
    for (int i = 0; i < len; i++) 
    {
        asic_push_onto_fifo_queue(asic, data[i]);
    }
}

uint8_t asic_receive_one(asic10_t *asic) 
{
    if (!asic->has_pending_response) 
    {
        fprintf(stderr, "No pending response from ASIC\n");
        return 0;
    }
    
    uint8_t value = asic->pending_response_byte;
    asic->has_pending_response = false;
    return value;
}

void asic_reset(asic10_t *asic) 
{
    memset(asic->shift_register, 0, sizeof(asic->shift_register));
    for (int i = 0; i < 64; i++) 
    {
        asic->fifo_buffer[i] = true;
    }
    asic->iterations = 1025;
    asic->crypto_enabled = false;
    asic->decoder_capture = false;
    asic->read_pointer = 0;
    asic->has_pending_response = false;
}

asic10_t* asic_create(void) 
{
    asic10_t *asic = (asic10_t*)malloc(sizeof(asic10_t));
    if (!asic) return NULL;
    asic_reset(asic);
    return asic;
}

void asic_destroy(asic10_t *asic) 
{
    free(asic);
}