/* hacktv - Analogue video transmitter for the HackRF                    */
/*=======================================================================*/
/* Copyright 2026 Philip Heron <phil@sanslogic.co.uk>                    */
/* Copyright 2026 Alex James                                             */
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

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "discret14-ca.h"

static const uint8_t kEepromBroadcastKey[8] =
{
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
};

static const uint8_t kValidationTarget[8] =
{
    0x51, 0x64, 0x7C, 0xCB, 0x51, 0x64, 0x7C, 0xCB
};

static const uint8_t kValidationTargetB[8] =
{
    0xA3, 0x17, 0x2E, 0x99, 0xA3, 0x17, 0x2E, 0x99
};

static uint8_t kProgramData8[8] =
{
    0x04, 0x1B, 0xF7, 0x00, 0x01, 0x92, 0xFF, 0x00
};

static const uint8_t kRomAsicKeyBase[8] =
{
    0x85, 0x1A, 0xF0, 0x30, 0xF6, 0x03, 0x02, 0x00
};

static const uint8_t kEepromAsicKey[8] =
{
    0x41, 0x42, 0x43, 0x4C, 0x49, 0x52, 0x4F, 0x59
};

static const int IP[64] =
{
    58,50,42,34,26,18,10, 2, 60,52,44,36,28,20,12, 4,
    62,54,46,38,30,22,14, 6, 64,56,48,40,32,24,16, 8,
    57,49,41,33,25,17, 9, 1, 59,51,43,35,27,19,11, 3,
    61,53,45,37,29,21,13, 5, 63,55,47,39,31,23,15, 7
};

static const int FP[64] =
{
    40, 8,48,16,56,24,64,32, 39, 7,47,15,55,23,63,31,
    38, 6,46,14,54,22,62,30, 37, 5,45,13,53,21,61,29,
    36, 4,44,12,52,20,60,28, 35, 3,43,11,51,19,59,27,
    34, 2,42,10,50,18,58,26, 33, 1,41, 9,49,17,57,25
};

static const int E_TBL[48] =
{
    32, 1, 2, 3, 4, 5,  4, 5, 6, 7, 8, 9,
     8, 9,10,11,12,13, 12,13,14,15,16,17,
    16,17,18,19,20,21, 20,21,22,23,24,25,
    24,25,26,27,28,29, 28,29,30,31,32, 1
};

static const int P_TBL[32] =
{
    16, 7,20,21, 29,12,28,17,  1,15,23,26,  5,18,31,10,
     2, 8,24,14, 32,27, 3, 9, 19,13,30, 6, 22,11, 4,25
};

static const int PC1[56] =
{
    57,49,41,33,25,17, 9,  1,58,50,42,34,26,18,
    10, 2,59,51,43,35,27, 19,11, 3,60,52,44,36,
    63,55,47,39,31,23,15,  7,62,54,46,38,30,22,
    14, 6,61,53,45,37,29, 21,13, 5,28,20,12, 4
};

static const int PC2[48] =
{
    14,17,11,24, 1, 5,  3,28,15, 6,21,10,
    23,19,12, 4,26, 8, 16, 7,27,20,13, 2,
    41,52,31,37,47,55, 30,40,51,45,33,48,
    44,49,39,56,34,53, 46,42,50,36,29,32
};

static const int SHIFTS[16] = { 1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1 };

static const uint8_t SBOX[8][64] =
{
    { 14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,
      0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
      4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,
      15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13 },
    { 15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,
      3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
      0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,
      13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9 },
    { 10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,
      13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
      13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,
      1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12 },
    { 7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,
      13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
      10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,
      3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14 },
    { 2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,
      14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
      4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,
      11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3 },
    { 12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,
      10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
      9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,
      4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13 },
    { 4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,
      13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
      1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,
      6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12 },
    { 13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,
      1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
      7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,
      2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11 }
};

static uint64_t bytes_to_u64(const uint8_t in[8])
{
    uint64_t x = 0;
    int i;
    for (i = 0; i < 8; i++)
        x = (x << 8) | in[i];
    return x;
}

static void u64_to_bytes(uint64_t x, uint8_t out[8])
{
    int i;
    for (i = 7; i >= 0; i--)
    {
        out[i] = (uint8_t)(x & 0xFF);
        x >>= 8;
    }
}

static uint64_t permute_bits(uint64_t in, const int *table, int n, int w)
{
    uint64_t out = 0;
    int i;
    for (i = 0; i < n; i++)
    {
        out <<= 1;
        out |= (in >> (w - table[i])) & 1ULL;
    }
    return out;
}

static uint32_t rol28(uint32_t x, int s)
{
    x &= 0x0FFFFFFF;
    return ((x << s) | (x >> (28 - s))) & 0x0FFFFFFF;
}

static void des_make_subkeys(const uint8_t key[8], uint64_t sk[16])
{
    uint64_t pc1 = permute_bits(bytes_to_u64(key), PC1, 56, 64);
    uint32_t c = (uint32_t)((pc1 >> 28) & 0x0FFFFFFF);
    uint32_t d = (uint32_t)(pc1 & 0x0FFFFFFF);
    int r;

    for (r = 0; r < 16; r++)
    {
        c = rol28(c, SHIFTS[r]);
        d = rol28(d, SHIFTS[r]);
        sk[r] = permute_bits(((uint64_t)c << 28) | d, PC2, 48, 56);
    }
}

static uint32_t des_f(uint32_t r, uint64_t sk)
{
    uint64_t x = permute_bits((uint64_t)r, E_TBL, 48, 32) ^ sk;
    uint32_t s_out = 0;
    int i;

    for (i = 0; i < 8; i++)
    {
        uint8_t ch = (uint8_t)((x >> (42 - 6 * i)) & 0x3F);
        s_out = (s_out << 4) |
                SBOX[i][(((ch & 0x20) >> 4) | (ch & 1)) * 16 + ((ch >> 1) & 0xF)];
    }
    return (uint32_t)permute_bits((uint64_t)s_out, P_TBL, 32, 32);
}

static void des_crypt_block(const uint8_t in[8], const uint8_t key[8],
                            uint8_t out[8], int decrypt)
{
    uint64_t sk[16], ip;
    uint32_t l, r, tmp;
    int rnd;

    des_make_subkeys(key, sk);
    ip = permute_bits(bytes_to_u64(in), IP, 64, 64);
    l = (uint32_t)(ip >> 32);
    r = (uint32_t)(ip & 0xFFFFFFFFUL);

    for (rnd = 0; rnd < 16; rnd++)
    {
        tmp = r;
        r = l ^ des_f(r, decrypt ? sk[15 - rnd] : sk[rnd]);
        l = tmp;
    }

    u64_to_bytes(permute_bits(((uint64_t)r << 32) | l, FP, 64, 64), out);
}

static void des_decrypt_block(const uint8_t in[8], const uint8_t key[8],
                              uint8_t out[8])
{
    des_crypt_block(in, key, out, 1);
}

static void des_encrypt_block(const uint8_t in[8], const uint8_t key[8],
                              uint8_t out[8])
{
    des_crypt_block(in, key, out, 0);
}


static void compute_asic_seeds(discret14_ca_t *ca)
{
    uint8_t akey[8], val[8];
    int i, all_zero = 1;

    memcpy(val, &ca->superframe[8], 8);
    for (i = 0; i < 8; i++)
    {
        if (val[i])
        {
            all_zero = 0;
            break;
        }
    }
    if (all_zero)
    {
        memset(ca->asic_seed, 0, 16);
        return;
    }

    if (kProgramData8[1] & 0x08)
    {
        memcpy(akey, kRomAsicKeyBase, 8);
        for (i = 0; i < 5; i++)
            akey[i] ^= kProgramData8[3 + i];
    }
    else
    {
        memcpy(akey, kEepromAsicKey, 8);
    }

    des_encrypt_block(val, akey, &ca->asic_seed[0]);
    des_encrypt_block(&ca->asic_seed[0], akey, &ca->asic_seed[8]);
}

static void print_hex(const char *label, const uint8_t *d, int n)
{
    int i;
    printf("%-20s", label);
    for (i = 0; i < n; i++)
        printf("%02X%s", d[i], i + 1 < n ? " " : "\n");
}

static void log_superframe(discret14_ca_t *ca, const uint8_t *prog,
                           const uint8_t *tgt_a, const uint8_t *cw_a,
                           const uint8_t *tgt_b, const uint8_t *cw_b)
{
    uint8_t interleaved[16];
    int i;

    for (i = 0; i < 8; i++)
    {
        interleaved[i * 2]     = ca->asic_seed[i];
        interleaved[i * 2 + 1] = ca->asic_seed[8 + i];
    }

    printf("--- Superframe ---\n");
    print_hex("Programme 0..7:",   prog, 8);
    print_hex("Target A (clear):", tgt_a, 8);
    print_hex("CW_A (encrypted):", cw_a, 8);
    print_hex("Target B (clear):", tgt_b, 8);
    print_hex("CW_B (encrypted):", cw_b, 8);
    print_hex("Full superframe:",  ca->superframe, D14_CA_SUPERFRAME_BYTES);
    print_hex("ASIC seed 0:",      &ca->asic_seed[0], 8);
    print_hex("ASIC seed 1:",      &ca->asic_seed[8], 8);
    print_hex("ASIC interleaved:", interleaved, 16);
    printf("  msg0=0x%02X cw_phase=%d\n", prog[0], ca->cw_phase);
}

void discret14_ca_init(discret14_ca_t *ca)
{
    memset(ca, 0, sizeof(*ca));
    ca->msg0_cycle = 1;
    ca->packets_until_toggle = 5;
    discret14_ca_build_superframe(ca, 1);
}

void discret14_ca_build_superframe(discret14_ca_t *ca, int log)
{
    uint8_t prog[8], key_a[8], key_b[8], cw_a[8], cw_b[8], msg0;
    const uint8_t *tgt_a, *tgt_b;
    int i;

    tgt_a = ca->cw_phase ? kValidationTargetB : kValidationTarget;
    tgt_b = ca->cw_phase ? kValidationTarget  : kValidationTargetB;

    msg0 = (uint8_t)(ca->msg0_cycle & 0x3F);
    if (ca->frame_phase5)
        msg0 |= 0x40;

    memcpy(prog, kProgramData8, 8);
    prog[0] = msg0;

    for (i = 0; i < 8; i++)
        key_a[i] = prog[i] ^ kEepromBroadcastKey[i];
    des_decrypt_block(tgt_a, key_a, cw_a);

    prog[0] ^= 0x40;
    for (i = 0; i < 8; i++)
        key_b[i] = prog[i] ^ kEepromBroadcastKey[i];
    des_decrypt_block(tgt_b, key_b, cw_b);
    prog[0] ^= 0x40;

    memcpy(&ca->superframe[0],  prog, 8);
    memcpy(&ca->superframe[8],  cw_a, 8);
    memcpy(&ca->superframe[16], cw_b, 8);

    if (!ca->ready || log)
        compute_asic_seeds(ca);

    if (!ca->ready)
        log = 1;

    if (log)
        log_superframe(ca, prog, tgt_a, cw_a, tgt_b, cw_b);

    ca->ready = 1;
}

void discret14_ca_advance_packet(discret14_ca_t *ca)
{
    if (++ca->msg0_cycle > 5)
        ca->msg0_cycle = 1;

    if (--ca->packets_until_toggle <= 0)
    {
        ca->packets_until_toggle = 5;
        ca->phase5_toggle_pending = 1;
    }

    discret14_ca_build_superframe(ca, 0);
}

int discret14_ca_toggle(discret14_ca_t *ca)
{
    ca->frame_phase5 ^= 0x20;
    ca->cw_phase ^= 1;
    ca->phase5_toggle_pending = 0;
    discret14_ca_build_superframe(ca, 1);
    return ca->cw_phase;
}

uint8_t discret14_ca_vbi_byte(discret14_ca_t *ca, int row, int col)
{
    if (!ca->ready)
        discret14_ca_build_superframe(ca, 0);

    switch (col)
    {
    case 1:
        return (uint8_t)(row | ca->frame_phase5);
    case 3:
        return ca->superframe[row];
    default:
        return 0x00;
    }
}