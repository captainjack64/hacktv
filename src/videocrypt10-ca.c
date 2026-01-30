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

#include "videocrypt10-ca.h"
#include "videocrypt10-asic.h"
#include "videocrypt10-data.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>

static int card_load_rainbow_table(card10_t *card, const char *filename)
{
    if (!card) return 0;
    
    printf("Loading 64MB rainbow table from %s...\n", filename);
    
    FILE *f = fopen(filename, "rb");
    if (!f)
    {
        fprintf(stderr, "Warning: Could not open rainbow table file %s\n", filename);
        return 0;
    }
    
    /* Allocate table */
    card->rainbow_table = (uint8_t**)calloc(0x1000000, sizeof(uint8_t*));
    if (!card->rainbow_table)
    {
        fclose(f);
        fprintf(stderr, "Failed to allocate rainbow table memory\n");
        return 0;
    }
    
    /* Load signatures */
    uint8_t signature[4];
    int loaded = 0;
    for (int i = 0; i < 0x1000000; i++)
    {
        if (fread(signature, 1, 4, f) != 4) break;
        
        /* Skip empty entries */
        if (signature[0] == 0 && signature[1] == 0 && 
            signature[2] == 0 && signature[3] == 0)
        {
            continue;
        }
        
        card->rainbow_table[i] = (uint8_t*)malloc(4);
        if (card->rainbow_table[i])
        {
            memcpy(card->rainbow_table[i], signature, 4);
            loaded++;
        }
    }
    
    fclose(f);
    card->rainbow_table_loaded = 1;
    printf("Loaded %d signatures from 64MB rainbow table\n", loaded);
    
    return 1;
}

static void _kernel_init(kernel10_t *kernel)
{
    kernel->bptr5 = 0x00;
    kernel->bptr7 = 0x05;
    
    const uint8_t init_buf[12] = {
        0xC1, 0x16, 0x3C, 0x8D, 0xC0, 0x62, 
        0xB8, 0x33, 0xBE, 0xD8, 0x4B, 0xE1
    };
    memcpy(kernel->buf, init_buf, 12);
    
    kernel->b = 0x00;
}

static void _kernel_hash(kernel10_t *kernel, uint8_t byte)
{
    for (int x = 0; x < 2; x++)
    {
        if (x == 0)
        {
            kernel->bptr5 = (kernel->bptr5 + 1) % 5;
        }
        else
        {
            kernel->bptr7 = 5 + ((kernel->bptr7 - 4) % 7);
        }

        kernel->buf[kernel->bptr5] += byte;
        kernel->buf[kernel->bptr5] = _vc_rotate_left(kernel->buf[kernel->bptr5]);
        kernel->buf[kernel->bptr7] ^= kernel->buf[kernel->bptr5];
        kernel->buf[kernel->bptr7] = _vc_rotate_left(kernel->buf[kernel->bptr7]);
        
        uint8_t a = kernel->buf[kernel->bptr7] - kernel->b;
        kernel->b = _vc_rotate_left(a);
        byte = kernel10_lut[a] ^ byte;
        
        kernel->buf[kernel->bptr5] ^= secret_key_10[kernel->b & 0x0F];
        kernel->buf[kernel->bptr7] ^= secret_key_10[(kernel->b >> 4) + 0x10];
    }
}

static uint8_t _kernel_get_current_xor_byte(kernel10_t *kernel)
{
    return (kernel->buf[kernel->bptr5] - kernel->buf[kernel->bptr7]) ^ kernel->b;
}

static void _kernel_prepare_for_message_hash(kernel10_t *kernel, uint8_t *output)
{
    for (int i = 0; i < 8; i++)
    {
        uint8_t b = kernel->b & 0xF;
        uint8_t a = kernel->buf[kernel->bptr7];
        
        if (b == 0)
        {
            a = ((a << 4) + (a >> 4) + 0xF);
        }
        else
        {
            uint8_t top_nibble = a << 4;
            uint8_t bottom_nibble = a >> 4;
            uint8_t div = bottom_nibble / b;
            uint8_t mod = bottom_nibble % b;
            a = top_nibble | (div + mod);
        }
        
        a = (a << 2) | (a >> 6);
        _kernel_hash(kernel, a);
    }
    
    /* Output is buf[0:4] + buf[5:9] */
    memcpy(output, kernel->buf, 4);
    memcpy(output + 4, kernel->buf + 5, 4);
}


/* Get signature for message hash */
static inline const uint8_t* _get_signature_for_hash(uint32_t message_hash)
{
    static uint8_t sig_bytes[4];
    
    for (int i = 0; i < sizeof(SIGNATURE_TABLE); i++)
    {
        if (SIGNATURE_TABLE[i].message_hash == message_hash)
        {
            uint32_t sig = SIGNATURE_TABLE[i].signature;
            
            /* Check if signature exists */
            if (sig != 0)
            {
                /* Convert uint32 to bytes */
                sig_bytes[0] = (sig >> 24) & 0xFF;
                sig_bytes[1] = (sig >> 16) & 0xFF;
                sig_bytes[2] = (sig >> 8) & 0xFF;
                sig_bytes[3] = sig & 0xFF;
                return sig_bytes;
            }
            return 0;
        }
    }
    return 0;
}

static int _vc10_encrypt_74(card10_t *card, const uint8_t *input_message, int input_len, message_data_t *output) 
{
    if (input_len < 5 || input_len > 27) return ENCRYPT_FAIL;
    
    uint8_t try_message[32];
    memcpy(try_message, input_message, input_len);
    memset(&try_message[input_len], 0, 32 - input_len);
    
    /* Initialise ASIC */
    asic_reset(card->asic);
    uint8_t cmd_set_iterations[] = {0x31, 0x01};
    asic_send(card->asic, cmd_set_iterations, 2);
    uint8_t cmd_init_registers[] = {0x51, 0xA5, 0x61, 0x12, 0x71, 0x34, 0x81, 0x56, 0x91, 0x78};
    asic_send(card->asic, cmd_init_registers, 10);
    uint8_t cmd_enable_decoder[] = {0x21, 0x04};
    asic_send(card->asic, cmd_enable_decoder, 2);
    
    /* Process first 3 bytes */
    for (int i = 0; i < 3; i++)
    {
        asic_send_from_decoder(card->asic, &try_message[i], 1);
        uint8_t cmd[] = {0x01, try_message[i]};
        asic_send(card->asic, cmd, 2);
    }
    
    /* Process 4th byte and enable crypto */
    asic_send_from_decoder(card->asic, &try_message[3], 1);
    uint8_t cmd_enable_crypto[] = {0x21, 0x07};
    asic_send(card->asic, cmd_enable_crypto, 2);
    
    /* Initialise kernel */
    _kernel_init(&card->kernel);
    for (int i = 0; i < 5; i++)
    {
        _kernel_hash(&card->kernel, try_message[i]);
    }
    
    /* Copy header */
    memcpy(output->message, try_message, 5);
    memset(&output->message[5], 0, 22);
    
    /* Encrypt bytes 5-26 */
    for (int i = 5; i < 27; i++)
    {
        uint8_t previous_encrypted_byte = output->message[i - 1];
        
        asic_send_from_decoder(card->asic, &previous_encrypted_byte, 1);
        uint8_t cmd[] = {0x13};
        asic_send(card->asic, cmd, 1);
        uint8_t byte_from_asic = asic_receive_one(card->asic);
        
        uint8_t kernel_xor = _kernel_get_current_xor_byte(&card->kernel);
        uint8_t final_xor = kernel_xor + byte_from_asic;
        output->message[i] = try_message[i] ^ final_xor;
        
        _kernel_hash(&card->kernel, try_message[i]);
    }
    
    asic_send_from_decoder(card->asic, &output->message[26], 1);
    
    /* Calculate message hash */
    uint8_t message_hash_asic_input[8];
    _kernel_prepare_for_message_hash(&card->kernel, message_hash_asic_input);
    
    for (int i = 0; i < 4; i++)
    {
        uint8_t cmd[] = {0x01, message_hash_asic_input[i]};
        asic_send(card->asic, cmd, 2);
    }
    
    uint8_t message_hash_asic_output[4];
    for (int i = 0; i < 4; i++)
    {
        uint8_t cmd[] = {0x13};
        asic_send(card->asic, cmd, 1);
        message_hash_asic_output[i] = asic_receive_one(card->asic);
        
        uint8_t cmd2[] = {0x01, message_hash_asic_input[4 + i]};
        asic_send(card->asic, cmd2, 2);
    }
    
    output->hash[0] = message_hash_asic_output[0] ^ message_hash_asic_output[1];
    output->hash[1] = message_hash_asic_output[0] ^ message_hash_asic_output[2];
    output->hash[2] = message_hash_asic_output[1] ^ message_hash_asic_output[3];
    output->hash[3] = message_hash_asic_output[2] ^ message_hash_asic_output[3];
    output->has_hash = true;
    
    /* Get signature */
    uint32_t message_hash = ((uint32_t)output->hash[2] << 16) | 
                            ((uint32_t)output->hash[1] << 8) | 
                            output->hash[0];
    
    /* Check embedded 256-entry table  */
    const uint8_t *sig = _get_signature_for_hash(message_hash);
    
    /* Load external rainbow table if signature is not found */
    if (!sig && !card->rainbow_table_loaded)
    {
        fprintf(stderr, "Signature not in embedded table, loading 64MB rainbow table...\n");
        if (card_load_rainbow_table(card, "videocrypt10-data.bin"))
        {
            /* Try again with loaded table */
            if (message_hash < 0x1000000 && card->rainbow_table[message_hash])
            {
                sig = card->rainbow_table[message_hash];
            }
        }
    }
    /* Tier 2: If already loaded, check it */
    else if (!sig && card->rainbow_table_loaded && message_hash < 0x1000000)
    {
        if (card->rainbow_table[message_hash])
        {
            sig = card->rainbow_table[message_hash];
        }
    }
    
    if (!sig)
    {
        fprintf(stderr, "No signature found for hash: %02X %02X %02X %02X\n",
                output->hash[0], output->hash[1], output->hash[2], output->hash[3]);
        return ENCRYPT_FAIL;
    }
    
    memcpy(&output->message[27], sig, 4);

    /* Calculate CRC */
    output->message[31] = _vc_crc(output->message);
    
    /* Get answer */
    uint8_t answer_bytes[8];
    for (int i = 0; i < 8; i++)
    {
        uint8_t cmd[] = {0x13};
        asic_send(card->asic, cmd, 1);
        answer_bytes[i] = asic_receive_one(card->asic);
    }
    
    /* Invert answer */
    for (int i = 0; i < 7; i++)
    {
        answer_bytes[i] = ~answer_bytes[i];
    }
    answer_bytes[7] &= 0x7F;
    
    output->answer = 0;
    output->answer = _rev_cw(answer_bytes);
    output->has_answer = true;
    
    return ENCRYPT_OK;
}

card10_t *card_create()
{
    card10_t *card = (card10_t*)malloc(sizeof(card10_t));
    if (!card) return NULL;
    
    card->asic = &card->asic_instance;
    asic_reset(card->asic);
    _kernel_init(&card->kernel);
    card->rainbow_table = NULL;
    card->rainbow_table_loaded = 0;
    
    return card;
}

void card_destroy(card10_t *card)
{
    if (card)
    {
        /* Free rainbow table if loaded */
        if (card->rainbow_table)
        {
            for (int i = 0; i < 0x1000000; i++)
            {
                if (card->rainbow_table[i])
                {
                    free(card->rainbow_table[i]);
                }
            }
            free(card->rainbow_table);
        }
        free(card);
    }
}

void vc_seed_sky_p10(_vc_block_t *s, int mode)
{
    /* Static card instance - persists across calls to cache rainbow table */
    static card10_t *card = NULL;
    static int initialized = 0;
    int i;
    
    if (!initialized)
    {
        card = card_create();
        if (!card) 
        {
            fprintf(stderr, "Failed to create card\n");
            return;
        }
        initialized = 1;
    }

    uint8_t plaintext[32] = {
        0xF8, 0x86, 0x03, 0x23, 0x62, 0x40, 0x00, 0x98, 
        0xFE, 0xFE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    
    if(mode == VC_SKY10_PPV)
    {        
        /*
            This mode requires an active Sky 10 (0A) series card with PPV enabled to decode.

            The packet below sets up credits and events you wish to purchase. The 12h/34h bytes are
            the first program/credit pair. The 56h/78h bytes are the second program/credit pair.
            The six bytes 01h-06h are the six event numbers to enable.

            53 86 01 00 2D 
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 12
            34 56 78 01 02 03 04 05 06 00 00 00 00 

            For these CWs, the following needs to be sent to the 
            card to activate it for event 66.

            53 86 01 00 2D
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 42
            34 00 00 42 00 00 00 00 00 00 00 00 00 

            This packet forces the new Pay Per View
            data into the card without authorization.

            53 74 01 00 20
            C0 8F 40 00 00 2E AB F5 19 26 98 B5 46 77 BB E3
            32 12 ED 50 49 FF 57 B7 52 C0 0A 02 02 02 02 02
        */
        uint8_t ppv_plaintext[32] = {
            0xF8, 0x86, 0x9C, 0xF0, 0x42, 0x40, 0x00, 0x98,
            0xFE, 0xFE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };
        memcpy(plaintext, ppv_plaintext, 32);
    }

    plaintext[10] = rand();

    if(s->showecm)
    {
        fprintf(stderr, "\n\nVC1 ECM In (plain): ");
        for(i = 0; i < 32; i++) fprintf(stderr, "%02X ", plaintext[i]);
    }

    /* Encrypt the packet */
    message_data_t encrypted;
    if (!_vc10_encrypt_74(card, plaintext, 27, &encrypted)) 
    {
        fprintf(stderr, "Encryption failed\n");
        return;
    }
    
    /* Copy encrypted message to message_data */
    memcpy(s->message_data->messages[5], encrypted.message, 32);
    
    /* Copy answer (codeword) to message_data - now just uint64_t */
    s->message_data->answer = encrypted.answer;
}
