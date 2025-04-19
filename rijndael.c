/*
 * Rijndael (AES) Implementation 
 * Author: Mingde Zhou
 * Student Number: D24128243
 * Description: This file implements the AES-128 block cipher algorithm (Rijndael).
 *              It contains all the core operations including:
 *              - Key expansion
 *              - Encryption/Decryption rounds
 *              - SubBytes, ShiftRows, MixColumns operations
 *              - Their inverse operations for decryption
 */

#include <stdlib.h>
#include <stdio.h>  // For potential debugging output
#include <string.h> // For memory operations if needed

 #include "rijndael.h"
 

 // sbox 
static const unsigned char sbox[256] = {
  0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
  0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
  0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
  0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
  0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
  0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
  0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
  0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
  0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
  0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
  0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
  0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
  0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
  0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
  0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
  0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
  0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
  0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
  0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
  0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
  0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
  0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
  0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
  0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
  0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
  0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
  0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
  0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
  0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
  0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
  0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
  0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

// inverse sbox
static const unsigned char inv_sbox[256] = {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

static const unsigned char Rcon[11] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};


/*
 * sub bytes 
 */
void sub_bytes(unsigned char *block) {
  for (int i = 0; i < BLOCK_SIZE; i++) {
    block[i] = sbox[block[i]];
  }
}

void shift_rows(unsigned char *block) {
  // row 0 no shift
  // row 1 shift 1 byte to left
  unsigned char temp = BLOCK_ACCESS(block, 1, 0);
  BLOCK_ACCESS(block, 1, 0) = BLOCK_ACCESS(block, 1, 1);
  BLOCK_ACCESS(block, 1, 1) = BLOCK_ACCESS(block, 1, 2);
  BLOCK_ACCESS(block, 1, 2) = BLOCK_ACCESS(block, 1, 3);
  BLOCK_ACCESS(block, 1, 3) = temp;

  // row 2 shift 2 bytes to left
  temp = BLOCK_ACCESS(block, 2, 0);
  BLOCK_ACCESS(block, 2, 0) = BLOCK_ACCESS(block, 2, 2);
  BLOCK_ACCESS(block, 2, 2) = temp;
  temp = BLOCK_ACCESS(block, 2, 1);
  BLOCK_ACCESS(block, 2, 1) = BLOCK_ACCESS(block, 2, 3);
  BLOCK_ACCESS(block, 2, 3) = temp;

  // row 3 shift 3 bytes to left (equivalent to 1 byte to right)
  temp = BLOCK_ACCESS(block, 3, 3);
  BLOCK_ACCESS(block, 3, 3) = BLOCK_ACCESS(block, 3, 2);
  BLOCK_ACCESS(block, 3, 2) = BLOCK_ACCESS(block, 3, 1);
  BLOCK_ACCESS(block, 3, 1) = BLOCK_ACCESS(block, 3, 0);
  BLOCK_ACCESS(block, 3, 0) = temp;
}

/* Multiplication in GF(2^8) finite field */
unsigned char gmul(unsigned char a, unsigned char b) {
    unsigned char p = 0;
    unsigned char hi_bit_set;
    for (int i = 0; i < 8; i++) {
        if (b & 1) {
            p ^= a;
        }
        hi_bit_set = a & 0x80;
        a <<= 1;
        if (hi_bit_set) {
            a ^= 0x1b; /* x^8 + x^4 + x^3 + x + 1 */
        }
        b >>= 1;
    }
    return p;
}

void mix_columns(unsigned char *block) {
    unsigned char tmp[16];
    
    for (int i = 0; i < 4; i++) {
        tmp[i*4]   = (unsigned char)(gmul(0x02, block[i*4]) ^ gmul(0x03, block[i*4+1]) ^ block[i*4+2] ^ block[i*4+3]);
        tmp[i*4+1] = (unsigned char)(block[i*4] ^ gmul(0x02, block[i*4+1]) ^ gmul(0x03, block[i*4+2]) ^ block[i*4+3]);
        tmp[i*4+2] = (unsigned char)(block[i*4] ^ block[i*4+1] ^ gmul(0x02, block[i*4+2]) ^ gmul(0x03, block[i*4+3]));
        tmp[i*4+3] = (unsigned char)(gmul(0x03, block[i*4]) ^ block[i*4+1] ^ block[i*4+2] ^ gmul(0x02, block[i*4+3]));
    }
    
    for (int i = 0; i < 16; i++) {
        block[i] = tmp[i];
    }
}

/*
 * Operations used when decrypting a block
 */
void invert_sub_bytes(unsigned char *block) {
  for (int i = 0; i < BLOCK_SIZE; i++) {
    block[i] = inv_sbox[block[i]];
  }
}

void invert_shift_rows(unsigned char *block) {
  // Row 0: no shift
  // Row 1: rotate right by 1 byte
  unsigned char temp = BLOCK_ACCESS(block, 1, 3);
  BLOCK_ACCESS(block, 1, 3) = BLOCK_ACCESS(block, 1, 2);
  BLOCK_ACCESS(block, 1, 2) = BLOCK_ACCESS(block, 1, 1);
  BLOCK_ACCESS(block, 1, 1) = BLOCK_ACCESS(block, 1, 0);
  BLOCK_ACCESS(block, 1, 0) = temp;

  // Row 2: rotate right by 2 bytes
  temp = BLOCK_ACCESS(block, 2, 0);
  BLOCK_ACCESS(block, 2, 0) = BLOCK_ACCESS(block, 2, 2);
  BLOCK_ACCESS(block, 2, 2) = temp;
  temp = BLOCK_ACCESS(block, 2, 1);
  BLOCK_ACCESS(block, 2, 1) = BLOCK_ACCESS(block, 2, 3);
  BLOCK_ACCESS(block, 2, 3) = temp;

  // Row 3: rotate right by 3 bytes (equivalent to left by 1 byte)
  temp = BLOCK_ACCESS(block, 3, 0);
  BLOCK_ACCESS(block, 3, 0) = BLOCK_ACCESS(block, 3, 1);
  BLOCK_ACCESS(block, 3, 1) = BLOCK_ACCESS(block, 3, 2);
  BLOCK_ACCESS(block, 3, 2) = BLOCK_ACCESS(block, 3, 3);
  BLOCK_ACCESS(block, 3, 3) = temp;
}

void invert_mix_columns(unsigned char *block) {
    unsigned char tmp[16];
    
    for (int i = 0; i < 4; i++) {
        tmp[i*4]   = (unsigned char)(gmul(0x0e, block[i*4]) ^ gmul(0x0b, block[i*4+1]) ^ gmul(0x0d, block[i*4+2]) ^ gmul(0x09, block[i*4+3]));
        tmp[i*4+1] = (unsigned char)(gmul(0x09, block[i*4]) ^ gmul(0x0e, block[i*4+1]) ^ gmul(0x0b, block[i*4+2]) ^ gmul(0x0d, block[i*4+3]));
        tmp[i*4+2] = (unsigned char)(gmul(0x0d, block[i*4]) ^ gmul(0x09, block[i*4+1]) ^ gmul(0x0e, block[i*4+2]) ^ gmul(0x0b, block[i*4+3]));
        tmp[i*4+3] = (unsigned char)(gmul(0x0b, block[i*4]) ^ gmul(0x0d, block[i*4+1]) ^ gmul(0x09, block[i*4+2]) ^ gmul(0x0e, block[i*4+3]));
    }
    
    for (int i = 0; i < 16; i++) {
        block[i] = tmp[i];
    }
}

/*
 * This operation is shared between encryption and decryption
 */
void add_round_key(unsigned char *block, unsigned char *round_key) {
    for (int i = 0; i < BLOCK_SIZE; i++) {
        block[i] ^= round_key[i];
    }
}

/*
 * This function should expand the round key. Given an input,
 * which is a single 128-bit key, it should return a 176-byte
 * vector, containing the 11 round keys one after the other
 */
/* Helper: Substitute 4-byte word using S-box */
void SubWord(unsigned char *word) {
    for (int i = 0; i < 4; i++) {
        word[i] = sbox[word[i]];
    }
}

/* Helper: Rotate 4-byte word left by 1 byte */
void RotWord(unsigned char *word) {
    unsigned char tmp = word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = tmp;
}

/* Key expansion implementation */
unsigned char *expand_key(unsigned char *cipher_key) {
    unsigned char *expanded_key = malloc(176); // 11 rounds × 16 bytes
    int key_size = 16; // 128 bits = 16 bytes
    
    // Copy initial key
    for (int i = 0; i < key_size; i++) {
        expanded_key[i] = cipher_key[i];
    }
    
    // Generate subsequent round keys
    for (int i = key_size; i < 176; i += 4) {
        unsigned char temp[4];
        
        // Get previous 4 bytes
        for (int j = 0; j < 4; j++) {
            temp[j] = expanded_key[i + j - 4];
        }
        
        // Every 16 bytes (1 round key) perform core operation
        if (i % key_size == 0) {
            RotWord(temp);
            SubWord(temp);
            temp[0] ^= Rcon[i/key_size];
        }
        
        // Generate new 4 bytes
        for (int j = 0; j < 4; j++) {
            expanded_key[i + j] = expanded_key[i + j - key_size] ^ temp[j];
        }
    }
    
    return expanded_key;
}

/*
 * The implementations of the functions declared in the
 * header file should go here
 */
unsigned char *aes_encrypt_block(unsigned char *plaintext, unsigned char *key) {
    unsigned char *output = (unsigned char *)malloc(BLOCK_SIZE);
    unsigned char *expanded_key = expand_key(key);
    unsigned char block[BLOCK_SIZE];
    
    // Copy plaintext to working block
    for (int i = 0; i < BLOCK_SIZE; i++) {
        block[i] = plaintext[i];
    }
    
    // Initial round key addition
    add_round_key(block, expanded_key);
    
    // 9 standard rounds
    for (int round = 1; round <= 9; round++) {
        sub_bytes(block);
        shift_rows(block);
        mix_columns(block);
        add_round_key(block, expanded_key + (round * BLOCK_SIZE));
    }
    
    // Final round (no mix columns)
    sub_bytes(block);
    shift_rows(block);
    add_round_key(block, expanded_key + (10 * BLOCK_SIZE));
    
    // Copy result to output
    for (int i = 0; i < BLOCK_SIZE; i++) {
        output[i] = block[i];
    }
    
    free(expanded_key);
    return output;
}

unsigned char *aes_decrypt_block(unsigned char *ciphertext, unsigned char *key) {
    unsigned char *output = (unsigned char *)malloc(BLOCK_SIZE);
    unsigned char *expanded_key = expand_key(key);
    unsigned char block[BLOCK_SIZE];
    
    // Copy ciphertext to working block
    for (int i = 0; i < BLOCK_SIZE; i++) {
        block[i] = ciphertext[i];
    }
    
    // Initial round key addition (using last round key)
    add_round_key(block, expanded_key + (10 * BLOCK_SIZE));
    
    // 9 standard rounds
    for (int round = 9; round >= 1; round--) {
        invert_shift_rows(block);
        invert_sub_bytes(block);
        add_round_key(block, expanded_key + (round * BLOCK_SIZE));
        invert_mix_columns(block);
    }
    
    // Final round (no inverse mix columns)
    invert_shift_rows(block);
    invert_sub_bytes(block);
    add_round_key(block, expanded_key);  // Use initial round key
    
    // Copy result to output
    for (int i = 0; i < BLOCK_SIZE; i++) {
        output[i] = block[i];
    }
    
    free(expanded_key);
    return output;
}
