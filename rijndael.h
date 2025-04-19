/*
 * Rijndael (AES) Implementation Header
 * Author: Mingde Zhou
 * Student Number: D24128243
 * Description: This header file defines the interface for AES-128 block encryption/decryption
 *              using the Rijndael algorithm. It provides functions for encrypting and decrypting
 *              128-bit blocks of data with a 128-bit key.
 */

#ifndef RIJNDAEL_H
#define RIJNDAEL_H

#define BLOCK_ACCESS(block, row, col) (block[(row * 4) + col])
#define BLOCK_SIZE 16

/*
 * These should be the main encrypt/decrypt functions (i.e. the main
 * entry point to the library for programmes hoping to use it to
 * encrypt or decrypt data)
 */
unsigned char *aes_encrypt_block(unsigned char *plaintext, unsigned char *key);
unsigned char *aes_decrypt_block(unsigned char *ciphertext, unsigned char *key);

#endif
