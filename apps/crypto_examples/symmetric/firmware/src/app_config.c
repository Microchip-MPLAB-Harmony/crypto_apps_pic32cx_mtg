/*******************************************************************************
  MPLAB Harmony Application Source File

  Company:
    Microchip Technology Inc.

  File Name:
    app_config.c

  Summary:
    Provides test vectors and functions for cryptographic tests.

  Description:
    This file contains test vectors and functions to test symmetric
    cryptographic functionalities.
 *******************************************************************************/

/* ************************************************************************** */
/* ************************************************************************** */
/* Section: Included Files                                                    */
/* ************************************************************************** */
/* ************************************************************************** */

#include "app_config.h"

/* ************************************************************************** */
/* ************************************************************************** */
/* Section: File Scope or Global Data                                         */
/* ************************************************************************** */
/* ************************************************************************** */

bool isKeyWrap = false;

uint8_t symData_AES_128[64];

uint8_t symData_AES_192[64];

uint8_t symData_AES_256[64];

// *****************************************************************************
/* NIST Test Vectors

  Summary:
    Following data is obtained from NIST for cryptographic tests.

  Description:
    https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers#AES
*/

uint8_t Plaintext_AES_ECB[64] = {
    0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96,
    0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
    0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C,
    0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51,
    0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11,
    0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF,
    0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17,
    0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10
};

uint8_t Key_AES_ECB128[16] = {
    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
    0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
};

uint8_t Ciphertext_AES_ECB128[64] = {
    0x3A, 0xD7, 0x7B, 0xB4, 0x0D, 0x7A, 0x36, 0x60,
    0xA8, 0x9E, 0xCA, 0xF3, 0x24, 0x66, 0xEF, 0x97,
    0xF5, 0xD3, 0xD5, 0x85, 0x03, 0xB9, 0x69, 0x9D,
    0xE7, 0x85, 0x89, 0x5A, 0x96, 0xFD, 0xBA, 0xAF,
    0x43, 0xB1, 0xCD, 0x7F, 0x59, 0x8E, 0xCE, 0x23,
    0x88, 0x1B, 0x00, 0xE3, 0xED, 0x03, 0x06, 0x88,
    0x7B, 0x0C, 0x78, 0x5E, 0x27, 0xE8, 0xAD, 0x3F,
    0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5D, 0xD4
};

uint8_t Key_AES_ECB192[24] = {
    0x8E, 0x73, 0xB0, 0xF7, 0xDA, 0x0E, 0x64, 0x52,
    0xC8, 0x10, 0xF3, 0x2B, 0x80, 0x90, 0x79, 0xE5,
    0x62, 0xF8, 0xEA, 0xD2, 0x52, 0x2C, 0x6B, 0x7B
};

uint8_t Ciphertext_AES_ECB192[64] = {
    0xBD, 0x33, 0x4F, 0x1D, 0x6E, 0x45, 0xF2, 0x5F,
    0xF7, 0x12, 0xA2, 0x14, 0x57, 0x1F, 0xA5, 0xCC,
    0x97, 0x41, 0x04, 0x84, 0x6D, 0x0A, 0xD3, 0xAD,
    0x77, 0x34, 0xEC, 0xB3, 0xEC, 0xEE, 0x4E, 0xEF,
    0xEF, 0x7A, 0xFD, 0x22, 0x70, 0xE2, 0xE6, 0x0A,
    0xDC, 0xE0, 0xBA, 0x2F, 0xAC, 0xE6, 0x44, 0x4E,
    0x9A, 0x4B, 0x41, 0xBA, 0x73, 0x8D, 0x6C, 0x72,
    0xFB, 0x16, 0x69, 0x16, 0x03, 0xC1, 0x8E, 0x0E
};

uint8_t Key_AES_ECB256[32] = {
    0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE,
    0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81,
    0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7,
    0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4
};

uint8_t Ciphertext_AES_ECB256[64] = {
    0xF3, 0xEE, 0xD1, 0xBD, 0xB5, 0xD2, 0xA0, 0x3C,
    0x06, 0x4B, 0x5A, 0x7E, 0x3D, 0xB1, 0x81, 0xF8,
    0x59, 0x1C, 0xCB, 0x10, 0xD4, 0x10, 0xED, 0x26,
    0xDC, 0x5B, 0xA7, 0x4A, 0x31, 0x36, 0x28, 0x70,
    0xB6, 0xED, 0x21, 0xB9, 0x9C, 0xA6, 0xF4, 0xF9,
    0xF1, 0x53, 0xE7, 0xB1, 0xBE, 0xAF, 0xED, 0x1D,
    0x23, 0x30, 0x4B, 0x7A, 0x39, 0xF9, 0xF3, 0xFF,
    0x06, 0x7D, 0x8D, 0x8F, 0x9E, 0x24, 0xEC, 0xC7
};

uint8_t AES_CBC_IV[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

uint8_t Plaintext_AES_CBC[64] = {
    0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96,
    0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
    0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C,
    0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51,
    0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11,
    0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF,
    0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17,
    0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10
};

uint8_t Key_AES_CBC128[16] = {
    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
    0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
};

uint8_t Ciphertext_AES_CBC128[64] = {
    0x76, 0x49, 0xAB, 0xAC, 0x81, 0x19, 0xB2, 0x46,
    0xCE, 0xE9, 0x8E, 0x9B, 0x12, 0xE9, 0x19, 0x7D,
    0x50, 0x86, 0xCB, 0x9B, 0x50, 0x72, 0x19, 0xEE,
    0x95, 0xDB, 0x11, 0x3A, 0x91, 0x76, 0x78, 0xB2,
    0x73, 0xBE, 0xD6, 0xB8, 0xE3, 0xC1, 0x74, 0x3B,
    0x71, 0x16, 0xE6, 0x9E, 0x22, 0x22, 0x95, 0x16,
    0x3F, 0xF1, 0xCA, 0xA1, 0x68, 0x1F, 0xAC, 0x09,
    0x12, 0x0E, 0xCA, 0x30, 0x75, 0x86, 0xE1, 0xA7
};

uint8_t Key_AES_CBC192[24] = {
    0x8E, 0x73, 0xB0, 0xF7, 0xDA, 0x0E, 0x64, 0x52,
    0xC8, 0x10, 0xF3, 0x2B, 0x80, 0x90, 0x79, 0xE5,
    0x62, 0xF8, 0xEA, 0xD2, 0x52, 0x2C, 0x6B, 0x7B
};

uint8_t Ciphertext_AES_CBC192[64] = {
    0x4F, 0x02, 0x1D, 0xB2, 0x43, 0xBC, 0x63, 0x3D,
    0x71, 0x78, 0x18, 0x3A, 0x9F, 0xA0, 0x71, 0xE8,
    0xB4, 0xD9, 0xAD, 0xA9, 0xAD, 0x7D, 0xED, 0xF4,
    0xE5, 0xE7, 0x38, 0x76, 0x3F, 0x69, 0x14, 0x5A,
    0x57, 0x1B, 0x24, 0x20, 0x12, 0xFB, 0x7A, 0xE0,
    0x7F, 0xA9, 0xBA, 0xAC, 0x3D, 0xF1, 0x02, 0xE0,
    0x08, 0xB0, 0xE2, 0x79, 0x88, 0x59, 0x88, 0x81,
    0xD9, 0x20, 0xA9, 0xE6, 0x4F, 0x56, 0x15, 0xCD
};

uint8_t Key_AES_CBC256[32] = {
    0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE,
    0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81,
    0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7,
    0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4
};

uint8_t Ciphertext_AES_CBC256[64] = {
    0xF5, 0x8C, 0x4C, 0x04, 0xD6, 0xE5, 0xF1, 0xBA,
    0x77, 0x9E, 0xAB, 0xFB, 0x5F, 0x7B, 0xFB, 0xD6,
    0x9C, 0xFC, 0x4E, 0x96, 0x7E, 0xDB, 0x80, 0x8D,
    0x67, 0x9F, 0x77, 0x7B, 0xC6, 0x70, 0x2C, 0x7D,
    0x39, 0xF2, 0x33, 0x69, 0xA9, 0xD9, 0xBA, 0xCF,
    0xA5, 0x30, 0xE2, 0x63, 0x04, 0x23, 0x14, 0x61,
    0xB2, 0xEB, 0x05, 0xE2, 0xC3, 0x9B, 0xE9, 0xFC,
    0xDA, 0x6C, 0x19, 0x07, 0x8C, 0x6A, 0x9D, 0x1B
};

uint8_t AES_CTR_NONCE[16] = {
    0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7,
    0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF
};

uint8_t Plaintext_AES_CTR[64] = {
    0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96,
    0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
    0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C,
    0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51,
    0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11,
    0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF,
    0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17,
    0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10
};

uint8_t Key_AES_CTR128[16] = {
    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
    0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
};

uint8_t Ciphertext_AES_CTR128[64] = {
    0x87, 0x4D, 0x61, 0x91, 0xB6, 0x20, 0xE3, 0x26,
    0x1B, 0xEF, 0x68, 0x64, 0x99, 0x0D, 0xB6, 0xCE,
    0x98, 0x06, 0xF6, 0x6B, 0x79, 0x70, 0xFD, 0xFF,
    0x86, 0x17, 0x18, 0x7B, 0xB9, 0xFF, 0xFD, 0xFF,
    0x5A, 0xE4, 0xDF, 0x3E, 0xDB, 0xD5, 0xD3, 0x5E,
    0x5B, 0x4F, 0x09, 0x02, 0x0D, 0xB0, 0x3E, 0xAB,
    0x1E, 0x03, 0x1D, 0xDA, 0x2F, 0xBE, 0x03, 0xD1,
    0x79, 0x21, 0x70, 0xA0, 0xF3, 0x00, 0x9C, 0xEE
};

uint8_t Key_AES_CTR192[24] = {
    0x8E, 0x73, 0xB0, 0xF7, 0xDA, 0x0E, 0x64, 0x52,
    0xC8, 0x10, 0xF3, 0x2B, 0x80, 0x90, 0x79, 0xE5,
    0x62, 0xF8, 0xEA, 0xD2, 0x52, 0x2C, 0x6B, 0x7B
};

uint8_t Ciphertext_AES_CTR192[64] = {
    0x1A, 0xBC, 0x93, 0x24, 0x17, 0x52, 0x1C, 0xA2,
    0x4F, 0x2B, 0x04, 0x59, 0xFE, 0x7E, 0x6E, 0x0B,
    0x09, 0x03, 0x39, 0xEC, 0x0A, 0xA6, 0xFA, 0xEF,
    0xD5, 0xCC, 0xC2, 0xC6, 0xF4, 0xCE, 0x8E, 0x94,
    0x1E, 0x36, 0xB2, 0x6B, 0xD1, 0xEB, 0xC6, 0x70,
    0xD1, 0xBD, 0x1D, 0x66, 0x56, 0x20, 0xAB, 0xF7,
    0x4F, 0x78, 0xA7, 0xF6, 0xD2, 0x98, 0x09, 0x58,
    0x5A, 0x97, 0xDA, 0xEC, 0x58, 0xC6, 0xB0, 0x50
};

uint8_t Key_AES_CTR256[32] = {
    0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE,
    0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81,
    0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7,
    0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4
};

uint8_t Ciphertext_AES_CTR256[64] = {
    0x60, 0x1E, 0xC3, 0x13, 0x77, 0x57, 0x89, 0xA5,
    0xB7, 0xA7, 0xF5, 0x04, 0xBB, 0xF3, 0xD2, 0x28,
    0xF4, 0x43, 0xE3, 0xCA, 0x4D, 0x62, 0xB5, 0x9A,
    0xCA, 0x84, 0xE9, 0x90, 0xCA, 0xCA, 0xF5, 0xC5,
    0x2B, 0x09, 0x30, 0xDA, 0xA2, 0x3D, 0xE9, 0x4C,
    0xE8, 0x70, 0x17, 0xBA, 0x2D, 0x84, 0x98, 0x8D,
    0xDF, 0xC9, 0xC5, 0x8D, 0xB6, 0x7A, 0xAD, 0xA6,
    0x13, 0xC2, 0xDD, 0x08, 0x45, 0x79, 0x41, 0xA6
};

uint8_t Plaintext_AES_KW128_Encrypt[16] = {
    0x42, 0x13, 0x6D, 0x3C, 0x38, 0x4A, 0x3E, 0xEA,
    0xC9, 0x5A, 0x06, 0x6F, 0xD2, 0x8F, 0xED, 0x3F
};

uint8_t Key_AES_KW128_Encrypt[16] = {
    0x75, 0x75, 0xDA, 0x3A, 0x93, 0x60, 0x7C, 0xC2,
    0xBF, 0xD8, 0xCE, 0xC7, 0xAA, 0xDF, 0xD9, 0xA6
};

uint8_t Ciphertext_AES_KW128_Encrypt[24] = {
    0x03, 0x1F, 0x6B, 0xD7, 0xE6, 0x1E, 0x64, 0x3D,
    0xF6, 0x85, 0x94, 0x81, 0x6F, 0x64, 0xCA, 0xA3,
    0xF5, 0x6F, 0xAB, 0xEA, 0x25, 0x48, 0xF5, 0xFB
};

uint8_t Plaintext_AES_KW128_Decrypt[16] = {
    0x9C, 0x4E, 0x67, 0x52, 0x77, 0xA3, 0xBD, 0xC3,
    0xA0, 0x71, 0x04, 0x8B, 0x32, 0x7A, 0x01, 0x1E
};

uint8_t Key_AES_KW128_Decrypt[16] = {
    0x1C, 0xBD, 0x2F, 0x79, 0x07, 0x8B, 0x95, 0x00,
    0xFA, 0xE2, 0x36, 0x96, 0x31, 0x19, 0x53, 0xEB
};

uint8_t Ciphertext_AES_KW128_Decrypt[24] = {
    0xEC, 0xBD, 0x7A, 0x17, 0xC5, 0xDA, 0x3C, 0xFD,
    0xFE, 0x22, 0x25, 0xD2, 0xBF, 0x9A, 0xC7, 0xAB,
    0xCE, 0x78, 0xC2, 0xB2, 0xAE, 0xFA, 0x6E, 0xAC
};

uint8_t Plaintext_AES_KW192_Encrypt[16] = {
    0x84, 0x84, 0xE4, 0x14, 0xB0, 0x91, 0xF8, 0xA9,
    0xF7, 0x2C, 0xFD, 0x13, 0x08, 0x7D, 0xDE, 0xC1
};

uint8_t Key_AES_KW192_Encrypt[24] = {
    0xA6, 0xA3, 0xF6, 0xD5, 0x09, 0x81, 0x18, 0x59,
    0x23, 0x8F, 0xC5, 0x69, 0xB5, 0x66, 0x46, 0x05,
    0xF7, 0xA7, 0x3C, 0x47, 0x5A, 0x69, 0x1A, 0x8F
};

uint8_t Ciphertext_AES_KW192_Encrypt[24] = {
    0x57, 0xD7, 0xA4, 0xB4, 0xE8, 0x5F, 0xFD, 0xCB,
    0x77, 0x88, 0xB9, 0xB6, 0x66, 0xCB, 0x63, 0x30,
    0x3D, 0xD2, 0xC5, 0xD0, 0xF1, 0x1B, 0x1B, 0xBB
};

uint8_t Plaintext_AES_KW192_Decrypt[16] = {
    0x94, 0xB8, 0x27, 0x67, 0x43, 0x18, 0x4D, 0x08,
    0x69, 0x62, 0xCE, 0x6C, 0x4E, 0x63, 0xBD, 0x53
};

uint8_t Key_AES_KW192_Decrypt[24] = {
    0x26, 0x04, 0x54, 0x02, 0x54, 0x8E, 0xE6, 0x19,
    0x6F, 0xC0, 0xA6, 0x02, 0x08, 0xFF, 0xDE, 0x21,
    0x13, 0x7D, 0xDB, 0x1C, 0x6C, 0x5D, 0x2B, 0xA0
};

uint8_t Ciphertext_AES_KW192_Decrypt[24] = {
    0xFC, 0xD5, 0x5C, 0x2C, 0x60, 0xFF, 0x6D, 0xE1,
    0x9E, 0xC3, 0xE6, 0xB1, 0x34, 0x90, 0xC2, 0x82,
    0x1F, 0x0C, 0x56, 0x5A, 0xBF, 0x10, 0xBE, 0x2D
};

uint8_t Plaintext_AES_KW256_Encrypt[16] = {
    0x73, 0xD3, 0x30, 0x60, 0xB5, 0xF9, 0xF2, 0xEB,
    0x57, 0x85, 0xC0, 0x70, 0x3D, 0xDF, 0xA7, 0x04
};

uint8_t Key_AES_KW256_Encrypt[32] = {
    0xF5, 0x97, 0x82, 0xF1, 0xDC, 0xEB, 0x05, 0x44,
    0xA8, 0xDA, 0x06, 0xB3, 0x49, 0x69, 0xB9, 0x21,
    0x2B, 0x55, 0xCE, 0x6D, 0xCB, 0xDD, 0x09, 0x75,
    0xA3, 0x3F, 0x4B, 0x3F, 0x88, 0xB5, 0x38, 0xDA
};

uint8_t Ciphertext_AES_KW256_Encrypt[24] = {
    0x2E, 0x63, 0x94, 0x6E, 0xA3, 0xC0, 0x90, 0x90,
    0x2F, 0xA1, 0x55, 0x83, 0x75, 0xFD, 0xB2, 0x90,
    0x77, 0x42, 0xAC, 0x74, 0xE3, 0x94, 0x03, 0xFC
};

uint8_t Plaintext_AES_KW256_Decrypt[16] = {
    0x0A, 0x25, 0x6B, 0xA7, 0x5C, 0xFA, 0x03, 0xAA,
    0xA0, 0x2B, 0xA9, 0x42, 0x03, 0xF1, 0x5B, 0xAA
};

uint8_t Key_AES_KW256_Decrypt[32] = {
    0x80, 0xAA, 0x99, 0x73, 0x27, 0xA4, 0x80, 0x6B,
    0x6A, 0x7A, 0x41, 0xA5, 0x2B, 0x86, 0xC3, 0x71,
    0x03, 0x86, 0xF9, 0x32, 0x78, 0x6E, 0xF7, 0x96,
    0x76, 0xFA, 0xFB, 0x90, 0xB8, 0x26, 0x3C, 0x5F
};

uint8_t Ciphertext_AES_KW256_Decrypt[24] = {
    0x42, 0x3C, 0x96, 0x0D, 0x8A, 0x2A, 0xC4, 0xC1,
    0xD3, 0x3D, 0x3D, 0x97, 0x7B, 0xF0, 0xA9, 0x15,
    0x59, 0xF9, 0x9C, 0x8A, 0xCD, 0x29, 0x3D, 0x43
};

/* ************************************************************************** */
/* ************************************************************************** */
// Section: Interface Functions                                               */
/* ************************************************************************** */
/* ************************************************************************** */

/*******************************************************************************
  Function:
    void AES_ECB_Test (void)

  Remarks:
    See prototype in app_config.h.
 */

void AES_ECB_Test (crypto_HandlerType_E cryptoHandler)
{
    st_Crypto_Sym_BlockCtx  Sym_Block_Ctx;

    AES ecb128 = {
        .Sym_Block_Ctx      = Sym_Block_Ctx,
        .handler            = cryptoHandler,
        .aesMode            = CRYPTO_SYM_OPMODE_ECB,
        .iv                 = NULL,
        .key                = Key_AES_ECB128,
        .keySize            = sizeof(Key_AES_ECB128),
        .pt                 = Plaintext_AES_ECB,
        .ptSize             = sizeof(Plaintext_AES_ECB),
        .symData            = symData_AES_128,
        .symDataSize        = sizeof(symData_AES_128),
        .cipher             = Ciphertext_AES_ECB128,
        .cipherSize         = sizeof(Ciphertext_AES_ECB128)
    };
    
    printf("\r\nAES-ECB 128 Init->Cipher Encrypt\r\n");
    MultiStepEncrypt(&ecb128);

    printf("\r\nAES-ECB 128 Init->Cipher Decrypt\r\n");
    MultiStepDecrypt(&ecb128);

    printf("\r\nAES-ECB 128 Direct Encrypt\r\n");
    SingleStepEncrypt(&ecb128);
    
    printf("\r\nAES-ECB 128 Direct Decrypt\r\n");
    SingleStepDecrypt(&ecb128);

    AES ecb192 = {
        .Sym_Block_Ctx      = Sym_Block_Ctx,
        .handler            = cryptoHandler,
        .aesMode            = CRYPTO_SYM_OPMODE_ECB,
        .iv                 = NULL,
        .key                = Key_AES_ECB192,
        .keySize            = sizeof(Key_AES_ECB192),
        .pt                 = Plaintext_AES_ECB,
        .ptSize             = sizeof(Plaintext_AES_ECB),
        .symData            = symData_AES_192,
        .symDataSize        = sizeof(symData_AES_192),
        .cipher             = Ciphertext_AES_ECB192,
        .cipherSize         = sizeof(Ciphertext_AES_ECB192)
    };
    
    printf("\r\nAES-ECB 192 Init->Cipher Encrypt\r\n");
    MultiStepEncrypt(&ecb192);

    printf("\r\nAES-ECB 192 Init->Cipher Decrypt\r\n");
    MultiStepDecrypt(&ecb192);

    printf("\r\nAES-ECB 192 Direct Encrypt\r\n");
    SingleStepEncrypt(&ecb192);
    
    printf("\r\nAES-ECB 192 Direct Decrypt\r\n");
    SingleStepDecrypt(&ecb192);

    AES ecb256 = {
        .Sym_Block_Ctx      = Sym_Block_Ctx,
        .handler            = cryptoHandler,
        .aesMode            = CRYPTO_SYM_OPMODE_ECB,
        .iv                 = NULL,
        .key                = Key_AES_ECB256,
        .keySize            = sizeof(Key_AES_ECB256),
        .pt                 = Plaintext_AES_ECB,
        .ptSize             = sizeof(Plaintext_AES_ECB),
        .symData            = symData_AES_256,
        .symDataSize        = sizeof(symData_AES_256),
        .cipher             = Ciphertext_AES_ECB256,
        .cipherSize         = sizeof(Ciphertext_AES_ECB256)
    };
    
    printf("\r\nAES-ECB 256 Init->Cipher Encrypt\r\n");
    MultiStepEncrypt(&ecb256);

    printf("\r\nAES-ECB 256 Init->Cipher Decrypt\r\n");
    MultiStepDecrypt(&ecb256);

    printf("\r\nAES-ECB 256 Direct Encrypt\r\n");
    SingleStepEncrypt(&ecb256);
    
    printf("\r\nAES-ECB 256 Direct Decrypt\r\n");
    SingleStepDecrypt(&ecb256);
}

/*******************************************************************************
  Function:
    void AES_CBC_Test (void)

  Remarks:
    See prototype in app_config.h.
 */

void AES_CBC_Test (crypto_HandlerType_E cryptoHandler)
{
    st_Crypto_Sym_BlockCtx  Sym_Block_Ctx;
    
    AES cbc128 = {
        .Sym_Block_Ctx      = Sym_Block_Ctx,
        .handler            = cryptoHandler,
        .aesMode            = CRYPTO_SYM_OPMODE_CBC,
        .iv                 = AES_CBC_IV,
        .key                = Key_AES_CBC128,
        .keySize            = sizeof(Key_AES_CBC128),
        .pt                 = Plaintext_AES_CBC,
        .ptSize             = sizeof(Plaintext_AES_CBC),
        .symData            = symData_AES_128,
        .symDataSize        = sizeof(symData_AES_128),
        .cipher             = Ciphertext_AES_CBC128,
        .cipherSize         = sizeof(Ciphertext_AES_CBC128)
    };

    printf("\r\nAES-CBC 128 Init->Cipher Encrypt\r\n");
    MultiStepEncrypt(&cbc128);

    printf("\r\nAES-CBC 128 Init->Cipher Decrypt\r\n");
    MultiStepDecrypt(&cbc128);

    printf("\r\nAES-CBC 128 Direct Encrypt\r\n");
    SingleStepEncrypt(&cbc128);

    printf("\r\nAES-CBC 128 Direct Decrypt\r\n");
    SingleStepDecrypt(&cbc128);

    AES cbc192 = {
        .Sym_Block_Ctx      = Sym_Block_Ctx,
        .handler            = cryptoHandler,
        .aesMode            = CRYPTO_SYM_OPMODE_CBC,
        .iv                 = AES_CBC_IV,
        .key                = Key_AES_CBC192,
        .keySize            = sizeof(Key_AES_CBC192),
        .pt                 = Plaintext_AES_CBC,
        .ptSize             = sizeof(Plaintext_AES_CBC),
        .symData            = symData_AES_192,
        .symDataSize        = sizeof(symData_AES_192),
        .cipher             = Ciphertext_AES_CBC192,
        .cipherSize         = sizeof(Ciphertext_AES_CBC192)
    };

    printf("\r\nAES-CBC 192 Init->Cipher Encrypt\r\n");
    MultiStepEncrypt(&cbc192);

    printf("\r\nAES-CBC 192 Init->Cipher Decrypt\r\n");
    MultiStepDecrypt(&cbc192);

    printf("\r\nAES-CBC 192 Direct Encrypt\r\n");
    SingleStepEncrypt(&cbc192);

    printf("\r\nAES-CBC 192 Direct Decrypt\r\n");
    SingleStepDecrypt(&cbc192);

    AES cbc256 = {
        .Sym_Block_Ctx      = Sym_Block_Ctx,
        .handler            = cryptoHandler,
        .aesMode            = CRYPTO_SYM_OPMODE_CBC,
        .iv                 = AES_CBC_IV,
        .key                = Key_AES_CBC256,
        .keySize            = sizeof(Key_AES_CBC256),
        .pt                 = Plaintext_AES_CBC,
        .ptSize             = sizeof(Plaintext_AES_CBC),
        .symData            = symData_AES_256,
        .symDataSize        = sizeof(symData_AES_256),
        .cipher             = Ciphertext_AES_CBC256,
        .cipherSize         = sizeof(Ciphertext_AES_CBC256)
    };

    printf("\r\nAES-CBC 256 Init->Cipher Encrypt\r\n");
    MultiStepEncrypt(&cbc256);

    printf("\r\nAES-CBC 256 Init->Cipher Decrypt\r\n");
    MultiStepDecrypt(&cbc256);

    printf("\r\nAES-CBC 256 Direct Encrypt\r\n");
    SingleStepEncrypt(&cbc256);

    printf("\r\nAES-CBC 256 Direct Decrypt\r\n");
    SingleStepDecrypt(&cbc256);
}

/*******************************************************************************
  Function:
    void AES_CTR_Test (void)

  Remarks:
    See prototype in app_config.h.
 */

void AES_CTR_Test (crypto_HandlerType_E cryptoHandler)
{    
    st_Crypto_Sym_BlockCtx  Sym_Block_Ctx;
    
    AES CTR128 = {
        .Sym_Block_Ctx      = Sym_Block_Ctx,
        .handler            = cryptoHandler,
        .aesMode            = CRYPTO_SYM_OPMODE_CTR,
        .iv                 = AES_CTR_NONCE,
        .key                = Key_AES_CTR128,
        .keySize            = sizeof(Key_AES_CTR128),
        .pt                 = Plaintext_AES_CTR,
        .ptSize             = sizeof(Plaintext_AES_CTR),
        .symData            = symData_AES_128,
        .symDataSize        = sizeof(symData_AES_128),
        .cipher             = Ciphertext_AES_CTR128,
        .cipherSize         = sizeof(Ciphertext_AES_CTR128)        
    };

    printf("\r\nAES-CTR 128 Init->Cipher Encrypt\r\n");
    MultiStepEncrypt(&CTR128);

    printf("\r\nAES-CTR 128 Init->Cipher Decrypt\r\n");
    MultiStepDecrypt(&CTR128);

    printf("\r\nAES-CTR 128 Direct Encrypt\r\n");
    SingleStepEncrypt(&CTR128);

    printf("\r\nAES-CTR 128 Direct Decrypt\r\n");
    SingleStepDecrypt(&CTR128);

    AES CTR192 = {
        .Sym_Block_Ctx      = Sym_Block_Ctx,
        .handler            = cryptoHandler,
        .aesMode            = CRYPTO_SYM_OPMODE_CTR,
        .iv                 = AES_CTR_NONCE,
        .key                = Key_AES_CTR192,
        .keySize            = sizeof(Key_AES_CTR192),
        .pt                 = Plaintext_AES_CTR,
        .ptSize             = sizeof(Plaintext_AES_CTR),
        .symData            = symData_AES_192,
        .symDataSize        = sizeof(symData_AES_192),
        .cipher             = Ciphertext_AES_CTR192,
        .cipherSize         = sizeof(Ciphertext_AES_CTR192)        
    };

    printf("\r\nAES-CTR 192 Init->Cipher Encrypt\r\n");
    MultiStepEncrypt(&CTR192);

    printf("\r\nAES-CTR 192 Init->Cipher Decrypt\r\n");
    MultiStepDecrypt(&CTR192);

    printf("\r\nAES-CTR 192 Direct Encrypt\r\n");
    SingleStepEncrypt(&CTR192);

    printf("\r\nAES-CTR 192 Direct Decrypt\r\n");
    SingleStepDecrypt(&CTR192);

    AES CTR256 = {
        .Sym_Block_Ctx      = Sym_Block_Ctx,
        .handler            = cryptoHandler,
        .aesMode            = CRYPTO_SYM_OPMODE_CTR,
        .iv                 = AES_CTR_NONCE,
        .key                = Key_AES_CTR256,
        .keySize            = sizeof(Key_AES_CTR256),
        .pt                 = Plaintext_AES_CTR,
        .ptSize             = sizeof(Plaintext_AES_CTR),
        .symData            = symData_AES_256,
        .symDataSize        = sizeof(symData_AES_256),
        .cipher         = Ciphertext_AES_CTR256,
        .cipherSize     = sizeof(Ciphertext_AES_CTR256)        
    };

    printf("\r\nAES-CTR 256 Init->Cipher Encrypt\r\n");
    MultiStepEncrypt(&CTR256);

    printf("\r\nAES-CTR 256 Init->Cipher Decrypt\r\n");
    MultiStepDecrypt(&CTR256);

    printf("\r\nAES-CTR 256 Direct Encrypt\r\n");
    SingleStepEncrypt(&CTR256);

    printf("\r\nAES-CTR 256 Direct Decrypt\r\n");
    SingleStepDecrypt(&CTR256);
}

/*******************************************************************************
  Function:
    void AES_KeyWrap_Test (void)

  Remarks:
    See prototype in app_config.h.
 */

void AES_KeyWrap_Test (crypto_HandlerType_E cryptoHandler) 
{    
    st_Crypto_Sym_BlockCtx  Sym_Block_Ctx;
    
    isKeyWrap = true;

    AES kw128_Encrypt = {
        .Sym_Block_Ctx      = Sym_Block_Ctx,
        .handler            = cryptoHandler,
        .iv                 = NULL,
        .key                = Key_AES_KW128_Encrypt,
        .keySize            = sizeof(Key_AES_KW128_Encrypt),
        .pt                 = Plaintext_AES_KW128_Encrypt,
        .ptSize             = sizeof(Plaintext_AES_KW128_Encrypt),
        .symData            = symData_AES_128,
        .symDataSize        = sizeof(symData_AES_128),
        .cipher             = Ciphertext_AES_KW128_Encrypt,
        .cipherSize         = sizeof(Ciphertext_AES_KW128_Encrypt)
    };

    AES kw128_Decrypt = {
        .Sym_Block_Ctx  = Sym_Block_Ctx,
        .handler            = cryptoHandler,
        .iv                 = NULL,
        .key                = Key_AES_KW128_Decrypt,
        .keySize            = sizeof(Key_AES_KW128_Decrypt),
        .pt                 = Plaintext_AES_KW128_Decrypt,
        .ptSize             = sizeof(Plaintext_AES_KW128_Decrypt),
        .symData            = symData_AES_128,
        .symDataSize        = sizeof(symData_AES_128),
        .cipher             = Ciphertext_AES_KW128_Decrypt,
        .cipherSize         = sizeof(Ciphertext_AES_KW128_Decrypt)
    };

    printf("\r\nAES-KW 128 Init->Cipher Encrypt\r\n");
    MultiStepEncrypt(&kw128_Encrypt);

    printf("\r\nAES-KW 128 Init->Cipher Decrypt\r\n");
    MultiStepDecrypt(&kw128_Decrypt);

    printf("\r\nAES-KW 128 Direct Encrypt\r\n");
    SingleStepEncrypt(&kw128_Encrypt);

    printf("\r\nAES-KW 128 Direct Decrypt\r\n");
    SingleStepDecrypt(&kw128_Decrypt);

    AES kw192_Encrypt = {
        .Sym_Block_Ctx      = Sym_Block_Ctx,
        .handler            = cryptoHandler,
        .iv                 = NULL,
        .key                = Key_AES_KW192_Encrypt,
        .keySize            = sizeof(Key_AES_KW192_Encrypt),
        .pt                 = Plaintext_AES_KW192_Encrypt,
        .ptSize             = sizeof(Plaintext_AES_KW192_Encrypt),
        .symData            = symData_AES_192,
        .symDataSize        = sizeof(symData_AES_192),
        .cipher             = Ciphertext_AES_KW192_Encrypt,
        .cipherSize         = sizeof(Ciphertext_AES_KW192_Encrypt)
    };

    AES kw192_Decrypt = {
        .Sym_Block_Ctx      = Sym_Block_Ctx,
        .handler            = cryptoHandler,
        .iv                 = NULL,
        .key                = Key_AES_KW192_Decrypt,
        .keySize            = sizeof(Key_AES_KW192_Decrypt),
        .pt                 = Plaintext_AES_KW192_Decrypt,
        .ptSize             = sizeof(Plaintext_AES_KW192_Decrypt),
        .symData            = symData_AES_192,
        .symDataSize        = sizeof(symData_AES_192),
        .cipher             = Ciphertext_AES_KW192_Decrypt,
        .cipherSize         = sizeof(Ciphertext_AES_KW192_Decrypt)
    };

    printf("\r\nAES-KW 192 Init->Cipher Encrypt\r\n");
    MultiStepEncrypt(&kw192_Encrypt);

    printf("\r\nAES-KW 192 Init->Cipher Decrypt\r\n");
    MultiStepDecrypt(&kw192_Decrypt);

    printf("\r\nAES-KW 192 Direct Encrypt\r\n");
    SingleStepEncrypt(&kw192_Encrypt);

    printf("\r\nAES-KW 192 Direct Decrypt\r\n");
    SingleStepDecrypt(&kw192_Decrypt);

    AES kw256_Encrypt = {
        .Sym_Block_Ctx      = Sym_Block_Ctx,
        .handler            = cryptoHandler,
        .iv                 = NULL,
        .key                = Key_AES_KW256_Encrypt,
        .keySize            = sizeof(Key_AES_KW256_Encrypt),
        .pt                 = Plaintext_AES_KW256_Encrypt,
        .ptSize             = sizeof(Plaintext_AES_KW256_Encrypt),
        .symData            = symData_AES_256,
        .symDataSize        = sizeof(symData_AES_256),
        .cipher             = Ciphertext_AES_KW256_Encrypt,
        .cipherSize         = sizeof(Ciphertext_AES_KW256_Encrypt)
    };

    AES kw256_Decrypt = {
        .Sym_Block_Ctx      = Sym_Block_Ctx,
        .handler            = cryptoHandler,
        .iv                 = NULL,
        .key                = Key_AES_KW256_Decrypt,
        .keySize            = sizeof(Key_AES_KW256_Decrypt),
        .pt                 = Plaintext_AES_KW256_Decrypt,
        .ptSize             = sizeof(Plaintext_AES_KW256_Decrypt),
        .symData            = symData_AES_256,
        .symDataSize        = sizeof(symData_AES_256),
        .cipher             = Ciphertext_AES_KW256_Decrypt,
        .cipherSize         = sizeof(Ciphertext_AES_KW256_Decrypt)
    };

    printf("\r\nAES-KW 256 Init->Cipher Encrypt\r\n");
    MultiStepEncrypt(&kw256_Encrypt);

    printf("\r\nAES-KW 256 Init->Cipher Decrypt\r\n");
    MultiStepDecrypt(&kw256_Decrypt);

    printf("\r\nAES-KW 256 Direct Encrypt\r\n");
    SingleStepEncrypt(&kw256_Encrypt);

    printf("\r\nAES-KW 256 Direct Decrypt\r\n");
    SingleStepDecrypt(&kw256_Decrypt);

    isKeyWrap = false;
}

/*******************************************************************************
  Function:
    bool CompareHexArray (uint8_t *arr1, uint8_t *arr2, size_t size)

  Remarks:
    See prototype in app_config.h.
 */

bool CompareHexArray(const uint8_t *arr1, const uint8_t *arr2, size_t size)
{
    for (size_t i = 0; i < size; i++)
    {
        if (arr1[i] != arr2[i])
        {
            return false;
        }
    }
    return true;
}

/* *****************************************************************************
 End of File
 */
