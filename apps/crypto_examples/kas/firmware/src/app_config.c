/*******************************************************************************
  MPLAB Harmony Application Source File

  Company:
    Microchip Technology Inc.

  File Name:
    app_config.c

  Summary:
    Provides test vectors and functions for cryptographic tests.

  Description:
    This file contains test vectors and functions to test SECP256R1 
    and SECP384R1 cryptographic functionalities.
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

uint8_t sharedSecret_SECP256R1[32];

uint8_t sharedSecret_SECP384R1[48];

// *****************************************************************************
/* NIST Test Vectors

  Summary:
    Following data is obtained from NIST for cryptographic tests.

  Description:
    https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/CAVP-TESTING-BLOCK-CIPHER-MODES
*/

uint8_t Priv_SECP256R1[32] = {
    0x59, 0x13, 0x7e, 0x38, 0x15, 0x23, 0x50, 0xb1,
    0x95, 0xc9, 0x71, 0x8d, 0x39, 0x67, 0x3d, 0x51,
    0x98, 0x38, 0x05, 0x5a, 0xd9, 0x08, 0xdd, 0x47,
    0x57, 0x15, 0x2f, 0xd8, 0x25, 0x5c, 0x09, 0xbf
};

uint8_t Publ_SECP256R1[65] = {
    0x04, 0x41, 0x19, 0x2d, 0x28, 0x13, 0xe7, 0x95,
    0x61, 0xe6, 0xa1, 0xd6, 0xf5, 0x3c, 0x8b, 0xc1,
    0xa4, 0x33, 0xa1, 0x99, 0xc8, 0x35, 0xe1, 0x41,
    0xb0, 0x5a, 0x74, 0xa9, 0x7b, 0x0f, 0xae, 0xb9,
    0x22, 0x1a, 0xf9, 0x8c, 0xc4, 0x5e, 0x98, 0xa7,
    0xe0, 0x41, 0xb0, 0x1c, 0xf3, 0x5f, 0x46, 0x2b,
    0x75, 0x62, 0x28, 0x13, 0x51, 0xc8, 0xeb, 0xf3,
    0xff, 0xa0, 0x2e, 0x33, 0xa0, 0x72, 0x2a, 0x13,
    0x28
};

uint8_t Pub1_SEC256R1_Compressed[33] = 
{
    0x02,
    0x41, 0x19, 0x2d, 0x28, 0x13, 0xe7, 0x95, 0x61,
    0xe6, 0xa1, 0xd6, 0xf5, 0x3c, 0x8b, 0xc1, 0xa4,
    0x33, 0xa1, 0x99, 0xc8, 0x35, 0xe1, 0x41, 0xb0,
    0x5a, 0x74, 0xa9, 0x7b, 0x0f, 0xae, 0xb9, 0x22
};

uint8_t Secret_SECP256R1[32] = {
    0x19, 0xd4, 0x4c, 0x8d, 0x63, 0xe8, 0xe8, 0xdd,
    0x12, 0xc2, 0x2a, 0x87, 0xb8, 0xcd, 0x4e, 0xce,
    0x27, 0xac, 0xdd, 0xe0, 0x4d, 0xbf, 0x47, 0xf7,
    0xf2, 0x75, 0x37, 0xa6, 0x99, 0x9a, 0x8e, 0x62
};

uint8_t Priv_SECP384R1[48] = {
    0x09, 0x9F, 0x3C, 0x70, 0x34, 0xD4, 0xA2, 0xC6,
    0x99, 0x88, 0x4D, 0x73, 0xA3, 0x75, 0xA6, 0x7F,
    0x76, 0x24, 0xEF, 0x7C, 0x6B, 0x3C, 0x0F, 0x16,
    0x06, 0x47, 0xB6, 0x74, 0x14, 0xDC, 0xE6, 0x55,
    0xE3, 0x5B, 0x53, 0x80, 0x41, 0xE6, 0x49, 0xEE,
    0x3F, 0xAE, 0xF8, 0x96, 0x78, 0x3A, 0xB1, 0x94
};

uint8_t Publ_SECP384R1[97] = {
    0x04, 0xE5, 0x58, 0xDB, 0xEF, 0x53, 0xEE, 0xCD,
    0xE3, 0xD3, 0xFC, 0xCF, 0xC1, 0xAE, 0xA0, 0x8A,
    0x89, 0xA9, 0x87, 0x47, 0x5D, 0x12, 0xFD, 0x95,
    0x0D, 0x83, 0xCF, 0xA4, 0x17, 0x32, 0xBC, 0x50,
    0x9D, 0x0D, 0x1A, 0xC4, 0x3A, 0x03, 0x36, 0xDE,
    0xF9, 0x6F, 0xDA, 0x41, 0xD0, 0x77, 0x4A, 0x35,
    0x71, 0xDC, 0xFB, 0xEC, 0x7A, 0xAC, 0xF3, 0x19,
    0x64, 0x72, 0x16, 0x9E, 0x83, 0x84, 0x30, 0x36,
    0x7F, 0x66, 0xEE, 0xBE, 0x3C, 0x6E, 0x70, 0xC4,
    0x16, 0xDD, 0x5F, 0x0C, 0x68, 0x75, 0x9D, 0xD1,
    0xFF, 0xF8, 0x3F, 0xA4, 0x01, 0x42, 0x20, 0x9D,
    0xFF, 0x5E, 0xAA, 0xD9, 0x6D, 0xB9, 0xE6, 0x38,
    0x6C
};

uint8_t Publ_SECP384R1_Compressed[49] = {
    0x02, 
    0xE5, 0x58, 0xDB, 0xEF, 0x53, 0xEE, 0xCD, 0xE3,
    0xD3, 0xFC, 0xCF, 0xC1, 0xAE, 0xA0, 0x8A, 0x89,
    0xA9, 0x87, 0x47, 0x5D, 0x12, 0xFD, 0x95, 0x0D,
    0x83, 0xCF, 0xA4, 0x17, 0x32, 0xBC, 0x50, 0x9D,
    0x0D, 0x1A, 0xC4, 0x3A, 0x03, 0x36, 0xDE, 0xF9,
    0x6F, 0xDA, 0x41, 0xD0, 0x77, 0x4A, 0x35, 0x71,
};

uint8_t Secret_SECP384R1[48] = {
    0x11, 0x18, 0x73, 0x31, 0xC2, 0x79, 0x96, 0x2D,
    0x93, 0xD6, 0x04, 0x24, 0x3F, 0xD5, 0x92, 0xCB,
    0x9D, 0x0A, 0x92, 0x6F, 0x42, 0x2E, 0x47, 0x18,
    0x75, 0x21, 0x28, 0x7E, 0x71, 0x56, 0xC5, 0xC4,
    0xD6, 0x03, 0x13, 0x55, 0x69, 0xB9, 0xE9, 0xD0,
    0x9C, 0xF5, 0xD4, 0xA2, 0x70, 0xF5, 0x97, 0x46
};


/* ************************************************************************** */
/* ************************************************************************** */
// Section: Interface Functions                                               */
/* ************************************************************************** */
/* ************************************************************************** */

/*******************************************************************************
  Function:
    void SECP256R1_Test (void)

  Remarks:
    See prototype in app_config.h.
 */

void SECP256R1_Test (crypto_HandlerType_E cryptoHandler)
{
    ECDH secp256r1 = {
        .handler         = cryptoHandler,
        .curveType          = CRYPTO_ECC_CURVE_SECP256R1,
        .privKey            = Priv_SECP256R1,
        .privKeySize        = sizeof(Priv_SECP256R1),
        .publKey            = Publ_SECP256R1,
        .publKeySize        = sizeof(Publ_SECP256R1),
        .sharedSecret       = sharedSecret_SECP256R1,
        .sharedSecretSize   = sizeof(sharedSecret_SECP256R1),
        .expectedSecret     = Secret_SECP256R1,
        .expectedSecretSize = sizeof(Secret_SECP256R1)
    };

    printf("\r\nsecp256r1 with Uncompressed Key\r\n");
    GenerateSharedSecret(&secp256r1);
  
  // wolfCrypt wrapper supports compressed key
  if (secp256r1.handler == CRYPTO_HANDLER_SW_WOLFCRYPT)
  {
    secp256r1.handler            = CRYPTO_HANDLER_SW_WOLFCRYPT;
    secp256r1.curveType          = CRYPTO_ECC_CURVE_SECP256R1;
    secp256r1.privKey            = Priv_SECP256R1;
    secp256r1.privKeySize        = sizeof(Priv_SECP256R1);
    secp256r1.publKey            = Pub1_SEC256R1_Compressed;
    secp256r1.publKeySize        = sizeof(Pub1_SEC256R1_Compressed);
    secp256r1.sharedSecret       = sharedSecret_SECP256R1;
    secp256r1.sharedSecretSize   = sizeof(sharedSecret_SECP256R1);
    secp256r1.expectedSecret     = Secret_SECP256R1;
    secp256r1.expectedSecretSize = sizeof(Secret_SECP256R1);
    
    printf("\r\nsecp256r1 with Compressed Key\r\n");
    GenerateSharedSecret(&secp256r1);
 }
}

void SECP384R1_Test(crypto_HandlerType_E cryptoHandler)
{
    ECDH secp384r1 = {
        .handler         = cryptoHandler,
        .curveType          = CRYPTO_ECC_CURVE_SECP384R1,
        .privKey            = Priv_SECP384R1,
        .privKeySize        = sizeof(Priv_SECP384R1),
        .publKey            = Publ_SECP384R1,
        .publKeySize        = sizeof(Publ_SECP384R1),
        .sharedSecret       = sharedSecret_SECP384R1,
        .sharedSecretSize   = sizeof(sharedSecret_SECP384R1),
        .expectedSecret     = Secret_SECP384R1,
        .expectedSecretSize = sizeof(Secret_SECP384R1)
    };

    printf("\r\nsecp384r1 with Uncompressed Key\r\n");
    GenerateSharedSecret(&secp384r1);
    
  // wolfCrypt wrapper supports compressed key
  if (secp384r1.handler == CRYPTO_HANDLER_SW_WOLFCRYPT)
  {
    secp384r1.handler            = CRYPTO_HANDLER_SW_WOLFCRYPT;
    secp384r1.curveType          = CRYPTO_ECC_CURVE_SECP384R1;
    secp384r1.privKey            = Priv_SECP384R1;
    secp384r1.privKeySize        = sizeof(Priv_SECP384R1);
    secp384r1.publKey            = Publ_SECP384R1_Compressed;
    secp384r1.publKeySize        = sizeof(Publ_SECP384R1_Compressed);
    secp384r1.sharedSecret       = sharedSecret_SECP384R1;
    secp384r1.sharedSecretSize   = sizeof(sharedSecret_SECP384R1);
    secp384r1.expectedSecret     = Secret_SECP384R1;
    secp384r1.expectedSecretSize = sizeof(Secret_SECP384R1);

    printf("\r\nsecp384r1 with Compressed Key\r\n");
    GenerateSharedSecret(&secp384r1); 
  }
}

/*******************************************************************************
  Function:
    bool CompareHexArray (uint8_t *arr1, uint8_t *arr2, size_t size)

  Remarks:
    See prototype in app_config.h.
 */

bool CompareHexArray(uint8_t *arr1, uint8_t *arr2, size_t size)
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
