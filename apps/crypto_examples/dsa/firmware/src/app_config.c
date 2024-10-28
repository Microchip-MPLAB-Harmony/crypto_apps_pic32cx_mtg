/*******************************************************************************
  MPLAB Harmony Application Source File

  Company:
    Microchip Technology Inc.

  File Name:
    app_config.c

  Summary:
    Provides test vectors and functions for cryptographic tests.

  Description:
    This file contains test vectors and functions to test SECP256R1 and 
    SECP384R1 cryptographic functionalities
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

uint8_t sig256[64];

uint8_t sig384[96];


// *****************************************************************************
/* NIST Test Vectors

  Summary:
    Following data is obtained from NIST for cryptographic tests.

  Description:
    https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Digital-Signatures#ecdsa2vs
*/

uint8_t msg[32] = 
{
    0xdd, 0x4d, 0x65, 0x49, 0xa3, 0x64, 0x76, 0xc0,
    0x73, 0x05, 0xdc, 0x05, 0x16, 0xb5, 0xee, 0x9f,
    0x82, 0xf9, 0xe9, 0x7d, 0x01, 0x1a, 0xdc, 0x88,
    0x5a, 0x59, 0x9c, 0x44, 0xcc, 0x47, 0xa4, 0x78
};

uint8_t privKeyECDSA256[32] =
{
    /* d */
    0x1e, 0xe7, 0x70, 0x07, 0xd3, 0x30, 0x94, 0x39,
    0x28, 0x90, 0xdf, 0x23, 0x88, 0x2c, 0x4a, 0x34,
    0x15, 0xdb, 0x4c, 0x43, 0xcd, 0xfa, 0xe5, 0x1f,
    0x3d, 0x4c, 0x37, 0xfe, 0x59, 0x3b, 0x96, 0xd8
};

//04 + qx + qy 
uint8_t pubKeyECDSA256[65] =
{
    /* Qx */
    0x04, 0x96, 0x93, 0x1c, 0x53, 0x0b, 0x43, 0x6c, 0x42,
    0x0c, 0x52, 0x90, 0xe4, 0xa7, 0xec, 0x98, 0xb1,
    0xaf, 0xd4, 0x14, 0x49, 0xd8, 0xc1, 0x42, 0x82,
    0x04, 0x78, 0xd1, 0x90, 0xae, 0xa0, 0x6c, 0x07,
    /* Qy */
    0xf2, 0x3a, 0xb5, 0x10, 0x32, 0x8d, 0xce, 0x9e,
    0x76, 0xa0, 0xd2, 0x8c, 0xf3, 0xfc, 0xa9, 0x94,
    0x43, 0x24, 0xe6, 0x82, 0x00, 0x40, 0xc6, 0xdb,
    0x1c, 0x2f, 0xcd, 0x38, 0x4b, 0x60, 0xdd, 0x61
};

uint8_t pubKeyECDSA256_Compressed[33] = 
{
    0x03, 
    0x96, 0x93, 0x1c, 0x53, 0x0b, 0x43, 0x6c, 0x42,
    0x0c, 0x52, 0x90, 0xe4, 0xa7, 0xec, 0x98, 0xb1,
    0xaf, 0xd4, 0x14, 0x49, 0xd8, 0xc1, 0x42, 0x82,
    0x04, 0x78, 0xd1, 0x90, 0xae, 0xa0, 0x6c, 0x07  
};

uint8_t privKeyECDSA384[48] =
{
    /* d */
    0xa4, 0xe5, 0x06, 0xe8, 0x06, 0x16, 0x3e, 0xab,
    0x89, 0xf8, 0x60, 0x43, 0xc0, 0x60, 0x25, 0xdb,
    0xba, 0x7b, 0xfe, 0x19, 0x35, 0x08, 0x55, 0x65,
    0x76, 0xe2, 0xdc, 0xe0, 0x01, 0x8b, 0x6b, 0x68,
    0xdf, 0xcf, 0x6f, 0x80, 0x12, 0xce, 0x79, 0x37,
    0xeb, 0x2b, 0x9c, 0x7b, 0xc4, 0x68, 0x1c, 0x74
};

//04 + qx + qy 
uint8_t pubKeyECDSA384[97] =
{
    /* Qx */
    0x04, 0xea, 0xcf, 0x93, 0x4f, 0x2c, 0x09, 0xbb, 0x39,
    0x14, 0x0f, 0x56, 0x64, 0xc3, 0x40, 0xb4, 0xdf,
    0x0e, 0x63, 0xae, 0xe5, 0x71, 0x4b, 0x00, 0xcc,
    0x04, 0x97, 0xff, 0xe1, 0xe9, 0x38, 0x96, 0xbb,
    0x5f, 0x91, 0xb2, 0x6a, 0xcc, 0xb5, 0x39, 0x5f,
    0x8f, 0x70, 0x59, 0xf1, 0x01, 0xf6, 0x5a, 0x2b,
    /* Qy */
    0x01, 0x6c, 0x68, 0x0b, 0xcf, 0x55, 0x25, 0xaf,
    0x6d, 0x98, 0x48, 0x0a, 0xa8, 0x74, 0xc9, 0xa9,
    0x17, 0xa0, 0x0c, 0xc3, 0xfb, 0xd3, 0x23, 0x68,
    0xfe, 0x04, 0x3c, 0x63, 0x50, 0x88, 0x3b, 0xb9,
    0x4f, 0x7c, 0x67, 0x34, 0xf7, 0x3b, 0xa9, 0x73,
    0xe7, 0x1b, 0xc3, 0x51, 0x5e, 0x22, 0x18, 0xec
};

uint8_t pubKeyECDSA384_Compressed[49] =
{
    0x02, 
    0xea, 0xcf, 0x93, 0x4f, 0x2c, 0x09, 0xbb, 0x39,
    0x14, 0x0f, 0x56, 0x64, 0xc3, 0x40, 0xb4, 0xdf,
    0x0e, 0x63, 0xae, 0xe5, 0x71, 0x4b, 0x00, 0xcc,
    0x04, 0x97, 0xff, 0xe1, 0xe9, 0x38, 0x96, 0xbb,
    0x5f, 0x91, 0xb2, 0x6a, 0xcc, 0xb5, 0x39, 0x5f,
    0x8f, 0x70, 0x59, 0xf1, 0x01, 0xf6, 0x5a, 0x2b 
};

/* ************************************************************************** */
/* ************************************************************************** */
// Section: Interface Functions                                               */
/* ************************************************************************** */
/* ************************************************************************** */

/*******************************************************************************
  Function:
    void ECDSA_Test (void)

  Remarks:
    See prototype in app_config.h.
 */

void ECDSA_Test (crypto_HandlerType_E cryptoHandler)
{
    ECDSA ECDSA_Sign256 = {
        .handler     = cryptoHandler,
        .curveType = CRYPTO_ECC_CURVE_SECP256R1,
        .inputHash = msg,
        .inputHashSize = sizeof(msg),
        .key = privKeyECDSA256,
        .keySize = sizeof(privKeyECDSA256),
        .sig = sig256,
        .sigSize = sizeof(sig256)
    };

    printf("\r\nECDSA P-256 Sign with Uncompressed Key\r\n");
    ECDSA_Sign_Test(&ECDSA_Sign256);

    ECDSA ECDSA_Verify256 = {
        .handler     = cryptoHandler,
        .curveType = CRYPTO_ECC_CURVE_SECP256R1,
        .inputHash = msg,
        .inputHashSize = sizeof(msg),
        .key = pubKeyECDSA256,
        .keySize = sizeof(pubKeyECDSA256),
        .sig = sig256,
        .sigSize = sizeof(sig256),
        .hashVerifyStat = 0
    };
    printf("\r\nECDSA P-256 Verify with Uncompressed Key\r\n");
    ECDSA_Verify_Test(&ECDSA_Verify256);

    // wolfCrypt wrapper supports compressed key
    if (ECDSA_Verify256.handler == CRYPTO_HANDLER_SW_WOLFCRYPT)
    {
        ECDSA_Verify256.handler   = CRYPTO_HANDLER_SW_WOLFCRYPT;
        ECDSA_Verify256.curveType = CRYPTO_ECC_CURVE_SECP256R1;
        ECDSA_Verify256.inputHash = msg;
        ECDSA_Verify256.inputHashSize = sizeof(msg);
        ECDSA_Verify256.key = pubKeyECDSA256_Compressed;
        ECDSA_Verify256.keySize = sizeof(pubKeyECDSA256_Compressed);
        ECDSA_Verify256.sig = sig256;
        ECDSA_Verify256.sigSize = sizeof(sig256);
        ECDSA_Verify256.hashVerifyStat = 0;
                
        printf("\r\nECDSA P-256 Verify with Compressed Key\r\n");
        ECDSA_Verify_Test(&ECDSA_Verify256);
    }
    
    ECDSA ECDSA_Sign384 = {
        .handler     = cryptoHandler,
        .curveType = CRYPTO_ECC_CURVE_SECP384R1,
        .inputHash = msg,
        .inputHashSize = sizeof(msg),
        .key = privKeyECDSA384,
        .keySize = sizeof(privKeyECDSA384),
        .sig = sig384,
        .sigSize = sizeof(sig384),
    };

    printf("\r\nECDSA P-384 Sign with Uncompressed Key\r\n");
    ECDSA_Sign_Test(&ECDSA_Sign384);

    ECDSA ECDSA_Verify384 = {
        .handler     = cryptoHandler,
        .curveType = CRYPTO_ECC_CURVE_SECP384R1,
        .inputHash = msg,
        .inputHashSize = sizeof(msg),
        .key = pubKeyECDSA384,
        .keySize = sizeof(pubKeyECDSA384),
        .sig = sig384,
        .sigSize = sizeof(sig384),
        .hashVerifyStat = 0
    };

    printf("\r\nECDSA P-384 Verify with Uncompressed Key\r\n");
    ECDSA_Verify_Test(&ECDSA_Verify384);
    
    // wolfCrypt wrapper supports compressed key
    if (ECDSA_Verify384.handler == CRYPTO_HANDLER_SW_WOLFCRYPT)
    {
        ECDSA_Verify384.handler   = CRYPTO_HANDLER_SW_WOLFCRYPT;
        ECDSA_Verify384.curveType = CRYPTO_ECC_CURVE_SECP384R1;
        ECDSA_Verify384.inputHash = msg;
        ECDSA_Verify384.inputHashSize = sizeof(msg);
        ECDSA_Verify384.key = pubKeyECDSA384_Compressed;
        ECDSA_Verify384.keySize = sizeof(pubKeyECDSA384_Compressed);
        ECDSA_Verify384.sig = sig384;
        ECDSA_Verify384.sigSize = sizeof(sig384);
        ECDSA_Verify384.hashVerifyStat = 0;
                
        printf("\r\nECDSA P-384 SW Verify with Compressed Key\r\n");
        ECDSA_Verify_Test(&ECDSA_Verify384);
    }
}

/*******************************************************************************
  Function:
    bool CompareHexArray (uint8_t *arr1, uint8_t *arr2, size_t size)

  Remarks:
    See prototype in dsa_data.h.
 */

bool CompareHexArray (uint8_t *arr1, uint8_t *arr2, size_t size)
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
