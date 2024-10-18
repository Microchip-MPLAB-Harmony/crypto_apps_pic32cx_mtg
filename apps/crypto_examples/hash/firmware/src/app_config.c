/*******************************************************************************
  MPLAB Harmony Application Source File

  Company:
    Microchip Technology Inc.

  File Name:
    app_config.c

  Summary:
    This file contains the data for hash algorithms for the demo app.

  Description:
    This file contains source code for the pic32cxmtg cryptov4 demo application.
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

uint8_t msgDigestMd5[14];

uint8_t msgDigestSha1[20];

uint8_t msgDigestSha2_224[28];

uint8_t msgDigestSha2_256[32];

uint8_t msgDigestSha2_384[48];

uint8_t msgDigestSha2_512[64];

// *****************************************************************************
/* NIST Test Vectors

  Summary:
    Following data is obtained from NIST for cryptographic tests.

  Description:
    https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing
*/

uint8_t msgMD5[14] = {
    0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20,
    0x64, 0x69, 0x67, 0x65, 0x73, 0x74
};

uint8_t expectedMD5[16] = {
    0xf9, 0x6b, 0x69, 0x7d, 0x7c, 0xb7, 0x93, 0x8d,
    0x52, 0x5a, 0x2f, 0x31, 0xaa, 0xf1, 0x61, 0xd0
};

uint8_t msgSha1[6] = {
    0xC0, 0xE5, 0xAB, 0xEA, 0xEA, 0x63
};

uint8_t expectedSha1[20] = {
    0xA6, 0xD3, 0x38, 0x45, 0x97, 0x80, 0xC0, 0x83,
    0x63, 0x09, 0x0F, 0xD8, 0xFC, 0x7D, 0x28, 0xDC,
    0x80, 0xE8, 0xE0, 0x1F
};

uint8_t msgSha2_224[5] = {
    0x49, 0x3e, 0x14, 0x62, 0x3c
};

uint8_t expectedSha2_224[28] = {
    0x7f, 0x63, 0x1f, 0x29, 0x5e, 0x02, 0x4e, 0x74,
    0x55, 0x20, 0x83, 0x24, 0x5c, 0xa8, 0xf9, 0x88,
    0xa3, 0xfb, 0x65, 0x68, 0x0a, 0xe9, 0x7c, 0x30,
    0x40, 0xd2, 0xe6, 0x5c
};

uint8_t msgSha2_256[21] = {
    0x0C, 0xF0, 0xDA, 0x29, 0x94, 0xE7, 0x84, 0x78,
    0x45, 0xDD, 0xE7, 0xBD, 0x4D, 0xC7, 0xCE, 0xBF,
    0x0A, 0xD1, 0x55, 0x36, 0x0E
};

uint8_t expectedSha2_256[32] = {
    0xF8, 0x69, 0x0B, 0xCC, 0x85, 0x5D, 0x92, 0x91,
    0x55, 0x39, 0xD0, 0x82, 0x88, 0x76, 0xC3, 0xE4,
    0x61, 0x89, 0x64, 0xEB, 0x8C, 0x06, 0x71, 0x6F,
    0x18, 0x47, 0xFF, 0xA2, 0x9E, 0x43, 0x6D, 0x88
};

uint8_t msgSha2_384[5] = {
    0x4B, 0x5F, 0xAB, 0x61, 0xE0
};

uint8_t expectedSha2_384[48] = {
    0xFB, 0x39, 0x0A, 0xA5, 0xB7, 0x0B, 0x06, 0x8A,
    0x54, 0xD6, 0xD5, 0x12, 0x7D, 0xF6, 0xA6, 0x22,
    0x7B, 0xEC, 0xC4, 0xD6, 0xF8, 0x91, 0xFD, 0x3F,
    0x60, 0x68, 0xB9, 0x17, 0xA8, 0x83, 0xC9, 0xB6,
    0x6F, 0x31, 0x8F, 0xDD, 0xB6, 0x38, 0x4D, 0x10,
    0xBE, 0x8C, 0x7A, 0xF0, 0xD3, 0x13, 0x2F, 0x03
};

uint8_t msgSha2_512[4] = {
    0x23, 0xBE, 0x86, 0xD5
};

uint8_t expectedSha2_512[64] = {
    0x76, 0xD4, 0x2C, 0x8E, 0xAD, 0xEA, 0x35, 0xA6,
    0x99, 0x90, 0xC6, 0x3A, 0x76, 0x2F, 0x33, 0x06,
    0x14, 0xA4, 0x69, 0x99, 0x77, 0xF0, 0x58, 0xAD,
    0xB9, 0x88, 0xF4, 0x06, 0xFB, 0x0B, 0xE8, 0xF2,
    0xEA, 0x3D, 0xCE, 0x3A, 0x2B, 0xBD, 0x1D, 0x82,
    0x7B, 0x70, 0xB9, 0xB2, 0x99, 0xAE, 0x6F, 0x9E,
    0x50, 0x58, 0xEE, 0x97, 0xB5, 0x0B, 0xD4, 0x92,
    0x2D, 0x6D, 0x37, 0xDD, 0xC7, 0x61, 0xF8, 0xEB
};

/* ************************************************************************** */
/* ************************************************************************** */
// Section: Interface Functions                                               */
/* ************************************************************************** */
/* ************************************************************************** */

/*******************************************************************************
  Function:
    void MD5_Test (void)

  Remarks:
    See prototype in app_config.h.
 */

void MD5_Test (crypto_HandlerType_E cryptoHandler)
{
    st_Crypto_Hash_Md5_Ctx  Hash_Md5_Ctx;
        
    HASH MD5 = {
        .Hash_Md5_Ctx    = Hash_Md5_Ctx,
        .handler         = cryptoHandler,
        .hashMode        = CRYPTO_HASH_MD5,
        .msg             = msgMD5,
        .msgSize         = sizeof(msgMD5),
        .msgDigest       = msgDigestMd5,
        .msgDigestSize   = sizeof(msgDigestMd5),
        .expectedMsg     = expectedMD5,
        .expectedMsgSize = sizeof(expectedMD5)
    };

    printf("\r\nMD5 Digest\r\n");
    SingleStepDigest(&MD5);

    printf("\r\nMD5 Init->Update->Final\r\n");
    MultiStepDigest(&MD5);
}

/*******************************************************************************
  Function:
    void SHA1_Test (void)

  Remarks:
    See prototype in app_config.h.
 */

void SHA1_Test (crypto_HandlerType_E cryptoHandler)
{
    st_Crypto_Hash_Sha_Ctx  Hash_Sha_Ctx;
    
    HASH SHA1 = {
        .Hash_Sha_Ctx    = Hash_Sha_Ctx,
        .handler         = cryptoHandler,
        .hashMode        = CRYPTO_HASH_SHA1,
        .msg             = msgSha1,
        .msgSize         = sizeof(msgSha1),
        .msgDigest       = msgDigestSha1,
        .msgDigestSize   = sizeof(msgDigestSha1),
        .expectedMsg     = expectedSha1,
        .expectedMsgSize = sizeof(expectedSha1)
    };
    
    printf("\r\nSHA1 Digest\r\n");
    SingleStepDigest(&SHA1);

    printf("\r\nSHA1 Init->Update->Final\r\n");
    MultiStepDigest(&SHA1);
}

/*******************************************************************************
  Function:
    void SHA2_Test (void)

  Remarks:
    See prototype in app_config.h.
 */

void SHA2_Test (crypto_HandlerType_E cryptoHandler)
{
    st_Crypto_Hash_Sha_Ctx  Hash_Sha_Ctx;
    
    HASH SHA2_224 = {
        .Hash_Sha_Ctx    = Hash_Sha_Ctx,
        .handler         = cryptoHandler,
        .hashMode        = CRYPTO_HASH_SHA2_224,
        .msg             = msgSha2_224,
        .msgSize         = sizeof(msgSha2_224),
        .msgDigest       = msgDigestSha2_224,
        .msgDigestSize   = sizeof(msgDigestSha2_224),
        .expectedMsg     = expectedSha2_224,
        .expectedMsgSize = sizeof(expectedSha2_224)
    };
    
    printf("\r\nSHA2_224 Digest\r\n");
    SingleStepDigest(&SHA2_224);

    printf("\r\nSHA2_224 Init->Update->Final\r\n");
    MultiStepDigest(&SHA2_224);

    HASH SHA2_256 = {
        .Hash_Sha_Ctx    = Hash_Sha_Ctx,
        .handler         = cryptoHandler,
        .hashMode        = CRYPTO_HASH_SHA2_256,
        .msg             = msgSha2_256,
        .msgSize         = sizeof(msgSha2_256),
        .msgDigest       = msgDigestSha2_256,
        .msgDigestSize   = sizeof(msgDigestSha2_256),
        .expectedMsg     = expectedSha2_256,
        .expectedMsgSize = sizeof(expectedSha2_256)
    };

    printf("\r\nSHA2_256 Digest\r\n");
    SingleStepDigest(&SHA2_256);

    printf("\r\nSHA2_256 Init->Update->Final\r\n");
    MultiStepDigest(&SHA2_256);

    HASH SHA2_384 = {
        .Hash_Sha_Ctx    = Hash_Sha_Ctx,
        .handler         = CRYPTO_HANDLER_HW_INTERNAL,
        .hashMode        = CRYPTO_HASH_SHA2_384,
        .msg             = msgSha2_384,
        .msgSize         = sizeof(msgSha2_384),
        .msgDigest       = msgDigestSha2_384,
        .msgDigestSize   = sizeof(msgDigestSha2_384),
        .expectedMsg     = expectedSha2_384,
        .expectedMsgSize = sizeof(expectedSha2_384)
    };

    printf("\r\nSHA2_384 Digest\r\n");
    SingleStepDigest(&SHA2_384);

    printf("\r\nSHA2_384 Init->Update->Final\r\n");
    MultiStepDigest(&SHA2_384);

    HASH SHA2_512 = {
        .Hash_Sha_Ctx    = Hash_Sha_Ctx,
        .handler         = cryptoHandler,
        .hashMode        = CRYPTO_HASH_SHA2_512,
        .msg             = msgSha2_512,
        .msgSize         = sizeof(msgSha2_512),
        .msgDigest       = msgDigestSha2_512,
        .msgDigestSize   = sizeof(msgDigestSha2_512),
        .expectedMsg     = expectedSha2_512,
        .expectedMsgSize = sizeof(expectedSha2_384),
    };

    printf("\r\nSHA2_512 Digest\r\n");
    SingleStepDigest(&SHA2_512);

    printf("\r\nSHA2_512 Init->Update->Final\r\n");
    MultiStepDigest(&SHA2_512);
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
