/*******************************************************************************
  MPLAB Harmony Application Source File

  Company:
    Microchip Technology Inc.

  File Name:
    app_config.c

  Summary:
    Provides test vectors and functions for cryptographic tests.

  Description:
    This file contains test vectors and functions to test AEAD GCM and CCM
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

uint8_t cipher[32];

uint8_t symData[32];

// *****************************************************************************
/* NIST Test Vectors

  Summary:
    Following data is obtained from NIST for cryptographic tests.

  Description:
    https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/CAVP-TESTING-BLOCK-CIPHER-MODES
*/

uint8_t AEAD_GCM_Plaintext[32] = {
    0x74, 0x68, 0x65, 0x20, 0x66, 0x61, 0x76, 0x6F,
    0x72, 0x69, 0x74, 0x65, 0x20, 0x6D, 0x69, 0x63,
    0x72, 0x6F, 0x63, 0x68, 0x69, 0x70, 0x20, 0x74,
    0x65, 0x73, 0x74, 0x20, 0x61, 0x70, 0x70, 0x21
};

uint8_t AEAD_GCM_Key[16] = {
    0x77, 0xbe, 0x63, 0x70, 0x89, 0x71, 0xc4, 0xe2,
    0x40, 0xd1, 0xcb, 0x79, 0xe8, 0xd7, 0x7f, 0xeb
};

uint8_t AEAD_GCM_IV[12] = {
    0xe0, 0xe0, 0x0f, 0x19, 0xfe, 0xd7, 0xba, 0x01,
    0x36, 0xa7, 0x97, 0xf3
};

uint8_t AEAD_GCM_AAD[16] = {
    0x7a, 0x43, 0xec, 0x1d, 0x9c, 0x0a, 0x5a, 0x78,
    0xa0, 0xb1, 0x65, 0x33, 0xa6, 0x21, 0x3c, 0xab
};

uint8_t AEAD_GCM_Tag[16] = {
    0x20, 0x9f, 0xcc, 0x8d, 0x36, 0x75, 0xed, 0x93,
    0x8e, 0x9c, 0x71, 0x66, 0x70, 0x9d, 0xd9, 0x46
};

uint8_t AEAD_CCM_Plaintext[32] = {
    0x74, 0x68, 0x65, 0x20, 0x66, 0x61, 0x76, 0x6F,
    0x72, 0x69, 0x74, 0x65, 0x20, 0x6D, 0x69, 0x63,
    0x72, 0x6F, 0x63, 0x68, 0x69, 0x70, 0x20, 0x74,
    0x65, 0x73, 0x74, 0x20, 0x61, 0x70, 0x70, 0x21
};

uint8_t AEAD_CCM_Key[16] = {
    0x4a, 0xe7, 0x01, 0x10, 0x3c, 0x63, 0xde, 0xca,
    0x5b, 0x5a, 0x39, 0x39, 0xd7, 0xd0, 0x59, 0x92
};

uint8_t AEAD_CCM_IV[7] = {
    0x5a, 0x8a, 0xa4, 0x85, 0xc3, 0x16, 0xe9
};

uint8_t AEAD_CCM_Tag[4] = {
    0x02, 0x20, 0x9f, 0x55
};

/* ************************************************************************** */
/* ************************************************************************** */
// Section: Interface Functions                                               */
/* ************************************************************************** */
/* ************************************************************************** */

/*******************************************************************************
  Function:
    void AES_GCM_Test (void)

  Remarks:
    See prototype in app_config.
 */

void AES_GCM_Test (void)
{
    st_Crypto_Aead_AesGcm_ctx AesGcm_ctx;
    
    GCM AES_GCM = {
        .AesGcm_ctx = AesGcm_ctx,
#ifdef CRYPTO_AEAD_HW_AESGCM_EN
        .handler     = CRYPTO_HANDLER_HW_INTERNAL,
#else
        .handler     = CRYPTO_HANDLER_SW_WOLFCRYPT,
#endif
        .pt          = AEAD_GCM_Plaintext,
        .ptSize      = sizeof(AEAD_GCM_Plaintext),
        .cipher      = cipher,
        .cipherSize  = sizeof(cipher),
        .symData     = symData,
        .symDataSize = sizeof(symData),
        .key         = AEAD_GCM_Key,
        .keySize     = sizeof(AEAD_GCM_Key),
        .iv          = AEAD_GCM_IV,
        .ivSize      = sizeof(AEAD_GCM_IV),
        .aad         = AEAD_GCM_AAD,
        .aadSize     = sizeof(AEAD_GCM_AAD),
        .authTag     = AEAD_GCM_Tag,
        .authTagSize = sizeof(AEAD_GCM_Tag)
    };

    printf("\r\n-----------------------------------\r\n");
#ifdef CRYPTO_AEAD_HW_AESGCM_EN
    printf("AES_GCM HW Single-Step Test\r\n");
#else
    printf("AES_GCM SW Single-Step Test\r\n");
#endif
    AES_GCM_SingleStep(&AES_GCM);

    printf("\r\n-----------------------------------\r\n");
#ifdef CRYPTO_AEAD_HW_AESGCM_EN
    printf("AES_GCM HW Multi-Step Test\r\n");
#else
    printf("AES_GCM SW Multi-Step Test\r\n");
#endif
    AES_GCM_MultiStep(&AES_GCM);
}


/*******************************************************************************
  Function:
    void AES_CCM_Test (void)

  Remarks:
    See prototype in app_config.
 */

void AES_CCM_Test (void)
{
    st_Crypto_Aead_AesCcm_ctx AesCcm_ctx;
    
    CCM AES_CCM = {
        .AesCcm_ctx = AesCcm_ctx,
#ifdef CRYPTO_AEAD_HW_AESCCM_EN
        .handler     = CRYPTO_HANDLER_HW_INTERNAL,
#else
        .handler     = CRYPTO_HANDLER_SW_WOLFCRYPT,
#endif
        .pt          = AEAD_CCM_Plaintext,
        .ptSize      = sizeof(AEAD_CCM_Plaintext),
        
        .cipher      = cipher,
        .cipherSize  = sizeof(cipher),
        
        .symData     = symData,
        .symDataSize = sizeof(symData),

        .key         = AEAD_CCM_Key,
        .keySize     = sizeof(AEAD_CCM_Key),

        .iv          = AEAD_CCM_IV,
        .ivSize      = sizeof(AEAD_CCM_IV),

        .aad         = NULL,
        .aadSize     = 0,

        .authTag     = AEAD_CCM_Tag,
        .authTagSize = sizeof(AEAD_CCM_Tag)
    };

//    printf("\r\n-----------------------------------\r\n");
//#ifdef CRYPTO_AEAD_HW_AESCCM_EN
//    printf("AES_CCM HW Single-Step Test\r\n");
//#else
//    printf("AES_CCM SW Single-Step Test\r\n");
//#endif
//    AES_CCM_Direct(&AES_CCM);

    printf("\r\n-----------------------------------\r\n");
#ifdef CRYPTO_AEAD_HW_AESCCM_EN
    printf("AES_CCM HW Multi-Step Test\r\n");
#else
    printf("AES_CCM SW Multi-Step Test\r\n");
#endif
    AES_CCM_MultiStep(&AES_CCM);
}

/*******************************************************************************
  Function:
    bool CompareHexArray (uint8_t *arr1, uint8_t *arr2, size_t size)

  Remarks:
    See prototype in app_config.
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
