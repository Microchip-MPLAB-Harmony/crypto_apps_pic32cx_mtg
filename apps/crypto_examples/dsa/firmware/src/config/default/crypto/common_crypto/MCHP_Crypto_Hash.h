/*******************************************************************************
  MPLAB Harmony Application Header File

  Company:
    Microchip Technology Inc.

  File Name:
    MCHP_Crypto_Hash.h

  Summary:
    This header file provides prototypes and definitions for the application.

  Description:
    This header file provides function prototypes and data type definitions for
    the application.  Some of these are required by the system (such as the
    "APP_Initialize" and "APP_Tasks" prototypes) and some of them are only used
    internally by the application (such as the "APP_STATES" definition).  Both
    are defined here for convenience.
*******************************************************************************/

#ifndef MCHP_CRYPTO_HASH_H
#define MCHP_CRYPTO_HASH_H

// *****************************************************************************
// *****************************************************************************
// Section: Included Files
// *****************************************************************************
// *****************************************************************************
#include "crypto/common_crypto/MCHP_Crypto_Common.h"
#include "crypto/common_crypto/MCHP_Crypto_Hash_Config.h"
// *****************************************************************************
// *****************************************************************************
// Section: Type Definitions
// *****************************************************************************
// *****************************************************************************
#define CRYPTO_HASH_SHA512CTX_SIZE (288)

typedef enum {
    CRYPTO_HASH_INVALID = 0,
    CRYPTO_HASH_SHA2_224 = 2,
    CRYPTO_HASH_SHA2_256 = 3,
    CRYPTO_HASH_SHA2_384 = 4,
    CRYPTO_HASH_SHA2_512 = 5,
    CRYPTO_HASH_MAX
}crypto_Hash_Algo_E;

typedef enum {
    CRYPTO_HASH_ERROR_NOTSUPPTED = -127,
    CRYPTO_HASH_ERROR_CTX = -126,
    CRYPTO_HASH_ERROR_INPUTDATA = -125,
    CRYPTO_HASH_ERROR_OUTPUTDATA = -124,
    CRYPTO_HASH_ERROR_SID = -123,
    CRYPTO_HASH_ERROR_ALGO = -122,
    CRYPTO_HASH_ERROR_KEY = -121,
    CRYPTO_HASH_ERROR_ARG = -120,
    CRYPTO_HASH_ERROR_HDLR = -119,
    CRYPTO_HASH_ERROR_FAIL = -118,
    CRYPTO_HASH_SUCCESS = 0
}crypto_Hash_Status_E;

//SHA-1, SHA-2, SHA-3(Except SHAKE)
typedef struct{
    uint32_t shaSessionId;
    crypto_Hash_Algo_E shaAlgo_en;
    crypto_HandlerType_E shaHandler_en;
    uint8_t arr_shaDataCtx[CRYPTO_HASH_SHA512CTX_SIZE] __attribute__((aligned (4)));
}st_Crypto_Hash_Sha_Ctx;
// *****************************************************************************

//SHA-1, SHA-2, SHA-3(Except SHAKE)
crypto_Hash_Status_E Crypto_Hash_Sha_Digest(crypto_HandlerType_E shaHandler_en, uint8_t *ptr_data, uint32_t dataLen, uint8_t *ptr_digest, crypto_Hash_Algo_E shaAlgorithm_en, uint32_t shaSessionId);
crypto_Hash_Status_E Crypto_Hash_Sha_Init(st_Crypto_Hash_Sha_Ctx *ptr_shaCtx_st, crypto_Hash_Algo_E shaAlgorithm_en, crypto_HandlerType_E shaHandler_en, uint32_t shaSessionId);
crypto_Hash_Status_E Crypto_Hash_Sha_Update(st_Crypto_Hash_Sha_Ctx *ptr_shaCtx_st, uint8_t *ptr_data, uint32_t dataLen);
crypto_Hash_Status_E Crypto_Hash_Sha_Final(st_Crypto_Hash_Sha_Ctx *ptr_shaCtx_st, uint8_t *ptr_digest);

uint32_t Crypto_Hash_GetHashAndHashSize(crypto_HandlerType_E shaHandler_en, crypto_Hash_Algo_E hashType_en, uint8_t *ptr_wcInputData, uint32_t wcDataLen, uint8_t *ptr_outHash);
#endif //MCHP_CRYPTO_HASH_H
