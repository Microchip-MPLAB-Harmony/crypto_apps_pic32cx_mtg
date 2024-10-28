/*******************************************************************************
  MPLAB Harmony Application Header File

  Company:
    Microchip Technology Inc.

  File Name:
    crypto_hash.h

  Summary:
    This header file provides prototypes and definitions for the application.

  Description:
    This header file provides function prototypes and data type definitions for
    the application.  Some of these are required by the system (such as the
    "APP_Initialize" and "APP_Tasks" prototypes) and some of them are only used
    internally by the application (such as the "APP_STATES" definition).  Both
    are defined here for convenience.
*******************************************************************************/

#ifndef CRYPTO_HASH_H
#define CRYPTO_HASH_H

// *****************************************************************************
// *****************************************************************************
// Section: Included Files
// *****************************************************************************
// *****************************************************************************
#include "crypto/common_crypto/crypto_common.h"
// *****************************************************************************
// *****************************************************************************
// Section: Type Definitions
// *****************************************************************************
// *****************************************************************************
#define CRYPTO_HASH_SHA512CTX_SIZE (288)

typedef enum {
    CRYPTO_HASH_INVALID = 0,
    CRYPTO_HASH_SHA1 = 1,
    CRYPTO_HASH_SHA2_224 = 2,
    CRYPTO_HASH_SHA2_256 = 3,
    CRYPTO_HASH_SHA2_384 = 4,
    CRYPTO_HASH_SHA2_512 = 5,
    CRYPTO_HASH_SHA2_512_224 = 6,
    CRYPTO_HASH_SHA2_512_256 = 7,
    CRYPTO_HASH_MD5 = 16,
    CRYPTO_HASH_RIPEMD160 = 17,
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

//MD5 Algorithm
typedef struct{
    uint32_t md5SessionId;
    crypto_HandlerType_E md5Handler_en;
    uint8_t arr_md5DataCtx[110];// __attribute__((aligned (8)));
}st_Crypto_Hash_Md5_Ctx;

//RIPEMD-160 Algorithm
typedef struct{
    uint32_t ripemd160SessionId;
    crypto_HandlerType_E ripedmd160Handler_en;
    uint8_t arr_ripemd160DataCtx[110];// __attribute__((aligned (8)));
}st_Crypto_Hash_Ripemd160_Ctx;

//SHA-1, SHA-2, SHA-3(Except SHAKE)
typedef struct{
    uint32_t shaSessionId;
    crypto_Hash_Algo_E shaAlgo_en;
    crypto_HandlerType_E shaHandler_en;
    uint8_t arr_shaDataCtx[CRYPTO_HASH_SHA512CTX_SIZE] __attribute__((aligned (4)));
}st_Crypto_Hash_Sha_Ctx;
// *****************************************************************************
//MD5 Algorithm
crypto_Hash_Status_E Crypto_Hash_Md5_Digest(crypto_HandlerType_E md5Handler_en, uint8_t *ptr_data, uint32_t dataLen, uint8_t *ptr_digest, uint32_t md5SessionId);
crypto_Hash_Status_E Crypto_Hash_Md5_Init(st_Crypto_Hash_Md5_Ctx *ptr_md5Ctx_st, crypto_HandlerType_E md5HandlerType_en, uint32_t md5SessionId);
crypto_Hash_Status_E Crypto_Hash_Md5_Update(st_Crypto_Hash_Md5_Ctx * ptr_md5Ctx_st, uint8_t *ptr_data, uint32_t dataLen);
crypto_Hash_Status_E Crypto_Hash_Md5_Final(st_Crypto_Hash_Md5_Ctx * ptr_md5Ctx_st, uint8_t *ptr_digest);

//RIPEMD-160 Algorithm
crypto_Hash_Status_E Crypto_Hash_Ripemd160_Digest(crypto_HandlerType_E ripedmd160Handler_en, uint8_t *ptr_data, uint32_t dataLen, uint8_t *ptr_digest, uint32_t ripemdSessionId);
crypto_Hash_Status_E Crypto_Hash_Ripemd160_Init(st_Crypto_Hash_Ripemd160_Ctx *ptr_ripemdCtx_st, crypto_HandlerType_E ripedmd160Handler_en, uint32_t ripemdSessionId);
crypto_Hash_Status_E Crypto_Hash_Ripemd160_Update(st_Crypto_Hash_Ripemd160_Ctx *ptr_ripemdCtx_st, uint8_t *ptr_data, uint32_t dataLen);
crypto_Hash_Status_E Crypto_Hash_Ripemd160_Final(st_Crypto_Hash_Ripemd160_Ctx *ptr_ripemdCtx_st, uint8_t *ptr_digest);

//SHA-1, SHA-2, SHA-3(Except SHAKE)
crypto_Hash_Status_E Crypto_Hash_Sha_Digest(crypto_HandlerType_E shaHandler_en, uint8_t *ptr_data, uint32_t dataLen, uint8_t *ptr_digest, crypto_Hash_Algo_E shaAlgorithm_en, uint32_t shaSessionId);
crypto_Hash_Status_E Crypto_Hash_Sha_Init(st_Crypto_Hash_Sha_Ctx *ptr_shaCtx_st, crypto_Hash_Algo_E shaAlgorithm_en, crypto_HandlerType_E shaHandler_en, uint32_t shaSessionId);
crypto_Hash_Status_E Crypto_Hash_Sha_Update(st_Crypto_Hash_Sha_Ctx *ptr_shaCtx_st, uint8_t *ptr_data, uint32_t dataLen);
crypto_Hash_Status_E Crypto_Hash_Sha_Final(st_Crypto_Hash_Sha_Ctx *ptr_shaCtx_st, uint8_t *ptr_digest);

uint32_t Crypto_Hash_GetHashAndHashSize(crypto_HandlerType_E shaHandler_en, crypto_Hash_Algo_E hashType_en, uint8_t *ptr_wcInputData, uint32_t wcDataLen, uint8_t *ptr_outHash);
#endif //CRYPTO_HASH_H
