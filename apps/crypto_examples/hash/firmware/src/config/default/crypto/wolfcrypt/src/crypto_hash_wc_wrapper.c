/*******************************************************************************
  MPLAB Harmony Application Source File

  Company:
    Microchip Technology Inc.

  File Name:
    crypto_hash_wc_wrapper.c

  Summary:
    This file contains the source code for the MPLAB Harmony application.

  Description:
    This file contains the source code for the MPLAB Harmony application.  It
    implements the logic of the application's state machine and it may call
    API routines of other MPLAB Harmony modules in the system, such as drivers,
    system services, and middleware.  However, it does not call any of the
    system interfaces (such as the "Initialize" and "Tasks" functions) of any of
    the modules in the system or make any assumptions about when those functions
    are called.  That is the responsibility of the configuration-specific system
    files.
*******************************************************************************/

 
// *****************************************************************************
// *****************************************************************************
// Section: Included Files
// *****************************************************************************
// *****************************************************************************
#include "crypto/common_crypto/crypto_common.h"
#include "crypto/common_crypto/crypto_hash.h"
#include "crypto/wolfcrypt/crypto_hash_wc_wrapper.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include "wolfssl/wolfcrypt/md5.h"
#include "wolfssl/wolfcrypt/ripemd.h"
#include "wolfssl/wolfcrypt/sha.h"
#include "wolfssl/wolfcrypt/sha256.h"
#include "wolfssl/wolfcrypt/sha512.h"
// *****************************************************************************
// *****************************************************************************
// Section: Global Data Definitions
// *****************************************************************************
// *****************************************************************************


// *****************************************************************************
crypto_Hash_Status_E Crypto_Hash_Wc_Md5Digest(uint8_t *ptr_data, uint32_t dataLen, uint8_t *ptr_digest)
{
	crypto_Hash_Status_E ret_md5Stat_en = CRYPTO_HASH_ERROR_NOTSUPPTED; 

    if( (ptr_data != NULL) && (ptr_digest != NULL) && (dataLen > 0u) )
    {
        wc_Md5 ptr_md5Ctx_st[1];
        ret_md5Stat_en = Crypto_Hash_Wc_Md5Init(ptr_md5Ctx_st);
        if(ret_md5Stat_en == CRYPTO_HASH_SUCCESS)
        {
            ret_md5Stat_en = Crypto_Hash_Wc_Md5Update(ptr_md5Ctx_st, ptr_data, dataLen);
            if(ret_md5Stat_en == CRYPTO_HASH_SUCCESS)
            {
                ret_md5Stat_en = Crypto_Hash_Wc_Md5Final(ptr_md5Ctx_st, ptr_digest);
            }
        }
    }
    else
    {
        ret_md5Stat_en = CRYPTO_HASH_ERROR_ARG;
    }
    return ret_md5Stat_en;
}

crypto_Hash_Status_E Crypto_Hash_Wc_Md5Init(void *ptr_md5Ctx_st)
{  	
	crypto_Hash_Status_E ret_md5Stat_en = CRYPTO_HASH_ERROR_NOTSUPPTED; 
    int wcMd5Status = BAD_FUNC_ARG;
    if(ptr_md5Ctx_st != NULL)
    {
        wcMd5Status = wc_InitMd5((wc_Md5*)ptr_md5Ctx_st);

        if(wcMd5Status == 0)
        {
            ret_md5Stat_en = CRYPTO_HASH_SUCCESS;
        }
        else if (wcMd5Status == BAD_FUNC_ARG)
        {
            ret_md5Stat_en = CRYPTO_HASH_ERROR_ARG;
        }
        else
        {
            ret_md5Stat_en = CRYPTO_HASH_ERROR_FAIL;
        }
    }
    else
    {
        ret_md5Stat_en = CRYPTO_HASH_ERROR_CTX;
    }
    return ret_md5Stat_en;
}

crypto_Hash_Status_E Crypto_Hash_Wc_Md5Update(void *ptr_md5Ctx_st, uint8_t *ptr_data, uint32_t dataLen)
{
    crypto_Hash_Status_E ret_md5Stat_en = CRYPTO_HASH_ERROR_NOTSUPPTED;
    int wcMd5Status = BAD_FUNC_ARG;
    if(ptr_md5Ctx_st != NULL)
    {
        wcMd5Status = wc_Md5Update((wc_Md5*)ptr_md5Ctx_st, (const byte*)ptr_data, (word32)dataLen);
        
        if(wcMd5Status == 0)
        {
            ret_md5Stat_en = CRYPTO_HASH_SUCCESS;
        }
        else if (wcMd5Status == BAD_FUNC_ARG)
        {
            ret_md5Stat_en = CRYPTO_HASH_ERROR_ARG;
        }
        else
        {
            ret_md5Stat_en = CRYPTO_HASH_ERROR_FAIL;
        }
    }
    else
    {
       ret_md5Stat_en = CRYPTO_HASH_ERROR_CTX;
    }
    return ret_md5Stat_en;
}

crypto_Hash_Status_E Crypto_Hash_Wc_Md5Final(void *ptr_md5Ctx_st, uint8_t *ptr_digest)
{
    crypto_Hash_Status_E ret_md5Stat_en = CRYPTO_HASH_ERROR_NOTSUPPTED;
    int wcMd5Status = BAD_FUNC_ARG;
    if(ptr_md5Ctx_st != NULL)
    {
        wcMd5Status = wc_Md5Final((wc_Md5*)ptr_md5Ctx_st, (byte*)ptr_digest);
        
        if(wcMd5Status == 0)
        {
            ret_md5Stat_en = CRYPTO_HASH_SUCCESS;
        }
        else if (wcMd5Status == BAD_FUNC_ARG)
        {
            ret_md5Stat_en = CRYPTO_HASH_ERROR_ARG;
        }
        else
        {
            ret_md5Stat_en = CRYPTO_HASH_ERROR_FAIL;
        }
    }
    else
    {
       ret_md5Stat_en = CRYPTO_HASH_ERROR_CTX;
    }
    return ret_md5Stat_en; 
}

crypto_Hash_Status_E Crypto_Hash_Wc_Ripemd160Digest(uint8_t *ptr_data, uint32_t dataLen, uint8_t *ptr_digest)
{
    crypto_Hash_Status_E ret_ripemdStat_en = CRYPTO_HASH_ERROR_NOTSUPPTED;  
    RipeMd ptr_ripemdCtx_st[1];
    if( (ptr_data != NULL) && (ptr_digest != NULL) && (dataLen != 0u) )
    {
        //Initialize the Ripemd160 context
        ret_ripemdStat_en = Crypto_Hash_Wc_Ripemd160Init(ptr_ripemdCtx_st);
        
        if(ret_ripemdStat_en == CRYPTO_HASH_SUCCESS)
        {
            ret_ripemdStat_en = Crypto_Hash_Wc_Ripemd160Update(ptr_ripemdCtx_st, ptr_data, dataLen);
        }
        if(ret_ripemdStat_en == CRYPTO_HASH_SUCCESS)
        {
            ret_ripemdStat_en = Crypto_Hash_Wc_Ripemd160Final(ptr_ripemdCtx_st, ptr_digest);
        }
        else
        {
            ret_ripemdStat_en = CRYPTO_HASH_ERROR_FAIL;
        }
    }
    else
    {
       ret_ripemdStat_en = CRYPTO_HASH_ERROR_ARG;
    }
    return ret_ripemdStat_en;
}

crypto_Hash_Status_E Crypto_Hash_Wc_Ripemd160Init(void *ptr_ripemdCtx_st)
{
	crypto_Hash_Status_E ret_ripemdStat_en = CRYPTO_HASH_ERROR_NOTSUPPTED; 
    int wcRipemdStatus = BAD_FUNC_ARG;
    if(ptr_ripemdCtx_st != NULL)
    {
        wcRipemdStatus = wc_InitRipeMd((RipeMd*)ptr_ripemdCtx_st);

        if(wcRipemdStatus == 0)
        {
            ret_ripemdStat_en = CRYPTO_HASH_SUCCESS;
        }
        else if (wcRipemdStatus == BAD_FUNC_ARG)
        {
            ret_ripemdStat_en = CRYPTO_HASH_ERROR_ARG;
        }
        else
        {
            ret_ripemdStat_en = CRYPTO_HASH_ERROR_FAIL;
        }
    }
    else
    {
        ret_ripemdStat_en = CRYPTO_HASH_ERROR_CTX;
    }   
    return ret_ripemdStat_en;
}

crypto_Hash_Status_E Crypto_Hash_Wc_Ripemd160Update(void *ptr_ripemdCtx_st, uint8_t *ptr_data, uint32_t dataLen)
{
    crypto_Hash_Status_E ret_ripemdStat_en = CRYPTO_HASH_ERROR_NOTSUPPTED;
    int wcRipemdStatus = BAD_FUNC_ARG;
    if(ptr_ripemdCtx_st != NULL)
    {
        wcRipemdStatus = wc_RipeMdUpdate((RipeMd*)ptr_ripemdCtx_st, (const byte*)ptr_data, (word32)dataLen);
        
        if(wcRipemdStatus == 0)
        {
            ret_ripemdStat_en = CRYPTO_HASH_SUCCESS;
        }
        else if (wcRipemdStatus == BAD_FUNC_ARG)
        {
            ret_ripemdStat_en = CRYPTO_HASH_ERROR_ARG;
        }
        else
        {
            ret_ripemdStat_en = CRYPTO_HASH_ERROR_FAIL;
        }
    }
    else
    {
       ret_ripemdStat_en = CRYPTO_HASH_ERROR_CTX;
    } 
    return ret_ripemdStat_en;
}

crypto_Hash_Status_E Crypto_Hash_Wc_Ripemd160Final(void *ptr_ripemdCtx_st, uint8_t *ptr_digest)
{   
    crypto_Hash_Status_E ret_ripemdStat_en = CRYPTO_HASH_ERROR_NOTSUPPTED;
    int wcRipemdStatus = BAD_FUNC_ARG;
    if( (ptr_ripemdCtx_st != NULL) && (ptr_digest != NULL) )
    {
        wcRipemdStatus = wc_RipeMdFinal((RipeMd*)ptr_ripemdCtx_st, (byte*)ptr_digest);
        
        if(wcRipemdStatus == 0)
        {
            ret_ripemdStat_en = CRYPTO_HASH_SUCCESS;
        }
        else if (wcRipemdStatus == BAD_FUNC_ARG)
        {
            ret_ripemdStat_en = CRYPTO_HASH_ERROR_ARG;
        }
        else
        {
            ret_ripemdStat_en = CRYPTO_HASH_ERROR_FAIL;
        }
    }
    else
    {
       ret_ripemdStat_en = CRYPTO_HASH_ERROR_ARG;
    }
    return ret_ripemdStat_en;
}
	
crypto_Hash_Status_E Crypto_Hash_Wc_ShaDigest(uint8_t *ptr_data, uint32_t dataLen, uint8_t *ptr_digest, crypto_Hash_Algo_E hashAlgo_en)
{
	crypto_Hash_Status_E ret_shaStat_en = CRYPTO_HASH_ERROR_NOTSUPPTED;
    
    //As due to VLA misra Issue maximum Size is allocated
    uint8_t arr_shaDataCtx[CRYPTO_HASH_SHA512CTX_SIZE];
    
    if( (ptr_data != NULL) && (dataLen > 0u) && (ptr_digest != NULL) )
    {
        ret_shaStat_en = Crypto_Hash_Wc_ShaInit(arr_shaDataCtx, hashAlgo_en);
        if(ret_shaStat_en == CRYPTO_HASH_SUCCESS)
        {
            ret_shaStat_en = Crypto_Hash_Wc_ShaUpdate(arr_shaDataCtx, ptr_data, dataLen, hashAlgo_en);
            if(ret_shaStat_en == CRYPTO_HASH_SUCCESS)
            {
                ret_shaStat_en = Crypto_Hash_Wc_ShaFinal(arr_shaDataCtx, ptr_digest, hashAlgo_en);
            }
        }
    }
    else
    {
        ret_shaStat_en = CRYPTO_HASH_ERROR_ARG;
    }
    return ret_shaStat_en;
}

crypto_Hash_Status_E Crypto_Hash_Wc_ShaInit(void *ptr_shaCtx_st, crypto_Hash_Algo_E hashAlgo_en)
{
    crypto_Hash_Status_E ret_shaStat_en = CRYPTO_HASH_ERROR_NOTSUPPTED;
	int wcShaStatus = BAD_FUNC_ARG;
	
    if(ptr_shaCtx_st != NULL)
    {
        switch(hashAlgo_en)
        {    
            case CRYPTO_HASH_SHA1:
                wcShaStatus = wc_InitSha((wc_Sha*)ptr_shaCtx_st);
                break;
            case CRYPTO_HASH_SHA2_224:
                wcShaStatus = wc_InitSha224((wc_Sha224*)ptr_shaCtx_st);
                break;
            case CRYPTO_HASH_SHA2_256:
                wcShaStatus = wc_InitSha256((wc_Sha256*)ptr_shaCtx_st);
                break;
            case CRYPTO_HASH_SHA2_384:
                wcShaStatus = wc_InitSha384((wc_Sha384*)ptr_shaCtx_st);
                break;
            case CRYPTO_HASH_SHA2_512:
                wcShaStatus = wc_InitSha512((wc_Sha512*)ptr_shaCtx_st);
                break;
            case CRYPTO_HASH_SHA2_512_224:
                wcShaStatus = wc_InitSha512_224((wc_Sha512*)ptr_shaCtx_st);
                break;
            case CRYPTO_HASH_SHA2_512_256:
                wcShaStatus = wc_InitSha512_256((wc_Sha512*)ptr_shaCtx_st);
                break;
            default:
                ret_shaStat_en = CRYPTO_HASH_ERROR_ALGO;
                break;
        }

        if(ret_shaStat_en == CRYPTO_HASH_ERROR_ALGO)
        {
            //do nothing
        }
        else if(wcShaStatus == 0)
        {
            ret_shaStat_en = CRYPTO_HASH_SUCCESS;
        }
        else if (wcShaStatus == BAD_FUNC_ARG)
        {
            ret_shaStat_en = CRYPTO_HASH_ERROR_ARG;
        }
        else
        {
            ret_shaStat_en = CRYPTO_HASH_ERROR_FAIL;
        }
    }
    else
    {
        ret_shaStat_en = CRYPTO_HASH_ERROR_CTX;
    }
    return ret_shaStat_en;
}

crypto_Hash_Status_E Crypto_Hash_Wc_ShaUpdate(void *ptr_shaCtx_st, uint8_t *ptr_data, uint32_t dataLen, crypto_Hash_Algo_E hashAlgo_en)
{
    crypto_Hash_Status_E ret_shaStat_en = CRYPTO_HASH_ERROR_NOTSUPPTED;
    int wcShaStatus = BAD_FUNC_ARG;
	
	switch(hashAlgo_en)
	{
		case CRYPTO_HASH_SHA1:
			wcShaStatus = wc_ShaUpdate((wc_Sha*)ptr_shaCtx_st, (const byte*)ptr_data, (word32)dataLen);
            break;
		case CRYPTO_HASH_SHA2_224:
			wcShaStatus = wc_Sha224Update((wc_Sha224*)ptr_shaCtx_st, (const byte*)ptr_data, (word32)dataLen);
            break;
		case CRYPTO_HASH_SHA2_256:
			wcShaStatus = wc_Sha256Update((wc_Sha256*)ptr_shaCtx_st, (const byte*)ptr_data, (word32)dataLen);
            break;
		case CRYPTO_HASH_SHA2_384:
			wcShaStatus = wc_Sha384Update((wc_Sha384*)ptr_shaCtx_st, (const byte*)ptr_data, (word32)dataLen);
            break;
		case CRYPTO_HASH_SHA2_512:
			wcShaStatus = wc_Sha512Update((wc_Sha512*)ptr_shaCtx_st, (const byte*)ptr_data, (word32)dataLen);
            break;	
        case CRYPTO_HASH_SHA2_512_224:
            wcShaStatus = wc_Sha512_224Update((wc_Sha512*)ptr_shaCtx_st, (const byte*)ptr_data, (word32)dataLen);
            break;
        case CRYPTO_HASH_SHA2_512_256:
            wcShaStatus = wc_Sha512_256Update((wc_Sha512*)ptr_shaCtx_st, (const byte*)ptr_data, (word32)dataLen);
            break;            
        default:
            ret_shaStat_en = CRYPTO_HASH_ERROR_ALGO;
            break;
	}

	if(wcShaStatus == 0)
	{
		ret_shaStat_en = CRYPTO_HASH_SUCCESS;
	}
    else if(ret_shaStat_en == CRYPTO_HASH_ERROR_ALGO)
    {
        //do nothing
    }
    else
    {
        ret_shaStat_en = CRYPTO_HASH_ERROR_FAIL;
    }
    
	return ret_shaStat_en;  
}

crypto_Hash_Status_E Crypto_Hash_Wc_ShaFinal(void *ptr_shaCtx_st, uint8_t *ptr_digest, crypto_Hash_Algo_E hashAlgo_en)
{
    crypto_Hash_Status_E ret_shaStat_en = CRYPTO_HASH_ERROR_NOTSUPPTED;
    int wcShaStatus = BAD_FUNC_ARG;
	
	switch(hashAlgo_en)
	{
		case CRYPTO_HASH_SHA1:
			wcShaStatus = wc_ShaFinal((wc_Sha*)ptr_shaCtx_st, (byte*)ptr_digest);
            break;
		case CRYPTO_HASH_SHA2_224:
			wcShaStatus = wc_Sha224Final((wc_Sha224*)ptr_shaCtx_st, (byte*)ptr_digest);
            break;
		case CRYPTO_HASH_SHA2_256:
			wcShaStatus = wc_Sha256Final((wc_Sha256*)ptr_shaCtx_st, (byte*)ptr_digest);
            break;
		case CRYPTO_HASH_SHA2_384:
			wcShaStatus = wc_Sha384Final((wc_Sha384*)ptr_shaCtx_st, (byte*)ptr_digest);
            break;
		case CRYPTO_HASH_SHA2_512:
			wcShaStatus = wc_Sha512Final((wc_Sha512*)ptr_shaCtx_st, (byte*)ptr_digest);
            break;	
        case CRYPTO_HASH_SHA2_512_224:
            wcShaStatus = wc_Sha512_224Final((wc_Sha512*)ptr_shaCtx_st, (byte*)ptr_digest);
            break;
        case CRYPTO_HASH_SHA2_512_256:
            wcShaStatus = wc_Sha512_256Final((wc_Sha512*)ptr_shaCtx_st, (byte*)ptr_digest);
            break;
        default:
            ret_shaStat_en = CRYPTO_HASH_ERROR_ALGO;
            break;
	}

	if(wcShaStatus == 0)
	{
		ret_shaStat_en = CRYPTO_HASH_SUCCESS;
	}
    else if(ret_shaStat_en == CRYPTO_HASH_ERROR_ALGO)
    {
        //do nothing
    }
    else
    {
        ret_shaStat_en = CRYPTO_HASH_ERROR_FAIL;
    }
    
	return ret_shaStat_en;  
}
