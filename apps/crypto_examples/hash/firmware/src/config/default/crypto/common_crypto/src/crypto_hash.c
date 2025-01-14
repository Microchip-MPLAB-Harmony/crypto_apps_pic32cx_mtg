/*******************************************************************************
  MPLAB Harmony Application Source File

  Company:
    Microchip Technology Inc.

  File Name:
    crypto_hash.c

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
#include "crypto/drivers/wrapper/crypto_hash_sha6156_wrapper.h"
#include "crypto/wolfcrypt/crypto_hash_wc_wrapper.h"

// *****************************************************************************
// *****************************************************************************
// Section: Global Data Definitions
// *****************************************************************************
// *****************************************************************************

#define CRYPTO_HASH_SESSION_MAX (1) 

// *****************************************************************************
// *****************************************************************************
// Section: Function Definitions
// *****************************************************************************
// *****************************************************************************

//MD5 Algorithm
crypto_Hash_Status_E Crypto_Hash_Md5_Digest(crypto_HandlerType_E md5Handler_en, uint8_t *ptr_data, uint32_t dataLen, uint8_t *ptr_digest, uint32_t md5SessionId)
{
   	crypto_Hash_Status_E ret_md5Stat_en = CRYPTO_HASH_ERROR_NOTSUPPTED;

    if( (ptr_data == NULL) || (dataLen == 0u) )
    {
        ret_md5Stat_en = CRYPTO_HASH_ERROR_INPUTDATA;
    }
    else if(ptr_digest == NULL)
    {      
        ret_md5Stat_en = CRYPTO_HASH_ERROR_OUTPUTDATA;
    }
    else if( (md5SessionId <= 0u) || (md5SessionId > (uint32_t)CRYPTO_HASH_SESSION_MAX) )
    {
        ret_md5Stat_en = CRYPTO_HASH_ERROR_SID;
    }
    else
    {
        switch(md5Handler_en)
        {
            case CRYPTO_HANDLER_SW_WOLFCRYPT:
                ret_md5Stat_en = Crypto_Hash_Wc_Md5Digest(ptr_data, dataLen, ptr_digest);
                break;
            default:
                ret_md5Stat_en = CRYPTO_HASH_ERROR_HDLR;
                break;
        };
    }
	return ret_md5Stat_en;  
}

crypto_Hash_Status_E Crypto_Hash_Md5_Init(st_Crypto_Hash_Md5_Ctx *ptr_md5Ctx_st, crypto_HandlerType_E md5HandlerType_en, uint32_t md5SessionId)
{
	crypto_Hash_Status_E ret_md5Stat_en = CRYPTO_HASH_ERROR_NOTSUPPTED;

    if(ptr_md5Ctx_st == NULL)
    {
        ret_md5Stat_en = CRYPTO_HASH_ERROR_CTX;
    }
    else if( (md5SessionId <= 0u) || (md5SessionId > (uint32_t)CRYPTO_HASH_SESSION_MAX) )
    {
        ret_md5Stat_en = CRYPTO_HASH_ERROR_SID;
    }
    else
    {
        ptr_md5Ctx_st->md5SessionId = md5SessionId;
        ptr_md5Ctx_st->md5Handler_en = md5HandlerType_en;
        
        switch(ptr_md5Ctx_st->md5Handler_en)
        {
            case CRYPTO_HANDLER_SW_WOLFCRYPT:
                ret_md5Stat_en = Crypto_Hash_Wc_Md5Init((void*)ptr_md5Ctx_st->arr_md5DataCtx);
                break;
            default:
                ret_md5Stat_en = CRYPTO_HASH_ERROR_HDLR;
                break;
        };
    }
	return ret_md5Stat_en;
}

crypto_Hash_Status_E Crypto_Hash_Md5_Update(st_Crypto_Hash_Md5_Ctx * ptr_md5Ctx_st, uint8_t *ptr_data, uint32_t dataLen)
{
	crypto_Hash_Status_E ret_md5Stat_en = CRYPTO_HASH_ERROR_NOTSUPPTED;
    
    if(ptr_md5Ctx_st == NULL)
    {
        ret_md5Stat_en = CRYPTO_HASH_ERROR_CTX;
    }
    else if( (ptr_data == NULL) || (dataLen == 0u) )
    {
        ret_md5Stat_en = CRYPTO_HASH_ERROR_INPUTDATA;
    }
    else
    {
        switch(ptr_md5Ctx_st->md5Handler_en)
        {
            case CRYPTO_HANDLER_SW_WOLFCRYPT:
                ret_md5Stat_en = Crypto_Hash_Wc_Md5Update((void*)ptr_md5Ctx_st->arr_md5DataCtx, ptr_data, dataLen);
                break;
            default:
                ret_md5Stat_en = CRYPTO_HASH_ERROR_HDLR;
                break;
        };
    }
	return ret_md5Stat_en;
}

crypto_Hash_Status_E Crypto_Hash_Md5_Final(st_Crypto_Hash_Md5_Ctx * ptr_md5Ctx_st, uint8_t *ptr_digest)
{
   	crypto_Hash_Status_E ret_md5Stat_en = CRYPTO_HASH_ERROR_NOTSUPPTED;
    
    if(ptr_md5Ctx_st == NULL)
    {
        ret_md5Stat_en = CRYPTO_HASH_ERROR_CTX;
    }
    else if(ptr_digest == NULL)
    {      
        ret_md5Stat_en = CRYPTO_HASH_ERROR_OUTPUTDATA;
    }
    else
    {
        switch(ptr_md5Ctx_st->md5Handler_en)
        {
            case CRYPTO_HANDLER_SW_WOLFCRYPT:
                ret_md5Stat_en = Crypto_Hash_Wc_Md5Final((void*)ptr_md5Ctx_st->arr_md5DataCtx, ptr_digest);
                break;
            default:
                ret_md5Stat_en = CRYPTO_HASH_ERROR_HDLR;
                break;
        };
    }
	return ret_md5Stat_en; 
}

//RIPEMD160 Algorithm
crypto_Hash_Status_E Crypto_Hash_Ripemd160_Digest(crypto_HandlerType_E ripedmd160Handler_en, uint8_t *ptr_data, uint32_t dataLen, uint8_t *ptr_digest, uint32_t ripemdSessionId)
{
   	crypto_Hash_Status_E ret_ripemdStat_en = CRYPTO_HASH_ERROR_NOTSUPPTED;
    
    if( (ptr_data == NULL) || (dataLen == 0u) )
    {
        ret_ripemdStat_en = CRYPTO_HASH_ERROR_INPUTDATA;
    }
    else if(ptr_digest == NULL)
    {      
        ret_ripemdStat_en = CRYPTO_HASH_ERROR_OUTPUTDATA;
    }
    else if( (ripemdSessionId <= 0u) || (ripemdSessionId > (uint32_t)CRYPTO_HASH_SESSION_MAX))
    {
        ret_ripemdStat_en = CRYPTO_HASH_ERROR_SID;
    }
    else
    {
        switch(ripedmd160Handler_en)
        {
            case CRYPTO_HANDLER_SW_WOLFCRYPT:
                ret_ripemdStat_en = Crypto_Hash_Wc_Ripemd160Digest(ptr_data, dataLen, ptr_digest);
                break;
            case CRYPTO_HANDLER_HW_INTERNAL:
			
                break;
            default:
                ret_ripemdStat_en = CRYPTO_HASH_ERROR_HDLR;
                break;
        } 
    } 
	return ret_ripemdStat_en;     
}

//RIPEMD160
crypto_Hash_Status_E Crypto_Hash_Ripemd160_Init(st_Crypto_Hash_Ripemd160_Ctx *ptr_ripemdCtx_st, crypto_HandlerType_E ripedmd160Handler_en, uint32_t ripemdSessionId)
{
	crypto_Hash_Status_E ret_ripemdStat_en = CRYPTO_HASH_ERROR_NOTSUPPTED;
    
    if(ptr_ripemdCtx_st == NULL)
    {
        ret_ripemdStat_en = CRYPTO_HASH_ERROR_CTX;
    }
    else if( (ripemdSessionId <= 0u) || (ripemdSessionId > (uint32_t)CRYPTO_HASH_SESSION_MAX) )
    {
        ret_ripemdStat_en = CRYPTO_HASH_ERROR_SID;
    }
    else
    {
        ptr_ripemdCtx_st->ripemd160SessionId = ripemdSessionId;
        ptr_ripemdCtx_st->ripedmd160Handler_en = ripedmd160Handler_en;
        
        switch(ptr_ripemdCtx_st->ripedmd160Handler_en)
        {
            case CRYPTO_HANDLER_SW_WOLFCRYPT:
                ret_ripemdStat_en = Crypto_Hash_Wc_Ripemd160Init((void*)ptr_ripemdCtx_st->arr_ripemd160DataCtx);
                break;
            case CRYPTO_HANDLER_HW_INTERNAL:

                break;
            default:
                ret_ripemdStat_en = CRYPTO_HASH_ERROR_HDLR;
                break;
        }
    } 
	return ret_ripemdStat_en;
}

crypto_Hash_Status_E Crypto_Hash_Ripemd160_Update(st_Crypto_Hash_Ripemd160_Ctx *ptr_ripemdCtx_st, uint8_t *ptr_data, uint32_t dataLen)
{
	crypto_Hash_Status_E ret_ripemdStat_en = CRYPTO_HASH_ERROR_NOTSUPPTED;
    
    if(ptr_ripemdCtx_st == NULL)
    {
        ret_ripemdStat_en = CRYPTO_HASH_ERROR_CTX;
    }
    if( (ptr_data == NULL) || (dataLen == 0u) )
    {
        ret_ripemdStat_en = CRYPTO_HASH_ERROR_INPUTDATA;
    }
    else
    {
        switch(ptr_ripemdCtx_st->ripedmd160Handler_en)
        {
            case CRYPTO_HANDLER_SW_WOLFCRYPT:
                ret_ripemdStat_en = Crypto_Hash_Wc_Ripemd160Update((void*)ptr_ripemdCtx_st->arr_ripemd160DataCtx, ptr_data, dataLen);
                break;
            case CRYPTO_HANDLER_HW_INTERNAL:
			
                break;
            default:
                ret_ripemdStat_en = CRYPTO_HASH_ERROR_HDLR;
                break;
        };
    }
	return ret_ripemdStat_en;
}

crypto_Hash_Status_E Crypto_Hash_Ripemd160_Final (st_Crypto_Hash_Ripemd160_Ctx *ptr_ripemdCtx_st, uint8_t *ptr_digest)
{
   	crypto_Hash_Status_E ret_ripemdStat_en = CRYPTO_HASH_ERROR_NOTSUPPTED;
    
    if(ptr_ripemdCtx_st == NULL)
    {
        ret_ripemdStat_en = CRYPTO_HASH_ERROR_CTX;
    }
    else if(ptr_digest == NULL)
    {
         ret_ripemdStat_en = CRYPTO_HASH_ERROR_OUTPUTDATA;   
    }
    else
    {
        switch(ptr_ripemdCtx_st->ripedmd160Handler_en)
        {
            case CRYPTO_HANDLER_SW_WOLFCRYPT:
                ret_ripemdStat_en = Crypto_Hash_Wc_Ripemd160Final((void*)ptr_ripemdCtx_st->arr_ripemd160DataCtx, ptr_digest);
                break;
            case CRYPTO_HANDLER_HW_INTERNAL:
                break;   
                
            default:
                ret_ripemdStat_en = CRYPTO_HASH_ERROR_HDLR;
                break;
        };
    }
	return ret_ripemdStat_en; 
}
	
//SHA-1, SHA-2 and SHA-3 except SHAKE Algorithm
crypto_Hash_Status_E Crypto_Hash_Sha_Digest(crypto_HandlerType_E shaHandler_en, uint8_t *ptr_data, uint32_t dataLen, 
                                                uint8_t *ptr_digest, crypto_Hash_Algo_E shaAlgorithm_en,  uint32_t shaSessionId)
{
 	crypto_Hash_Status_E ret_shaStat_en = CRYPTO_HASH_ERROR_NOTSUPPTED;
    
    if( (ptr_data == NULL) || (dataLen == 0u) )
    {
        ret_shaStat_en = CRYPTO_HASH_ERROR_INPUTDATA;
    }
    else if(ptr_digest == NULL)
    {      
        ret_shaStat_en = CRYPTO_HASH_ERROR_OUTPUTDATA;
    }
    else if( (shaAlgorithm_en <= CRYPTO_HASH_INVALID) || (shaAlgorithm_en >= CRYPTO_HASH_MAX))
    {
        ret_shaStat_en = CRYPTO_HASH_ERROR_ALGO;
    }
    else if( (shaSessionId <= 0u) || (shaSessionId > (uint32_t)CRYPTO_HASH_SESSION_MAX) )
    {
        ret_shaStat_en = CRYPTO_HASH_ERROR_SID;
    }
	else
    {
        switch(shaHandler_en)
        {
            case CRYPTO_HANDLER_SW_WOLFCRYPT:
                ret_shaStat_en = Crypto_Hash_Wc_ShaDigest(ptr_data, dataLen, ptr_digest, shaAlgorithm_en);
                break;
            case CRYPTO_HANDLER_HW_INTERNAL:
                ret_shaStat_en = Crypto_Hash_Hw_Sha_Digest((void*)ptr_data, dataLen, ptr_digest, shaAlgorithm_en);
                break;
            default:
                ret_shaStat_en = CRYPTO_HASH_ERROR_HDLR;
                break;
        }
    }
	return ret_shaStat_en;
}

crypto_Hash_Status_E Crypto_Hash_Sha_Init(st_Crypto_Hash_Sha_Ctx *ptr_shaCtx_st, crypto_Hash_Algo_E shaAlgorithm_en, crypto_HandlerType_E shaHandler_en, uint32_t shaSessionId)
{
 	crypto_Hash_Status_E ret_shaStat_en = CRYPTO_HASH_ERROR_NOTSUPPTED;
    
    if(ptr_shaCtx_st == NULL)
    {
        ret_shaStat_en = CRYPTO_HASH_ERROR_CTX;
    }
    else if( (shaAlgorithm_en <= CRYPTO_HASH_INVALID) || (shaAlgorithm_en >= CRYPTO_HASH_MAX))
    {
        ret_shaStat_en = CRYPTO_HASH_ERROR_ALGO;
    }
    else if( (shaSessionId <= 0u) || (shaSessionId > (uint32_t)CRYPTO_HASH_SESSION_MAX) )
    {
        ret_shaStat_en = CRYPTO_HASH_ERROR_SID;
    }
	else
    {
        ptr_shaCtx_st->shaSessionId = shaSessionId;
        ptr_shaCtx_st->shaAlgo_en = shaAlgorithm_en;
        ptr_shaCtx_st->shaHandler_en = shaHandler_en;

        switch(ptr_shaCtx_st->shaHandler_en)
        {
            case CRYPTO_HANDLER_SW_WOLFCRYPT:
                ret_shaStat_en = Crypto_Hash_Wc_ShaInit((void*)ptr_shaCtx_st->arr_shaDataCtx, ptr_shaCtx_st->shaAlgo_en);
                break;
            case CRYPTO_HANDLER_HW_INTERNAL:
                ret_shaStat_en = Crypto_Hash_Hw_Sha_Init((void*)ptr_shaCtx_st->arr_shaDataCtx, ptr_shaCtx_st->shaAlgo_en);
                break;
            default:
                ret_shaStat_en = CRYPTO_HASH_ERROR_HDLR;
                break;
        }
    }
	return ret_shaStat_en;
}

crypto_Hash_Status_E Crypto_Hash_Sha_Update(st_Crypto_Hash_Sha_Ctx *ptr_shaCtx_st, uint8_t *ptr_data, uint32_t dataLen)
{
	crypto_Hash_Status_E ret_shaStat_en = CRYPTO_HASH_ERROR_NOTSUPPTED;
    
    if(ptr_shaCtx_st == NULL)
    {
        ret_shaStat_en = CRYPTO_HASH_ERROR_CTX;
    }
    else if( (ptr_data == NULL) || (dataLen == 0u) )
    {
        ret_shaStat_en = CRYPTO_HASH_ERROR_INPUTDATA;
    }
    else
    {
        switch(ptr_shaCtx_st->shaHandler_en)
        {
            case CRYPTO_HANDLER_SW_WOLFCRYPT:
                ret_shaStat_en = Crypto_Hash_Wc_ShaUpdate((void*)ptr_shaCtx_st->arr_shaDataCtx, ptr_data, dataLen, ptr_shaCtx_st->shaAlgo_en);
                break;
            case CRYPTO_HANDLER_HW_INTERNAL:
                ret_shaStat_en = Crypto_Hash_Hw_Sha_Update((void*)ptr_shaCtx_st->arr_shaDataCtx, ptr_data, dataLen);
                break;
            default:
                ret_shaStat_en = CRYPTO_HASH_ERROR_HDLR;
                break;
        }
    }
	return ret_shaStat_en;
}

crypto_Hash_Status_E Crypto_Hash_Sha_Final(st_Crypto_Hash_Sha_Ctx *ptr_shaCtx_st, uint8_t *ptr_digest)
{
	crypto_Hash_Status_E ret_shaStat_en = CRYPTO_HASH_ERROR_NOTSUPPTED;
    
    if(ptr_shaCtx_st == NULL)
    {
        ret_shaStat_en = CRYPTO_HASH_ERROR_CTX;
    }
    else if(ptr_digest == NULL)
    {
        ret_shaStat_en = CRYPTO_HASH_ERROR_OUTPUTDATA;
    }
	else
    {
        switch(ptr_shaCtx_st->shaHandler_en)
        {
            case CRYPTO_HANDLER_SW_WOLFCRYPT:
                ret_shaStat_en = Crypto_Hash_Wc_ShaFinal((void*)ptr_shaCtx_st->arr_shaDataCtx, ptr_digest, ptr_shaCtx_st->shaAlgo_en);
                break;
            case CRYPTO_HANDLER_HW_INTERNAL:
                ret_shaStat_en = Crypto_Hash_Hw_Sha_Final((void*)ptr_shaCtx_st->arr_shaDataCtx, ptr_digest);
                break;
            default:
                ret_shaStat_en = CRYPTO_HASH_ERROR_HDLR;
                break;
        }
    }
	return ret_shaStat_en;
}

//SHAKE
crypto_Hash_Status_E Crypto_Hash_Shake_Digest(crypto_HandlerType_E shakeHandlerType_en, crypto_Hash_Algo_E shakeAlgorithm_en, 
                                                    uint8_t *ptr_data, uint32_t dataLen, uint8_t *ptr_digest, uint32_t digestLen, uint32_t shakeSessionId)
{
    crypto_Hash_Status_E ret_shakeStat_en = CRYPTO_HASH_ERROR_NOTSUPPTED;
    
    if( (shakeAlgorithm_en <= CRYPTO_HASH_INVALID) || (shakeAlgorithm_en >= CRYPTO_HASH_MAX))
    {
        ret_shakeStat_en = CRYPTO_HASH_ERROR_ALGO;
    }   
    else if( (ptr_data == NULL) || (dataLen == 0u) )
    {
        ret_shakeStat_en = CRYPTO_HASH_ERROR_INPUTDATA;
    }
    else if( (ptr_digest == NULL) || (digestLen == 0u) )
    {      
        ret_shakeStat_en = CRYPTO_HASH_ERROR_OUTPUTDATA;
    }
    else if( (shakeSessionId <= 0u) || (shakeSessionId > (uint32_t)CRYPTO_HASH_SESSION_MAX) )
    {
        ret_shakeStat_en = CRYPTO_HASH_ERROR_SID;
    }
	else
    {
        switch(shakeHandlerType_en)
        {
            case CRYPTO_HANDLER_SW_WOLFCRYPT:
                ret_shakeStat_en = Crypto_Hash_Wc_ShakeDigest(ptr_data, dataLen, ptr_digest, digestLen, shakeAlgorithm_en);
                break;
            case CRYPTO_HANDLER_HW_INTERNAL:
                break;
            default:
                ret_shakeStat_en = CRYPTO_HASH_ERROR_HDLR;
                break;
        }
    }
	return ret_shakeStat_en;   
}

crypto_Hash_Status_E Crypto_Hash_Shake_Init(st_Crypto_Hash_Shake_Ctx* ptr_shakeCtx_st, crypto_Hash_Algo_E shakeAlgorithm_en, 
                                                crypto_HandlerType_E shakeHandlerType_en, uint32_t digestLen, uint32_t shakeSessionId)
{
  	crypto_Hash_Status_E ret_shakeStat_en = CRYPTO_HASH_ERROR_NOTSUPPTED;
    
    if(ptr_shakeCtx_st == NULL)
    {
        ret_shakeStat_en = CRYPTO_HASH_ERROR_CTX;
    }
    if( (shakeAlgorithm_en <= CRYPTO_HASH_INVALID) || (shakeAlgorithm_en >= CRYPTO_HASH_MAX))
    {
        ret_shakeStat_en = CRYPTO_HASH_ERROR_ALGO;
    }   
    else if(digestLen == 0u)
    {      
        ret_shakeStat_en = CRYPTO_HASH_ERROR_ARG;
    }
    else if( (shakeSessionId <= 0u) || (shakeSessionId > (uint32_t)CRYPTO_HASH_SESSION_MAX) )
    {
        ret_shakeStat_en = CRYPTO_HASH_ERROR_SID;
    }
    else
    {
        ptr_shakeCtx_st->shakeSessionId = shakeSessionId;
        ptr_shakeCtx_st->shakeAlgo_en = shakeAlgorithm_en;
        ptr_shakeCtx_st->shakeHandler_en = shakeHandlerType_en;
        ptr_shakeCtx_st->digestLen = digestLen;

        switch(ptr_shakeCtx_st->shakeHandler_en)
        {
            case CRYPTO_HANDLER_SW_WOLFCRYPT:
                ret_shakeStat_en = Crypto_Hash_Wc_ShakeInit((void*)ptr_shakeCtx_st->arr_shakeDataCtx, ptr_shakeCtx_st->shakeAlgo_en);
                break;
            case CRYPTO_HANDLER_HW_INTERNAL:
			
                break;
            default:
                ret_shakeStat_en = CRYPTO_HASH_ERROR_HDLR;
                break;
        }
    }
	return ret_shakeStat_en;   
}

crypto_Hash_Status_E Crypto_Hash_Shake_Update(st_Crypto_Hash_Shake_Ctx* ptr_shakeCtx_st, uint8_t *ptr_data, uint32_t dataLen)
{
  	crypto_Hash_Status_E ret_shakeStat_en = CRYPTO_HASH_ERROR_NOTSUPPTED;
    
    if(ptr_shakeCtx_st == NULL)
    {
        ret_shakeStat_en = CRYPTO_HASH_ERROR_CTX;
    }
    else if( (ptr_data == NULL) || (dataLen == 0u) )
    {
        ret_shakeStat_en = CRYPTO_HASH_ERROR_INPUTDATA;
    }        
	else
    {
        switch(ptr_shakeCtx_st->shakeHandler_en)
        {
            case CRYPTO_HANDLER_SW_WOLFCRYPT:
                ret_shakeStat_en = Crypto_Hash_Wc_ShakeUpdate((void*)ptr_shakeCtx_st->arr_shakeDataCtx, ptr_data, dataLen, ptr_shakeCtx_st->shakeAlgo_en);
                break;
            case CRYPTO_HANDLER_HW_INTERNAL:
			
                break;
            default:
                ret_shakeStat_en = CRYPTO_HASH_ERROR_HDLR;
                break;
        }
    }
	return ret_shakeStat_en;   
}

crypto_Hash_Status_E Crypto_Hash_Shake_Final(st_Crypto_Hash_Shake_Ctx* ptr_shakeCtx_st, uint8_t *ptr_digest)
{
  	crypto_Hash_Status_E ret_shakeStat_en = CRYPTO_HASH_ERROR_NOTSUPPTED;
    
    if(ptr_shakeCtx_st == NULL)
    {
        ret_shakeStat_en = CRYPTO_HASH_ERROR_CTX;
    }
    else if(ptr_digest == NULL)
    {      
        ret_shakeStat_en = CRYPTO_HASH_ERROR_OUTPUTDATA;
    }
	else
    {
        switch(ptr_shakeCtx_st->shakeHandler_en)
        {
            case CRYPTO_HANDLER_SW_WOLFCRYPT:
                ret_shakeStat_en = Crypto_Hash_Wc_ShakeFinal((void*)ptr_shakeCtx_st->arr_shakeDataCtx, ptr_digest, ptr_shakeCtx_st->digestLen, ptr_shakeCtx_st->shakeAlgo_en);
                break;
                
            case CRYPTO_HANDLER_HW_INTERNAL:
			
                break;
            default:
                ret_shakeStat_en = CRYPTO_HASH_ERROR_HDLR;
                break;
        }
    }
	return ret_shakeStat_en;   
}

//BLAKE
crypto_Hash_Status_E Crypto_Hash_Blake_Digest(crypto_HandlerType_E blakeHandlerType_en, crypto_Hash_Algo_E blakeAlgorithm_en, uint8_t *ptr_data, uint32_t dataLen, 
                                                uint8_t *ptr_blakeKey, uint32_t keySize, uint8_t *ptr_digest, uint32_t digestLen, uint32_t blakeSessionId)
{
    crypto_Hash_Status_E ret_blakeStat_en = CRYPTO_HASH_ERROR_NOTSUPPTED;
    
    if( (blakeAlgorithm_en <= CRYPTO_HASH_INVALID) || (blakeAlgorithm_en >= CRYPTO_HASH_MAX))
    {
        ret_blakeStat_en = CRYPTO_HASH_ERROR_ALGO;
    }   
    else if( (ptr_data == NULL) || (dataLen == 0u) )
    {
        ret_blakeStat_en = CRYPTO_HASH_ERROR_INPUTDATA;
    }
    else if( ((ptr_blakeKey != NULL) && (keySize == 0u)) 
                || ((ptr_blakeKey == NULL) && (keySize > 0u)) )
    {
        ret_blakeStat_en = CRYPTO_HASH_ERROR_KEY;
    }
    else if( (ptr_digest == NULL) || (digestLen == 0u ) )
    {      
        ret_blakeStat_en = CRYPTO_HASH_ERROR_OUTPUTDATA;
    }
    else if( (blakeSessionId <= 0u) || (blakeSessionId > (uint32_t)CRYPTO_HASH_SESSION_MAX) )
    {
        ret_blakeStat_en = CRYPTO_HASH_ERROR_SID;
    }
    else
    {
        switch(blakeHandlerType_en)
        {
            case CRYPTO_HANDLER_SW_WOLFCRYPT:
                ret_blakeStat_en = Crypto_Hash_Wc_BlakeDigest(ptr_data, dataLen, ptr_blakeKey, keySize, ptr_digest, digestLen, blakeAlgorithm_en);
                break;
            case CRYPTO_HANDLER_HW_INTERNAL:
			
                break;
            default:
                ret_blakeStat_en = CRYPTO_HASH_ERROR_HDLR;
                break;
        }
    }
    return ret_blakeStat_en;    
}

crypto_Hash_Status_E Crypto_Hash_Blake_Init(st_Crypto_Hash_Blake_Ctx* ptr_blakeCtx_st, crypto_Hash_Algo_E blakeAlgorithm_en, uint8_t *ptr_blakeKey,
                                                uint32_t keySize, uint32_t digestSize, crypto_HandlerType_E blakeHandlerType_en, uint32_t blakeSessionId)
{
    crypto_Hash_Status_E ret_blakeStat_en = CRYPTO_HASH_ERROR_NOTSUPPTED;
    
    if(ptr_blakeCtx_st == NULL)
    {
        ret_blakeStat_en = CRYPTO_HASH_ERROR_CTX;
    }
    if( (blakeAlgorithm_en <= CRYPTO_HASH_INVALID) || (blakeAlgorithm_en >= CRYPTO_HASH_MAX))
    {
        ret_blakeStat_en = CRYPTO_HASH_ERROR_ALGO;
    }   
    else if( ((ptr_blakeKey == NULL) && (keySize > 0u) ) 
            || ( (ptr_blakeKey != NULL) &&(keySize == 0u) ) )
    {
        ret_blakeStat_en = CRYPTO_HASH_ERROR_KEY;
    }
    else if(digestSize == 0u)
    {      
        ret_blakeStat_en = CRYPTO_HASH_ERROR_ARG;
    }
    else if( (blakeSessionId <= 0u) || (blakeSessionId > (uint32_t)CRYPTO_HASH_SESSION_MAX) )
    {
        ret_blakeStat_en = CRYPTO_HASH_ERROR_SID;
    }
	else 
    {
        ptr_blakeCtx_st->blakeSessionId = blakeSessionId;
        ptr_blakeCtx_st->blakeAlgo_en = blakeAlgorithm_en;
        ptr_blakeCtx_st->blakeHandler_en = blakeHandlerType_en;
        ptr_blakeCtx_st->digestLen = digestSize;
        ptr_blakeCtx_st->ptr_key = ptr_blakeKey;
        ptr_blakeCtx_st->keyLen = keySize;

        switch(ptr_blakeCtx_st->blakeHandler_en)
        {
            case CRYPTO_HANDLER_SW_WOLFCRYPT:
                ret_blakeStat_en = Crypto_Hash_Wc_BlakeInit((void*)ptr_blakeCtx_st->arr_blakeDataCtx, ptr_blakeCtx_st->blakeAlgo_en, ptr_blakeKey, keySize, digestSize);
                break;
            case CRYPTO_HANDLER_HW_INTERNAL:
			
                break;
            default:
                ret_blakeStat_en = CRYPTO_HASH_ERROR_HDLR;
                break;
        }
    }
    return ret_blakeStat_en;    
}

crypto_Hash_Status_E Crypto_Hash_Blake_Update(st_Crypto_Hash_Blake_Ctx * ptr_blakeCtx_st, uint8_t *ptr_data, uint32_t dataLen)
{
    crypto_Hash_Status_E ret_blakeStat_en = CRYPTO_HASH_ERROR_NOTSUPPTED;
    
    if(ptr_blakeCtx_st == NULL)
    {
        ret_blakeStat_en = CRYPTO_HASH_ERROR_CTX;
    }
    else if( (ptr_data == NULL) || (dataLen == 0u) )
    {
        ret_blakeStat_en = CRYPTO_HASH_ERROR_INPUTDATA;
    }
	else
    {
        switch(ptr_blakeCtx_st->blakeHandler_en)
        {
            case CRYPTO_HANDLER_SW_WOLFCRYPT:
                ret_blakeStat_en = Crypto_Hash_Wc_BlakeUpdate((void*)ptr_blakeCtx_st->arr_blakeDataCtx, ptr_data, dataLen, ptr_blakeCtx_st->blakeAlgo_en);
                break;
            case CRYPTO_HANDLER_HW_INTERNAL:
			
                break;
            default:
                ret_blakeStat_en = CRYPTO_HASH_ERROR_HDLR;
                break;
        }
    }
    return ret_blakeStat_en;    
}

crypto_Hash_Status_E Crypto_Hash_Blake_Final(st_Crypto_Hash_Blake_Ctx * ptr_blakeCtx_st, uint8_t *ptr_digest)
{
    crypto_Hash_Status_E ret_blakeStat_en = CRYPTO_HASH_ERROR_NOTSUPPTED;
    
    if(ptr_blakeCtx_st == NULL)
    {
        ret_blakeStat_en = CRYPTO_HASH_ERROR_CTX;
    }
    else if(ptr_digest == NULL)
    {
        ret_blakeStat_en = CRYPTO_HASH_ERROR_OUTPUTDATA;
    }
	else
    {
        switch(ptr_blakeCtx_st->blakeHandler_en)
        {
            case CRYPTO_HANDLER_SW_WOLFCRYPT:
                ret_blakeStat_en = Crypto_Hash_Wc_BlakeFinal((void*)ptr_blakeCtx_st->arr_blakeDataCtx, ptr_digest, ptr_blakeCtx_st->digestLen, ptr_blakeCtx_st->blakeAlgo_en);
                break;
            case CRYPTO_HANDLER_HW_INTERNAL:
			
                break;
            default:
                ret_blakeStat_en = CRYPTO_HASH_ERROR_HDLR;
                break;
        }
    }
    return ret_blakeStat_en;    
}

static crypto_Hash_Status_E Crypto_Hash_GetHashSize(crypto_Hash_Algo_E hashType_en, uint32_t *hashSize)
{
    crypto_Hash_Status_E ret_val_en = CRYPTO_HASH_SUCCESS;
       
    switch(hashType_en)
    {
        case CRYPTO_HASH_SHA1:
            *hashSize = 0x14;   //20 Bytes
            break;
        case CRYPTO_HASH_SHA2_224:
            *hashSize = 0x1C;   //28 Bytes
            break;
        case CRYPTO_HASH_SHA2_256:
            *hashSize = 0x20;   //32 Bytes
            break;
        case CRYPTO_HASH_SHA2_384:
            *hashSize = 0x30;   //48 Bytes
            break;
        case CRYPTO_HASH_SHA2_512:
            *hashSize = 0x40;   //64 Bytes
            break;
        case CRYPTO_HASH_SHA2_512_224:
            *hashSize = 0x1C;   //28 Bytes
            break;
        case CRYPTO_HASH_SHA2_512_256:
            *hashSize = 0x20;   //32 Bytes
            break;
        case CRYPTO_HASH_SHA3_224:
                *hashSize = 0x1C;   //28 Bytes
                break;
        case CRYPTO_HASH_SHA3_256:
            *hashSize = 0x20;   //32 Bytes
            break;
        case CRYPTO_HASH_SHA3_384:
            *hashSize = 0x30;   //48 Bytes
            break;
        case CRYPTO_HASH_SHA3_512:
            *hashSize = 0x40;   //64 Bytes
            break;
        case CRYPTO_HASH_MD5:
            *hashSize = 0x10;   //16 Bytes
            break;
        case CRYPTO_HASH_RIPEMD160:
                *hashSize = 0x14;   //20 Bytes
                break;
        default:
            ret_val_en = CRYPTO_HASH_ERROR_NOTSUPPTED;
            break;    
    }; 
    return ret_val_en;
}

uint32_t Crypto_Hash_GetHashAndHashSize(crypto_HandlerType_E shaHandler_en, crypto_Hash_Algo_E hashType_en, uint8_t *ptr_wcInputData, 
                                                                                                        uint32_t wcDataLen, uint8_t *ptr_outHash)
{
    crypto_Hash_Status_E hashStatus_en = CRYPTO_HASH_ERROR_FAIL;
    uint32_t hashSize = 0x00;
       
    switch(hashType_en)
    {
        case CRYPTO_HASH_SHA1:
            hashStatus_en = Crypto_Hash_Sha_Digest(shaHandler_en, ptr_wcInputData, wcDataLen, ptr_outHash, CRYPTO_HASH_SHA1, 1); 
            break;
        case CRYPTO_HASH_SHA2_224:
            hashStatus_en = Crypto_Hash_Sha_Digest(shaHandler_en, ptr_wcInputData, wcDataLen, ptr_outHash, CRYPTO_HASH_SHA2_224, 1); 
            break;
        case CRYPTO_HASH_SHA2_256:
            hashStatus_en = Crypto_Hash_Sha_Digest(shaHandler_en, ptr_wcInputData, wcDataLen, ptr_outHash, CRYPTO_HASH_SHA2_256, 1); 
            break;            
        case CRYPTO_HASH_SHA2_384:
            hashStatus_en = Crypto_Hash_Sha_Digest(shaHandler_en, ptr_wcInputData, wcDataLen, ptr_outHash, CRYPTO_HASH_SHA2_384, 1); 
            break;               
        case CRYPTO_HASH_SHA2_512:
            hashStatus_en = Crypto_Hash_Sha_Digest(shaHandler_en, ptr_wcInputData, wcDataLen, ptr_outHash, CRYPTO_HASH_SHA2_512, 1); 
            break;              
        case CRYPTO_HASH_SHA2_512_224:
            hashStatus_en = Crypto_Hash_Sha_Digest(shaHandler_en, ptr_wcInputData, wcDataLen, ptr_outHash, CRYPTO_HASH_SHA2_512_224, 1); 
            break;              
        case CRYPTO_HASH_SHA2_512_256:
            hashStatus_en = Crypto_Hash_Sha_Digest(shaHandler_en, ptr_wcInputData, wcDataLen, ptr_outHash, CRYPTO_HASH_SHA2_512_256, 1); 
            break;              
        case CRYPTO_HASH_SHA3_224:
            hashStatus_en = Crypto_Hash_Sha_Digest(shaHandler_en, ptr_wcInputData, wcDataLen, ptr_outHash, CRYPTO_HASH_SHA3_224, 1); 
            break;              
        case CRYPTO_HASH_SHA3_256:
            hashStatus_en = Crypto_Hash_Sha_Digest(shaHandler_en, ptr_wcInputData, wcDataLen, ptr_outHash, CRYPTO_HASH_SHA3_256, 1); 
            break;            
        case CRYPTO_HASH_SHA3_384:
            hashStatus_en = Crypto_Hash_Sha_Digest(shaHandler_en, ptr_wcInputData, wcDataLen, ptr_outHash, CRYPTO_HASH_SHA3_384, 1); 
            break;              
        case CRYPTO_HASH_SHA3_512:
            hashStatus_en = Crypto_Hash_Sha_Digest(shaHandler_en, ptr_wcInputData, wcDataLen, ptr_outHash, CRYPTO_HASH_SHA3_512, 1); 
            break;  
        case CRYPTO_HASH_MD5:
            hashStatus_en = Crypto_Hash_Md5_Digest(shaHandler_en, ptr_wcInputData, wcDataLen, ptr_outHash, 1);
            break;
        case CRYPTO_HASH_RIPEMD160:
            hashStatus_en = Crypto_Hash_Ripemd160_Digest(shaHandler_en, ptr_wcInputData, wcDataLen, ptr_outHash,1);
            break;
        default:
            hashStatus_en = CRYPTO_HASH_ERROR_NOTSUPPTED;
            break;    
    };
    
    if(hashStatus_en == CRYPTO_HASH_SUCCESS)
    {
        hashStatus_en = Crypto_Hash_GetHashSize(hashType_en, &hashSize);
        
        if(hashStatus_en != CRYPTO_HASH_SUCCESS)
        {
           hashSize = 0x00U;  
        }
    }
    else
    {
       hashSize = 0x00U; 
    }
    return hashSize;
}
