/*******************************************************************************
  MPLAB Harmony Application Source File

  Company:
    Microchip Technology Inc.

  File Name:
    crypto_aead_cipher.c

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
#include "crypto/common_crypto/crypto_aead_cipher.h"
#include "crypto/drivers/wrapper/crypto_aead_aes6149_wrapper.h"
#include "crypto/wolfcrypt/crypto_aead_wc_wrapper.h"

// *****************************************************************************
// *****************************************************************************
// Section: Global Data Definitions
// *****************************************************************************
// ***************************************************************************** 

#define CRYPTO_AEAD_SESSION_MAX (1)

// *****************************************************************************
// *****************************************************************************
// Section: Function Definitions
// *****************************************************************************
// *****************************************************************************

crypto_Aead_Status_E Crypto_Aead_AesCcm_Init(st_Crypto_Aead_AesCcm_ctx *ptr_aesCcmCtx_st, crypto_HandlerType_E handlerType_en, 
                                              uint8_t *ptr_key, uint32_t keyLen, uint32_t sessionID)
{
    crypto_Aead_Status_E ret_aesCcmStat_en = CRYPTO_AEAD_ERROR_CIPNOTSUPPTD;
    
    if(ptr_aesCcmCtx_st == NULL)
    {
        ret_aesCcmStat_en = CRYPTO_AEAD_ERROR_CTX;
    }
    else if( (ptr_key == NULL) || 
                ( (keyLen != (uint32_t)CRYPTO_AESKEYSIZE_128)
                    && (keyLen != (uint32_t)CRYPTO_AESKEYSIZE_192)
                    && (keyLen != (uint32_t)CRYPTO_AESKEYSIZE_256) ) ) 
    {
       ret_aesCcmStat_en =  CRYPTO_AEAD_ERROR_KEY;
    }
    else if( (sessionID <= 0u) || (sessionID > (uint32_t)CRYPTO_AEAD_SESSION_MAX) )
    {
       ret_aesCcmStat_en =  CRYPTO_AEAD_ERROR_SID; 
    }
    else
    {
        ptr_aesCcmCtx_st->cryptoSessionID =  sessionID;
        ptr_aesCcmCtx_st->aeadHandlerType_en = handlerType_en;
        ptr_aesCcmCtx_st->ptr_key = ptr_key;
        ptr_aesCcmCtx_st->aeadKeySize = keyLen;
        
        switch(ptr_aesCcmCtx_st->aeadHandlerType_en)
        {
            case CRYPTO_HANDLER_SW_WOLFCRYPT:
                    ret_aesCcmStat_en = Crypto_Aead_Wc_AesCcm_Init((void*)ptr_aesCcmCtx_st->arr_aeadDataCtx, ptr_aesCcmCtx_st->ptr_key, ptr_aesCcmCtx_st->aeadKeySize);     
                break;
               
            case CRYPTO_HANDLER_HW_INTERNAL:
                
                break;
				
            default:
                ret_aesCcmStat_en = CRYPTO_AEAD_ERROR_HDLR;
                break;
        }
        
    }
    return ret_aesCcmStat_en;
}

crypto_Aead_Status_E Crypto_Aead_AesCcm_Cipher(st_Crypto_Aead_AesCcm_ctx *ptr_aesCcmCtx_st, crypto_CipherOper_E cipherOper_en, uint8_t *ptr_inputData, uint32_t dataLen, 
                                                    uint8_t *ptr_outData, uint8_t *ptr_nonce, uint32_t nonceLen, uint8_t *ptr_authTag,
                                                    uint32_t authTagLen, uint8_t *ptr_aad, uint32_t aadLen)
{
    crypto_Aead_Status_E ret_aesCcmStat_en = CRYPTO_AEAD_ERROR_CIPNOTSUPPTD;
    
    if(ptr_aesCcmCtx_st == NULL)
    {
        ret_aesCcmStat_en = CRYPTO_AEAD_ERROR_CTX;
    }
    else if( ((ptr_inputData == NULL)&& (dataLen != 0u))
                || ((ptr_inputData != NULL)&& (dataLen == 0u)) )
    {
        ret_aesCcmStat_en = CRYPTO_AEAD_ERROR_INPUTDATA;
    }
    else if( ((ptr_inputData != NULL) && (ptr_outData == NULL))
                || ((ptr_inputData == NULL) && (ptr_outData != NULL)) )
    {
        ret_aesCcmStat_en = CRYPTO_AEAD_ERROR_OUTPUTDATA;
    }
    else if( (ptr_nonce == NULL) || (nonceLen < 7u) || (nonceLen > 13u) )
    {
        ret_aesCcmStat_en = CRYPTO_AEAD_ERROR_NONCE;
    }
    else if( (ptr_authTag == NULL) || (authTagLen < 4u) || (authTagLen > 16u) )
    {
        ret_aesCcmStat_en = CRYPTO_AEAD_ERROR_AUTHTAG;
    }
    else if( ((ptr_aad == NULL) && (aadLen != 0u))
                || ((ptr_aad != NULL) && (aadLen == 0u)))
    {
        ret_aesCcmStat_en = CRYPTO_AEAD_ERROR_AAD;
    }
    else if((ptr_inputData == NULL) && (ptr_aad == NULL))
    {
        ret_aesCcmStat_en = CRYPTO_AEAD_ERROR_ARG;
    }
    else if((cipherOper_en != CRYPTO_CIOP_ENCRYPT) && (cipherOper_en != CRYPTO_CIOP_DECRYPT))
    {
        ret_aesCcmStat_en = CRYPTO_AEAD_ERROR_CIPOPER;
    }
    else
    {
        switch(ptr_aesCcmCtx_st->aeadHandlerType_en)
        {
            case CRYPTO_HANDLER_SW_WOLFCRYPT:
                ret_aesCcmStat_en = Crypto_Aead_Wc_AesCcm_Cipher(cipherOper_en, ptr_aesCcmCtx_st->arr_aeadDataCtx, ptr_inputData, dataLen, 
                                                        ptr_outData, ptr_nonce, nonceLen, ptr_authTag, authTagLen, ptr_aad, aadLen);
                break; 

            case CRYPTO_HANDLER_HW_INTERNAL:

                break;
				
            default:
                ret_aesCcmStat_en = CRYPTO_AEAD_ERROR_HDLR;
                break;
        }
    }
    return ret_aesCcmStat_en;
}
 
crypto_Aead_Status_E Crypto_Aead_AesEax_Init(st_Crypto_Aead_AesEax_ctx *ptr_aesEaxCtx_st, crypto_HandlerType_E handlerType_en, crypto_CipherOper_E cipherOper_en, 
                                                uint8_t *ptr_key, uint32_t keyLen, uint8_t *ptr_nonce, uint32_t nonceLen, uint8_t *ptr_aad, uint32_t aadLen, uint32_t sessionID)
{
    crypto_Aead_Status_E ret_aesEaxStat_en = CRYPTO_AEAD_ERROR_CIPNOTSUPPTD;
    if(ptr_aesEaxCtx_st == NULL)
    {
        ret_aesEaxStat_en = CRYPTO_AEAD_ERROR_CTX;
    }
    else if( (ptr_key == NULL) || 
                ( (keyLen != (uint32_t)CRYPTO_AESKEYSIZE_128)
                    && (keyLen != (uint32_t)CRYPTO_AESKEYSIZE_192)
                    && (keyLen != (uint32_t)CRYPTO_AESKEYSIZE_256) ) ) 
    {
       ret_aesEaxStat_en =  CRYPTO_AEAD_ERROR_KEY;
    }
    else if((ptr_nonce == NULL) || (nonceLen == 0u))
    {
        ret_aesEaxStat_en = CRYPTO_AEAD_ERROR_NONCE;
    }
    else if( ((ptr_aad == NULL) && (aadLen > 0u)) 
                || ((ptr_aad != NULL) && (aadLen == 0u)) )
    {
        ret_aesEaxStat_en = CRYPTO_AEAD_ERROR_AAD;
    }
    else if((cipherOper_en != CRYPTO_CIOP_ENCRYPT) && (cipherOper_en != CRYPTO_CIOP_DECRYPT))
    {
        ret_aesEaxStat_en = CRYPTO_AEAD_ERROR_CIPOPER;
    }
    else if( (sessionID <= 0u) || (sessionID > (uint32_t)CRYPTO_AEAD_SESSION_MAX) )
    {
       ret_aesEaxStat_en =  CRYPTO_AEAD_ERROR_SID; 
    }    
    else
    {
        ptr_aesEaxCtx_st->cryptoSessionID =  sessionID;
        ptr_aesEaxCtx_st->aeadHandlerType_en = handlerType_en;
        ptr_aesEaxCtx_st->ptr_key = ptr_key;
        ptr_aesEaxCtx_st->aeadKeySize = keyLen;
        ptr_aesEaxCtx_st->ptr_aeadNonce = ptr_nonce;
        ptr_aesEaxCtx_st->aeadNonceLen = nonceLen;
        ptr_aesEaxCtx_st->aeadCipherOper_en = cipherOper_en;
        
        switch(ptr_aesEaxCtx_st->aeadHandlerType_en)
        {
            case CRYPTO_HANDLER_SW_WOLFCRYPT:
                    ret_aesEaxStat_en = Crypto_Aead_Wc_AesEax_Init((void*)ptr_aesEaxCtx_st->arr_aeadDataCtx, ptr_aesEaxCtx_st->ptr_key, ptr_aesEaxCtx_st->aeadKeySize,
                                                                       ptr_aesEaxCtx_st->ptr_aeadNonce, ptr_aesEaxCtx_st->aeadNonceLen, ptr_aad, aadLen);     
                break;

            case CRYPTO_HANDLER_HW_INTERNAL:
                
                break;
				
            default:
                ret_aesEaxStat_en = CRYPTO_AEAD_ERROR_HDLR;
                break;
        }
        
    }
    return ret_aesEaxStat_en;
}

crypto_Aead_Status_E Crypto_Aead_AesEax_Cipher(st_Crypto_Aead_AesEax_ctx *ptr_aesEaxCtx_st, uint8_t *ptr_inputData, uint32_t dataLen, 
                                                    uint8_t *ptr_outData, uint8_t *ptr_aad, uint32_t aadLen)
{
    crypto_Aead_Status_E ret_aesEaxStat_en = CRYPTO_AEAD_ERROR_CIPNOTSUPPTD;
    if(ptr_aesEaxCtx_st == NULL)
    {
        ret_aesEaxStat_en = CRYPTO_AEAD_ERROR_CTX;
    }
    else if((ptr_inputData == NULL) || (dataLen == 0u))
    {
        ret_aesEaxStat_en = CRYPTO_AEAD_ERROR_INPUTDATA;
    }
    else if(ptr_outData == NULL)
    {
       ret_aesEaxStat_en =  CRYPTO_AEAD_ERROR_OUTPUTDATA; 
    }  
    else if( ((ptr_aad == NULL) && (aadLen > 0u)) 
                || ((ptr_aad != NULL) && (aadLen == 0u)) )
    {
        ret_aesEaxStat_en = CRYPTO_AEAD_ERROR_AAD;
    }
    else
    {
        switch(ptr_aesEaxCtx_st->aeadHandlerType_en)
        {
            case CRYPTO_HANDLER_SW_WOLFCRYPT:
                ret_aesEaxStat_en = Crypto_Aead_Wc_AesEax_Cipher(ptr_aesEaxCtx_st->aeadCipherOper_en, ptr_aesEaxCtx_st->arr_aeadDataCtx, 
                                                                    ptr_inputData, dataLen, ptr_outData, ptr_aad, aadLen);
                break;  
         
            case CRYPTO_HANDLER_HW_INTERNAL:

                break;
				
            default:
                ret_aesEaxStat_en = CRYPTO_AEAD_ERROR_HDLR;
                break;
        }
    }
    return ret_aesEaxStat_en;
}
crypto_Aead_Status_E Crypto_Aead_AesEax_Final(st_Crypto_Aead_AesEax_ctx *ptr_aesEaxCtx_st, uint8_t *ptr_authTag, uint32_t authTagLen)
{
    crypto_Aead_Status_E ret_aesEaxStat_en = CRYPTO_AEAD_ERROR_CIPNOTSUPPTD;
    if(ptr_aesEaxCtx_st == NULL)
    {
        ret_aesEaxStat_en = CRYPTO_AEAD_ERROR_CTX;
    }
    else if(ptr_authTag == NULL || authTagLen == 0u)
    {
        ret_aesEaxStat_en = CRYPTO_AEAD_ERROR_AUTHTAG;
    }
    else
    {
        switch(ptr_aesEaxCtx_st->aeadHandlerType_en)
        {
            case CRYPTO_HANDLER_SW_WOLFCRYPT:
                ret_aesEaxStat_en = Crypto_Aead_Wc_AesEax_Final(ptr_aesEaxCtx_st->aeadCipherOper_en, ptr_aesEaxCtx_st->arr_aeadDataCtx, 
                                                                    ptr_authTag, authTagLen);
                break; 
            
            case CRYPTO_HANDLER_HW_INTERNAL:

                break;
				
            default:
                ret_aesEaxStat_en = CRYPTO_AEAD_ERROR_HDLR;
                break;
        }
    }
    return ret_aesEaxStat_en;
}
crypto_Aead_Status_E Crypto_Aead_AesEax_AddAadData(st_Crypto_Aead_AesEax_ctx *ptr_aesEaxCtx_st, uint8_t *ptr_aad, uint32_t aadLen)
{
    crypto_Aead_Status_E ret_aesEaxStat_en = CRYPTO_AEAD_ERROR_CIPNOTSUPPTD;
    if(ptr_aesEaxCtx_st == NULL)
    {
        ret_aesEaxStat_en = CRYPTO_AEAD_ERROR_CTX;
    }
    else if( (aadLen == 0u) || (ptr_aad == NULL) )
    {
        ret_aesEaxStat_en = CRYPTO_AEAD_ERROR_AAD;
    }
    else
    {
        switch(ptr_aesEaxCtx_st->aeadHandlerType_en)
        {
            case CRYPTO_HANDLER_SW_WOLFCRYPT:
                ret_aesEaxStat_en = Crypto_Aead_Wc_AesEax_AddAadData(ptr_aesEaxCtx_st->arr_aeadDataCtx, ptr_aad, aadLen); 
                break;  
        
            case CRYPTO_HANDLER_HW_INTERNAL:

                break;
				
            default:
                ret_aesEaxStat_en = CRYPTO_AEAD_ERROR_HDLR;
                break;
        }
    }
    return ret_aesEaxStat_en;
}

crypto_Aead_Status_E Crypto_Aead_AesEax_EncryptAuthDirect(crypto_HandlerType_E handlerType_en, uint8_t *ptr_inputData, uint32_t dataLen, 
                                                            uint8_t *ptr_outData, uint8_t *ptr_key, uint32_t keyLen, uint8_t *ptr_nonce, 
                                                            uint32_t nonceLen, uint8_t *ptr_aad, uint32_t aadLen, uint8_t *ptr_authTag, uint32_t authTagLen, uint32_t sessionID)
{
    crypto_Aead_Status_E ret_aesEaxStat_en = CRYPTO_AEAD_ERROR_CIPNOTSUPPTD;
    if((ptr_inputData == NULL) || (dataLen == 0u))
    {
        ret_aesEaxStat_en = CRYPTO_AEAD_ERROR_INPUTDATA;
    }
    else if(ptr_outData == NULL)
    {
       ret_aesEaxStat_en =  CRYPTO_AEAD_ERROR_OUTPUTDATA; 
    }
    else if( (ptr_key == NULL) || 
                ( (keyLen != (uint32_t)CRYPTO_AESKEYSIZE_128)
                    && (keyLen != (uint32_t)CRYPTO_AESKEYSIZE_192)
                    && (keyLen != (uint32_t)CRYPTO_AESKEYSIZE_256) ) ) 
    {
       ret_aesEaxStat_en =  CRYPTO_AEAD_ERROR_KEY;
    }
    else if( (sessionID <= 0u) || (sessionID > (uint32_t)CRYPTO_AEAD_SESSION_MAX) )
    {
       ret_aesEaxStat_en =  CRYPTO_AEAD_ERROR_SID; 
    } 
    else if((ptr_nonce == NULL) || (nonceLen == 0u))
    {
        ret_aesEaxStat_en = CRYPTO_AEAD_ERROR_NONCE;
    }
    else if( ((aadLen > 0u) && (ptr_aad == NULL))
               || ((aadLen == 0u) && (ptr_aad != NULL)) )
    {
        ret_aesEaxStat_en = CRYPTO_AEAD_ERROR_AAD;
    }
    else if((ptr_authTag == NULL) || (authTagLen == 0u))
    {
        ret_aesEaxStat_en = CRYPTO_AEAD_ERROR_AUTHTAG;
    }
    else
    {
        switch(handlerType_en)
        {
            case CRYPTO_HANDLER_SW_WOLFCRYPT:
                ret_aesEaxStat_en = Crypto_Aead_Wc_AesEax_EncDecAuthDirect(CRYPTO_CIOP_ENCRYPT, ptr_inputData, dataLen, ptr_outData, 
                                                                           ptr_key, keyLen, ptr_nonce, nonceLen, ptr_aad, aadLen, ptr_authTag, authTagLen);
                break;
          
            case CRYPTO_HANDLER_HW_INTERNAL:

                break;
				
            default:
                ret_aesEaxStat_en = CRYPTO_AEAD_ERROR_HDLR;
                break;
        }
    }
    return ret_aesEaxStat_en;
}

crypto_Aead_Status_E Crypto_Aead_AesEax_DecryptAuthDirect(crypto_HandlerType_E handlerType_en, uint8_t *ptr_inputData, uint32_t dataLen, 
                                                            uint8_t *ptr_outData, uint8_t *ptr_key, uint32_t keyLen, uint8_t *ptr_nonce, 
                                                            uint32_t nonceLen, uint8_t *ptr_aad, uint32_t aadLen, uint8_t *ptr_authTag, uint32_t authTagLen, uint32_t sessionID)
{
    crypto_Aead_Status_E ret_aesEaxStat_en = CRYPTO_AEAD_ERROR_CIPNOTSUPPTD;
    if((ptr_inputData == NULL) || (dataLen == 0u))
    {
        ret_aesEaxStat_en = CRYPTO_AEAD_ERROR_INPUTDATA;
    }
    else if(ptr_outData == NULL)
    {
       ret_aesEaxStat_en =  CRYPTO_AEAD_ERROR_OUTPUTDATA; 
    }
    else if( (ptr_key == NULL) || 
                ( (keyLen != (uint32_t)CRYPTO_AESKEYSIZE_128)
                    && (keyLen != (uint32_t)CRYPTO_AESKEYSIZE_192)
                    && (keyLen != (uint32_t)CRYPTO_AESKEYSIZE_256) ) ) 
    {
       ret_aesEaxStat_en =  CRYPTO_AEAD_ERROR_KEY;
    }
    else if( (sessionID <= 0u) || (sessionID > (uint32_t)CRYPTO_AEAD_SESSION_MAX) )
    {
       ret_aesEaxStat_en =  CRYPTO_AEAD_ERROR_SID; 
    } 
    else if((ptr_nonce == NULL) || (nonceLen == 0u))
    {
        ret_aesEaxStat_en = CRYPTO_AEAD_ERROR_NONCE;
    }
    else if( ((aadLen > 0u) && (ptr_aad == NULL))
               || ((aadLen == 0u) && (ptr_aad != NULL)) )
    {
        ret_aesEaxStat_en = CRYPTO_AEAD_ERROR_AAD;
    }
    else if((ptr_authTag == NULL) || (authTagLen == 0u))
    {
        ret_aesEaxStat_en = CRYPTO_AEAD_ERROR_AUTHTAG;
    }
    else
    {
        switch(handlerType_en)
        {
            case CRYPTO_HANDLER_SW_WOLFCRYPT:
                ret_aesEaxStat_en = Crypto_Aead_Wc_AesEax_EncDecAuthDirect(CRYPTO_CIOP_DECRYPT, ptr_inputData, dataLen, ptr_outData, 
                                                                           ptr_key, keyLen, ptr_nonce, nonceLen, ptr_aad, aadLen, ptr_authTag, authTagLen);
                break;  
 
            case CRYPTO_HANDLER_HW_INTERNAL:

                break;
				
            default:
                ret_aesEaxStat_en = CRYPTO_AEAD_ERROR_HDLR;
                break;
        }
    }
    return ret_aesEaxStat_en;
}

crypto_Aead_Status_E Crypto_Aead_AesGcm_Init(st_Crypto_Aead_AesGcm_ctx *ptr_aesGcmCtx_st, crypto_HandlerType_E handlerType_en, crypto_CipherOper_E cipherOper_en, 
                                                              uint8_t *ptr_key, uint32_t keyLen, uint8_t *ptr_initVect, uint32_t initVectLen, uint32_t sessionID)
{
    crypto_Aead_Status_E ret_aesGcmStat_en = CRYPTO_AEAD_ERROR_CIPNOTSUPPTD;
    
    if(ptr_aesGcmCtx_st == NULL)
    {
        ret_aesGcmStat_en = CRYPTO_AEAD_ERROR_CTX;
    }
    else if( (ptr_key == NULL) || 
                    ( (keyLen != (uint32_t)CRYPTO_AESKEYSIZE_128)
                        && (keyLen != (uint32_t)CRYPTO_AESKEYSIZE_192)
                        && (keyLen != (uint32_t)CRYPTO_AESKEYSIZE_256) ) ) 
    {
       ret_aesGcmStat_en =  CRYPTO_AEAD_ERROR_KEY;
    }
    else if(ptr_initVect == NULL || initVectLen == 0u)
    {
        ret_aesGcmStat_en = CRYPTO_AEAD_ERROR_NONCE;
    }
    else if((cipherOper_en != CRYPTO_CIOP_ENCRYPT) && (cipherOper_en != CRYPTO_CIOP_DECRYPT))
    {
        ret_aesGcmStat_en = CRYPTO_AEAD_ERROR_CIPOPER;
    }
    else if( (sessionID <= 0u) || (sessionID > (uint32_t)CRYPTO_AEAD_SESSION_MAX) )
    {
       ret_aesGcmStat_en =  CRYPTO_AEAD_ERROR_SID; 
    }
    else
    {
        ptr_aesGcmCtx_st->cryptoSessionID =  sessionID;
        ptr_aesGcmCtx_st->aeadHandlerType_en = handlerType_en;
        ptr_aesGcmCtx_st->ptr_key = ptr_key;
        ptr_aesGcmCtx_st->aeadKeySize = keyLen;
        ptr_aesGcmCtx_st->aeadCipherOper_en = cipherOper_en;
        ptr_aesGcmCtx_st->ptr_initVect = ptr_initVect;
        ptr_aesGcmCtx_st->initVectLen = initVectLen;
                
        switch(ptr_aesGcmCtx_st->aeadHandlerType_en)
        {
            case CRYPTO_HANDLER_SW_WOLFCRYPT:
                ret_aesGcmStat_en = Crypto_Aead_Wc_AesGcm_Init((void*)ptr_aesGcmCtx_st->arr_aeadDataCtx, ptr_aesGcmCtx_st->ptr_key, 
                                                                                ptr_aesGcmCtx_st->aeadKeySize, ptr_initVect, initVectLen);     
                break;
            case CRYPTO_HANDLER_HW_INTERNAL:
                ret_aesGcmStat_en = Crypto_Aead_Hw_AesGcm_Init((void*)ptr_aesGcmCtx_st->arr_aeadDataCtx,cipherOper_en, ptr_aesGcmCtx_st->ptr_key, ptr_aesGcmCtx_st->aeadKeySize);    
				break;	
            default:
                ret_aesGcmStat_en = CRYPTO_AEAD_ERROR_HDLR;
                break;
        }
        
    }
    return ret_aesGcmStat_en;
}

crypto_Aead_Status_E Crypto_Aead_AesGcm_AddAadData(st_Crypto_Aead_AesGcm_ctx *ptr_aesGcmCtx_st, uint8_t *ptr_aad, uint32_t aadLen)
{
    crypto_Aead_Status_E ret_aesGcmStat_en = CRYPTO_AEAD_ERROR_CIPNOTSUPPTD;
    if(ptr_aesGcmCtx_st == NULL)
    {
        ret_aesGcmStat_en = CRYPTO_AEAD_ERROR_CTX;
    }
    else if((ptr_aad == NULL) || (aadLen == 0u))
    {
        ret_aesGcmStat_en = CRYPTO_AEAD_ERROR_AAD;
    }
    else
    {
        switch(ptr_aesGcmCtx_st->aeadHandlerType_en)
        {
            case CRYPTO_HANDLER_SW_WOLFCRYPT:
                ret_aesGcmStat_en = Crypto_Aead_Wc_AesGcm_AddAadData(ptr_aesGcmCtx_st->aeadCipherOper_en, ptr_aesGcmCtx_st->arr_aeadDataCtx, ptr_aad, aadLen);
                break;  
            case CRYPTO_HANDLER_HW_INTERNAL:
                ret_aesGcmStat_en = Crypto_Aead_Hw_AesGcm_Cipher((void*)ptr_aesGcmCtx_st->arr_aeadDataCtx, NULL, 0, NULL, 0, NULL, ptr_aad, aadLen, NULL, 0); 
                break;
            default:
                ret_aesGcmStat_en = CRYPTO_AEAD_ERROR_HDLR;
                break;
        }
    }
    return ret_aesGcmStat_en;
}

crypto_Aead_Status_E Crypto_Aead_AesGcm_Cipher(st_Crypto_Aead_AesGcm_ctx *ptr_aesGcmCtx_st, uint8_t *ptr_inputData, uint32_t dataLen, 
                                                    uint8_t *ptr_outData)
{
    crypto_Aead_Status_E ret_aesGcmStat_en = CRYPTO_AEAD_ERROR_CIPNOTSUPPTD;
    if(ptr_aesGcmCtx_st == NULL)
    {
        ret_aesGcmStat_en = CRYPTO_AEAD_ERROR_CTX;
    }
    else if((ptr_inputData == NULL) || (dataLen == 0u))
    {
        ret_aesGcmStat_en = CRYPTO_AEAD_ERROR_INPUTDATA;
    }
    else if(ptr_outData == NULL)
    {
       ret_aesGcmStat_en =  CRYPTO_AEAD_ERROR_OUTPUTDATA; 
    }  
    else
    {
        switch(ptr_aesGcmCtx_st->aeadHandlerType_en)
        {
            case CRYPTO_HANDLER_SW_WOLFCRYPT:
                ret_aesGcmStat_en = Crypto_Aead_Wc_AesGcm_Cipher(ptr_aesGcmCtx_st->aeadCipherOper_en, ptr_aesGcmCtx_st->arr_aeadDataCtx, 
                                                                    ptr_inputData, dataLen, ptr_outData);
                break;  
            case CRYPTO_HANDLER_HW_INTERNAL:
                ret_aesGcmStat_en = Crypto_Aead_Hw_AesGcm_Cipher((void*)ptr_aesGcmCtx_st->arr_aeadDataCtx, ptr_aesGcmCtx_st->ptr_initVect, ptr_aesGcmCtx_st->initVectLen,
                                                                                                             ptr_inputData, dataLen, ptr_outData, NULL, 0, NULL, 0);     
                break;
            default:
                ret_aesGcmStat_en = CRYPTO_AEAD_ERROR_HDLR;
                break;
        }
    }
    return ret_aesGcmStat_en;
}

crypto_Aead_Status_E Crypto_Aead_AesGcm_Final(st_Crypto_Aead_AesGcm_ctx *ptr_aesGcmCtx_st, uint8_t *ptr_authTag, uint8_t authTagLen)
{
    crypto_Aead_Status_E ret_aesGcmStat_en = CRYPTO_AEAD_ERROR_CIPNOTSUPPTD;
    if(ptr_aesGcmCtx_st == NULL)
    {
        ret_aesGcmStat_en = CRYPTO_AEAD_ERROR_CTX;
    }
    else if((ptr_authTag == NULL) || (authTagLen > 16u) || (authTagLen < 4u))
    {
        ret_aesGcmStat_en = CRYPTO_AEAD_ERROR_AUTHTAG;
    }
    else
    {
        switch(ptr_aesGcmCtx_st->aeadHandlerType_en)
        {
            case CRYPTO_HANDLER_SW_WOLFCRYPT:
                ret_aesGcmStat_en = Crypto_Aead_Wc_AesGcm_Final(ptr_aesGcmCtx_st->aeadCipherOper_en, ptr_aesGcmCtx_st->arr_aeadDataCtx, 
                                                                    ptr_authTag, authTagLen);
                break; 
            case CRYPTO_HANDLER_HW_INTERNAL:
                ret_aesGcmStat_en = Crypto_Aead_Hw_AesGcm_Cipher((void*)ptr_aesGcmCtx_st->arr_aeadDataCtx, NULL, 0,NULL, 0, NULL, NULL, 0, ptr_authTag, authTagLen);     
                break;
            default:
                ret_aesGcmStat_en = CRYPTO_AEAD_ERROR_HDLR;
                break;
        }
    }
    return ret_aesGcmStat_en;
}

crypto_Aead_Status_E Crypto_Aead_AesGcm_EncryptAuthDirect(crypto_HandlerType_E handlerType_en, uint8_t *ptr_inputData, uint32_t dataLen, 
                                                            uint8_t *ptr_outData, uint8_t *ptr_key, uint32_t keyLen, uint8_t *ptr_initVect, 
                                                            uint32_t initVectLen, uint8_t *ptr_aad, uint32_t aadLen, uint8_t *ptr_authTag, uint8_t authTagLen, uint32_t sessionID)
{
    crypto_Aead_Status_E ret_aesGcmStat_en = CRYPTO_AEAD_ERROR_CIPNOTSUPPTD;
    if( ((ptr_inputData == NULL) && (dataLen > 0u))
                || ((ptr_inputData != NULL) && (dataLen == 0u)) )
    {
        ret_aesGcmStat_en = CRYPTO_AEAD_ERROR_INPUTDATA;
    }
    else if( ((ptr_inputData != NULL) && (ptr_outData == NULL))
                || ((ptr_inputData == NULL) && (ptr_outData != NULL)) )
    {
       ret_aesGcmStat_en =  CRYPTO_AEAD_ERROR_OUTPUTDATA; 
    }
    else if( (ptr_key == NULL) || 
                ( (keyLen != (uint32_t)CRYPTO_AESKEYSIZE_128)
                    && (keyLen != (uint32_t)CRYPTO_AESKEYSIZE_192)
                    && (keyLen != (uint32_t)CRYPTO_AESKEYSIZE_256) ) ) 
    {
       ret_aesGcmStat_en =  CRYPTO_AEAD_ERROR_KEY;
    }
    else if(ptr_initVect == NULL || initVectLen == 0u)
    {
        ret_aesGcmStat_en = CRYPTO_AEAD_ERROR_NONCE;
    }
    else if( ((ptr_aad == NULL) && (aadLen > 0u))
                || ((ptr_aad != NULL) && (aadLen == 0u)) )
    {
        ret_aesGcmStat_en = CRYPTO_AEAD_ERROR_AAD;
    }
    else if((ptr_authTag == NULL) || (authTagLen > 16u) || (authTagLen < 4u))
    {
        ret_aesGcmStat_en = CRYPTO_AEAD_ERROR_AUTHTAG;
    }
//    else if((ptr_aad == NULL) && (ptr_inputData == NULL))
//    {
//        ret_aesGcmStat_en = CRYPTO_AEAD_ERROR_ARG;
//    }
    else if( (sessionID <= 0u) || (sessionID > (uint32_t)CRYPTO_AEAD_SESSION_MAX) )
    {
       ret_aesGcmStat_en =  CRYPTO_AEAD_ERROR_SID; 
    } 
    else
    {
        switch(handlerType_en)
        {
            case CRYPTO_HANDLER_SW_WOLFCRYPT:
                ret_aesGcmStat_en =  Crypto_Aead_Wc_AesGcm_EncDecAuthDirect(CRYPTO_CIOP_ENCRYPT, ptr_inputData, dataLen, ptr_outData, ptr_key, keyLen, 
                                                ptr_initVect, initVectLen, ptr_aad, aadLen, ptr_authTag, authTagLen);
                break;
            case CRYPTO_HANDLER_HW_INTERNAL:
                ret_aesGcmStat_en = Crypto_Aead_Hw_AesGcm_EncryptAuthDirect(ptr_inputData, dataLen, ptr_outData, ptr_key, keyLen, 
                                                            ptr_initVect, initVectLen, ptr_aad, aadLen, ptr_authTag, authTagLen);
                break;
            default:
                ret_aesGcmStat_en = CRYPTO_AEAD_ERROR_HDLR;
                break;
        }
    }
    return ret_aesGcmStat_en;
}

crypto_Aead_Status_E Crypto_Aead_AesGcm_DecryptAuthDirect(crypto_HandlerType_E handlerType_en, uint8_t *ptr_inputData, uint32_t dataLen, 
                                                            uint8_t *ptr_outData, uint8_t *ptr_key, uint32_t keyLen, uint8_t *ptr_initVect, 
                                                            uint32_t initVectLen, uint8_t *ptr_aad, uint32_t aadLen, uint8_t *ptr_authTag, uint8_t authTagLen, uint32_t sessionID)
{
    crypto_Aead_Status_E ret_aesGcmStat_en = CRYPTO_AEAD_ERROR_CIPNOTSUPPTD;
    if( ((ptr_inputData == NULL) && (dataLen > 0u))
        || ((ptr_inputData != NULL) && (dataLen == 0u)) )
    {
        ret_aesGcmStat_en = CRYPTO_AEAD_ERROR_INPUTDATA;
    }
    else if( ((ptr_inputData != NULL) && (ptr_outData == NULL))
                || ((ptr_inputData == NULL) && (ptr_outData != NULL)) )
    {
       ret_aesGcmStat_en =  CRYPTO_AEAD_ERROR_OUTPUTDATA; 
    }
    else if( (ptr_key == NULL) || 
                ( (keyLen != (uint32_t)CRYPTO_AESKEYSIZE_128)
                    && (keyLen != (uint32_t)CRYPTO_AESKEYSIZE_192)
                    && (keyLen != (uint32_t)CRYPTO_AESKEYSIZE_256) ) ) 
    {
       ret_aesGcmStat_en =  CRYPTO_AEAD_ERROR_KEY;
    }
        else if(ptr_initVect == NULL || initVectLen == 0u)
    {
        ret_aesGcmStat_en = CRYPTO_AEAD_ERROR_NONCE;
    }
    else if( ((ptr_aad == NULL) && (aadLen > 0u))
                || ((ptr_aad != NULL) && (aadLen == 0u)) )
    {
        ret_aesGcmStat_en = CRYPTO_AEAD_ERROR_AAD;
    }
    else if((ptr_authTag == NULL) || (authTagLen > 16u) || (authTagLen < 4u))
    {
        ret_aesGcmStat_en = CRYPTO_AEAD_ERROR_AUTHTAG;
    }
    else if((ptr_aad == NULL) && (ptr_inputData == NULL))
    {
        ret_aesGcmStat_en = CRYPTO_AEAD_ERROR_ARG;
    }
    else if( (sessionID <= 0u) || (sessionID > (uint32_t)CRYPTO_AEAD_SESSION_MAX) )
    {
       ret_aesGcmStat_en =  CRYPTO_AEAD_ERROR_SID; 
    } 
    else
    {
        switch(handlerType_en)
        {
            case CRYPTO_HANDLER_SW_WOLFCRYPT:
                ret_aesGcmStat_en =  Crypto_Aead_Wc_AesGcm_EncDecAuthDirect(CRYPTO_CIOP_DECRYPT, ptr_inputData, dataLen, ptr_outData, ptr_key, keyLen, 
                                                ptr_initVect, initVectLen, ptr_aad, aadLen, ptr_authTag, authTagLen);
                break;
            case CRYPTO_HANDLER_HW_INTERNAL:
                ret_aesGcmStat_en = Crypto_Aead_Hw_AesGcm_DecryptAuthDirect(ptr_inputData, dataLen, ptr_outData, ptr_key, keyLen, 
                                                            ptr_initVect, initVectLen, ptr_aad, aadLen, ptr_authTag, authTagLen);
                break;
            default:
                ret_aesGcmStat_en = CRYPTO_AEAD_ERROR_HDLR;
                break;
        }
    }
    return ret_aesGcmStat_en;
}
// *****************************************************************************