/*******************************************************************************
  MPLAB Harmony Application Source File

  Company:
    Microchip Technology Inc.

  File Name:
    crypto_kas_wc_wrapper.c

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
#include "crypto/common_crypto/crypto_common.h"
#include "crypto/common_crypto/crypto_kas.h"
#include "crypto/wolfcrypt/crypto_kas_wc_wrapper.h"
#include "crypto/wolfcrypt/crypto_common_wc_wrapper.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include "wolfssl/wolfcrypt/ecc.h"

crypto_Kas_Status_E Crypto_Kas_Wc_Ecdh_SharedSecret(uint8_t *ptr_wcPrivKey, uint32_t wcPrivKeyLen, uint8_t *ptr_wcPubKey, uint32_t wcPubKeyLen, uint8_t *ptr_wcSharedSecret,
                                                    uint32_t wcSharedSecretLen, crypto_EccCurveType_E wcEccCurveType_en)
{
    crypto_Kas_Status_E ret_wcEcdhStat_en = CRYPTO_KAS_ERROR_ALGONOTSUPPTD;
    ecc_key wcEccPrivKey_st;
    ecc_key wcEccPubKey_st;
    int wcEcdhStatus = BAD_FUNC_ARG;
    int wcEccCurveId = (int)ECC_CURVE_INVALID;
    word32 sharedSecretLen = wcSharedSecretLen;
    
    wcEccCurveId = Crypto_Common_Wc_Ecc_GetWcCurveId(wcEccCurveType_en);
    
    if(wcEccCurveId == (int)ECC_CURVE_INVALID)
    {
        ret_wcEcdhStat_en = CRYPTO_KAS_ERROR_CURVE;
    }
    else
    {
        //Process ECC Private Key 
        wcEcdhStatus = wc_ecc_init(&wcEccPrivKey_st);
        if(wcEcdhStatus == 0)
        {
            /* Import private key, public part optional if (pub) passed as NULL */
            wcEcdhStatus = wc_ecc_import_private_key_ex(ptr_wcPrivKey, wcPrivKeyLen, /* private key "d" */
                                                        NULL, 0,            /* public (optional) */
                                                        &wcEccPrivKey_st,
                                                        wcEccCurveId     /* ECC Curve Id */
                                                        );
            if(wcEcdhStatus == 0)
            {
                //Process ECC Public Key 
                wcEcdhStatus = wc_ecc_init(&wcEccPubKey_st);

                if(wcEcdhStatus == 0)
                {
                    /* Import public ECC key in ANSI X9.63 format */
                    wcEcdhStatus = wc_ecc_import_x963_ex(ptr_wcPubKey, wcPubKeyLen, &wcEccPubKey_st, wcEccCurveId);
                    if(wcEcdhStatus == 0)
                    {
                        /* Generate Shared Secret using ECDH*/
                        wcEcdhStatus = wc_ecc_shared_secret(&wcEccPrivKey_st, &wcEccPubKey_st, ptr_wcSharedSecret, &sharedSecretLen);
                    }
                }
            }
        }
        if(wcEcdhStatus == 0)
        {
            ret_wcEcdhStat_en = CRYPTO_KAS_SUCCESS;
        }
        else if(wcEcdhStatus == ECC_CURVE_OID_E)
        {
            ret_wcEcdhStat_en = CRYPTO_KAS_ERROR_CURVE;
        }
        else if( (wcEcdhStatus == BAD_FUNC_ARG) || (wcEcdhStatus == ECC_BAD_ARG_E) )
        {
            ret_wcEcdhStat_en = CRYPTO_KAS_ERROR_ARG;
        }
        else
        {
            ret_wcEcdhStat_en = CRYPTO_KAS_ERROR_FAIL;
        }
    }
    return ret_wcEcdhStat_en;
}
