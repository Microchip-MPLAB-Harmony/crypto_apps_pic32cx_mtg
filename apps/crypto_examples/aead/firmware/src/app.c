/*******************************************************************************
  MPLAB Harmony Application Source File

  Company:
    Microchip Technology Inc.

  File Name:
    app.c

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

#include "app.h"

// *****************************************************************************
// *****************************************************************************
// Section: Global Data Definitions
// *****************************************************************************
// *****************************************************************************

#define SESSION_ID    1

uint8_t testsPassed;
uint8_t testsFailed;

// *****************************************************************************
/* Application Data

  Summary:
    Holds application data

  Description:
    This structure holds the application's data.

  Remarks:
    This structure should be initialized by the APP_Initialize function.

    Application strings and buffers are be defined outside this structure.
*/

APP_DATA appData;

// *****************************************************************************
// *****************************************************************************
// Section: Application Local Functions
// *****************************************************************************
// *****************************************************************************

/*******************************************************************************
  Function:
    void AES_GCM_SingleStep (GCM *gcm)

  Remarks:
    See prototype in app.h.
 */

void AES_GCM_SingleStep (GCM *gcm)
{
    crypto_Aead_Status_E status;
    
    (void) memset(gcm->symData, 0, gcm->symDataSize);

    SYSTICK_TimerRestart();
    uint32_t startTime = 0, endTime = 0;
    startTime = SYSTICK_TimerCounterGet();
    
    status = Crypto_Aead_AesGcm_EncryptAuthDirect(
        gcm->handler,
        gcm->pt,
        gcm->ptSize,
        gcm->symData,
        gcm->key,
        gcm->keySize,
        gcm->iv,
        gcm->ivSize,
        gcm->aad,
        gcm->aadSize,
        gcm->authTag,
        gcm->authTagSize,
        SESSION_ID
    );
    if (status != CRYPTO_AEAD_CIPHER_SUCCESS)
    {
        printf("Failed to create cipher text\r\n");
        printf("Status: %d\r\n", status);
    }
    
    /* save ciphertext from msgOut to decipher*/
    (void) memcpy(gcm->cipher, gcm->symData, gcm->cipherSize);
           
    status = Crypto_Aead_AesGcm_DecryptAuthDirect(
        gcm->handler,
        gcm->cipher,
        gcm->cipherSize,
        gcm->symData,
        gcm->key,
        gcm->keySize,
        gcm->iv,
        gcm->ivSize,
        gcm->aad,
        gcm->aadSize,
        gcm->authTag,
        gcm->authTagSize,
        SESSION_ID
    );

    endTime = SYSTICK_TimerCounterGet();
    printf("Time elapsed (ms): %f\r\n", (double)(startTime - endTime)/(SYSTICK_FREQ/1000U));

    if (status != CRYPTO_AEAD_CIPHER_SUCCESS)
    {
        printf("Failed to decipher text, status: %d\r\n", status);
        testsFailed++;
    }
    else
    {
        bool outputMatch = CompareHexArray(gcm->symData, gcm->pt, gcm->ptSize);

        if (outputMatch)
        {
            testsPassed++;
            printf("Test successful\r\n");
        }
        else
        {
            testsFailed++;
            printf("Test unsuccessful\r\n");
        }
    }
}


/*******************************************************************************
  Function:
    void AES_GCM_MultiStep (GCM *gcm)

  Remarks:
    See prototype in app.h.
 */

void AES_GCM_MultiStep (GCM *gcm)
{
    crypto_Aead_Status_E status;
    
    (void) memset(gcm->symData, 0, gcm->symDataSize);
    
    SYSTICK_TimerRestart();
    uint32_t startTime = 0, endTime = 0;
    startTime = SYSTICK_TimerCounterGet();
    
    status = Crypto_Aead_AesGcm_Init(
        &gcm->AesGcm_ctx,
        gcm->handler,
        CRYPTO_CIOP_ENCRYPT,
        gcm->key,
        gcm->keySize,
        gcm->iv,
        gcm->ivSize,
        SESSION_ID
    );
    if (status != CRYPTO_AEAD_CIPHER_SUCCESS)
    {
        printf("Failed to initialize structure, status: %d\r\n", status);
    }

    status =  Crypto_Aead_AesGcm_AddAadData(
        &gcm->AesGcm_ctx,
        gcm->aad,
        gcm->aadSize
    );
    if (status != CRYPTO_AEAD_CIPHER_SUCCESS)
    {
        printf("Failed to add associated data\r\n");
        printf("Status: %d\r\n", status);
    }

    status = Crypto_Aead_AesGcm_Cipher(
        &gcm->AesGcm_ctx,
        gcm->pt,
        gcm->ptSize,
        gcm->symData
    );
    if (status != CRYPTO_AEAD_CIPHER_SUCCESS)
    {
        printf("Failed to add select cipher direction, status: \r\n", status);
    }

    status = Crypto_Aead_AesGcm_Final(
        &gcm->AesGcm_ctx,
        gcm->authTag,
        gcm->authTagSize
    );
    if (status != CRYPTO_AEAD_CIPHER_SUCCESS)
    {
        printf("Failed to finalize cipher text, status: %d\r\n", status);
    }

    /* save ciphertext from msgOut to decipher*/
    (void) memcpy(gcm->cipher, gcm->symData, gcm->cipherSize);

    status = Crypto_Aead_AesGcm_Init(
        &gcm->AesGcm_ctx,
        gcm->handler,
        CRYPTO_CIOP_DECRYPT,
        gcm->key,
        gcm->keySize,
        gcm->iv,
        gcm->ivSize,
        SESSION_ID
    );
    if (status != CRYPTO_AEAD_CIPHER_SUCCESS)
    {
        printf("Failed to initialize structure, status: %d\r\n", status);
    }

    status =  Crypto_Aead_AesGcm_AddAadData(
        &gcm->AesGcm_ctx,
        gcm->aad,
        gcm->aadSize
    );
    if (status != CRYPTO_AEAD_CIPHER_SUCCESS)
    {
        printf("Failed to add associated data\r\n");
    }

    status = Crypto_Aead_AesGcm_Cipher(
        &gcm->AesGcm_ctx,
        gcm->cipher,
        gcm->cipherSize,
        gcm->symData
    );
    if (status != CRYPTO_AEAD_CIPHER_SUCCESS)
    {
        printf("Failed to add select cipher direction, status: %d\r\n", status);
    }

    status = Crypto_Aead_AesGcm_Final(
        &gcm->AesGcm_ctx,
        gcm->authTag,
        gcm->authTagSize
    );

    endTime = SYSTICK_TimerCounterGet();
    printf("Time elapsed (ms): %f\r\n", (double)(startTime - endTime)/(SYSTICK_FREQ/1000U));

    if (status != CRYPTO_AEAD_CIPHER_SUCCESS)
    {
        printf("Failed to decipher text, status: %d\r\n", status);
        testsFailed++;
    }
    else
    {
        bool outputMatch = CompareHexArray(gcm->symData, gcm->pt, gcm->ptSize);

        if (outputMatch)
        {
            testsPassed++;
            printf("Test successful\r\n");
        }
        else
        {
            testsFailed++;
            printf("Test unsuccessful\r\n");
        }
    }
}


/*******************************************************************************
  Function:
    void AES_CCM_MultiStep (CCM *ccm)

  Remarks:
    See prototype in app.h.
 */

void AES_CCM_MultiStep (CCM *ccm)
{    
    crypto_Aead_Status_E status;
    
    (void) memset(ccm->symData, 0, ccm->symDataSize);

    SYSTICK_TimerRestart();
    uint32_t startTime = 0, endTime = 0;
    startTime = SYSTICK_TimerCounterGet(); 

    status = Crypto_Aead_AesCcm_Init(
        &ccm->AesCcm_ctx,
        ccm->handler,
        ccm->key,
        ccm->keySize,
        SESSION_ID
    );
    if (status != CRYPTO_AEAD_CIPHER_SUCCESS)
    {
        printf("Failed to initialize structure, status: %d\r\n", status);
    }

    status = Crypto_Aead_AesCcm_Cipher(
        &ccm->AesCcm_ctx,
        CRYPTO_CIOP_ENCRYPT,
        ccm->pt,
        ccm->ptSize,
        ccm->symData,
        ccm->iv,
        ccm->ivSize,
        ccm->authTag,
        ccm->authTagSize,
        ccm->aad,
        ccm->aadSize
    );
    if (status != CRYPTO_AEAD_CIPHER_SUCCESS)
    {
        printf("Failed to add select cipher direction, status: \r\n", status);
    }

    status = Crypto_Aead_AesCcm_Cipher(
        &ccm->AesCcm_ctx,
        CRYPTO_CIOP_DECRYPT,
        ccm->symData,
        ccm->ptSize,
        ccm->symData,
        ccm->iv,
        ccm->ivSize,
        ccm->authTag,
        ccm->authTagSize,
        ccm->aad,
        ccm->aadSize
    );

    endTime = SYSTICK_TimerCounterGet();
    printf("Time elapsed (ms): %f\r\n", (double)(startTime - endTime)/(SYSTICK_FREQ/1000U));

    if (status != CRYPTO_AEAD_CIPHER_SUCCESS)
    {
        printf("Failed to decipher text, status: %d\r\n", status);
        testsFailed++;
    }
    else
    {
        bool outputMatch = CompareHexArray(ccm->symData, ccm->pt, ccm->ptSize);

        if (outputMatch)
        {
            testsPassed++;
            printf("Test successful\r\n");
        }
        else
        {
            testsFailed++;
            printf("Test unsuccessful\r\n");
        }
    }
}

// *****************************************************************************
// *****************************************************************************
// Section: Application Initialization and State Machine Functions
// *****************************************************************************
// *****************************************************************************

/*******************************************************************************
  Function:
    void APP_Initialize ( void )

  Remarks:
    See prototype in app.h.
 */

void APP_Initialize ( void )
{
    /* Place the App state machine in its initial state. */
    appData.state = APP_STATE_INIT;
    appData.isTestedAES_GCM = false;
}

/******************************************************************************
  Function:
    void APP_Tasks ( void )

  Remarks:
    See prototype in app.h.
 */

void APP_Tasks ( void )
{
    /* Check the application's current state. */
    switch ( appData.state )
    {
        /* Application's initial state. */
        case APP_STATE_INIT:
        {
            testsPassed = 0;
            testsFailed = 0;
            
            SYSTICK_TimerInitialize();
            SYSTICK_TimerPeriodSet(INT32_MAX);

            bool appInitialized = true;

            if (appInitialized)
            {
                appData.state = APP_STATE_SERVICE_TASKS;
            }

            break;
        }

        case APP_STATE_SERVICE_TASKS:
        {           
            if (!appData.isTestedAES_GCM && !appData.isTestedAES_CCM)
            {
                SYSTICK_TimerStart(); 
                
                printf("\r\n-------AEAD AES-GCM Hardware Wrapper-------\r\n");
                AES_GCM_Test(CRYPTO_HANDLER_HW_INTERNAL);
                
                printf("\r\n-------AEAD AES-GCM wolfCrypt Wrapper-------\r\n");
                AES_GCM_Test(CRYPTO_HANDLER_SW_WOLFCRYPT);
                
                appData.isTestedAES_GCM = true;
                
                printf("\r\n-------AEAD AES-CCM wolfCrypt Wrapper-------\r\n");
                AES_CCM_Test(CRYPTO_HANDLER_SW_WOLFCRYPT);
                
                appData.isTestedAES_CCM = true;
                               
                printf("\r\n-----------------------------------\r\n");
                printf("Tests attempted: %d", testsPassed + testsFailed);
                printf("\r\nTests successful: %d\r\n", testsPassed);
                
                SYSTICK_TimerStop();
            }
            
            break;
        }

        /* The default state should never be executed. */
        default:
        {
            __conditional_software_breakpoint(1);
            break;
        }
    }

}

/*******************************************************************************
 End of File
 */
