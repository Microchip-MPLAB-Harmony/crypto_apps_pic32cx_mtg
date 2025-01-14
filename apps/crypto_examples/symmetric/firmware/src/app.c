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
    void MultiStepEncrypt (AES *aes)

  Remarks:
    See prototype in app.h.
 */

void MultiStepEncrypt (AES *aes)
{
    crypto_Sym_Status_E status;
    
    (void) memset(aes->symData, 0, aes->symDataSize);
    
    SYSTICK_TimerRestart();
    uint32_t startTime = 0, endTime = 0;
    startTime = SYSTICK_TimerCounterGet(); 
    
    if (isKeyWrap == true)
    {
        status = Crypto_Sym_AesKeyWrap_Init(
            &aes->Sym_Block_Ctx,
            aes->handler,
            CRYPTO_CIOP_ENCRYPT,
            aes->key,
            aes->keySize,
            aes->iv,
            SESSION_ID
        );
    }
    else
    {
        status = Crypto_Sym_Aes_Init(
            &aes->Sym_Block_Ctx,
            aes->handler,
            CRYPTO_CIOP_ENCRYPT,
            aes->aesMode,
            aes->key,
            aes->keySize,
            aes->iv, // null for ECB and XTS mode
            SESSION_ID
        );
    }

    if (status != CRYPTO_SYM_CIPHER_SUCCESS)
    {
        printf("Failed to initialize, status: %d\r\n", status);
    }
    if (isKeyWrap == true )
    {
        status = Crypto_Sym_AesKeyWrap_Cipher(
            &aes->Sym_Block_Ctx,
            aes->pt,
            aes->ptSize,
            aes->symData
        );
    }
    else
    {
        status = Crypto_Sym_Aes_Cipher(
            &aes->Sym_Block_Ctx,
            aes->pt,
            aes->ptSize,
            aes->symData
        );
    }
    
    endTime = SYSTICK_TimerCounterGet();
    printf("Time elapsed (ms): %f\r\n", (double)(startTime - endTime)/(SYSTICK_FREQ/1000U));
    
    if (status != CRYPTO_SYM_CIPHER_SUCCESS)
    {
        printf("Failed to cipher, status: %d\r\n",status);
        testsFailed++;
    }
    else
    {
        bool outputMatch = CompareHexArray(aes->symData, aes->cipher, aes->cipherSize);

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
    void MultiStepDecrypt (AES *aes)

  Remarks:
    See prototype in app.h.
 */

void MultiStepDecrypt (AES *aes)
{
    crypto_Sym_Status_E status;
    
    (void) memset(aes->symData, 0, aes->symDataSize);

    SYSTICK_TimerRestart();
    uint32_t startTime = 0, endTime = 0;
    startTime = SYSTICK_TimerCounterGet(); 
    
    if (isKeyWrap == true)
    {
        status = Crypto_Sym_AesKeyWrap_Init(
            &aes->Sym_Block_Ctx,
            aes->handler,
            CRYPTO_CIOP_DECRYPT,
            aes->key,
            aes->keySize,
            aes->iv,
            SESSION_ID
        );
    }
    else
    {
        status = Crypto_Sym_Aes_Init(
            &aes->Sym_Block_Ctx,
            aes->handler,
            CRYPTO_CIOP_DECRYPT,
            aes->aesMode,
            aes->key,
            aes->keySize,
            aes->iv, // null for ECB and XTS mode
            SESSION_ID
        );
    }

    if (status != CRYPTO_SYM_CIPHER_SUCCESS)
    {
        printf("Failed to initialize, status: %d\r\n", status);
    }

    if (isKeyWrap == true)
    {
        status = Crypto_Sym_AesKeyWrap_Cipher(
            &aes->Sym_Block_Ctx,
            aes->cipher,
            aes->cipherSize,
            aes->symData
        );
    }
    else
    {
        status = Crypto_Sym_Aes_Cipher(
            &aes->Sym_Block_Ctx,
            aes->cipher,
            aes->cipherSize,
            aes->symData
        );
    }

    endTime = SYSTICK_TimerCounterGet();
    printf("Time elapsed (ms): %f\r\n", (double)(startTime - endTime)/(SYSTICK_FREQ/1000U));
    
    if (status != CRYPTO_SYM_CIPHER_SUCCESS)
    {
        printf("Failed to cipher, status: %d\r\n", status);
        testsFailed++;
    }
    else
    {
        bool outputMatch = CompareHexArray(aes->symData, aes->pt, aes->ptSize);

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
    void SingleStepEncrypt (AES *aes)

  Remarks:
    See prototype in app.h.
 */

void SingleStepEncrypt (AES *aes)
{
    crypto_Sym_Status_E status;
    
    (void) memset(aes->symData, 0, aes->symDataSize);

    SYSTICK_TimerRestart();
    uint32_t startTime = 0, endTime = 0;
    startTime = SYSTICK_TimerCounterGet(); 
    
    if (isKeyWrap == true)
    {
        status = Crypto_Sym_AesKeyWrapDirect(
            aes->handler,
            aes->pt,
            aes->ptSize,
            aes->symData,
            aes->key,
            aes->keySize,
            aes->iv,
            SESSION_ID
        );
    }
    else
    {
        status = Crypto_Sym_Aes_EncryptDirect(
            aes->handler,
            aes->aesMode,
            aes->pt,
            aes->ptSize,
            aes->symData,
            aes->key,
            aes->keySize,
            aes->iv,
            SESSION_ID
        );
    }

    endTime = SYSTICK_TimerCounterGet();
    printf("Time elapsed (ms): %f\r\n", (double)(startTime - endTime)/(SYSTICK_FREQ/1000U));

    if (status != CRYPTO_SYM_CIPHER_SUCCESS)
    {
        printf("Failed to encrypt direct\r\n");
        testsFailed++;
    }
    else
    {
        bool outputMatch = CompareHexArray(aes->symData, aes->cipher, aes->cipherSize);

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
    void SingleStepDecrypt (AES *aes)

  Remarks:
    See prototype in app.h.
 */

void SingleStepDecrypt (AES *aes)
{
    crypto_Sym_Status_E status;
    
    (void) memset(aes->symData, 0, aes->symDataSize);
    
    SYSTICK_TimerRestart();
    uint32_t startTime = 0, endTime = 0;
    startTime = SYSTICK_TimerCounterGet(); 

    if (isKeyWrap == true )
    {
        status = Crypto_Sym_AesKeyUnWrapDirect(
            aes->handler,
            aes->cipher,
            aes->cipherSize,
            aes->symData,
            aes->key,
            aes->keySize,
            aes->iv,
            SESSION_ID
        );
    }
    else
    {
        status = Crypto_Sym_Aes_DecryptDirect(
            aes->handler,
            aes->aesMode,
            aes->cipher,
            aes->cipherSize,
            aes->symData,
            aes->key,
            aes->keySize,
            aes->iv,
            SESSION_ID
        );
    }
    
    endTime = SYSTICK_TimerCounterGet();
    printf("Time elapsed (ms): %f\r\n", (double)(startTime - endTime)/(SYSTICK_FREQ/1000U));

    if (status != CRYPTO_SYM_CIPHER_SUCCESS)
    {
        printf("Failed to decrypt direct\r\n");
        testsFailed++;
    }
    else
    {
        bool outputMatch = CompareHexArray(aes->symData, aes->pt, aes->ptSize);

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

void APP_Initialize(void) {
    /* Place the App state machine in its initial state. */
    appData.state = APP_STATE_INIT;
    appData.isTestedAes = false;
    appData.isTestedCamellia = false;
    appData.isTestedTdes = false;
    appData.isTestedChaCha20 = false;
    appData.isTestedKeyWrap = false;
}

/******************************************************************************
  Function:
    void APP_Tasks ( void )

  Remarks:
    See prototype in app.h.
 */

void APP_Tasks(void) {

    /* Check the application's current state. */
    switch (appData.state)
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
            if (
                    !appData.isTestedAes       &&
                    !appData.isTestedCamellia  &&
                    !appData.isTestedTdes      &&
                    !appData.isTestedChaCha20  &&
                    !appData.isTestedKeyWrap
                )
            {
                SYSTICK_TimerStart();
                
                printf("\r\n-----------AES-ECB Hardware Wrapper-------------\r\n");
                AES_ECB_Test(CRYPTO_HANDLER_HW_INTERNAL);
                
                printf("\r\n-----------AES-ECB wolfCrypt Wrapper-------------\r\n");
                AES_ECB_Test(CRYPTO_HANDLER_SW_WOLFCRYPT);
                
                printf("\r\n-----------AES-CBC Hardware Wrapper-------------\r\n");
                AES_CBC_Test(CRYPTO_HANDLER_HW_INTERNAL);
                
                printf("\r\n-----------AES-CBC wolfCrypt Wrapper-------------\r\n");
                AES_CBC_Test(CRYPTO_HANDLER_SW_WOLFCRYPT);
                                
                printf("\r\n-----------AES-CTR Hardware Wrapper-------------\r\n");
                AES_CTR_Test(CRYPTO_HANDLER_HW_INTERNAL);
                
                printf("\r\n-----------AES-CTR wolfCrypt Wrapper-------------\r\n");
                AES_CTR_Test(CRYPTO_HANDLER_SW_WOLFCRYPT);
                
                appData.isTestedAes      = true;
                
                printf("\r\n-----------AES-KW wolfCrypt Wrapper-------------\r\n");
                AES_KeyWrap_Test(CRYPTO_HANDLER_SW_WOLFCRYPT);
                
                appData.isTestedKeyWrap  = true;

                // TODO - Not yet supported on Crypto_v4
                appData.isTestedCamellia = true;
                appData.isTestedTdes     = true;
                appData.isTestedChaCha20 = true;

                printf("\r\n-----------------------------------\r\n");
                printf("Tests attempted: %d", testsPassed + testsFailed);
                printf("\r\nTests successful: %d\r\n", testsPassed);
                
                SYSTICK_TimerStop();
            }
           
            break;
        }
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
