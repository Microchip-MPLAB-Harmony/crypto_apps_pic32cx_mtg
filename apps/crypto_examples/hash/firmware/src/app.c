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
    void SingleStepDigest(HASH *hash)

  Remarks:
    See prototype in app.h.
 */

void SingleStepDigest(HASH *hash)
{
    crypto_Hash_Status_E status;

    (void) memset(hash->msgDigest, 0, hash->msgDigestSize);

    SYSTICK_TimerRestart();
    uint32_t startTime = 0, endTime = 0;
    startTime = SYSTICK_TimerCounterGet(); 
    
    if (hash->hashMode == CRYPTO_HASH_MD5)
    {
        status = Crypto_Hash_Md5_Digest(
            hash->handler,
            hash->msg,
            hash->msgSize,
            hash->msgDigest,
            SESSION_ID
        );
    }
    else
    {
        status = Crypto_Hash_Sha_Digest(
            hash->handler,
            hash->msg,
            hash->msgSize,
            hash->msgDigest,
            hash->hashMode,
            SESSION_ID
        );
    }

    endTime = SYSTICK_TimerCounterGet();
    printf("Time elapsed (ms): %f\r\n", (double)(startTime - endTime)/(SYSTICK_FREQ/1000U));

    if (status != CRYPTO_HASH_SUCCESS)
    {
        printf("Failed to create message digest, status: %d\r\n", status);
        testsFailed++;
    }
    else
    {
        bool outputMatch = CompareHexArray(hash->msgDigest, hash->expectedMsg, hash->msgDigestSize);

        if (outputMatch) {
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
    void MultiStepDigest(HASH *hash)

  Remarks:
    See prototype in app.h.
 */

void MultiStepDigest(HASH *hash)
{
    crypto_Hash_Status_E status;

    (void) memset(hash->msgDigest, 0, hash->msgDigestSize);

    SYSTICK_TimerRestart();
    uint32_t startTime = 0, endTime = 0;
    startTime = SYSTICK_TimerCounterGet(); 
    
    if (hash->hashMode == CRYPTO_HASH_MD5)
    {
        status = Crypto_Hash_Md5_Init(
            &hash->Hash_Md5_Ctx,
            hash->handler,
            SESSION_ID
        );
    }
    else
    {
        status = Crypto_Hash_Sha_Init(
            &hash->Hash_Sha_Ctx,
            hash->hashMode,
            hash->handler,
            SESSION_ID
        );
    }

    if (status != CRYPTO_HASH_SUCCESS)
    {
        printf("Init Failed, status: %d\r\n", status);
    }

    if (hash->hashMode == CRYPTO_HASH_MD5)
    {
        status = Crypto_Hash_Md5_Update(&hash->Hash_Md5_Ctx, hash->msg, hash->msgSize);
    }
    else
    {
        status = Crypto_Hash_Sha_Update(&hash->Hash_Sha_Ctx, hash->msg, hash->msgSize);
    }

    if (status != CRYPTO_HASH_SUCCESS)
    {
        printf("Update Failed, status: %d\r\n", status);
    }

    if (hash->hashMode == CRYPTO_HASH_MD5)
    {
        status = Crypto_Hash_Md5_Final(&hash->Hash_Md5_Ctx, hash->msgDigest);
    }
    else
    {
        status = Crypto_Hash_Sha_Final(&hash->Hash_Sha_Ctx, hash->msgDigest);
    }
    
    endTime = SYSTICK_TimerCounterGet();
    printf("Time elapsed (ms): %f\r\n", (double)(startTime - endTime)/(SYSTICK_FREQ/1000U));

    if (status != CRYPTO_HASH_SUCCESS)
    {
        printf("Failed to create message digest, status: %d\r\n", status);
        testsFailed++;
    }
    else
    {
        bool outputMatch = CompareHexArray(hash->msgDigest, hash->expectedMsg, hash->msgDigestSize);

        if (outputMatch) {
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
    void APP_Initialize (void)

  Remarks:
    See prototype in app.h.
 */

void APP_Initialize (void)
{
    /* Place the App state machine in its initial state. */
    appData.state = APP_STATE_INIT;
    appData.isTestedMd5  = false;
    appData.isTestedSha1 = false;
    appData.isTestedSha2 = false;
}

/******************************************************************************
  Function:
    void APP_Tasks (void)

  Remarks:
    See prototype in app.h.
 */

void APP_Tasks (void)
{

    /* Check the application's current state. */
    switch (appData.state)
    {
        /* Application's initial state. */
        case APP_STATE_INIT:
        {
            testsPassed = 0;
            testsFailed = 0;

            bool appInitialized = true;

            SYSTICK_TimerInitialize();
            SYSTICK_TimerPeriodSet(INT32_MAX);
            
            if (appInitialized)
            {
                appData.state = APP_STATE_SERVICE_TASKS;
            }
            break;
        }

        case APP_STATE_SERVICE_TASKS:
        {            
            if (
                    !appData.isTestedSha1   &&
                    !appData.isTestedSha2   &&
                    !appData.isTestedMd5
                )
            {
                SYSTICK_TimerStart();
                
                printf("\r\n-----------MD5 wolfCrypt Wrapper-------------\r\n");
                MD5_Test(CRYPTO_HANDLER_SW_WOLFCRYPT);
                
                appData.isTestedMd5 = true;

                printf("\r\n-----------SHA1 Hardware Wrapper-------------\r\n");
                SHA1_Test(CRYPTO_HANDLER_HW_INTERNAL);
                
                printf("\r\n-----------SHA1 wolfCrypt Wrapper-------------\r\n");
                SHA1_Test(CRYPTO_HANDLER_SW_WOLFCRYPT);
                
                appData.isTestedSha1 = true;
                
                printf("\r\n-----------SHA2 Hardware Wrapper-------------\r\n");
                SHA2_Test(CRYPTO_HANDLER_HW_INTERNAL);
                
                printf("\r\n-----------SHA2 wolfCrypt Wrapper-------------\r\n");
                SHA2_Test(CRYPTO_HANDLER_SW_WOLFCRYPT);
                
                appData.isTestedSha2 = true;

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