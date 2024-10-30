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
    void GenerateSharedSecret (ECDH *ecdh)

  Remarks:
    See prototype in app.h.
 */

void GenerateSharedSecret (ECDH *ecdh)
{
    crypto_Kas_Status_E status;
    
    (void) memset(ecdh->sharedSecret, 0, ecdh->sharedSecretSize);
    
    SYSTICK_TimerRestart();
    uint32_t startTime = 0, endTime = 0;
    startTime = SYSTICK_TimerCounterGet(); 

    status = Crypto_Kas_Ecdh_SharedSecret (
        ecdh->handler,
        ecdh->privKey,
        ecdh->privKeySize,
        ecdh->publKey,
        ecdh->publKeySize,
        ecdh->sharedSecret,
        ecdh->expectedSecretSize,
        ecdh->curveType,
        SESSION_ID
    );
    
    endTime = SYSTICK_TimerCounterGet();
    printf("Time elapsed (ms): %f\r\n", (double)(startTime - endTime)/(SYSTICK_FREQ/1000U));

    if (status != CRYPTO_KAS_SUCCESS)
    {
        printf("Failed to create shared secret, status: %d\r\n", status);
        testsFailed++;
    }
    else
    {
        bool outputMatch = CompareHexArray(
            ecdh->sharedSecret,
            ecdh->expectedSecret,
            ecdh->expectedSecretSize
        );

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
    void APP_Initialize ( void )

  Remarks:
    See prototype in app.h.
 */

void APP_Initialize ( void )
{
    /* Place the App state machine in its initial state. */
    appData.state = APP_STATE_INIT;

    appData.isTestedECDH = false;
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
            if (!appData.isTestedECDH)
            {
                SYSTICK_TimerStart();

                printf("\r\n-----------ECDH SECP256 Hardware Wrapper-------------\r\n");
                SECP256R1_Test(CRYPTO_HANDLER_HW_INTERNAL);

                printf("\r\n-----------ECDH SECP256 wolfCrypt Wrapper-------------\r\n");
                SECP256R1_Test(CRYPTO_HANDLER_SW_WOLFCRYPT);
                
                printf("\r\n-----------ECDH SECP384 Hardware Wrapper-------------\r\n");
                SECP384R1_Test(CRYPTO_HANDLER_HW_INTERNAL);

                printf("\r\n-----------ECDH SECP384 wolfCrypt Wrapper------------\r\n");
                SECP384R1_Test(CRYPTO_HANDLER_SW_WOLFCRYPT);
                                
                appData.isTestedECDH = true;

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
