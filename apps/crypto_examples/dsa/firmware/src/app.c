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

uint64_t diffCount;

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
    void ECDSA_Sign_Test(ECDSA *ecdsa)

  Remarks:
    See prototype in app.h.
 */

void ECDSA_Sign_Test(ECDSA *ecdsa)
{    
    crypto_DigiSign_Status_E status;
    
    (void) memset(ecdsa->sig, 0, ecdsa->sigSize);

    appData.prevCounterVal = SYS_TIME_Counter64Get();
    
    status = Crypto_DigiSign_Ecdsa_Sign(
        ecdsa->handler,
        ecdsa->inputHash,
        ecdsa->inputHashSize,
        ecdsa->sig,
        ecdsa->sigSize,
        ecdsa->key,
        ecdsa->keySize,
        ecdsa->curveType,
        SESSION_ID
    );
    
    diffCount = (SYS_TIME_Counter64Get() - appData.prevCounterVal);
    printf("Time elapsed (ms): %d\r\n", (int)SYS_TIME_CountToMS(diffCount));

    if (status != CRYPTO_DIGISIGN_SUCCESS)
    {
        printf("Failed to create message signature\r\n");
        printf("Status: %d\r\n", status);
        appData.testsFailed++;
    }
    else
    {
        printf("Test successful\r\n");
        appData.testsPassed++;
    }
}

/*******************************************************************************
  Function:
    void ECDSA_Verify_Test(ECDSA *ecdsa)

  Remarks:
    See prototype in app.h.
 */

void ECDSA_Verify_Test(ECDSA *ecdsa)
{
    crypto_DigiSign_Status_E status;
    
    appData.prevCounterVal = SYS_TIME_Counter64Get();
    
    status = Crypto_DigiSign_Ecdsa_Verify(
        ecdsa->handler,
        ecdsa->inputHash,
        ecdsa->inputHashSize,
        ecdsa->sig,
        ecdsa->sigSize,
        ecdsa->key,
        ecdsa->keySize,
        &(ecdsa->hashVerifyStat),
        ecdsa->curveType,
        SESSION_ID
    );
    
    diffCount = (SYS_TIME_Counter64Get() - appData.prevCounterVal);
    printf("Time elapsed (ms): %d\r\n", (int)SYS_TIME_CountToMS(diffCount));

    if (status != CRYPTO_DIGISIGN_SUCCESS)
    {
        printf("Failed to verify signature\r\n");
        printf("Status: %d\r\n", status);
        appData.testsFailed++;
    }

    if (ecdsa->hashVerifyStat)
    {
        appData.testsPassed++;
        printf("Test successful\r\n");
    }
    else
    {
        appData.testsFailed++;
        printf("Test unsuccessful\r\n");
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
    
    appData.speedTest = SYS_TIME_HANDLE_INVALID;

    appData.testsPassed = 0; 
    appData.testsFailed = 0;

    appData.isTestedECDSA = false;
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
            bool appInitialized = true;

            if (appInitialized)
            {
                appData.state = APP_STATE_SERVICE_TASKS;
            }

            break;
        }

        case APP_STATE_SERVICE_TASKS:
        {               
            if (!appData.isTestedECDSA)
            {
                printf("\r\n-----------ECDSA Hardware Wrapper-------------\r\n");
                ECDSA_Test(CRYPTO_HANDLER_HW_INTERNAL);
                
                printf("\r\n-----------ECDSA wolfCrypt Wrapper-------------\r\n");
                ECDSA_Test(CRYPTO_HANDLER_SW_WOLFCRYPT);
                
                appData.isTestedECDSA = true;

                printf("\r\n-----------------------------------\r\n");
                printf("Tests attempted: %d", appData.testsPassed + appData.testsFailed);
                printf("\r\nTests successful: %d\r\n", appData.testsPassed);
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
