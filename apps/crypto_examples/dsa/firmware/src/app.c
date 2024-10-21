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
#define TEN_NS_TO_MS  0.00001

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
    void ECDSA_Sign_Test(ECDSA *ecdsa)

  Remarks:
    See prototype in app.h.
 */

void ECDSA_Sign_Test(ECDSA *ecdsa)
{    
    crypto_DigiSign_Status_E status;
    
    (void) memset(ecdsa->sig, 0, ecdsa->sigSize);

    uint32_t startTime = 0, endTime = 0;
    startTime = TC0_CH0_TimerCounterGet(); 

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
    
    endTime = TC0_CH0_TimerCounterGet();
    printf("\r\nTime elapsed (ms): %lf\r\n", (endTime - startTime)*TEN_NS_TO_MS);

    if (status != CRYPTO_DIGISIGN_SUCCESS)
    {
        printf("\r\nFailed to create message signature\r\n");
        printf("\r\nStatus: %d\r\n", status);
        testsFailed++;
    }
    else
    {
        testsPassed++;
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
    
    uint32_t startTime = 0, endTime = 0;
    startTime = TC0_CH0_TimerCounterGet(); 
    
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
    
    endTime = TC0_CH0_TimerCounterGet();
    printf("\r\nTime elapsed (ms): %lf", (endTime - startTime)*TEN_NS_TO_MS);

    if (status != CRYPTO_DIGISIGN_SUCCESS)
    {
        printf("\r\nFailed to verify signature\r\n");
        printf("\r\nStatus: %d\r\n", status);
        testsFailed++;
    }

    printf("\r\nVerify signature (1 = pass, 0 = fail): %d\r\n", ecdsa->hashVerifyStat);
    if (ecdsa->hashVerifyStat)
    {
        testsPassed++;
    }
    else
    {
        testsFailed++;
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
            testsPassed = 0;
            testsFailed = 0;

            bool appInitialized = true;

            if (appInitialized)
            {
                appData.state = APP_STATE_SERVICE_TASKS;
            }

            break;
        }

        case APP_STATE_SERVICE_TASKS:
        {
            TC0_CH0_TimerStart();
                
            if (!appData.isTestedECDSA)
            {
                printf("\r\nBegin DSA Demo Application\r\n");
                printf("\r\n-----------DSA SW test-------------\r\n");
                ECDSA_Test(CRYPTO_HANDLER_SW_WOLFCRYPT);
                printf("\r\n-----------DSA HW test-------------\r\n");
                ECDSA_Test(CRYPTO_HANDLER_HW_INTERNAL);
                
                appData.isTestedECDSA = true;

                printf("\r\n-----------------------------------\r\n");
                printf("Tests attempted: %d", testsPassed + testsFailed);
                printf("\r\nTests successful: %d\r\n", testsPassed);
            }

            TC0_CH0_TimerStop();
            
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
