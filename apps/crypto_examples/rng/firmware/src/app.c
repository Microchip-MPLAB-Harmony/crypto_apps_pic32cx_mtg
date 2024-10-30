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

#define DATA_SIZE     32
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
    void GenerateRng (void)

  Remarks:
    See prototype in app.h.
 */

void GenerateRng (crypto_HandlerType_E cryptoHandler)
{
    crypto_Rng_Status_E status;
    uint8_t rngData[DATA_SIZE];  
    
    (void) memset(rngData, 0, DATA_SIZE);
    
    SYSTICK_TimerRestart();
    uint32_t startTime = 0, endTime = 0;
    startTime = SYSTICK_TimerCounterGet(); 
    
    status = Crypto_Rng_Prng_Generate(
            cryptoHandler,
            rngData,
            DATA_SIZE,
            NULL,       // ptr_nonce
            0,          // sizeof(nonce)
            SESSION_ID
    );
    
    endTime = SYSTICK_TimerCounterGet();
    printf("Time elapsed (ms): %f\r\n", (double)(startTime - endTime)/(SYSTICK_FREQ/1000U));

    if (status != CRYPTO_RNG_SUCCESS)
    {
        testsFailed++;
        printf("Failed, status: %d\r\n", status);
    }
    else
    {
        testsPassed++;
        printf("Test successful\r\n");
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
    /* Place the App state machine in its  state. */
    appData.state = APP_STATE_INIT;
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
            
            if ( !appData.isTestedRng )
            {
                SYSTICK_TimerStart();

                printf("\r\n-----------RNG Hardware Wrapper-------------\r\n");
                printf("\r\nTRNG\r\n");
                GenerateRng(CRYPTO_HANDLER_HW_INTERNAL);

                printf("\r\n-----------RNG wolfCrypt Wrapper-------------\r\n");
                printf("\r\nPRNG\r\n");
                GenerateRng(CRYPTO_HANDLER_SW_WOLFCRYPT);
                                
                appData.isTestedRng = true;

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
