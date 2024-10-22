/*******************************************************************************
  MPLAB Harmony Application Source File

  Company:
    Microchip Technology Inc.

  File Name:
    crypto_wc_common_wrapper.c

  Summary:
    This file contains the Common code for the Wolfcrypt Library application.

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
#include <stdlib.h>
#include <time.h>

#include "crypto/wolfcrypt/crypto_wc_common_wrapper.h"

__attribute__((weak)) int Crypto_Rng_Wc_Prng_EntropySource(void)
{
    /* MISRA C-2012 deviation block start */
    /* MISRA C-2012 Rule 21.10 deviated: 1. Deviation record ID - H3_MISRAC_2012_R_21_10_DR_1 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunknown-pragmas"
#pragma coverity compliance block deviate "MISRA C-2012 Rule 21.10" "H3_MISRAC_2012_R_21_10_DR_1"
  return (int) time(NULL);
#pragma coverity compliance end_block "MISRA C-2012 Rule 21.10"
#pragma GCC diagnostic pop
    /* MISRA C-2012 deviation block end */
}

__attribute__((weak)) int Crypto_Rng_Wc_Prng_Srand(uint8_t* output, unsigned int sz)
{
    // Seed the random number generator
    srand((unsigned int)Crypto_Rng_Wc_Prng_EntropySource());
    
    unsigned int i;
    for (i = 0; i < sz; i++)
    {
        int randVal = rand() % 256;
        output[i] = (uint8_t)randVal;
    }
    
    return 0;
}