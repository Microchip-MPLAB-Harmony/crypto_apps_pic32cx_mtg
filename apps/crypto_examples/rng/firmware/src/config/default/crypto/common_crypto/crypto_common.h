/*******************************************************************************
  MPLAB Harmony Application Header File

  Company:
    Microchip Technology Inc.

  File Name:
    crypto_common.h

  Summary:
    This header file provides prototypes and definitions for the application.

  Description:
    This header file provides function prototypes and data type definitions for
    the application.  Some of these are required by the system (such as the
    "APP_Initialize" and "APP_Tasks" prototypes) and some of them are only used
    internally by the application (such as the "APP_STATES" definition).  Both
    are defined here for convenience.
*******************************************************************************/

#ifndef CRYPTO_COMMON_H
#define CRYPTO_COMMON_H


// *****************************************************************************
// *****************************************************************************
// Section: Included Files
// *****************************************************************************
// *****************************************************************************

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "crypto/wolfcrypt/wolfcrypt_config.h"
//******************************************************************************
#define CRYPTO_ECC_MAX_KEY_LENGTH (66) //Max size of Private key; Public Key will be double of it for ECC

// *****************************************************************************
// *****************************************************************************
// Section: Type Definitions
// *****************************************************************************
// *****************************************************************************
typedef enum {
	CRYPTO_HANDLER_INVALID = 0,
	CRYPTO_HANDLER_HW_INTERNAL = 1,     //Enum used when HW crypto engine is used
#ifdef CRYPTO_WOLFCRYPT_SUPPORT_ENABLE            
	CRYPTO_HANDLER_SW_WOLFCRYPT = 2,    //Enum used when SW library Wolfssl is used
#endif /* CRYPTO_WOLFCRYPT_SUPPORTED */            
	CRYPTO_HANDLER_EXTERNAL_TA100 = 3,  //When external TA100 used for crypto
	CRYPTO_HANDLER_EXTERNAL_ECC508 = 4, //When external ECC508 used for crypto
	CRYPTO_HANDLER_MAX
}crypto_HandlerType_E;


// *****************************************************************************
#endif //CRYPTO_COMMON_H
