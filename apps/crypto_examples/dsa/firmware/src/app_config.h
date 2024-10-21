/*******************************************************************************
  MPLAB Harmony Application Header File

  Company:
    Microchip Technology Inc.

  File Name:
    app_config.h

  Summary:
    Provides test vectors and functions for cryptographic tests.

  Description:
    This file contains test vectors and functions to test SECP256R1 and 
    SECP384R1 cryptographic functionalities
 *******************************************************************************/

#ifndef APP_CONFIG_H    /* Guard against multiple inclusion */
#define APP_CONFIG_H

/* ************************************************************************** */
/* ************************************************************************** */
/* Section: Included Files                                                    */
/* ************************************************************************** */
/* ************************************************************************** */

#include "configuration.h"
#include "crypto/common_crypto/MCHP_Crypto_Common.h"
#include "crypto/common_crypto/MCHP_Crypto_DigSign.h"
#include "definitions.h"

/* Provide C++ Compatibility */
#ifdef __cplusplus
extern "C" {
#endif

    // *****************************************************************************
    // *****************************************************************************
    // Section: Data Types
    // *****************************************************************************
    // *****************************************************************************
    
    // *****************************************************************************
    /** ECDSA

      @Summary
        Data structure for ECDSA (Elliptic Curve Digital Signature Algorithm) context.

      @Description
        This structure contains all the necessary parameters for performing ECDSA
        cryptographic operations. It includes the handler type, curve type, input hash,
        key, signature, and the status of the hash verification.

      @Remarks
        This structure is used in ECDSA signing and verification functions.
    */
   
    typedef struct
    {
        crypto_HandlerType_E handler;
        crypto_EccCurveType_E curveType;

        uint8_t *inputHash;
        size_t inputHashSize;

        uint8_t *key;
        size_t keySize;

        uint8_t *sig;
        size_t sigSize;
        
        int8_t hashVerifyStat;
    } ECDSA;

    // *****************************************************************************
    // *****************************************************************************
    // Section: Interface Functions
    // *****************************************************************************
    // *****************************************************************************

    // *****************************************************************************
    /**
      @Function
        void ECDSA_Test (void)

      @Summary
        Runs a basic test of the ECDSA functionality.

      @Description
        This function performs a basic test of the ECDSA (Elliptic Curve Digital Signature
        Algorithm) functionality to ensure that the signing and verification processes
        work correctly.

      @Precondition
        None.

      @Parameters
        None.

      @Returns
        None.

      @Remarks
        None.
    */
void ECDSA_Test (crypto_HandlerType_E cryptoHandler);

    // *****************************************************************************
    /**
      @Function
        void ECDSA_Sign_Test(ECDSA *ctx)

      @Summary
        Performs an ECDSA signing test using the provided context.

      @Description
        This function performs an ECDSA signing operation using the provided context. 
        The context contains the necessary parameters such as the key, input hash, 
        and other relevant data required for signing.

      @Precondition
        The ECDSA context (ECDSA structure) must be properly initialized with the
        necessary parameters including the key and input hash.

      @Parameters
        @param ctx Pointer to the ECDSA context (ECDSA structure) containing the necessary
                  parameters for the signing operation.

      @Returns
        None.

      @Remarks
        None.
    */
    void ECDSA_Sign_Test(ECDSA *ctx);

    // *****************************************************************************
    /**
      @Function
        void ECDSA_Verify_Test(ECDSA *ctx)

      @Summary
        Performs an ECDSA verification test using the provided context.

      @Description
        This function performs an ECDSA verification operation using the provided context.
        The context contains the necessary parameters such as the key, signature, input
        hash, and other relevant data required for verification.

      @Precondition
        The ECDSA context (ECDSA structure) must be properly initialized with the
        necessary parameters including the key, signature, and input hash.

      @Parameters
        @param ctx Pointer to the ECDSA context (ECDSA structure) containing the necessary
                  parameters for the verification operation.

      @Returns
        None.

      @Remarks
        None.
    */
    void ECDSA_Verify_Test(ECDSA *ctx);

    // *****************************************************************************
    /**
      @Function
        bool CompareHexArray (uint8_t *arr1, uint8_t *arr2, size_t size)

      @Summary
        Compares two hexadecimal arrays.

      @Description
        This function compares two hexadecimal arrays of the same size and returns
        true if they are identical, otherwise it returns false.

      @Precondition
        None.

      @Parameters
        @param arr1 Pointer to the first hexadecimal array.
    
        @param arr2 Pointer to the second hexadecimal array.
    
        @param size The size of the arrays to compare.

      @Returns
        - true  Indicates that the arrays are identical.
        - false Indicates that the arrays are not identical.

      @Remarks
        This function is used for validating the results of cryptographic operations
        by comparing the expected and actual output.
     */

    bool CompareHexArray (uint8_t *arr1, uint8_t *arr2, size_t size);


    /* Provide C++ Compatibility */
#ifdef __cplusplus
}
#endif

#endif /* _APP_CONFIG_H */

/* *****************************************************************************
 End of File
 */
