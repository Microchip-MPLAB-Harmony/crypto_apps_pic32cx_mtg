/*******************************************************************************
  MPLAB Harmony Application Source File

  Company:
    Microchip Technology Inc.

  File Name:
    app_config.h

  Summary:
    Provides test vectors and functions for cryptographic tests.

  Description:
    This file contains test vectors and functions to test SECP256R1 
    and SECP384R1 cryptographic functionalities.
 *******************************************************************************/

#ifndef APP_CONFIG_H    /* Guard against multiple inclusion */
#define APP_CONFIG_H

/* ************************************************************************** */
/* ************************************************************************** */
/* Section: Included Files                                                    */
/* ************************************************************************** */
/* ************************************************************************** */

#include "configuration.h"
#include "crypto/common_crypto/MCHP_Crypto_Kas.h"
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
    /** ECDH

      @Summary
        Data structure for ECDH context.

      @Description
        This structure contains all the necessary parameters for performing ECDH
        (Elliptic Curve Diffie-Hellman) cryptographic operations. It includes the
        handler, curve type, private key, public key, shared secret, and expected secret.

      @Remarks
        This structure is used in ECDH key exchange functions.
    */

    typedef struct {
        crypto_HandlerType_E handler;
        crypto_EccCurveType_E curveType;

        uint8_t *privKey;
        size_t privKeySize;

        uint8_t *publKey;
        size_t publKeySize;
        
        uint8_t *sharedSecret;
        size_t sharedSecretSize;

        uint8_t *expectedSecret;
        size_t expectedSecretSize;
    } ECDH;

    // *****************************************************************************
    // *****************************************************************************
    // Section: Interface Functions
    // *****************************************************************************
    // *****************************************************************************


    // *****************************************************************************
    /**
      @Function
        void GenerateSharedSecret (ECDH *ctx)

      @Summary
        Generates the shared secret using ECDH key exchange.

      @Description
        This function performs the generation of a shared secret using the ECDH
        (Elliptic Curve Diffie-Hellman) key exchange algorithm. It uses the private
        and public keys specified in the context to compute the shared secret.

      @Precondition
        The ECDH context (ECDH structure) must be properly initialized with the
        necessary parameters including the curve type, private key, and public key.

      @Parameters
        @param ctx Pointer to the ECDH context (ECDH structure) containing the necessary
                  parameters for the key exchange operation.

      @Returns
        None.

      @Remarks
        None.
    */
    void GenerateSharedSecret (ECDH *ctx);

    // *****************************************************************************
    /**
      @Function
        void SECP384R1_Test(crypto_HandlerType_E cryptoHandler)

      @Summary
        Runs SECP384R1 test vectors.

      @Description
        This function runs the predefined SECP384R1 (P-384) test vectors to verify 
        the correctness of the SECP384R1 implementation. It performs the necessary 
        cryptographic operations and prints the results.

      @Precondition
        None.

      @Parameters
        None.

      @Returns
        None.

      @Remarks
        This function is used for testing purposes to validate the SECP384R1 implementation.
    */
    void SECP384R1_Test(crypto_HandlerType_E cryptoHandler);

    // *****************************************************************************
    /**
      @Function
        void SECP256R1_Test (crypto_HandlerType_E cryptoHandler);

      @Summary
        Runs SECP256R1 test vectors.

      @Description
        This function runs the predefined SECP256R1 (P-256) test vectors to verify 
        the correctness of the SECP256R1 implementation. It performs the necessary 
        cryptographic operations and prints the results.

      @Precondition
        None.

      @Parameters
        None.

      @Returns
        None.

      @Remarks
        This function is used for testing purposes to validate the SECP256R1 implementation.
    */
    void SECP256R1_Test (crypto_HandlerType_E cryptoHandler);

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

    bool CompareHexArray(uint8_t *arr1, uint8_t *arr2, size_t size);

    /* Provide C++ Compatibility */
#ifdef __cplusplus
}
#endif

#endif /* _APP_CONFIG_H */

/* *****************************************************************************
 End of File
 */
