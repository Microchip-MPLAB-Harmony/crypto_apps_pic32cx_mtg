/*******************************************************************************
  MPLAB Harmony Application Header File

  Company:
    Microchip Technology Inc.

  File Name:
    app_config.h

  Summary:
    Provides test vectors and functions for cryptographic tests.

  Description:
    This file contains test vectors and functions to test hashing
    cryptographic functionalities.
 *******************************************************************************/

#ifndef APP_CONFIG_H    /* Guard against multiple inclusion */
#define APP_CONFIG_H

/* ************************************************************************** */
/* ************************************************************************** */
/* Section: Included Files                                                    */
/* ************************************************************************** */
/* ************************************************************************** */

#include "configuration.h"
#include "crypto/common_crypto/crypto_hash.h"
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
    /** HASH

      @Summary
        Data structure for HASH context.

      @Description
        This structure contains all the necessary parameters for performing hash
        cryptographic operations. It includes contexts for SHA and MD5 hashing,
        handler type, hash mode, message, message digest, and expected message digest.

      @Remarks
        This structure is used in various hash computation functions.
    */
    typedef struct {
        st_Crypto_Hash_Sha_Ctx  Hash_Sha_Ctx;
        st_Crypto_Hash_Md5_Ctx  Hash_Md5_Ctx;

        crypto_HandlerType_E handler;
        crypto_Hash_Algo_E hashMode;

        uint8_t *msg;
        size_t msgSize;

        uint8_t *msgDigest;
        size_t msgDigestSize;

        uint8_t *expectedMsg;
        size_t expectedMsgSize;
        
    } HASH;

    // *****************************************************************************
    // *****************************************************************************
    // Section: Interface Functions
    // *****************************************************************************
    // *****************************************************************************

    // *****************************************************************************
    /**
    @Function
      void SingleStepDigest (HASH *ctx)

    @Summary
      Performs hashing in a single step.

    @Description
      This function performs a hash operation in one step using the provided context. 
      The context simplifies the calling process, but is not required for the API. 
      It exists to demonstrate the necessary input data.

    @Precondition
      The hash context (HASH structure) must be properly initialized with the 
      necessary parameters, including the hash algorithm and any initial data.

    @Parameters
      @param ctx Pointer to the hash context (HASH structure) containing the necessary 
                  parameters for the operation.

    @Returns
      None.

    @Remarks
      None.
    */

    void SingleStepDigest (HASH *ctx);

    // *****************************************************************************
    /**
    @Function
      void MultiStepDigest (HASH *ctx)

    @Summary
      Performs hashing step-by-step.

    @Description
      This function performs a hash operation in multiple steps using the provided context. 
      The context simplifies the calling process, but is not required for the API. 
      It exists to demonstrate the necessary input data.

    @Precondition
      The hash context (HASH structure) must be properly initialized with the 
      necessary parameters, including the hash algorithm and any initial data.

    @Parameters
      @param ctx Pointer to the hash context (HASH structure) containing the necessary 
                  parameters for the operation.

    @Returns
      None.

    @Remarks
      None.
    */

    void MultiStepDigest (HASH *ctx);

    // *****************************************************************************
    /**
      @Function
        void MD5_Test (void)

      @Summary
        Runs MD5 test vectors.

      @Description
        This function runs the predefined MD5 test vectors to verify the correctness 
        of the MD5 implementation. It performs both single-step and multi-step MD5 
        operations and prints the results.

      @Precondition
        None.

      @Parameters
        None.

      @Returns
        None.

      @Remarks
        This function is used for testing purposes to validate the MD5 implementation.
      */

    void MD5_Test (crypto_HandlerType_E cryptoHandler);

    // *****************************************************************************
    /**
      @Function
        void SHA1_Test (void)

      @Summary
        Runs SHA1 test vectors.

      @Description
        This function runs the predefined SHA1 test vectors to verify the correctness 
        of the SHA1 implementation. It performs both single-step and multi-step SHA1 
        operations and prints the results.

      @Precondition
        None.

      @Parameters
        None.

      @Returns
        None.

      @Remarks
        This function is used for testing purposes to validate the SHA1 implementation.
      */

    void SHA1_Test (crypto_HandlerType_E cryptoHandler);

    // *****************************************************************************
    /**
      @Function
        void SHA2_Test (void)

      @Summary
        Runs SHA2 test vectors.

      @Description
        This function runs the predefined SHA2 test vectors to verify the correctness 
        of the SHA2 implementation. It performs both single-step and multi-step SHA2 
        operations and prints the results.

      @Precondition
        None.

      @Parameters
        None.

      @Returns
        None.

      @Remarks
        This function is used for testing purposes to validate the SHA2 implementation.
      */

    void SHA2_Test (crypto_HandlerType_E cryptoHandler);

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
    
    bool CompareHexArray(const uint8_t *arr1, const uint8_t *arr2, size_t size);

    /* Provide C++ Compatibility */
#ifdef __cplusplus
}
#endif

#endif /* _APP_CONFIG_H */

/* *****************************************************************************
 End of File
 */
