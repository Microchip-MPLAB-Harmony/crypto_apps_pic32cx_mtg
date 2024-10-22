/*******************************************************************************
  MPLAB Harmony Application Source File

  Company:
    Microchip Technology Inc.

  File Name:
    app_config.h

  Summary:
    Provides test vectors and functions for cryptographic tests.

  Description:
    This file contains test vectors and functions to test symmetric
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
#include "crypto/common_crypto/MCHP_Crypto_Sym_Cipher.h"
#include "definitions.h"

/* Provide C++ Compatibility */
#ifdef __cplusplus
extern "C" {
#endif

    /* ************************************************************************** */
    /* ************************************************************************** */
    /* Section: Constants                                                         */
    /* ************************************************************************** */
    /* ************************************************************************** */

    // *****************************************************************************
    /** isKeyWrap

      @Summary
        Tracks whether running a symmetric operation with key wrapping enabled.
    
      @Description
        Either true or false, simply used as a flag that is toggled within 
        the key wrap test below.
    
      @Remarks
        None.
     */

    extern bool isKeyWrap;
      
    // *****************************************************************************
    // *****************************************************************************
    // Section: Data Types
    // *****************************************************************************
    // *****************************************************************************

    // *****************************************************************************
    /** AES

      @Summary
        Data structure for AES context.

      @Description
        This structure contains all the necessary parameters for performing AES
        (Advanced Encryption Standard) cryptographic operations. It includes the
        context for symmetric stream and block operations, handler, AES mode, 
        initialization vector (IV), key, plaintext, and ciphertext.

      @Remarks
        This structure is used in AES encryption and decryption functions.
    */

    typedef struct {
//        st_Crypto_Sym_StreamCtx Sym_Stream_Ctx;
        st_Crypto_Sym_BlockCtx  Sym_Block_Ctx;

        crypto_HandlerType_E handler;
        crypto_Sym_OpModes_E aesMode;

        uint8_t *iv;

        uint8_t *key;
        size_t keySize;

        uint8_t *pt;
        size_t ptSize;

        uint8_t *symData;
        size_t symDataSize;

        uint8_t *cipher;
        size_t cipherSize;    
    } AES;

    // *****************************************************************************
    // *****************************************************************************
    // Section: Interface Functions
    // *****************************************************************************
    // *****************************************************************************

    // *****************************************************************************
    /**
      @Function
        void MultiStepEncrypt (AES *ctx)

      @Summary
        Performs AES encryption in multiple steps.

      @Description
        This function performs AES encryption operation in multiple steps using the
        provided context. The context makes it simpler to call, but it is not 
        necessary for the API. It exists to show the necessary input data and 
        manage state across multiple steps.

      @Precondition
        The AES context (AES structure) must be properly initialized with the 
        necessary parameters including the key, IV, and other relevant data.

      @Parameters
        @param ctx Pointer to the AES context (AES structure) containing the necessary
                  parameters for the encryption operation.

      @Returns
        None.

      @Remarks
        None.
    */
    void MultiStepEncrypt (AES *ctx);

    // *****************************************************************************
    /**
      @Function
        void MultiStepDecrypt (AES *ctx)

      @Summary
        Performs AES decryption in multiple steps.

      @Description
        This function performs AES decryption operation in multiple steps using the
        provided context. The context makes it simpler to call, but it is not 
        necessary for the API. It exists to show the necessary input data and 
        manage state across multiple steps.

      @Precondition
        The AES context (AES structure) must be properly initialized with the 
        necessary parameters including the key, IV, and other relevant data.

      @Parameters
        @param ctx Pointer to the AES context (AES structure) containing the necessary
                  parameters for the decryption operation.

      @Returns
        None.

      @Remarks
        None.
    */
    void MultiStepDecrypt (AES *ctx);

    // *****************************************************************************
    /**
      @Function
        void SingleStepEncrypt (AES *ctx)

      @Summary
        Performs AES encryption in a single step.

      @Description
        This function performs AES encryption operation in a single step using the
        provided context. It is intended for cases where the entire operation can 
        be completed in one go without the need for multiple steps.

      @Precondition
        The AES context (AES structure) must be properly initialized with the 
        necessary parameters including the key, IV, and other relevant data.

      @Parameters
        @param ctx Pointer to the AES context (AES structure) containing the necessary
                  parameters for the encryption operation.

      @Returns
        None.

      @Remarks
        None.
    */
    void SingleStepEncrypt (AES *ctx);

    // *****************************************************************************
    /**
      @Function
        void SingleStepDecrypt (AES *ctx)

      @Summary
        Performs AES decryption in a single step.

      @Description
        This function performs AES decryption operation in a single step using the
        provided context. It is intended for cases where the entire operation can 
        be completed in one go without the need for multiple steps.

      @Precondition
        The AES context (AES structure) must be properly initialized with the 
        necessary parameters including the key, IV, and other relevant data.

      @Parameters
        @param ctx Pointer to the AES context (AES structure) containing the necessary
                  parameters for the decryption operation.

      @Returns
        None.

      @Remarks
        None.
    */
    void SingleStepDecrypt (AES *ctx);

    // *****************************************************************************
    /**
      @Function
        void AES_ECB_Test (void)

      @Summary
        Runs ECB test vectors.

      @Description
        This function runs the predefined ECB (Electronic Codebook) test vectors to
        verify the correctness of the ECB implementation. It performs both single-step
        and multi-step ECB operations and prints the results.

      @Precondition
        None.

      @Parameters
        None.

      @Returns
        None.

      @Remarks
        This function is used for testing purposes to validate the ECB implementation.
    */

    void AES_ECB_Test (crypto_HandlerType_E cryptoHandler);

    // *****************************************************************************
    /**
      @Function
        void AES_CBC_Test (void)

      @Summary
        Runs CBC test vectors.

      @Description
        This function runs the predefined CBC (Cipher Block Chaining) test vectors to
        verify the correctness of the CBC implementation. It performs both single-step
        and multi-step CBC operations and prints the results.

      @Precondition
        None.

      @Parameters
        None.

      @Returns
        None.

      @Remarks
        This function is used for testing purposes to validate the CBC implementation.
    */

    void AES_CBC_Test (crypto_HandlerType_E cryptoHandler);

    // *****************************************************************************
    /**
      @Function
        void AES_CTR_Test (void)

      @Summary
        Runs CTR test vectors.

      @Description
        This function runs the predefined CTR (Counter) test vectors to verify the
        correctness of the CTR implementation. It performs both single-step and
        multi-step CTR operations and prints the results.

      @Precondition
        None.

      @Parameters
        None.

      @Returns
        None.

      @Remarks
        This function is used for testing purposes to validate the CTR implementation.
    */

    void AES_CTR_Test (crypto_HandlerType_E cryptoHandler);

    // *****************************************************************************
    /**
      @Function
        void AES_KeyWrap_Test (void)

      @Summary
        Runs Key Wrap test vectors.

      @Description
        This function runs the predefined Key Wrap test vectors to verify the correctness
        of the Key Wrap implementation. It performs both single-step and multi-step Key
        Wrap operations and prints the results.

      @Precondition
        None.

      @Parameters
        None.

      @Returns
        None.

      @Remarks
        This function is used for testing purposes to validate the Key Wrap implementation.
    */

    void AES_KeyWrap_Test (crypto_HandlerType_E cryptoHandler);

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
    
    bool CompareHexArray (const uint8_t *arr1, const uint8_t *arr2, size_t size);

    /* Provide C++ Compatibility */
#ifdef __cplusplus
}
#endif

#endif /* _APP_CONFIG_H */

/* *****************************************************************************
 End of File
 */
