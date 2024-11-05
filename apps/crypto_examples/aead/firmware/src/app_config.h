/*******************************************************************************
  MPLAB Harmony Application Header File

  Company:
    Microchip Technology Inc.

  File Name:
    app_config.h

  Summary:
    Provides test vectors and functions for cryptographic tests.

  Description:
    This file contains test vectors and functions to test AEAD GCM and CCM
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
#include "crypto/common_crypto/crypto_common.h"
#include "crypto/common_crypto/crypto_aead_cipher.h"
#include "definitions.h"

/* Provide C++ Compatibility */
#ifdef __cplusplus
extern "C" {
#endif

    /* ************************************************************************** */
    /* ************************************************************************** */
    /* Section: Data Types                                                        */
    /* ************************************************************************** */
    /* ************************************************************************** */

    // *****************************************************************************
    /** GCM

      @Summary
        Data structure for GCM context.
    
      @Description
        This structure contains all the necessary parameters for performing GCM
        (Galois/Counter Mode) cryptographic operations. It includes the context,
        handler, plaintext, ciphertext, key, initialization vector (IV), additional
        authenticated data (AAD), and authentication tag.
    
      @Remarks
        This structure is used in GCM encryption and decryption functions.
     */
    
    typedef struct
    {
        st_Crypto_Aead_AesGcm_ctx   AesGcm_ctx;

        crypto_HandlerType_E handler;
        
        uint8_t *pt;
        size_t ptSize;

        uint8_t *cipher;
        size_t cipherSize;

        uint8_t *symData;
        size_t symDataSize;
        
        uint8_t *key;
        size_t keySize;

        uint8_t *iv;
        size_t ivSize;

        uint8_t *aad;
        size_t aadSize;

        uint8_t *authTag;
        size_t authTagSize;
    } GCM;


    // *****************************************************************************
    /** CCM

      @Summary
        Data structure for CCM context.
    
      @Description
        This structure contains all the necessary parameters for performing CCM
        (Counter with CBC-MAC) cryptographic operations. It includes the context,
        handler, plaintext, ciphertext, key, initialization vector (IV), additional
        authenticated data (AAD), and authentication tag.
    
      @Remarks
        This structure is used in CCM encryption and decryption functions.
     */

    typedef struct
    {
        st_Crypto_Aead_AesCcm_ctx AesCcm_ctx;

        crypto_HandlerType_E handler;
        
        uint8_t *pt;
        size_t ptSize;

        uint8_t *cipher;
        size_t cipherSize;

        uint8_t *symData;
        size_t symDataSize;

        uint8_t *key;
        size_t keySize;

        uint8_t *iv;
        size_t ivSize;

        uint8_t *aad;
        size_t aadSize;

        uint8_t *authTag;
        size_t authTagSize;
    } CCM;

    // *****************************************************************************
    // *****************************************************************************
    // Section: Interface Functions
    // *****************************************************************************
    // *****************************************************************************

    // *****************************************************************************
    /**
      @Function
        void AES_GCM_MultiStep (GCM *ctx)

      @Summary
        Performs GCM encryption/decryption step-by-step. 

      @Description
        This function performs the GCM (Galois/Counter Mode) encryption or decryption
        operation in multiple steps using the provided context. The context makes it 
        simpler to call, but of course it not necessary for the API. It exists to 
        show the necessary input data.  

      @Precondition
        The GCM context (GCM structure) must be properly initialized with the
        necessary parameters including the key, IV, AAD, and other relevant data.

      @Parameters
        @param ctx Pointer to the GCM context (GCM structure) containing the necessary
                   parameters for the operation.

      @Returns
        None.

      @Remarks
        None.
     */

    void AES_GCM_MultiStep (GCM *ctx);

    // *****************************************************************************
    /**
      @Function
        void AES_GCM_MultiStep (GCM *ctx)

      @Summary
        Performs GCM encryption/decryption in one step. 

      @Description
        This function performs the GCM (Galois/Counter Mode) encryption or decryption
        operation in multiple steps using the provided context. The context makes it 
        simpler to call, but of course it not necessary for the API. It exists to 
        show the necessary input data.  

      @Precondition
        The GCM context (GCM structure) must be properly initialized with the
        necessary parameters including the key, IV, AAD, and other relevant data.

      @Parameters
        @param ctx Pointer to the GCM context (GCM structure) containing the necessary
                   parameters for the operation.

      @Returns
        None.

      @Remarks
        None.
     */

    void AES_GCM_SingleStep (GCM *ctx);
    
    // *****************************************************************************
    /**
      @Function
        void AES_CCM_MultiStep (CCM *ctx)

      @Summary
        Performs CCM encryption/decryption step-by-step.

      @Description
        This function performs the CCM (Counter with CBC-MAC) encryption or decryption
        operation in multiple steps using the provided context. The context makes it 
        simpler to call, but of course it not necessary for the API. It exists to 
        show the necessary input data.  

      @Precondition
        The CCM context (CCM structure) must be properly initialized with the
        necessary parameters including the key, IV, AAD, and other relevant data.

      @Parameters
        @param ctx Pointer to the CCM context (CCM structure) containing the necessary
                   parameters for the operation.

      @Returns
        None.

      @Remarks
        None.
     */

    void AES_CCM_MultiStep (CCM *ctx);

    // *****************************************************************************
    /**
      @Function
        void AES_GCM_Test (void)

      @Summary
        Runs GCM test vectors.

      @Description
        This function runs the predefined GCM (Galois/Counter Mode) test vectors to
        verify the correctness of the GCM implementation. It performs both single-step
        and multi-step GCM operations and prints the results.

      @Precondition
        None.

      @Parameters
        None.

      @Returns
        None.

      @Remarks
        This function is used for testing purposes to validate the GCM implementation.
     */

    void AES_GCM_Test (crypto_HandlerType_E cryptoHandler);

    // *****************************************************************************
    /**
      @Function
        void AES_CCM_Test (void)

      @Summary
        Runs CCM test vectors.

      @Description
        This function runs the predefined CCM (Counter with CBC-MAC) test vectors to
        verify the correctness of the CCM implementation. It performs both single-step
        and multi-step CCM operations and prints the results.

      @Precondition
        None.

      @Parameters
        None.

      @Returns
        None.

      @Remarks
        This function is used for testing purposes to validate the CCM implementation.
     */

    void AES_CCM_Test (crypto_HandlerType_E cryptoHandler);
        
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
