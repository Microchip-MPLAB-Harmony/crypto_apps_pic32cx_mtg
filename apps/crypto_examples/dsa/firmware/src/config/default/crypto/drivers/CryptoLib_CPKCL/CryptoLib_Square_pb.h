/**************************************************************************
  Crypto Framework Library Source

  Company:
    Microchip Technology Inc.

  File Name:
    CryptoLib_Square_pb.h

  Summary:
    Crypto Framework Library interface file for hardware Cryptography.

  Description:
    This file provides an example for interfacing with the CPKCC module
    on the PIC32CXMxxx device family.
**************************************************************************/

//DOM-IGNORE-BEGIN
/*
Copyright (C) 2024, Microchip Technology Inc., and its subsidiaries. All rights reserved.

The software and documentation is provided by microchip and its contributors
"as is" and any express, implied or statutory warranties, including, but not
limited to, the implied warranties of merchantability, fitness for a particular
purpose and non-infringement of third party intellectual property rights are
disclaimed to the fullest extent permitted by law. In no event shall microchip
or its contributors be liable for any direct, indirect, incidental, special,
exemplary, or consequential damages (including, but not limited to, procurement
of substitute goods or services; loss of use, data, or profits; or business
interruption) however caused and on any theory of liability, whether in contract,
strict liability, or tort (including negligence or otherwise) arising in any way
out of the use of the software and documentation, even if advised of the
possibility of such damage.

Except as expressly permitted hereunder and subject to the applicable license terms
for any third-party software incorporated in the software and any applicable open
source software license terms, no license or other rights, whether express or
implied, are granted under any patent or other intellectual property rights of
Microchip or any third party.
*/
//DOM-IGNORE-END

#ifndef CRYPTOLIB_SQUARE_PB_INCLUDED
#define CRYPTOLIB_SQUARE_PB_INCLUDED

// Structure definition
typedef struct struct_CPKCL_square {
               nu1       nu1ModBase;
               nu1       nu1CnsBase;
               u2        u2ModLength;

               nu1       nu1XBase;
               u2        padding0;
               nu1       nu1ZBase;
               nu1       nu1RBase;
               u2        padding1;
               u2        u2XLength;
               } CPKCL_SQUARE_STRUCT, *CPPKCL_SQUARE_STRUCT;

// Options definition
#define CPKCL_SQUARE_ONLY            MULT_ONLY
#define CPKCL_SQUARE_ADD             MULT_ADD
#define CPKCL_SQUARE_SUB             MULT_SUB


#endif // CRYPTOLIB_SQUARE_PB_INCLUDED