/**************************************************************************
  Crypto Framework Library Source

  Company:
    Microchip Technology Inc.

  File Name:
    CryptoLib_PrimeGen_pb.h

  Summary:
    Crypto Framework Library interface file for hardware Cryptography.

  Description:
    This file provides an example for interfacing with the CPKCC module.
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

#ifndef CRYPTOLIB_PRIMEGEN_PB_INCLUDED
#define CRYPTOLIB_PRIMEGEN_PB_INCLUDED

// Structure definition
typedef struct struct_CPKCL_primegen {
               nu1       nu1NBase;           //
               nu1       nu1CnsBase;
               u2        u2NLength;

               nu1       nu1RndBase;         // (3*u2NLength + 6) words
               nu1       nu1PrecompBase;     // (u2NLength + 2) words
               nu1       padding0;
               nu1       nu1RBase;           // (Significant length of 'N' without the padding word)
               nu1       nu1ExpBase;         // (u2NLength) words
               u1        u1MillerRabinIterations;
               u1        padding1;
               u2        u2MaxIncrement;
               } CPKCL_PRIMEGEN_STRUCT, *PPKCL_PRIMEGEN_STRUCT;

// Options definition
#define CPKCL_PRIMEGEN_TEST          0x02
#define CPKCL_PRIMEGEN_MASK          0x03


#endif // CRYPTOLIB_PRIMEGEN_PB_INCLUDED
