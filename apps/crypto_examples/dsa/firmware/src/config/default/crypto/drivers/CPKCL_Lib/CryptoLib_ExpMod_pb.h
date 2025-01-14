/**************************************************************************
  Crypto Framework Library Source

  Company:
    Microchip Technology Inc.

  File Name:
    CryptoLib_ExpMod_pb.h

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

#ifndef CRYPTOLIB_EXPMOD_PB_INCLUDED
#define CRYPTOLIB_EXPMOD_PB_INCLUDED

// Structure definition
typedef struct struct_CPKCL_expmod {
               nu1       nu1ModBase;
               nu1       nu1CnsBase;
               u2        u2ModLength;

               nu1       nu1XBase;           // (3*u2NLength + 6) words LSW is always zero
               nu1       nu1PrecompBase;     // xxx words LSW is always zero
               u2        u2ExpLength;
               pfu1      pfu1ExpBase;        // u2ExpLength words
               u1        u1Blinding;         // Exponent blinding using a 32-bits Xor
               u1        padding0;
               u2        padding1;
               } CPKCL_EXPMOD_STRUCT, *PPKCL_EXPMOD_STRUCT;

// Options definition
#define CPKCL_EXPMOD_REGULARRSA      0x01
#define CPKCL_EXPMOD_EXPINPKCCRAM    0x02
#define CPKCL_EXPMOD_FASTRSA         0x04
#define CPKCL_EXPMOD_OPERATIONMASK   0x07
#define CPKCL_EXPMOD_MODEMASK        0x05     // For faults protection

#define CPKCL_EXPMOD_WINDOWSIZE_MASK 0x18
#define CPKCL_EXPMOD_WINDOWSIZE_1    0x00
#define CPKCL_EXPMOD_WINDOWSIZE_2    0x08
#define CPKCL_EXPMOD_WINDOWSIZE_3    0x10
#define CPKCL_EXPMOD_WINDOWSIZE_4    0x18
#define CPKCL_EXPMOD_WINDOWSIZE_BIT(a)   (u2)((a) & CPKCL_EXPMOD_WINDOWSIZE_MASK) >> 3


#endif // CRYPTOLIB_EXPMOD_PB_INCLUDED
