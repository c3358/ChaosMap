#if defined(_MSC_VER)
#pragma once
#endif

#include "ntapi.h"

// Crypto API calling convention
#define CRYPTAPI  NTAPI

// Magical XOR value
#define CRYPT_MAGICAL_MAGIC 0xA55A5AA5


SIZE_T
CRYPTAPI
CryptGetEncryptedXTEABufferSize(
    IN SIZE_T UnencryptedSize,
    IN BOOLEAN WithXorSeed
    );

VOID
CRYPTAPI
CryptEncryptXTEABuffer(
    IN PUCHAR UnencryptedBuffer,
    IN SIZE_T UnencryptedSize,
    IN CONST PULONG Key,
    IN ULONG XorSeed OPTIONAL,
    OUT PUCHAR EncryptedBuffer,
    OUT PSIZE_T EncryptedSize
    );

VOID
CRYPTAPI
CryptDecryptXTEABuffer(
    IN PUCHAR EncryptedBuffer,
    IN SIZE_T EncryptedSize,
    IN CONST PULONG Key,
    IN ULONG XorSeed OPTIONAL,
    OUT PUCHAR UnencryptedBuffer,
    OUT PSIZE_T UnencryptedSize
    );
