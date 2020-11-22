#if defined(_MSC_VER)
#pragma once
#endif

#include "ntapi.h"

#define MMAPI       NTAPI

#define MM_POOL_TAG '  mM'


PVOID
MMAPI
MmAllocateNonPaged(
    IN SIZE_T NumberOfBytes
    );

PVOID
MMAPI
MmAllocateNonPagedNx(
    IN SIZE_T NumberOfBytes
    );

PVOID
MMAPI
MmAllocatePaged(
    IN SIZE_T NumberOfBytes
    );

VOID
MMAPI
MmFreeNonPaged(
    IN PVOID P
    );

#define MmFreeNonPagedNx MmFreeNonPaged

VOID
MMAPI
MmFreePaged(
    IN PVOID P
    );

