#include "mm.h"

PVOID
MMAPI
MmAllocateNonPaged(
    IN SIZE_T NumberOfBytes
)
{
    return ExAllocatePoolWithTag(NonPagedPool, NumberOfBytes, MM_POOL_TAG);
}

PVOID
MMAPI
MmAllocateNonPagedNx(
    IN SIZE_T NumberOfBytes
)
{
    return ExAllocatePoolWithTag(NonPagedPoolNx, NumberOfBytes, MM_POOL_TAG);
}

PVOID
MMAPI
MmAllocatePaged(
    IN SIZE_T NumberOfBytes
)
{
    return ExAllocatePoolWithTag(PagedPool, NumberOfBytes, MM_POOL_TAG);
}

VOID
MMAPI
MmFreeNonPaged(
    IN PVOID P
)
{
    ExFreePoolWithTag(P, MM_POOL_TAG);
}

VOID
MMAPI
MmFreePaged(
    IN PVOID P
)
{
    ExFreePoolWithTag(P, MM_POOL_TAG);
}