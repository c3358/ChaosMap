#if defined(_MSC_VER)
#pragma once
#endif

#include "driver.h"

_Dispatch_type_(IRP_MJ_CREATE) DRIVER_DISPATCH BoDeviceCreate; // This function handles the 'create' irp.
_Dispatch_type_(IRP_MJ_CLOSE) DRIVER_DISPATCH BoDeviceClose; // This function handles the 'close' irp.
_Dispatch_type_(IRP_MJ_CLEANUP) DRIVER_DISPATCH BoDeviceCleanup; // This function handles the 'cleanup' irp.
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL) DRIVER_DISPATCH BoDeviceControl; // This function handles the 'ioctl' irp.