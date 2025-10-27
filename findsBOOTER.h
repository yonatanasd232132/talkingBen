#ifndef FINDS_BOOTER_H
#define FINDS_BOOTER_H

#include <Uefi.h>

/**
  Locate the device path for the Windows Boot Manager (bootmgfw.efi).

  @param[in]  ImageHandle   The image handle of the calling application.
  @param[out] DevicePath    On success, receives an allocated device path
                            describing the discovered Boot Manager. The
                            caller is responsible for freeing this buffer via
                            FreePool().

  @retval EFI_SUCCESS             The device path was found and returned.
  @retval EFI_NOT_FOUND           The Boot Manager could not be located.
  @retval EFI_INVALID_PARAMETER   DevicePath is NULL.
  @retval Others                  Error codes propagated from Boot Services.
**/
EFI_STATUS
GetWindowsBootManagerDevicePath(
    IN  EFI_HANDLE ImageHandle,
    OUT EFI_DEVICE_PATH_PROTOCOL **DevicePath
    );

#endif // FINDS_BOOTER_H
