#include "findsBOOTER.h"

#include <Library/DevicePathLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/SimpleFileSystem.h>

// Windows Boot Manager path
#define WINDOWS_BOOTMGR_PATH L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi"

EFI_STATUS
GetWindowsBootManagerDevicePath(
    IN  EFI_HANDLE ImageHandle,
    OUT EFI_DEVICE_PATH_PROTOCOL **DevicePath
    )
{
    EFI_STATUS                  Status;
    EFI_HANDLE                 *Handles = NULL;
    UINTN                       HandleCount = 0;
    EFI_DEVICE_PATH_PROTOCOL   *LocalDevicePath = NULL;

    if (DevicePath == NULL) {
        return EFI_INVALID_PARAMETER;
    }

    *DevicePath = NULL;

    Status = gBS->LocateHandleBuffer(
        ByProtocol,
        &gEfiSimpleFileSystemProtocolGuid,
        NULL,
        &HandleCount,
        &Handles
        );

    if (EFI_ERROR(Status)) {
        return Status;
    }

    for (UINTN Index = 0; Index < HandleCount && LocalDevicePath == NULL; ++Index) {
        EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *FileSystem = NULL;

        Status = gBS->OpenProtocol(
            Handles[Index],
            &gEfiSimpleFileSystemProtocolGuid,
            (VOID **)&FileSystem,
            ImageHandle,
            NULL,
            EFI_OPEN_PROTOCOL_GET_PROTOCOL
            );

        if (EFI_ERROR(Status)) {
            continue;
        }

        EFI_FILE_PROTOCOL *Volume = NULL;
        Status = FileSystem->OpenVolume(FileSystem, &Volume);

        if (!EFI_ERROR(Status)) {
            EFI_FILE_PROTOCOL *File = NULL;
            Status = Volume->Open(
                Volume,
                &File,
                WINDOWS_BOOTMGR_PATH,
                EFI_FILE_MODE_READ,
                EFI_FILE_READ_ONLY
                );

            if (!EFI_ERROR(Status)) {
                File->Close(File);
                LocalDevicePath = FileDevicePath(Handles[Index], WINDOWS_BOOTMGR_PATH);
                if (LocalDevicePath != NULL) {
                    Print(L"[+] Found Windows Boot Manager at: %s\n", WINDOWS_BOOTMGR_PATH);
                }
            }

            if (Volume != NULL) {
                Volume->Close(Volume);
            }
        }

        gBS->CloseProtocol(
            Handles[Index],
            &gEfiSimpleFileSystemProtocolGuid,
            ImageHandle,
            NULL
            );
    }

    if (Handles != NULL) {
        FreePool(Handles);
    }

    if (LocalDevicePath == NULL) {
        return EFI_NOT_FOUND;
    }

    *DevicePath = LocalDevicePath;
    return EFI_SUCCESS;
}
