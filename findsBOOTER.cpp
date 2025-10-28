#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DevicePathLib.h>
#include <Library/BaseLib.h>
#include <Protocol/SimpleFileSystem.h>
#include <Protocol/LoadedImage.h>
#include <Guid/FileInfo.h>

static CHAR16 WINDOWS_BOOTMGR_PATH[] = {
    '\\', 'E', 'F', 'I', '\\', 'M', 'i', 'c', 'r', 'o', 's', 'o', 'f', 't',
    '\\', 'B', 'o', 'o', 't', '\\', 'b', 'o', 'o', 't', 'm', 'g', 'f', 'w',
    '.', 'e', 'f', 'i', '\0'
};

static const CHAR16 FAILED_FS_HANDLES_FMT[] = {
    'F', 'a', 'i', 'l', 'e', 'd', ' ', 't', 'o', ' ', 'g', 'e', 't', ' ', 'f',
    'i', 'l', 'e', 's', 'y', 's', 't', 'e', 'm', ' ', 'h', 'a', 'n', 'd', 'l',
    'e', 's', ':', ' ', '%', 'r', '\n', '\0'
};

static const CHAR16 FOUND_BOOTMGR_FMT[] = {
    '[', '+', ']', ' ', 'F', 'o', 'u', 'n', 'd', ' ', 'W', 'i', 'n', 'd', 'o',
    'w', 's', ' ', 'B', 'o', 'o', 't', ' ', 'M', 'a', 'n', 'a', 'g', 'e', 'r',
    ' ', 'a', 't', ':', ' ', '%', 's', '\n', '\0'
};

EFI_DEVICE_PATH_PROTOCOL*
giveMeTHeBOOTER(IN EFI_HANDLE ImageHandle)
{
    // Finds the Windows Boot Manager on any available filesystem and returns
    // a device path describing its location.
    EFI_STATUS Status;
    EFI_HANDLE* Handles = NULL; // All handles that support SimpleFileSystem
    UINTN HandleCount = 0;
    EFI_DEVICE_PATH_PROTOCOL* DevicePath = NULL;


    Status = gBS->LocateHandleBuffer(
        ByProtocol,
        &gEfiSimpleFileSystemProtocolGuid,
        NULL,
        &HandleCount,
        &Handles
    );

    if (EFI_ERROR(Status)) {
        Print(FAILED_FS_HANDLES_FMT, Status);
        return NULL;
    }

    // Check each filesystem for bootmgfw.efi
    for (UINTN i = 0; i < HandleCount && !DevicePath; ++i) {
        EFI_SIMPLE_FILE_SYSTEM_PROTOCOL* FileSystem;

        // Open the SimpleFileSystem protocol
        Status = gBS->OpenProtocol(
            Handles[i],
            &gEfiSimpleFileSystemProtocolGuid,
            (VOID**)&FileSystem,
            ImageHandle,
            NULL,
            EFI_OPEN_PROTOCOL_GET_PROTOCOL
        );

        if (EFI_ERROR(Status)) {
            continue;
        }

        // Open the root volume
        EFI_FILE_PROTOCOL* Volume;
        Status = FileSystem->OpenVolume(FileSystem, &Volume);

        if (!EFI_ERROR(Status)) {
            // Try to open the Windows Boot Manager file
            EFI_FILE_PROTOCOL* File;
            CHAR16 BootPathBuffer[260];
            StrCpyS(
                BootPathBuffer,
                sizeof(BootPathBuffer) / sizeof(BootPathBuffer[0]),
                WINDOWS_BOOTMGR_PATH
            );

            Status = Volume->Open(
                Volume,
                &File,
                BootPathBuffer,
                EFI_FILE_MODE_READ,
                EFI_FILE_READ_ONLY
            );

            if (!EFI_ERROR(Status)) {
                // Found it! Close the file and create device path
                File->Close(File);
                DevicePath = FileDevicePath(Handles[i], WINDOWS_BOOTMGR_PATH);
                Print(FOUND_BOOTMGR_FMT, WINDOWS_BOOTMGR_PATH);
            }

            Volume->Close(Volume);
        }

        // Close the protocol
        gBS->CloseProtocol(
            Handles[i],
            &gEfiSimpleFileSystemProtocolGuid,
            ImageHandle,
            NULL
        );
    }

    // Free the handle buffer
    if (Handles) {
        FreePool(Handles);
    }

    return DevicePath;
}
