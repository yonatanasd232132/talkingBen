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

static CHAR16 WINDOWS_BOOTMGR_PATH[] = L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi";

static const CHAR16 FAILED_FS_HANDLES_FMT[] = L"Failed to get filesystem handles: %r\n";
static const CHAR16 FOUND_BOOTMGR_FMT[] = L"[+] Found Windows Boot Manager at: %s\n";

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
