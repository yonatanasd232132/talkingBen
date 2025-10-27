#include <Uefi.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Protocol/Cpu.h>
#include <Protocol/DxeServices.h>

#include "findsBOOTER.h"

#define PATCH_JUMP_SIZE 14 // size for jmp instruction in x64 (ff 25 + rip + 8-byte address)
#define PAGE_SIZE 0x1000

// Signature for ImgArchStartBootApplication in bootmgfw.efi
// This is the pattern BlackLotus searches for
STATIC CONST UINT8 SigImgArchStartBootApplication[] = {
    0x41, 0xB8, 0x09, 0x00, 0x00, 0x00, // mov r8d, 9
    0x48, 0x83, 0xEC, 0x28,             // sub rsp, 28h
    0x48, 0x8B, 0x05, 0x11              // mov rax, [rip+11h] (truncated demo pattern)
};

STATIC
VOID
EFIAPI
MyHookFunction(VOID)
{
    Print(L"[hook] ImgArchStartBootApplication hook triggered!\n");
}

// Pattern matching function to find code signatures in memory
VOID *
FindPattern(
    IN VOID  *Base,
    IN UINTN  Size,
    IN UINT8 *Pattern,
    IN UINTN  PatternSize
    )
{
    if (Base == NULL || Pattern == NULL || PatternSize == 0 || Size == 0) {
        return NULL;
    }

    if (PatternSize > Size) {
        return NULL;
    }

    UINT8 *Memory = (UINT8 *)Base;

    for (UINTN Index = 0; Index <= Size - PatternSize; Index++) {
        BOOLEAN Match = TRUE;

        for (UINTN PatternIndex = 0; PatternIndex < PatternSize; PatternIndex++) {
            if (Memory[Index + PatternIndex] != Pattern[PatternIndex]) {
                Match = FALSE;
                break;
            }
        }

        if (Match) {
            return &Memory[Index];
        }
    }

    return NULL;
}

/**
  Patch a target function prologue with a 14-byte x64 absolute indirect jump:
    ff 25 00 00 00 00      ; jmp qword ptr [rip]
    <8-byte absolute address>

  - TargetAddress: virtual address to patch
  - HookFunction: absolute address to jump to
  - OriginalBytes: on success, receives a buffer (PATCH_JUMP_SIZE bytes)
    containing the original bytes; caller must FreePool it.

  Returns EFI_SUCCESS on success.
**/
EFI_STATUS
PatchFunctionWithJump(
    IN  VOID   *TargetAddress,
    IN  VOID   *HookFunction,
    OUT UINT8 **OriginalBytes
    )
{
    EFI_STATUS                 Status;
    EFI_PHYSICAL_ADDRESS       PhysBase;
    UINTN                      OffsetInPage;
    EFI_PHYSICAL_ADDRESS       PageBase;
    UINT64                     PageLength;
    UINT64                     BytesToCover;
    UINT8                      JumpBytes[PATCH_JUMP_SIZE];
    EFI_CPU_ARCH_PROTOCOL     *Cpu          = NULL;
    EFI_DXE_SERVICES_PROTOCOL *DxeServices  = NULL;
    BOOLEAN                    UsedDxeService = FALSE;

    if (OriginalBytes == NULL || TargetAddress == NULL || HookFunction == NULL) {
        return EFI_INVALID_PARAMETER;
    }

    *OriginalBytes = AllocatePool(PATCH_JUMP_SIZE);
    if (*OriginalBytes == NULL) {
        return EFI_OUT_OF_RESOURCES;
    }

    CopyMem(*OriginalBytes, TargetAddress, PATCH_JUMP_SIZE);

    ZeroMem(JumpBytes, sizeof(JumpBytes));
    JumpBytes[0] = 0xFF;
    JumpBytes[1] = 0x25;
    *(UINT32 *)&JumpBytes[2] = 0x00000000;
    *(UINT64 *)&JumpBytes[6] = (UINT64)(UINTN)HookFunction;

    PhysBase = (EFI_PHYSICAL_ADDRESS)(UINTN)TargetAddress;
    OffsetInPage = (UINTN)(PhysBase & (PAGE_SIZE - 1));
    BytesToCover = (UINT64)PATCH_JUMP_SIZE + OffsetInPage;
    PageBase = PhysBase & ~(PAGE_SIZE - 1);
    PageLength = (BytesToCover + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1);

    Status = gBS->LocateProtocol(&gEfiDxeServicesProtocolGuid, NULL, (VOID **)&DxeServices);
    if (!EFI_ERROR(Status) && DxeServices != NULL) {
        UsedDxeService = TRUE;
        Status = DxeServices->SetMemorySpaceAttributes(PageBase, PageLength, 0);
        if (EFI_ERROR(Status)) {
            DEBUG((DEBUG_ERROR, "DxeServices->SetMemorySpaceAttributes failed: %r\n", Status));
            UsedDxeService = FALSE;
        }
    }

    if (!UsedDxeService) {
        Status = gBS->LocateProtocol(&gEfiCpuArchProtocolGuid, NULL, (VOID **)&Cpu);
        if (EFI_ERROR(Status) || Cpu == NULL) {
            DEBUG((DEBUG_ERROR, "Failed to locate CPU protocol: %r\n", Status));
            FreePool(*OriginalBytes);
            *OriginalBytes = NULL;
            return EFI_UNSUPPORTED;
        }

        Status = Cpu->SetMemoryAttributes(Cpu, PageBase, PageLength, 0);
        if (EFI_ERROR(Status)) {
            DEBUG((DEBUG_ERROR, "Cpu->SetMemoryAttributes failed: %r\n", Status));
            FreePool(*OriginalBytes);
            *OriginalBytes = NULL;
            return Status;
        }
    }

    CopyMem(TargetAddress, JumpBytes, PATCH_JUMP_SIZE);

    if (UsedDxeService && DxeServices != NULL) {
        UINT64 RestoreAttributes = (UINT64)(EFI_MEMORY_XP | EFI_MEMORY_RO);
        Status = DxeServices->SetMemorySpaceAttributes(PageBase, PageLength, RestoreAttributes);
        if (EFI_ERROR(Status)) {
            DEBUG((DEBUG_WARN, "Failed to restore attributes via DxeServices: %r\n", Status));
        }
    } else if (Cpu != NULL) {
        UINT64 RestoreAttributes = (UINT64)(EFI_MEMORY_XP | EFI_MEMORY_RO);
        Status = Cpu->SetMemoryAttributes(Cpu, PageBase, PageLength, RestoreAttributes);
        if (EFI_ERROR(Status)) {
            DEBUG((DEBUG_WARN, "Failed to restore attributes via Cpu protocol: %r\n", Status));
        }
    }

    return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
UefiMain(
    IN EFI_HANDLE        ImageHandle,
    IN EFI_SYSTEM_TABLE *SystemTable
    )
{
    EFI_STATUS Status;
    EFI_DEVICE_PATH_PROTOCOL *BootManagerPath = NULL;

    Status = GetWindowsBootManagerDevicePath(ImageHandle, &BootManagerPath);
    if (EFI_ERROR(Status)) {
        Print(L"[-] Failed to locate Windows Boot Manager: %r\n", Status);
    } else {
        Print(L"[+] Windows Boot Manager device path acquired.\n");
    }

    UINT8 DemoCodeTemplate[PATCH_JUMP_SIZE] = {0};
    UINTN BytesToCopy = sizeof(SigImgArchStartBootApplication) < sizeof(DemoCodeTemplate)
                            ? sizeof(SigImgArchStartBootApplication)
                            : sizeof(DemoCodeTemplate);
    CopyMem(DemoCodeTemplate, SigImgArchStartBootApplication, BytesToCopy);

    UINT8 *DemoExecutable = (UINT8 *)AllocatePool(sizeof(DemoCodeTemplate));
    if (DemoExecutable != NULL) {
        CopyMem(DemoExecutable, DemoCodeTemplate, sizeof(DemoCodeTemplate));

        VOID *Found = FindPattern(
            DemoExecutable,
            sizeof(DemoCodeTemplate),
            (UINT8 *)SigImgArchStartBootApplication,
            sizeof(SigImgArchStartBootApplication)
            );

        if (Found != NULL) {
            UINT8 *SavedBytes = NULL;
            Status = PatchFunctionWithJump(Found, (VOID *)MyHookFunction, &SavedBytes);
            if (EFI_ERROR(Status)) {
                DEBUG((DEBUG_ERROR, "Patch failed: %r\n", Status));
            } else {
                DEBUG((DEBUG_INFO, "Patch applied successfully.\n"));
            }

            if (SavedBytes != NULL) {
                FreePool(SavedBytes);
            }
        } else {
            DEBUG((DEBUG_WARN, "Pattern not found in demo buffer.\n"));
        }

        FreePool(DemoExecutable);
    } else {
        DEBUG((DEBUG_ERROR, "Failed to allocate demo buffer.\n"));
    }

    if (BootManagerPath != NULL) {
        FreePool(BootManagerPath);
    }

    DEBUG((DEBUG_INFO, "Patch demo finished.\n"));
    return EFI_SUCCESS;
}
