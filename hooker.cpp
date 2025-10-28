#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Protocol/Cpu.h>
#include <Protocol/DxeServices.h>
#include <Library/PrintLib.h>

#define C16(Str) ((CONST CHAR16*)(Str))

#define PATCH_JUMP_SIZE 14 // size for jmp instruction in x64 (ff 25 + rip + 8-byte address)
#define PAGE_SIZE 0x1000
#ifndef EFI_MEMORY_XP
#define EFI_MEMORY_XP 0x1000000000000000ULL
#endif
#ifndef EFI_MEMORY_RO
#define EFI_MEMORY_RO 0x2000000000000000ULL
#endif

EFI_STATUS
EFIAPI
MyHookFunction(
    IN VOID* ApplicationEntryPoint,
    IN EFI_HANDLE ImageHandle,
    IN UINT32 Flags,
    IN EFI_HANDLE ParentImageHandle,
    IN VOID* FilePath
)
{
    DEBUG((DEBUG_INFO, "MyHookFunction invoked. Hook success!\n"));

    (void)ApplicationEntryPoint;
    (void)ImageHandle;
    (void)Flags;
    (void)ParentImageHandle;
    (void)FilePath;

    return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TargetFunction(
    IN EFI_HANDLE ImageHandle,
    IN EFI_SYSTEM_TABLE* SystemTable
)
{
    static CONST CHAR16* const ORIGINAL_TARGET_MSG = C16(L"Original TargetFunction should not execute after hooking.\n");
    Print(ORIGINAL_TARGET_MSG);

    (void)ImageHandle;
    (void)SystemTable;

    return EFI_SUCCESS;
}

/**
  Patch a target function prologue with a 14-byte x64 absolute indirect jump:
    ff 25 00 00 00 00      ; jmp qword ptr [rip]
    <8-byte absolute address>

  - TargetAddress: virtual address to patch
  - HookFunction: absolute address to jump to
  - OriginalBytes: on success, receives a buffer (PATCH_JUMP_SIZE bytes) containing the original bytes; caller must FreePool it.

  Returns EFI_SUCCESS on success.
**/
EFI_STATUS
PatchFunctionWithJump(
    IN  VOID* TargetAddress,
    IN  VOID* HookFunction,
    OUT UINT8** OriginalBytes
)
{
    EFI_STATUS                  Status;
    EFI_PHYSICAL_ADDRESS        PhysBase;
    UINTN                       OffsetInPage;
    EFI_PHYSICAL_ADDRESS        PageBase;
    UINT64                      PageLength;
    UINT64                      BytesToCover;
    UINT8                       JumpBytes[PATCH_JUMP_SIZE];
    EFI_CPU_ARCH_PROTOCOL*      Cpu = NULL;
    EFI_DXE_SERVICES_PROTOCOL*  DxeServices = NULL;
    BOOLEAN                     UsedDxeService = FALSE;

    if (OriginalBytes == NULL || TargetAddress == NULL || HookFunction == NULL) {
        return EFI_INVALID_PARAMETER;
    }

    // Allocate buffer to store original bytes
    *OriginalBytes = AllocatePool(PATCH_JUMP_SIZE);
    if (*OriginalBytes == NULL) {
        return EFI_OUT_OF_RESOURCES;
    }

    // Save original bytes
    CopyMem(*OriginalBytes, TargetAddress, PATCH_JUMP_SIZE);

    // Build the 14-byte jump:
    // ff 25 00 00 00 00         ; JMP QWORD PTR [RIP + 0]
    // <8-byte address>
    ZeroMem(JumpBytes, sizeof(JumpBytes));
    JumpBytes[0] = 0xFF;
    JumpBytes[1] = 0x25;
    // next 4 bytes are zero (disp32)
    *(UINT32*)&JumpBytes[2] = 0x00000000;
    // then 8-byte absolute address
    *(UINT64*)&JumpBytes[6] = (UINT64)(UINTN)HookFunction;

    // Calculate physical page range that covers the patched bytes
    PhysBase = (EFI_PHYSICAL_ADDRESS)(UINTN)TargetAddress;
    OffsetInPage = (UINTN)(PhysBase & (PAGE_SIZE - 1));
    BytesToCover = (UINT64)PATCH_JUMP_SIZE + OffsetInPage;
    PageBase = PhysBase & ~(PAGE_SIZE - 1);
    PageLength = (BytesToCover + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1); // round up to page size

    // Try using DXE Services protocol to set memory attributes if available
    Status = gBS->LocateProtocol(&gEfiDxeServicesProtocolGuid, NULL, (VOID**)&DxeServices);
    if (!EFI_ERROR(Status) && DxeServices != NULL) {
        UsedDxeService = TRUE;

        // Remove execute-protect/readonly attributes (set attributes to 0)
        Status = DxeServices->SetMemorySpaceAttributes(PageBase, PageLength, 0);
        if (EFI_ERROR(Status)) {
            DEBUG((DEBUG_ERROR, "DxeServices->SetMemorySpaceAttributes failed: %r\n", Status));
            UsedDxeService = FALSE;
        }
    }

    // If DXE Services unavailable / failed, use CPU protocol
    if (!UsedDxeService) {
        Status = gBS->LocateProtocol(&gEfiCpuArchProtocolGuid, NULL, (VOID**)&Cpu);
        if (EFI_ERROR(Status) || Cpu == NULL) {
            DEBUG((DEBUG_ERROR, "Failed to locate CPU protocol: %r\n", Status));
            FreePool(*OriginalBytes);
            *OriginalBytes = NULL;
            return EFI_UNSUPPORTED;
        }

        // Set memory attributes -- remove protections by clearing attributes (0)
        Status = Cpu->SetMemoryAttributes(Cpu, PageBase, PageLength, 0);
        if (EFI_ERROR(Status)) {
            DEBUG((DEBUG_ERROR, "Cpu->SetMemoryAttributes failed: %r\n", Status));
            FreePool(*OriginalBytes);
            *OriginalBytes = NULL;
            return Status;
        }
    }

    // Overwrite the target with our jump
    CopyMem(TargetAddress, JumpBytes, PATCH_JUMP_SIZE);

    // Restore memory attributes
    if (UsedDxeService) {
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

#ifdef __cplusplus
extern "C" {
#endif

EFI_STATUS
EFIAPI
UefiMain(
    IN EFI_HANDLE ImageHandle,
    IN EFI_SYSTEM_TABLE* SystemTable
)
{
    EFI_STATUS Status = EFI_SUCCESS;
    UINT8* SavedBytes = NULL;

    static CONST CHAR16* const HOOK_ATTEMPT_MSG = C16(L"Attempting to hook TargetFunction...\n");
    Print(HOOK_ATTEMPT_MSG);

    Status = PatchFunctionWithJump((VOID*)TargetFunction, (VOID*)MyHookFunction, &SavedBytes);
    if (EFI_ERROR(Status)) {
        DEBUG((DEBUG_ERROR, "Patch failed: %r\n", Status));
        if (SavedBytes != NULL) {
            FreePool(SavedBytes);
        }
        return Status;
    }

    DEBUG((DEBUG_INFO, "Patch applied. Invoking TargetFunction to validate hook.\n"));

    EFI_STATUS HookResult = TargetFunction(ImageHandle, SystemTable);
    if (EFI_ERROR(HookResult)) {
        DEBUG((DEBUG_ERROR, "TargetFunction returned error: %r\n", HookResult));
    } else {
        DEBUG((DEBUG_INFO, "Hook executed successfully.\n"));
    }

    if (SavedBytes != NULL) {
        FreePool(SavedBytes);
    }

    DEBUG((DEBUG_INFO, "Patch demo finished\n"));
    return HookResult;
}

#ifdef __cplusplus
}
#endif

