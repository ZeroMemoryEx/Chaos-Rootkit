# Chaos-Rootkit

<p align="center">
  <img src="https://user-images.githubusercontent.com/60795188/227610457-51555f6e-885c-47fd-8a04-ab2351035a2b.png" alt="Image Description" width="320">
</p>


  * Chaos-Rootkit is a x64 ring0 rootkit with process hiding, privilege escalation, and capabilities for protecting and unprotecting processes, work on the latest Windows versions .

* Gui version
  
  ![29](https://github.com/ZeroMemoryEx/Chaos-Rootkit/assets/60795188/04c9303f-b180-413d-bb38-2dd824db4ef5)

# Features

* Hide process: This feature allows you to hide processes from listing tools via DKOM.

* Elevate specific process privileges : This feature enables you to elevate specific processes privilege .

* Spawn elevated process: launch command prompt with elevated privileges .

* Unprotect all processes

* Protect a specific process with any given protection level (WinSystem, WinTcb, Windows, Authenticode, Lsa, Antimalware) .


# Technical Details

* First, we locate the `ActiveProcessLinks`, which is a pointer to the `PLIST_ENTRY` structure. In our case, the `ActiveProcessLinks` pointer is located at offset `0x448` within the `EPROCESS` structure. It is important to note that this offset may vary across different windows versions .

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

* The `PLIST_ENTRY` structure is a doubly linked list structure . It contains two members, `Blink` and `Flink`, which are pointers to the previous and next entries in the list, respectively, These pointers allow for efficient traversal of the linked list in both directions.

  ![image](https://user-images.githubusercontent.com/60795188/227370531-b1a90f9a-4fe7-4f57-8787-e1da1543e1b7.png)
 
* The flink member resides in offset `0x0` and the blink member resides in offset `0x8`. The flink address `0xffff9c8b\`071e3488` points to the next process node, while the blink address `0xfffff805\`5121e0a0` points to the previous process node

  ![Screenshot 2023-03-23 222046](https://user-images.githubusercontent.com/60795188/227380821-92717306-66ee-40a0-8831-1cfc1a819eda.png)

* a diagram represents the `PLIST_ENTRY` structure.

  ![Screenshot 2023-03-23 181753](https://user-images.githubusercontent.com/60795188/227361450-d35e0fbb-cfbd-4fbf-bfd6-cef3373ab07a.png)
  
* To hide our chosen process in a listing tool, we can use a technique where we modify the flink and blink pointers of the adjacent process nodes to point to each other, effectively removing our process from the linked list. Specifically, we make the next process node's blink pointer point to the previous node, and the previous process node's flink pointer point to the next node. This makes our process appear invisible in the listing tool's view of the linked list of processes

  ![image](https://user-images.githubusercontent.com/60795188/227380533-0e80298c-0800-485a-8797-1cc7a0efb757.png)

* Note: After removing the node from PLIST_ENTRY structure, it is important to set the corresponding pointer to NULL, Otherwise, when attempting to close the process, the PLIST_ENTRY structure will get sent to the PspDeleteProcess API to free all its resources, after the API does not find the process in the structure, it will suspect that the process has already been freed, resulting in a Blue Screen of Death (BSOD), as shown below  .

  ![image](https://user-images.githubusercontent.com/60795188/228383831-f1a4940a-4ebb-4478-b964-ec54d4eab8e7.png)


## Elevate process privileges

* When a process is created, it inherits the token of the user who created it, The token is used by the system to determine what actions the process can perform, The token contains information about the user's security identifier (SID), group memberships, and privileges.

  ![image](https://user-images.githubusercontent.com/60795188/226148214-1d63149a-e2e6-4938-9067-30df7939c9db.png)
  
* The Token member resides at offset `0x4b8` in the `_EPROCESS` structure, which is a data structure that represents a process object. The Token member is defined in  `_EX_FAST_REF` structure, which is a union type that can store either a pointer to a kernel object or a reference count, depending on the size of the pointer , The offset of the `_EX_FAST_REF` structure within `_EPROCESS` depends on the specific version of Windows being used, but it is typically located at an offset of `0x4b8` in recent versions of Windows..

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

* You can either spawn a privileged process or elevate an already existing process ID. 

  ![image](https://user-images.githubusercontent.com/60795188/226211454-7266638a-8cce-4417-a139-d3490d1fb68e.png) 

* For the sake of this explanation, we will focus on the second option and use CMD as an example

  ![image](https://user-images.githubusercontent.com/60795188/226149275-cfd76437-dda3-4964-9a54-43fa20247b3e.png)
  
* CMD inherited Token

  ![image](https://user-images.githubusercontent.com/60795188/226149373-2bf16ae9-e67f-4150-86b3-8376b0eb8428.png)
  
* we send the Process ID to the driver through an IOCTL 

  ![image](https://user-images.githubusercontent.com/60795188/226196873-f5cd9ab4-5c71-4d05-a0d4-4ae80a8dd809.png)

* after the driver receives the PID from the user mode application, it uses it to obtain a pointer to the `_EPROCESS` structure for the target process. The driver then accesses the Token member of the `_EPROCESS` structure to obtain a pointer to the process token, which it replaces with the system token, effectively changing the security context of the process to that of the system. However, if the driver does not correctly locate the Token member within the `_EPROCESS` structure or if the offset of the Token is other than `0x4b8` , the driver may crash the system or the target process ,this problem will be fixed in the next updates .

 
* cmd token after
 
  ![image](https://user-images.githubusercontent.com/60795188/227381408-58e9cc54-95ac-4ec5-8d9c-5de6c28f7062.png)

* the process privileges, groups, rights 
  
  ![image](https://user-images.githubusercontent.com/60795188/226149800-e80ea9d8-5f69-4425-ad0e-a4a65cd946d9.png)

# DEMO



  https://user-images.githubusercontent.com/60795188/227605986-dd59463e-f9f1-4fa0-ba87-3c06d3c34ca0.mp4


