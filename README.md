# Chaos-Rootkit

<p align="center">
  <img src="https://github.com/user-attachments/assets/c352d7c4-f444-453d-995a-65575d3c0e9a" alt="Image Description" width="320">
</p>


*  Chaos-Rootkit is an x64 Ring 0 rootkit i wrote to better understand kernel internals and rootkit techniques.

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

* Swap the driver on disk and in memory with a Microsoft driver: All credit for this implementation goes to [IDontCode](https://x.com/_xeroxz) [Back Engineering](https://back.engineering/) for his exceptional work, I've also handled the unload and shutdown routines for this feature so that the rootkits driver doesn’t get corrupted or crash at some point.

* Restrict file access for user-mode applications except for the provided process ID
  
* Spawn elevated process: launch command prompt with elevated privileges .

* Bypass the file integrity check and protect it against anti-malware : this work by redirecting file operations to a legitimate file, making our file appear authentic and signed with a valid certificate also if   an anti-malware attempting to scan it, the rootkit will immediately kill the anti-malware process.
  
* Unprotect all processes

* Protect a specific process with any given protection level (WinSystem, WinTcb, Windows, Authenticode, Lsa, Antimalware) .
  
* Protect a specific file against anti-malware, when an anti malware tries to scan it the rootkit will shut it down this done by checking the caller EPROCESS protection member .

# Contribution

* Contributions are welcome, but when contributing, please pay attention to the implementation details of how the rootkit is designed. For example, see this [code](https://github.com/ZeroMemoryEx/Chaos-Rootkit/blob/1d38a4141fc5f958258af0f09a109454f59ec777/Chaos-Rootkit/Driver.c#L551). Ignoring this logic will break the driver. The last contribution did not follow this design, and I had to push several updates to fix it :(.
  
# Writeup
* https://www.hackandhide.com/chaos-rootkit-internals-explained/

# CREDITS

* [Yassine Jerroudi](https://x.com/Jerroudi_Yass) : Helped significantly with the early version of the rootkit client GUI, since I was a complete noob with IMGUI. Deserves all the credit.
* [IDontCode](https://x.com/_xeroxz) [BackEngineerLab](https://x.com/BackEngineerLab): All credit for the implementation of swapping the driver on disk and in memory.
* [sixtyvividtails](https://x.com/sixtyvividtails) : Thanks to him for recommending probing ObjectAttributes->ObjectName->Buffer at all three levels, since we are hooking NtCreateFile and receive user-controlled pointers.
* [Pavel Yosifovich](https://x.com/zodiacon) : the author of Windows Kernel Programming, this book remains the single most valuable resource I rely on, without a solid understanding of kernel internals, you can’t just vibe-code drivers. real knowledge is the only thing that keeps you from getting completely cooked <img src="https://github.com/user-attachments/assets/fafe8039-9d47-4d6c-87e9-c11a5fcdc130"
     alt="bsod"
     style="width:30px;height:25px;vertical-align:middle;"> ..
* To contributors: Special thanks to [UncleJ4ck](https://x.com/UncleJa4ck), the first contributor, for implementing error handling, and to [staarblitz](https://github.com/staarblitz) for adding Windows 11 24H2 offsets and GUI protection.




