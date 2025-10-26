# Chaos-Rootkit

<p align="center">
  <img src="https://user-images.githubusercontent.com/60795188/227610457-51555f6e-885c-47fd-8a04-ab2351035a2b.png" alt="Image Description" width="320">
</p>


*  Chaos-Rootkit is an x64 Ring 0 rootkit with capabilities for process hiding, privilege escalation, protecting and unprotecting processes, and restricting access to files except for whitelisted processes. It can bypass file integrity checks and protect it against anti-malware, and swap the driver in memory and on disk with a signed Microsoft driver, working seamlessly on the latest Windows versions

* Gui version
  
<p align="center">
    <img src="https://github.com/user-attachments/assets/be4a4203-9ad4-4be3-b4b5-da86edceff2a" alt="image">
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

  


