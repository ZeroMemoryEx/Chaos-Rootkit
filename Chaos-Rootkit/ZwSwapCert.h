#ifndef ZWSWAPCERT_H  
#define ZWSWAPCERT_H  

#include <ntifs.h>
#include <windef.h>
#include <intrin.h>

typedef struct _IMAGE_DOS_HEADER
{
	/* 0x0000 */ unsigned short e_magic;
	/* 0x0002 */ unsigned short e_cblp;
	/* 0x0004 */ unsigned short e_cp;
	/* 0x0006 */ unsigned short e_crlc;
	/* 0x0008 */ unsigned short e_cparhdr;
	/* 0x000a */ unsigned short e_minalloc;
	/* 0x000c */ unsigned short e_maxalloc;
	/* 0x000e */ unsigned short e_ss;
	/* 0x0010 */ unsigned short e_sp;
	/* 0x0012 */ unsigned short e_csum;
	/* 0x0014 */ unsigned short e_ip;
	/* 0x0016 */ unsigned short e_cs;
	/* 0x0018 */ unsigned short e_lfarlc;
	/* 0x001a */ unsigned short e_ovno;
	/* 0x001c */ unsigned short e_res[4];
	/* 0x0024 */ unsigned short e_oemid;
	/* 0x0026 */ unsigned short e_oeminfo;
	/* 0x0028 */ unsigned short e_res2[10];
	/* 0x003c */ long e_lfanew;
} IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER; /* size: 0x0040 */

typedef struct _IMAGE_FILE_HEADER
{
	/* 0x0000 */ unsigned short Machine;
	/* 0x0002 */ unsigned short NumberOfSections;
	/* 0x0004 */ unsigned long TimeDateStamp;
	/* 0x0008 */ unsigned long PointerToSymbolTable;
	/* 0x000c */ unsigned long NumberOfSymbols;
	/* 0x0010 */ unsigned short SizeOfOptionalHeader;
	/* 0x0012 */ unsigned short Characteristics;
} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER; /* size: 0x0014 */

typedef struct _IMAGE_DATA_DIRECTORY
{
	/* 0x0000 */ unsigned long VirtualAddress;
	/* 0x0004 */ unsigned long Size;
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY; /* size: 0x0008 */

typedef struct _IMAGE_OPTIONAL_HEADER64
{
	/* 0x0000 */ unsigned short Magic;
	/* 0x0002 */ unsigned char MajorLinkerVersion;
	/* 0x0003 */ unsigned char MinorLinkerVersion;
	/* 0x0004 */ unsigned long SizeOfCode;
	/* 0x0008 */ unsigned long SizeOfInitializedData;
	/* 0x000c */ unsigned long SizeOfUninitializedData;
	/* 0x0010 */ unsigned long AddressOfEntryPoint;
	/* 0x0014 */ unsigned long BaseOfCode;
	/* 0x0018 */ unsigned __int64 ImageBase;
	/* 0x0020 */ unsigned long SectionAlignment;
	/* 0x0024 */ unsigned long FileAlignment;
	/* 0x0028 */ unsigned short MajorOperatingSystemVersion;
	/* 0x002a */ unsigned short MinorOperatingSystemVersion;
	/* 0x002c */ unsigned short MajorImageVersion;
	/* 0x002e */ unsigned short MinorImageVersion;
	/* 0x0030 */ unsigned short MajorSubsystemVersion;
	/* 0x0032 */ unsigned short MinorSubsystemVersion;
	/* 0x0034 */ unsigned long Win32VersionValue;
	/* 0x0038 */ unsigned long SizeOfImage;
	/* 0x003c */ unsigned long SizeOfHeaders;
	/* 0x0040 */ unsigned long CheckSum;
	/* 0x0044 */ unsigned short Subsystem;
	/* 0x0046 */ unsigned short DllCharacteristics;
	/* 0x0048 */ unsigned __int64 SizeOfStackReserve;
	/* 0x0050 */ unsigned __int64 SizeOfStackCommit;
	/* 0x0058 */ unsigned __int64 SizeOfHeapReserve;
	/* 0x0060 */ unsigned __int64 SizeOfHeapCommit;
	/* 0x0068 */ unsigned long LoaderFlags;
	/* 0x006c */ unsigned long NumberOfRvaAndSizes;
	/* 0x0070 */ struct _IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64; /* size: 0x00f0 */

typedef struct _IMAGE_NT_HEADERS64
{
	/* 0x0000 */ unsigned long Signature;
	/* 0x0004 */ struct _IMAGE_FILE_HEADER FileHeader;
	/* 0x0018 */ struct _IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64; /* size: 0x0108 */

typedef struct _IMAGE_SECTION_HEADER
{
	/* 0x0000 */ unsigned char Name[8];
	union
	{
		union
		{
			/* 0x0008 */ unsigned long PhysicalAddress;
			/* 0x0008 */ unsigned long VirtualSize;
		}; /* size: 0x0004 */
	} /* size: 0x0004 */ Misc;
	/* 0x000c */ unsigned long VirtualAddress;
	/* 0x0010 */ unsigned long SizeOfRawData;
	/* 0x0014 */ unsigned long PointerToRawData;
	/* 0x0018 */ unsigned long PointerToRelocations;
	/* 0x001c */ unsigned long PointerToLinenumbers;
	/* 0x0020 */ unsigned short NumberOfRelocations;
	/* 0x0022 */ unsigned short NumberOfLinenumbers;
	/* 0x0024 */ unsigned long Characteristics;
} IMAGE_SECTION_HEADER, * PIMAGE_SECTION_HEADER; /* size: 0x0028 */

UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\Device\\KDChaos");

UNICODE_STRING SymbName = RTL_CONSTANT_STRING(L"\\??\\KDChaos");

PUNICODE_STRING registryPathCopy;


#ifdef __cplusplus
extern "C" {
#endif

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);

// set this to your entry point in the linker...
NTSTATUS	ScDriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
DWORD		write_to_read_only_memory(void* address, void* buffer, size_t size);
int			GetPeHdrSize();
void		PrepareDriverForUnload();

#ifdef __cplusplus
}
#endif

#endif