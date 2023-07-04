#pragma once

typedef unsigned char BYTE;         // 1 byte
typedef unsigned short WORD;        // 2 byte
typedef unsigned long DWORD;        // 4 byte
typedef unsigned long long QWORD;   // 8 byte
typedef unsigned long LONG;

typedef __int64 LONGLONG;
typedef unsigned __int64 ULONGLONG;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
#define IMAGE_DOS_SIGNATURE              0x5A4D
#define IMAGE_NT_OPTIONAL_HDR32_MAGIC    0x10b
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC    0x20b

typedef struct _IMAGE_DOS_HEADER {
    WORD e_magic;                     // Magic number
    WORD e_cblp;                      // BYTEs on last page of file
    WORD e_cp;                        // Pages in file
    WORD e_crlc;                      // Relocations
    WORD e_cparhdr;                   // Size of header in paragraphs
    WORD e_minalloc;                  // Minimum extra paragraphs needed
    WORD e_maxalloc;                  // Maximum extra paragraphs needed
    WORD e_ss;                        // Initial (relative) SS value
    WORD e_sp;                        // Initial SP value
    WORD e_csum;                      // Checksum
    WORD e_ip;                        // Initial IP value
    WORD e_cs;                        // Initial (relative) CS value
    WORD e_lfarlc;                    // File address of relocation table
    WORD e_ovno;                      // Overlay number
    WORD e_res[4];                    // Reserved WORDs
    WORD e_oemid;                     // OEM identifier (for e_oeminfo)
    WORD e_oeminfo;                   // OEM information; e_oemid specific
    WORD e_res2[10];                  // Reserved WORDs
    LONG e_lfanew;                    // File address of new exe header
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER{
    WORD    Machine;
    WORD    NumberOfSections;
    DWORD   TimeDateStamp;
    DWORD   PointerToSymbolTable;
    DWORD   NumberOfSymbols;
    WORD    SizeOfOptionalHeader;
    WORD    Characteristics;
}IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD RVA;
    DWORD Size;
}IMAGE_DATA_DIRECTORY;


typedef struct _IMAGE_OPTIONAL_HEADER {
    WORD    Magic;
    BYTE    MajorLinkerVersion;
    BYTE    MinorLinkerVersion;
    DWORD   SizeOfCode;
    DWORD   SizeOfInitializedData;
    DWORD   SizeOfUninitializedData;
    DWORD   AddressOfEntryPoint;
    DWORD   BaseOfCode;
    DWORD   BaseOfData;

    DWORD   ImageBase;
    DWORD   SectionAlignment;
    DWORD   FileAlignment;
    WORD    MajorOperatingSystemVersion;
    WORD    MinorOperatingSystemVersion;
    WORD    MajorImageVersion;
    WORD    MinorImageVersion;
    WORD    MajorSubsystemVersion;
    WORD    MinorSubsystemVersion;
    DWORD   Win32VersionValue;
    DWORD   SizeOfImage;
    DWORD   SizeOfHeaders;
    DWORD   CheckSum;
    WORD    Subsystem;
    WORD    DllCharacteristics;
    DWORD   SizeOfStackReserve;
    DWORD   SizeOfStackCommit;
    DWORD   SizeOfHeapReserve;
    DWORD   SizeOfHeapCommit;
    DWORD   LoaderFlags;
    DWORD   NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
}IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    WORD    Magic;
    BYTE    MajorLinkerVersion;
    BYTE    MinorLinkerVersion;
    DWORD   SizeOfCode;
    DWORD   SizeOfInitializedData;
    DWORD   SizeOfUninitializedData;
    DWORD   AddressOfEntryPoint;
    DWORD   BaseOfCode;

    ULONGLONG ImageBase;
    DWORD SectionAlignment;
    DWORD FileAlignment;
    WORD MajorOperatingSystemVersion;
    WORD MinorOperatingSystemVersion;
    WORD MajorImageVersion;
    WORD MinorImageVersion;
    WORD MajorSubsystemVersion;
    WORD MinorSubsystemVersion;
    DWORD Win32VersionValue;
    DWORD SizeOfImage;
    DWORD SizeOfHeaders;
    DWORD CheckSum;
    WORD Subsystem;
    WORD DllCharacteristics;
    ULONGLONG SizeOfStackReserve;
    ULONGLONG SizeOfStackCommit;
    ULONGLONG SizeOfHeapReserve;
    ULONGLONG SizeOfHeapCommit;
    DWORD LoaderFlags;
    DWORD NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
}IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADER {
    DWORD                   Signature;
    IMAGE_FILE_HEADER       FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
}IMAGE_NT_HEADER, *PIMAGE_NT_HEADER;

typedef struct _IMAGE_NT_HEADER64 {
    DWORD                   Signature;
    IMAGE_FILE_HEADER       FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
}IMAGE_NT_HEADER64, *PIMAGE_NT_HEADER64;

typedef struct _IMAGE_SECTION_HEADER {
    BYTE Name[8];
    DWORD VirtualSize;
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD  NumberOfRelocations;
    WORD  NumberOfLinenumbers;
    DWORD Characteristics;
}IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;