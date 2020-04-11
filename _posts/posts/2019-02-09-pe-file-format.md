---
layout: post
title: PE File Format
date: 2019-02-07 20:00:00
categories: posts
comments: true
en: true
description: Little post about the windows PE file format
keywords: "PE, Windows, Executables, Reversing"
authors:
    - Fare9
---

# PE File Format (by Fare9)

Usually when I give a talk or I give a class about reversing or malware analysis, after give an introduction to the x86 architecture (sorry I don't do ARM) and to the operating systems, I talk about the executable file formats. Once I read (I don't remember where) that the format of the executables use to define the operating system where these are run.
On this post we are going to see the parts of this PE header, as these are structures used by the operating system to load the binary in memory, get the imports that the binary will use, and finally give the control flow to the binary for the execution. Also here we will find metadata from the binary inside of some fields from the structure.

Let's start

## Some terminology

I'm going to explain some terms before starting with the post, as they will be necessary to understand some things about PE header:

* **Base Address**: when our binary is loaded in memory, the loader will load the file at a specific memory (virtual memory) location, this must be multiple of 64k, depending of architecture (32 bits or 64 bits) this value will have a size of 4 or 8 bytes (size for a pointer), and it can be any value in the user memory space but usually it will have the next values: 0x10000000 for a DLL, 0x00010000 for a Windows CE EXE, and 0x00400000 default for Windows NT EXEs. When we program, we can modify this default value modifying linker options, or with the next pragma:

```C
#pragma comment(linker,"/BASE:0x15000000")
```

* **Virtual Address (VA)**: also called *Linear Address* this is the address used in the binary to reference data or code in an absolute way, this value is dependent on the base address value.

* **Relative Virtual Address (RVA)**: this value is widely used on PE Header to avoid the dependency of the base address. This value is added to the base address to get the virtual address, so in this way it will be easy to get values from the binary.

```C
RVA = VA - Base Address
VA  = RVA + Base Address
```

* **Offset**: value which tells us the physical place of something in the binary.

## DOS Header

From those times of MS-DOS and COM files, the EXE file inherits this header. This header and all the others can be found as structures on the file *winnt.h*. This is the structure:

```C
typedef struct _IMAGE_DOS_HEADER {
    WORD  e_magic;      /* 00: MZ Header signature */
    WORD  e_cblp;       /* 02: Bytes on last page of file */
    WORD  e_cp;         /* 04: Pages in file */
    WORD  e_crlc;       /* 06: Relocations */
    WORD  e_cparhdr;    /* 08: Size of header in paragraphs */
    WORD  e_minalloc;   /* 0a: Minimum extra paragraphs needed */
    WORD  e_maxalloc;   /* 0c: Maximum extra paragraphs needed */
    WORD  e_ss;         /* 0e: Initial (relative) SS value */
    WORD  e_sp;         /* 10: Initial SP value */
    WORD  e_csum;       /* 12: Checksum */
    WORD  e_ip;         /* 14: Initial IP value */
    WORD  e_cs;         /* 16: Initial (relative) CS value */
    WORD  e_lfarlc;     /* 18: File address of relocation table */
    WORD  e_ovno;       /* 1a: Overlay number */
    WORD  e_res[4];     /* 1c: Reserved words */
    WORD  e_oemid;      /* 24: OEM identifier (for e_oeminfo) */
    WORD  e_oeminfo;    /* 26: OEM information; e_oemid specific */
    WORD  e_res2[10];   /* 28: Reserved words */
    DWORD e_lfanew;     /* 3c: Offset to extended header */
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
```

This structure can be found (and for exe file must be found) in the offset 0 of the file, and with this one we can go to the next header. The value *e_magic* must be the values "MZ" (or in hexadecimal 0x4D5A), these two values are the initials of <a href="https://en.wikipedia.org/wiki/Mark_Zbikowski">Mark Zbikowski</a> one of the developers of MS-DOS. The others values (but e_lfanew) are used when an EXE file is executed under MS-DOS, and are used to execute a stub (a little chunk of code) of 16 bits which usually shows the message *"This program cannot be run in DOS mode"*.
Finally the DWORD e_lfanew contains the offset of the PE file header, so to get the address (in memory or in the file) of this header, we just have to add this offset to the base address of the file in memory, or go to that offset on disk.

```console
				; IDA Disassembly of DOS Stub
                public start
start           proc near
                push    cs
                pop     ds
                assume ds:seg000
                mov     dx, 0Eh
                mov     ah, 9
                int     21h             ; DOS - PRINT STRING
                                        ; DS:DX -> string terminated by "$"
                mov     ax, 4C01h
                int     21h             ; DOS - 2+ - QUIT WITH EXIT CODE (EXIT)
start           endp                    ; AL = exit code
; ---------------------------------------------------------------------------
aThisProgramCan db 'This program cannot be run in DOS mode.',0Dh,0Dh,0Ah
                db '$',0
```

## PE File Header

Here we are going to start watching the real header of our Exe files, where we will be able to find the interesting information. The PE File Header consists on 3 parts:

1. **Signature**: a DWORD value where it's possible to find the string "PE\\0\\0" or in hexadecimal 0x50 0x45 0x00 0x00, this is the signature used to know we are working with a PE file.
2. **COFF File Header**: information about the file.
3. **Optional Header**: information about the file.

From the last two headers we will see now with the structures what every field means. These three headers are inside of one struct, different for each architecture (32 or 64 bits):

```C
typedef struct _IMAGE_NT_HEADERS {
  DWORD Signature; /* "PE"\0\0 */	/* 0x00 */
  IMAGE_FILE_HEADER FileHeader;		/* 0x04 */
  IMAGE_OPTIONAL_HEADER32 OptionalHeader;	/* 0x18 */
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

typedef struct _IMAGE_NT_HEADERS64 {
  DWORD Signature;
  IMAGE_FILE_HEADER FileHeader;
  IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;
```

As we can see the difference for this two structures comes in the optional header, as one will have some fields the other not. The coff header is implemented on the IMAGE_FILE_HEADER, so let's going to look this structure:

```C
typedef struct _IMAGE_FILE_HEADER {
  WORD  Machine;
  WORD  NumberOfSections;
  DWORD TimeDateStamp;
  DWORD PointerToSymbolTable;
  DWORD NumberOfSymbols;
  WORD  SizeOfOptionalHeader;
  WORD  Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
```

* **Machine**: identifies the type of target machine (some example values: IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_IA64, IMAGE_FILE_MACHINE_ARM, IMAGE_FILE_MACHINE_AMD64).
* **NumberOfSections**: number of sections that binary will have, it will be used to know the size of an struct we will see later. Those sections are chunks of bytes that represent the code, data, strings, and so on.
* **TimeDateStamp**: seconds since 00:00 January 1, 1970 (a C run-time time_t value), that indicates when the file was created. This value can be modified, so it is not reliable.
* **PointerToSymbolTable**: offset for the symbols' table, zero in case those symbols are not present.
* **NumberOfSymbols**: number of entries in the symbols' table.
* **SizeOfOptionalHeader**: size for the optional header (unexpected, no?).
* **Characteristics**: attributes of the file (som examples: IMAGE_FILE_EXECUTABLE_IMAGE, IMAGE_FILE_RELOCS_STRIPPED, IMAGE_FILE_32BIT_MACHINE, IMAGE_FILE_DLL).

Now let's gonna see the structure for optional header, the name of optional is just a name as it will be necessary for the loader to load and run the executable file.

```C
typedef struct _IMAGE_OPTIONAL_HEADER {

  /* Standard fields */

  WORD  Magic; /* 0x10b or 0x107 */ /* 0x00 */
  BYTE  MajorLinkerVersion;
  BYTE  MinorLinkerVersion;
  DWORD SizeOfCode;
  DWORD SizeOfInitializedData;
  DWORD SizeOfUninitializedData;
  DWORD AddressOfEntryPoint;    /* 0x10 */
  DWORD BaseOfCode;
  DWORD BaseOfData;             /* only present on PE32 */

  /* NT additional fields */

  DWORD ImageBase;
  DWORD SectionAlignment;   /* 0x20 */
  DWORD FileAlignment;
  WORD  MajorOperatingSystemVersion;
  WORD  MinorOperatingSystemVersion;
  WORD  MajorImageVersion;
  WORD  MinorImageVersion;
  WORD  MajorSubsystemVersion;    /* 0x30 */
  WORD  MinorSubsystemVersion;
  DWORD Win32VersionValue;
  DWORD SizeOfImage;
  DWORD SizeOfHeaders;
  DWORD CheckSum;     /* 0x40 */
  WORD  Subsystem;
  WORD  DllCharacteristics;
  DWORD SizeOfStackReserve;
  DWORD SizeOfStackCommit;
  DWORD SizeOfHeapReserve;    /* 0x50 */
  DWORD SizeOfHeapCommit;
  DWORD LoaderFlags;
  DWORD NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES]; /* 0x60 */
  /* 0xE0 */
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
  WORD  Magic; /* 0x20b */
  BYTE MajorLinkerVersion;
  BYTE MinorLinkerVersion;
  DWORD SizeOfCode;
  DWORD SizeOfInitializedData;
  DWORD SizeOfUninitializedData;
  DWORD AddressOfEntryPoint;
  DWORD BaseOfCode;
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
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;
``` 

We are not going to say what is each field, but we will talk about some of them that could be important:

* **magic**: identifies the state of the image file, this will be used to determine if an image is a PE32 (0x10b, 32 bits) binary or a PE32+ (0x20b, 64 bits) binary.

* **AddressOfEntryPoint**: RVA of the first instruction of the binary that will be executed, this is optional for DLLs as these libraries export functions to execute.

* **ImageBase**: virtual memory address where the binary will be loaded, this value can be 4 or 8 bytes, depending of binary's bit architecture. The loader can follow or not this value to load the binary.

* **SectionAlignment**: alignment of the sections when are loaded in memory. By default, page size for the architecture (usually 4k = 0x1000).

* **FileAlignment**: alignment used to align the raw data of sections in the image file (on disk). Value should be a power of 2 between 512 and 64k. Default is 512 (0x200). If we find that SectionAlignment is less than page size, FileAlignment must be EQUALS to SectionAlignment.

* **SizeOfImage**: size in bytes of the binary in memory, including all the headers. So this value must be multiple of SectionAlignment.

* **SizeOfHeaders**: size of all the headers (MS-DOS, PE Header, Section headers) rounded up to a multiple of FileAlignment.

* **DllCharacteristics**: information related to the file, here we can find for example security flags (examples: IMAGE_DLLCHARACTERISTICS_NX_COMPAT, IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE, IMAGE_DLLCHARACTERISTICS_ NO_SEH).
 
* **NumberOfRvaAndSizes**: in the remainder of the optional header we have some structures called IMAGE_DATA_DIRECTORY, these structures represent information about the binary as the exports, the imports, the relocations, and so on. The optional header save space for IMAGE_NUMBEROF_DIRECTORY_ENTRIES of them (usually 16), but it's possible to have less than this number, for that reason exists this field.

To complete the explanation about the IMAGE_DATA_DIRECTORY, let's going to see the structure:

```C
typedef struct _IMAGE_DATA_DIRECTORY {
  DWORD VirtualAddress;
  DWORD Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
```

Each Data Directory is referenced by the field VirtualAddress, which is a RVA to this directory. Finally we have the size of the directory, which could be useful in case of parsing the file to avoid read out of bounds of the directory. Let's discuss some of the directories that I consider interesting:

* **Export Table**: information about symbols that other binaries can access through dynamic linking. Usually this table is found in DLLs as these dynamic libraries export functions. This table is represented on the next structure:

```C
typedef struct _IMAGE_EXPORT_DIRECTORY {
  DWORD Characteristics;
  DWORD TimeDateStamp;
  WORD  MajorVersion;
  WORD  MinorVersion;
  DWORD Name; // RVA to the ASCII string with the name of the DLL
  DWORD Base; // starting value for the ordinal number of the exports.
  DWORD NumberOfFunctions; // number of entries for exported functions.
  DWORD NumberOfNames; // number of string names for the exported functions.
  /*
  * These three values correspond to three RVAs
  * for tables, each table save some data:
  * AddressOfFunctions: each table entry saves the RVA of an exported function.
  * AddressOfNames: each table entry saves the RVA to a name of function.
  * AddressOfNamOrdinals: each table entry saves 16-bit ordinals indexes of functions.
  *
  * We can use these three tables to get the address of a DLL function
  * by name, using the next operation:
  * i = Search_ExportNamePointerTable (ExportName);
  * ordinal = ExportOrdinalTable [i];
  * SymbolRVA = ExportAddressTable [ordinal - Base];
  */
  DWORD AddressOfFunctions;
  DWORD AddressOfNames;
  DWORD AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY,*PIMAGE_EXPORT_DIRECTORY;
```

* **Import Table**: series of tables which specify the import symbols of a binary, the last table MUST be empty (everything to NULL, or at least the related to DLL name). Each table is represented with the next structure:

```C
typedef struct _IMAGE_IMPORT_DESCRIPTOR {
  union {
    DWORD Characteristics; /* 0 for terminating null import descriptor  */
    DWORD OriginalFirstThunk; /* RVA to original unbound IAT */
  } DUMMYUNIONNAME;
  DWORD TimeDateStamp;  /* 0 if not bound,
         * -1 if bound, and real date\time stamp
         *    in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT
         * (new BIND)
         * otherwise date/time stamp of DLL bound to
         * (Old BIND)
         */
  DWORD ForwarderChain; /* -1 if no forwarders */
  DWORD Name;
  /* RVA to IAT (if bound this IAT has actual addresses) */
  DWORD FirstThunk;
} IMAGE_IMPORT_DESCRIPTOR,*PIMAGE_IMPORT_DESCRIPTOR;
```

I'm going to explain 3 of these fields: 

  * **Name**: this is a RVA to a DLL name which exports all the functions referenced by the others two fields.
  * **FirstThunk**: RVA to a serie of RVA of names, or RVA to a serie of ordinals, the value will be name or ordinal depending of its most significant bit, if it is 1 it means the value is ordinal, if it is 0 it means the value is a RVA to a function name. We can use the mask 0x80000000 for 32 bits, or the mask 0x8000000000000000 for 64 bits.
  * **OriginalFirstThunk**: RVA to a serie of RVA of names, or RVA to a serie of ordinals, the value will be name or ordinal depending of its most significant bit, if it is 1 it means the value is ordinal, if it is 0 it means the value is a RVA to a function name. We can use the mask 0x80000000 for 32 bits, or the mask 0x8000000000000000 for 64 bits.

Yes, as we can see, FirstThunk and OriginalFirstThunk contain the same data, but the OriginalFirstThunk has something interesting, and it's that the loader will change each RVA to name or each ordinal by the address of the function once the DLL is loaded with the binary.

* **Reloc table**: table that contains entries for all relocations of the binary. This is necessary for binaries which support realocation like the DLLs, if a binary is not loaded in the ImageAddress specified, some of the references to data or code will not work, so this table contains pointers to the addresses to fix, the fix will be applied with the difference between the ImageBase and the loaded address. Let's going to see the structure:

```C
/*
* The first structure we find for a reloc,
* specify the base address of a serie of
* addresses to fix (for example the RVA 0x1000
* can have 4 different pointers to fix)
*/
typedef struct _IMAGE_BASE_RELOCATION
{
  DWORD VirtualAddress;
  DWORD SizeOfBlock; // total number of bytes of this structure + x number of the next word
  /* WORD TypeOffset[1]; */ // first 4 bits indicate the type of base relocation to apply
                            // the others 12 bits are an offset to add to VirtualAddress and get where to fix
} IMAGE_BASE_RELOCATION,*PIMAGE_BASE_RELOCATION;
```

Finally, we go to the sections, as I said before a section is a chunk of data which are code, data, strings, etc. But this sections must be pointed by some header, and here we go, we have the Section table, the number of these tables is indicated in the IMAGE_FILE_HEADER structure by the field *NumberOfSections*. This section is represented by the next structure:

```C
#define IMAGE_SIZEOF_SHORT_NAME 8

typedef struct _IMAGE_SECTION_HEADER {
  BYTE  Name[IMAGE_SIZEOF_SHORT_NAME];
  union {
    DWORD PhysicalAddress;
    DWORD VirtualSize;
  } Misc;
  DWORD VirtualAddress;
  DWORD SizeOfRawData;
  DWORD PointerToRawData;
  DWORD PointerToRelocations;
  DWORD PointerToLinenumbers;
  WORD  NumberOfRelocations;
  WORD  NumberOfLinenumbers;
  DWORD Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
```

Let's gonna check some interesting fields:

* **Name**: name of the section with a maximun length of 8 bytes.
* **VirtualSize**: size of the section when loaded in memory, if the value is greater than SizeOfRawData the loader will padd with zeroes.
* **VirtualAddress**: RVA to the first byte of the section in memory.
* **SizeOfRawData**: size of the section on disk. Must be multiple of FileAlignment, can be greater than VirtualSize.
* **PointerToRawData**: file pointer to the first page of the section within the COFF file. In another words, this will be the offset on disk where you'll find the section. Must be mutiple of FileAlignment.
* **Characteristics**: flags that describe the characteristics of the section (some examples: IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE, IMAGE_SCN_MEM_SHARED).

## RVA to Offset, Offset to RVA

Usually when people talk about the PE header just talk about the structures and nothing more, what I'm going to talk about here is the operation to get the Offset from a RVA or the RVA from an Offset.

* **RVA to Offset**: to calculate this, we have to go through the sections to know in which section is the RVA, for that we can do something like this:

```C
PIMAGE_SECTION_HEADER section = (PIMAGE_SECTION_HEADER)(base_address + dos_header.e_lfanew + 
  sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + file_header.SizeOfOptionalHeader);

for (index = 0; index < numberOfSections; index++)
{
  if (rva >= section[i].VirtualAddress && rva < (section[i].VirtualAddress + section[i].VirtualSize))
    return rva - section[i].VirtualAddress + section[i].PointerToRawData;
}
```

* **Offset to RVA**: as before, we have to know inside of which section is the offset, so to calculate that we can apply this:

```C
PIMAGE_SECTION_HEADER section = (PIMAGE_SECTION_HEADER)(base_address + dos_header.e_lfanew + 
  sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + file_header.SizeOfOptionalHeader);

for (index = 0; index < numberOfSections; index++)
{
  if (offset >= section[i].PointerToRawData && offset < (section[i].PointerToRawData + section[i].SizeOfRawData))
    return offset - section[i].PointerToRawData + section[i].VirtualAddress;
}
```

## How the loader imports DLL functions.

If we remember, we had this structure for the imports:

```C
typedef struct _IMAGE_IMPORT_DESCRIPTOR {
  union {
    DWORD Characteristics; /* 0 for terminating null import descriptor  */
    DWORD OriginalFirstThunk; /* RVA to original unbound IAT */
  } DUMMYUNIONNAME;
  DWORD TimeDateStamp;  /* 0 if not bound,
         * -1 if bound, and real date\time stamp
         *    in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT
         * (new BIND)
         * otherwise date/time stamp of DLL bound to
         * (Old BIND)
         */
  DWORD ForwarderChain; /* -1 if no forwarders */
  DWORD Name;
  /* RVA to IAT (if bound this IAT has actual addresses) */
  DWORD FirstThunk;
} IMAGE_IMPORT_DESCRIPTOR,*PIMAGE_IMPORT_DESCRIPTOR;
```

We will have many of these structures finished in one with values to zero, all this array of structures corresponds to the import table.

Let's going to imagine that the field *name* has the next value:

```C
> name = 0x3020
```

When the loader loads the binary for example in the address *0x00400000*, if we go to the address *0x00403020* we will see a DLL name string, for example *kernel32.dll*, in this way, the loader can use a function as *LoadLibraryA* to load the DLL and get the address.
Once we have a handler for the DLL, the loader goes to the original first thunk, this original first thunk it is another RVA, for example:

```C
> OriginalFirstThunk = 0x5780
```

The loader will take this DWORD and the image base, and it will have the address *0x00405780* here we will have an array of DWORDs, that as we said can be a RVA of a function name, or an ordinal of the function, let's imagine this four DWORDs

```console
0x00007030  0x80000100 0x00007040 0x00000000
```

If we use the constant to check if it is ordinal or not (0x80000000 in 32 bit, and 0x8000000000000000 in 64 bits), we can see the first one it is not an ordinal, so it is a RVA to a function name, in the address *0x00407030* we can have for example the function *CreateFileA* finished with a character 0, then we have one that match with our constant, so it is the ordinal 0x100, we could use *Dependency Walker* to see that ordinal, after that we have another RVA to name, so in the address *0x00407040* we can have for example the string *CreateProcessA* finished again in 0. To finish this array we have one with zeroes. 
The loader will use a function such as *GetProcAddress* to get using the DLL handler and the name or the ordinal, the address to the DLL function. Once it has the address, it will replace in the original first thunk the RVA or the ordinal by the function address.

## Great notes about old experts

After releasing this post, and send to some friends, one of them who is maybe the most expert I know about File infectors told me to include this code, that maybe we can find on malware samples.
Usually you can find codes like this one:

```
mov     edi, dword ptr [ebp + BaseDLL]  
mov     eax, dword ptr [edi + 03Ch]     ; field e_lfanew of DOS_HEADER   
add     eax, edi                        ; point to PE Header        
mov     dword ptr [ebp + PEHeader], eax 

mov     edi, dword ptr [ebp + PEHeader]  
mov     eax, dword ptr [edi + 078h]     ; PE Header + 78h = RVA of export table
add     eax, dword ptr [ebp + BaseDLL]  ; eax = export table

mov edx, dword ptr [eax+020h]           ; Get RVA AddressOfNames
add edx, dword ptr [ebp + BaseDLL]
mov ebx, dword ptr [eax+24h]            ; Get RVA AddressOfNameOrdinals
add ebx, dword ptr [ebp + BaseDLL]
mov ecx, dword ptr [eax+01Ch]           ; Get RVA AddressOfFunctions
add ecx, dword ptr [ebp + BaseDLL]
```

As we can see, here we have many hardcoded offsets that once we are alerted are very easy to recognize. Before we explained about the Export Table and some of its fields, here we see three of its fields by their offsets, this is used to get address of functions without importing them by the IAT.



## References
[SalSA PE File Format](https://github.com/deptofdefense/SalSA/wiki/PE-File-Format)
[kowalczyk PE File Format](https://blog.kowalczyk.info/articles/pefileformat.html)
[Peering Inside the PE](https://github.com/tpn/pdfs/blob/master/Peering%20Inside%20the%20PE%20-%20A%20Tour%20of%20the%20Win32%20Portable%20Executable%20File%20Format.pdf)
[Microsoft docs PE File Format](https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format)
[winnt.h](https://raw.githubusercontent.com/Alexpux/mingw-w64/master/mingw-w64-tools/widl/include/winnt.h)
[Cool PDF with all the PE structures](http://www.openrce.org/reference_library/files/reference/PE%20Format.pdf)
[Ero Carrera's pe file parser](https://github.com/erocarrera/pefile)
[LordPE pe file parser and editor](https://www.aldeid.com/wiki/LordPE)
[PEView pe file parser with a great GUI to see the headers](http://wjradburn.com/software/)
[The Rootkit Arsenal, book with a lot of interesting information about the PE](https://www.amazon.com/dp/144962636X/ref=pd_lpo_sbs_dp_ss_1?pf_rd_p=b4bbef4e-170e-463d-8538-7eff3394b224&pf_rd_s=lpo-top-stripe-1&pf_rd_t=201&pf_rd_i=1598220616&pf_rd_m=ATVPDKIKX0DER&pf_rd_r=8QKKVBWE2X2H9E3TBRK3&pf_rd_r=8QKKVBWE2X2H9E3TBRK3&pf_rd_p=b4bbef4e-170e-463d-8538-7eff3394b224)