---
layout: post
title: Introduction to Reverse Engineering
date: 2021-01-04 12:40:00
categories: posts
comments: true
en: true
description: Post about introduction to reverse engineering
keywords: "ELF, Linux, Reverse Engineering, Computer Architecture, Ghidra"
authors: Fare9
---

# Introduction to Reverse Engineering

This text will be a first approach to reverse engineering aimed to teach those with no previous knowledge into the area, we will cover simple explanation about how a computer works (briefly), an explanation about the x86 architecture (32 and 64 bits), introduction to assembly, tools and so on.

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/re-1.png" alt="Example of Intel x86-64 bits disassembled code"/>

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/re-2.png" alt="Example of ARM disassembled code"/>

## Reverse Engineering

The art of reverse engineering is not something from recent history nor something that was created in ancient times of the first mainframes computers, we can go to the book *Reversing: Secrets of Reverse Engineering* by Eldad Eilam in order to give a description of what is this art:

*Reverse engineering is the process of extracting the knowledge or design blueprints from anyting man-made*

So it's the art of take anything done by human and extract what it does or how was done without looking the exact sources.

We will look at it from a computer science perspective view, more exactly to software (as reverse engineering can be applied also to hardware). In our case reverse engineering is the process of extracting information from a software without the source code of the program. For this aim we have a plethora of tools like disassemblers, debuggers, emulators, symbolic execution engines and so on.

In this post we will make use of Ubuntu as our Operating System for the examples, and our tools will be:

* *Ghidra*: for disassembling our binaries, it will allow us to see the program from a static perspective without executing the program, *Ghidra* will also recognize functions bounds and in case it detects some functions from libraries it will rename them. This tool also provides a decompiler for many architectures.
* *gdb*: we will use *gdb* with the plugin *gdb-peda* (I recommend the next one [gdb-peda-intel](https://github.com/alset0326/peda-arm/blob/master/peda-intel.py)).

The knowledge acquired in this post could be useful for you in malware analysis, exploiting or cracking. Not always these skills are used from an *evil* perspective, as companies can use people with reverse engineering skills to find vulnerabilities and errors in their programs in order to correct them as soon as possible.

## Computer Architecture

As a first approach to reverse engineering I think it's interesting to learn where all our software run, having a deep knowledge of the architecture it's useful in our analysis as it helps us to understand what the instruction does, and how the binaries work.

We will focus mainly in the Intel x86 architecture, both for 32 bits and 64 bits but before moving to Intel, we will move back to my computer architecture class from university. Commonly you can find two models of computer architectures one is [*Harvard*](https://en.wikipedia.org/wiki/Harvard_architecture) and the other is [*von Neumann*](https://en.wikipedia.org/wiki/Von_Neumann_architecture). Intel is based on the latter.

The architecture explains how is the memory model, the CPU and also the I/O system, in *Von Neumann* architecture we have that both data and code is stored in same memory, this would be in our computer the *RAM* memory. A *Control Unit* is the part that schedule the instruction to execute reading the address of the instruction from something called *Program Counter*, the instructions from the control unit and the retrieved data go through the *buses*, the control unit has to decode the instruction to know what order send to the *ALU* (Arithmetic-Logic Unit) and also the data it needs for the instruction. Inside of the *CPU* there are a set of registers, that are memory units of low capacity but extremely fast access compared to the data from main memory.

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/von-neumann.jpeg"/>

So from the picture we can divide the architecture in:

* *CPU*
    * *Central Unit*
    * *Arithmetic-Logic Unit*
    * *Registers*
* *Main memory*
* *Input/Output devices*

## Intel Processors

Intel Processors are the most common processor you can see in PCs or laptops (apart from recent use of ARM by Apple in their new M1 MacBook Pro). The Intel Processors are based on *Von Neumann* and have a [*CISC*](https://en.wikipedia.org/wiki/Complex_instruction_set_computer) set of instructions, it means that it contains a more complex set of instructions compared to a [*RISC*](https://en.wikipedia.org/wiki/Reduced_instruction_set_computer) set of instructions, where programs have a more reduced set of instructions increasing size of a program.

The **security** of this architecture is based on a serie of *rings* as the next picture shows:

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/intel-rings.png"/>

Being the most privileged zone the center, and the least privileged zone the external rings, we will see only those programs that run on the last ring, these are the user-mode applications.

The architecture works in two modes, once is the **real mode**, this is the mode used when the computer boot, and run instructions of 16 bits allowing high privilege instructions, this mode quickly set the architecture to work in the **protected mode**, this mode allows the concepts of virtual memory, and memory pages (the real mode works with memory segments), the memory pages implement permissions that are used for security too.


### How User Application Interfaces with Kernel?

User applications in order to use some utilities offered by the kernel, user programs needs a way to communicate with it, this mechanism is known as *system calls*, we will see later how this is implemented in *Linux* but for the moment is good to know that this mechanism is the one used to work with files, networking, threads, processes and so on. Without this, programs would be merely a bunch of mathematics operations.

We will also see later that as the use of this *system calls* can be tough, interfaces exist in order to make easy the use through libraries that offers to programmers an easy way to use the *system calls* from their programs.

## Intel Registers

Once we've seen little bit of theory about the architecture, we'll see something that we'll see in every moment while debugging our binaries, these are the registers. As we said registers are memories with low storage capacity but fast to access, commonly data will be stored here in order to be used in instructions different code constructions can use different registers, we'll see later.

### Registers for 32-bits

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/32-bit-registers.png"/>

Previous picture shows the registers we can find in the intel architecture for 32 bits (and all of them contain as maximum 32-bit data), some of them can be used for general purposes (commonly found in the instructions) these are the *EAX, EBX, ECX, EDX, ESI and EDI*, the first four registers can be also divided into a subset of registers of 16 bits (*AX,BX,CX and DX*), and these are divided in two different registers of 8 bits each one, one being the lower part (finished in *L*) and the other the higher part (finished in *H*) of the 16-bit registers, these are inherited from previous architectures. 

*ESI* and *EDI* are commonly used in special instructions for strings or memory arrays, where *ESI* points to a source memory, and *EDI* to destination. 

*EAX* is used in many mathematics operations as the *accumulator* and the result is stored in here, we'll see later that *EAX* is very important in functions too.

*ECX* is used as counter in loops.

*ESP* and *EBP* are used in a memory structure used a lot during the execution, this memory holds the parameters of the functions, the local variables and return addresses, one of the registers point to the base (*EBP*) and the other to the top (*ESP*).

Finally there's one register called *EIP* which points to the instruction to be executed.

Those registers that are used as pointers to memory (*ESI*, *EDI*, *EBP*, *ESP* and *EIP*) are not used with lower size suffixes as those general purpose registers, as a pointer has a size of 32-bit.

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/32-bit-eflags.jpeg"/>

Finally to finish with registers of 32 bits, we have the *EFLAGS* these are used bit to bit, each bit has a meaning that is useful for different instructions, for example for conditional jumps as we will see.

We commonly should care about:

* SF (*Sign Flag*): set when the last mathematical operation modifies the last bit (used to indicate the sign of a number).
* ZF (*Zero Flag*): set when last mathematical operation result in a zero value, used a lot in comparisons for conditional code constructions (*if/else*).
* CF (*Carry Flag*): set when an arithmetic carry or borrow has been generated by an operation (a bit out of the bit-width of a register).

The others are also important, but commonly we will use these.

### Registers for 64-bits

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/64-bit-registers.png"/>

As we can see the registers in the architecture of 64 bits are an extension of previous registers, some other general purpose registers have been included: *r8, r9, r10, r11, r12, r13, r14 and r15*. These registers are useful for passing arguments to functions as we will see, because instead of using the stack for passing arguments to functions, we have a lot of register for this purpose.

For our reversing the *RFLAGS* (extension of *EFLAGS*) will be like in previous case, we will use SF, ZF and CF.

## Compilers and Compilation Process

The explained processor only understand about bits, a bunch of '1's and '0's, as we know we join groups of 8 bits into a *byte*. Humans in order to represent bytes in a better way join series of 4 bits into what is called a *nibble* represented in hexadecimal.

The bytes for the processor represent *op-codes* or *operation codes*, depending on the operation code the processor will do different things (mathematic operation, moving bytes, jumps, call functions, and so on). 

At the beginning of programming [*punched cards*](https://en.wikipedia.org/wiki/Punched_card) were used for represeting a program through the presence or not of a hole in the card, programs were also programmed using the hexadecimal representations of the opcodes.

As this process was pretty hard, something more related to human language was created, this is known as *assembly language* the instructions contains mnemonic names easier to remember than numbers, and a program known as *assembler* was the one who managed the translation from the assembly to the op-codes. The assembly language is specific to the architecture as not all the architectures have the same instructions nor the same registers.

Finally, due to the lazy nature of human (and as a way to improve programming making it easier and faster), high-level languages were created, these were even closer to human language with logic constructions from english, these were languages like COBOL, C, FORTRAN, Pascal, and so on. These languages need by a special program called *Compiler* which parse the source code of the program to translate it to a serie of assembly instructions to finally assembly them into a binary loadable by an operating system. Currently the approach is different so a compiler commonly parses the source code into an intermmediate language, different optimizations are applied to this intermmediate representation of the program, a translation to a specific assembly language is done, this assembly is converted into an object file which contains references to other objects that need linking from libraries or other objects to finally generate a binary program.

We can follow these steps with *gcc*, let's create a program called *test.c* with next content:

```c
#include <stdio.h>

#define SHOW "Hello world!\n"

int
main(int argc, char **argv)
{
	printf(SHOW);

	return 0;
}
```

Now apply first the preprocessor of *gcc* which include the headers and expand all the macros: 

```console
$ gcc -E test.c -o test.i
$ cat test.i
...
# 216 "/usr/lib/gcc/x86_64-linux-gnu/7/include/stddef.h" 3 4
typedef long unsigned int size_t;
# 34 "/usr/include/stdio.h" 2 3 4

# 1 "/usr/include/x86_64-linux-gnu/bits/types.h" 1 3 4
# 27 "/usr/include/x86_64-linux-gnu/bits/types.h" 3 4
# 1 "/usr/include/x86_64-linux-gnu/bits/wordsize.h" 1 3 4
# 28 "/usr/include/x86_64-linux-gnu/bits/types.h" 2 3 4


typedef unsigned char __u_char;
typedef unsigned short int __u_short;
typedef unsigned int __u_int;
typedef unsigned long int __u_long;
...
# 868 "/usr/include/stdio.h" 3 4

# 2 "prueba.c" 2




# 5 "prueba.c"
int
main(int argc, char **argv)
{
 printf("Hello world!\n");

 return 0;
}
```

Now let's compile this .i file into a .s which contains the assembly code:

```console
$ gcc -S test.i -o test.s
$ cat test.s
	.file	"test.c"
	.text
	.section	.rodata
.LC0:
	.string	"Hello world!"
	.text
	.globl	main
	.type	main, @function
main:
.LFB0:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$16, %rsp
	movl	%edi, -4(%rbp)
	movq	%rsi, -16(%rbp)
	leaq	.LC0(%rip), %rdi
	call	puts@PLT
	movl	$0, %eax
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE0:
	.size	main, .-main
	.ident	"GCC: (Ubuntu 7.5.0-3ubuntu1~18.04) 7.5.0"
	.section	.note.GNU-stack,"",@progbits
```

Now we create the object file, this has been assembled but external references has not been resolved through linking, so we cannot *cat* this file, finally after that, we can link:

```console
$ gcc -c test.s -o test.o
$ gcc test.o -o test
$ file test.o
test.o: ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV), not stripped
$ file test
test: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, 
BuildID[sha1]=2af7d08ae5500a8677dbc0fa99dc960b5f92cf39, not stripped
```

This process is a one-way process so when a binary is provided, commonly is not possible to go back to source code apart from various decompilation techniques.

## Linux

As we said at the beginning, we will use Ubuntu as our system for learning about reverse engineering, this mean that we will use a system based on a *Linux* kernel, as we said the way a user program has for communicating with kernel is through system calls, in Linux two different ways are used one if the system is 32 bits or the other if system is 64 bits, system calls has a number that must be set in *eax*/*rax*, then the parameters must reside in the others registers (or in case of 32 bits on the stack too).

The numbers of the system calls are different from 32 bits to 64 bit, next lists from Chromium OS Docs give system calls from Intel 32 and 64 bits, and also ARM and ARM64: [syscall numbers](https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md)

Here we have two examples of a syscall to read in 32 bits and 64 bits:

```
000017d7 <read>:
    17d7:	f3 0f 1e fb          	endbr32 
    17db:	55                   	push   ebp
    17dc:	89 e5                	mov    ebp,esp
    17de:	53                   	push   ebx
    17df:	83 ec 10             	sub    esp,0x10
    17e2:	e8 be 00 00 00       	call   18a5 <__x86.get_pc_thunk.ax>
    17e7:	05 0d 28 00 00       	add    eax,0x280d
    17ec:	8b 4d 0c             	mov    ecx,DWORD PTR [ebp+0xc]
    17ef:	8b 55 10             	mov    edx,DWORD PTR [ebp+0x10]
    17f2:	b8 03 00 00 00       	mov    eax,0x3
    17f7:	8b 5d 08             	mov    ebx,DWORD PTR [ebp+0x8]
    17fa:	cd 80                	int    0x80
    17fc:	89 45 f8             	mov    DWORD PTR [ebp-0x8],eax
    17ff:	8b 45 f8             	mov    eax,DWORD PTR [ebp-0x8]
    1802:	83 c4 10             	add    esp,0x10
    1805:	5b                   	pop    ebx
    1806:	5d                   	pop    ebp
    1807:	c3                   	ret  
```

And 64 bits:

```
0000000000001954 <_read>:
    1954:	f3 0f 1e fa          	endbr64 
    1958:	55                   	push   rbp
    1959:	48 89 e5             	mov    rbp,rsp
    195c:	89 7d ec             	mov    DWORD PTR [rbp-0x14],edi
    195f:	48 89 75 e0          	mov    QWORD PTR [rbp-0x20],rsi
    1963:	48 89 55 d8          	mov    QWORD PTR [rbp-0x28],rdx
    1967:	48 8b 7d ec          	mov    rdi,QWORD PTR [rbp-0x14]
    196b:	48 8b 75 e0          	mov    rsi,QWORD PTR [rbp-0x20]
    196f:	48 8b 55 d8          	mov    rdx,QWORD PTR [rbp-0x28]
    1973:	48 c7 c0 00 00 00 00 	mov    rax,0x0
    197a:	0f 05                	syscall 
    197c:	48 89 c0             	mov    rax,rax
    197f:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
    1983:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
    1987:	5d                   	pop    rbp
    1988:	c3                   	ret    
```

As we can see, in 32 bits an interruption (a trap for the system) was used in order to do the system call, in 64 bits a specific instruction is used for the system call, it represent a faster way of doing a system call as no interruption must be managed by the system, this different mechanism is an improvement from previous one. Another thing we can see is that the number of system call is different, in 32 bits is 3 and in 64 bits is 0.

### ELF Binaries

The most common type of binaries that is executed under a Linux system are ELF binaries, these binaries contains different structures with information about target machine, the type of binary (executable/EXE or shared object/DYN for example), and also information about how the file is structured. 

The first structure we can find in an ELF binary is the *Elf Header*:

```c
#define EI_NIDENT 16

typedef struct {
    unsigned char e_ident[EI_NIDENT];
    uint16_t      e_type;
    uint16_t      e_machine;
    uint32_t      e_version;
    ElfN_Addr     e_entry;
    ElfN_Off      e_phoff;
    ElfN_Off      e_shoff;
    uint32_t      e_flags;
    uint16_t      e_ehsize;
    uint16_t      e_phentsize;
    uint16_t      e_phnum;
    uint16_t      e_shentsize;
    uint16_t      e_shnum;
    uint16_t      e_shstrndx;
} ElfN_Ehdr;
```

This as we said contains information about the file, and offsets to the other headers, and ELF binary is made of segments pointed by *program headers* in order to read the program headers, the field *e_phoff* must be used to know the offset of the structures:

```c
typedef struct {
    uint32_t   p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    uint32_t   p_filesz;
    uint32_t   p_memsz;
    uint32_t   p_flags;
    uint32_t   p_align;
} Elf32_Phdr;

typedef struct {
    uint32_t   p_type;
    uint32_t   p_flags;
    Elf64_Off  p_offset;
    Elf64_Addr p_vaddr;
    Elf64_Addr p_paddr;
    uint64_t   p_filesz;
    uint64_t   p_memsz;
    uint64_t   p_align;
} Elf64_Phdr;
```

These segment structures contain information about the offset on disk, the virtual address or the relative virtual address (depending on the binary type) in memory, sizes on disk and in memory, flags about the segment (for example permissions like readable, writable or executable segment) and also the type of the segment, different types can be found, but maybe the most important for us is the **PT_LOAD** segments, these are the segments that are loaded in memory.

Elf binaries also contains information that is important for linker, but it's not loaded to memory, these are the sections, the section structures are pointed by the field *e_shoff* from the first structure we say, and are the next structures:

```c
typedef struct {
    uint32_t   sh_name;
    uint32_t   sh_type;
    uint32_t   sh_flags;
    Elf32_Addr sh_addr;
    Elf32_Off  sh_offset;
    uint32_t   sh_size;
    uint32_t   sh_link;
    uint32_t   sh_info;
    uint32_t   sh_addralign;
    uint32_t   sh_entsize;
} Elf32_Shdr;

typedef struct {
    uint32_t   sh_name;
    uint32_t   sh_type;
    uint64_t   sh_flags;
    Elf64_Addr sh_addr;
    Elf64_Off  sh_offset;
    uint64_t   sh_size;
    uint32_t   sh_link;
    uint32_t   sh_info;
    uint64_t   sh_addralign;
    uint64_t   sh_entsize;
} Elf64_Shdr;
```

Different information is represented in sections, the sections are contained inside of the segments, and as we said this is not loaded to memory as it's not necessary for the binary loader, and all the information for the dynamic solver (if dynamic solving of external functions is used), can be found in the Elf Dynamic header:

```c
typedef struct {
    Elf32_Sword    d_tag;
    union {
        Elf32_Word d_val;
        Elf32_Addr d_ptr;
    } d_un;
} Elf32_Dyn;
extern Elf32_Dyn _DYNAMIC[];

typedef struct {
    Elf64_Sxword    d_tag;
    union {
        Elf64_Xword d_val;
        Elf64_Addr  d_ptr;
    } d_un;
} Elf64_Dyn;
extern Elf64_Dyn _DYNAMIC[];
```

These last header is pointed one of the segments, so dynamic linker can retrieve the address of these structures. This structure appears in those binaries compiled with dynamic linking, where all the necessary libraries are loaded with the binary and the imports are resolved by dynamic linker in run-time, other binaries are those compiled statically that contain the whole code from the library functions embedded in the binary, these are harder to analyze as nor the disassembler nor the debugger recognize these functions directly (recognition patterns must be used in order to detect the functions).

#### PLT & GOT

ELF binaries compiled with dynamic linking contains different sections that are used for loading imports from libraries, these involve sections with *plt* and *got* name, due to the fact that a program cannot reference an unknown address (an external function) directly, the program points to a section called *plt*, *plt* contains an indirect jump instruction, this means that in the jump instruction a pointer is used, the value of the pointer should be the external function address, the pointer is in the *got* section. If the binary use lazy binding, the external functions are not resolved at first, but are resolved in the moment they are called. Let's going to explain it with an example:

```
08049196 <main>:
8049196:	f3 0f 1e fb          	endbr32 
804919a:	8d 4c 24 04          	lea    0x4(%esp),%ecx
804919e:	83 e4 f0             	and    $0xfffffff0,%esp
80491a1:	ff 71 fc             	pushl  -0x4(%ecx)
80491a4:	55                   	push   %ebp
80491a5:	89 e5                	mov    %esp,%ebp
80491a7:	53                   	push   %ebx
80491a8:	51                   	push   %ecx
80491a9:	e8 28 00 00 00       	call   80491d6 <__x86.get_pc_thunk.ax>
80491ae:	05 52 2e 00 00       	add    $0x2e52,%eax
80491b3:	83 ec 0c             	sub    $0xc,%esp
80491b6:	8d 90 08 e0 ff ff    	lea    -0x1ff8(%eax),%edx
80491bc:	52                   	push   %edx
80491bd:	89 c3                	mov    %eax,%ebx
80491bf:	e8 9c fe ff ff       	call   8049060 <puts@plt>
```

```
Section .plt:

08049030 <.plt>:
 8049030:	ff 35 04 c0 04 08    	pushl  0x804c004
 8049036:	ff 25 08 c0 04 08    	jmp    *0x804c008
 804903c:	0f 1f 40 00          	nopl   0x0(%eax)
 8049040:	f3 0f 1e fb          	endbr32 
 8049044:	68 00 00 00 00       	push   $0x0
 8049049:	e9 e2 ff ff ff       	jmp    8049030 <.plt>
 804904e:	66 90                	xchg   %ax,%ax

Section .plt.sec:

08049060 <puts@plt>:
 8049060:	f3 0f 1e fb          	endbr32 
 8049064:	ff 25 0c c0 04 08    	jmp    *0x804c00c
 804906a:	66 0f 1f 44 00 00    	nopw   0x0(%eax,%eax,1)

Section .got.plt:

0804c000 <_GLOBAL_OFFSET_TABLE_>:
 804c000:	14 bf 04 08 00 00 00 00 00 00 00 00 40 90 04 08     ............@...
 804c010:	50 90 04 08 
```

In the main function we have a call to the address 0x8049060, this is an address in the section *.plt.sec*, in this section, there's a jump to the address pointed by the address 0x804c00c, as this binary use lazy binding, the address 0x804c00c does not contains the external address but it contains a pointer (0x08049040) to the section *.plt*, in that section we see an instruction pushing a value *0* and then a jump at the beginning of the *.plt*, with this the dynamic linker starts working to search the address of the function in all the loaded libraries.
The pushed value (0), is an index in the *.rel.plt* section:

```
Found reloc section .rel.plt, relocs (2):

[ ID]   OFFSET             INFO         REL. TYPE          SYM. VALUE       Symbol Name
[  0] 000000000804c00c 0000000000000107 R_386_JMP_SLOT     0000000000000000 puts
```

Dynamic linker extracts from here the name (*puts*) and the address (0x0804c00c), this address will be overwritten with the address of the function once is resolved.


More information about ELF exist on the elf man page, or my set of [elf notes](https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/pdfs/documents/elf_notes.pdf).


### Linux API

As well as on Windows you can find the well-known *"WIN32 API"* that specify the functions binaries can use from the different windows dlls (*kernel32.dll*, *user32.dll*, *ntdll.dll* and so on) to work with system resources as files, networking, windows registry or even crypto. On Linux we can find a great standard used as a compatibility layer between operating systems, these defines the *Application Programming Interface*(API), but it also defines the command line shells or the utilities the operating system must implement. This standard is known as **POSIX** (*Portable Operating System Interface*).

This application programming interface provides ways to manage process creation and control (*fork*), control of signals produced by the program (*signal*), file management (*open*, *read*, *write*, *lseek*, *stat*, etc), I/O, sockets, etc. 

Inside of POSIX we can also find the standard C specification, so standard management of files and other resources can be used (calls like *fopen* or *fread* are part of the standard C).

In the same way analyst search information in msdn about different Windows Functions, we can search information about a function in manual pages of our operating system with the command *man* followed by the function name.

## Tooling

At the beginning we said the tools we were gonna use, our disassembler will be *Ghidra* and as debugger we will use *gdb* with *gdb-peda*, let's gonna start looking how ghidra works and useful utilities from this disassembler.

### Ghidra

In order to start using Ghidra we need to install Java JDK that commonly also comes with JRE, the JDK version to install will be the version 11, you can download java from [here](https://adoptopenjdk.net/releases.html?variant=openjdk11&jvmVariant=hotspot). Once we have installed Java, we will download Ghidra, we can download it from [here](https://ghidra-sre.org/). Ghidra is already compiled and comes with different scripts to launch it:

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/ghidra-1.png"/>

The scripts are both for Linux and for Windows, we will use the one for Linux. Once we open Ghidra, we'll see a screen like the next one:

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/ghidra-2.png"/>

As no previous project exists, we will have to create a new project, the projects will contain the analyzed files, so click in *"File"*, and *"New Project"*, in the next window we select *Non-shared project* and we have to choose a path to store the project and a name for the project.

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/ghidra-3.png"/>

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/ghidra-4.png"/>

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/ghidra-5.png"/>

Finally we will have something like the next window:

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/ghidra-6.png"/>

We just have to drag and drop a file to the screen to import it:

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/ghidra-7.png"/>

Ghidra will try to recognize the file type, architecture, endianess and if possible the compiler and with this recognize the calling convention we will see later. If we click twice on the file, the tool *Code Browser* will start and if the file has not been previously analyzed, the tool will ask us to auto-analyze it:

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/ghidra-8.png"/>

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/ghidra-9.png"/>

We will leave the default options, and then wait until analysis has finished. Let's move to a function and see the main GUI of Ghidra:

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/ghidra-10.png"/>

Let's going to describe what we see:

* Left side:
    * Top: *Program Trees*: sections from the binary, these sections as we said are contained in ELF segments.
    * Middle: *Symbol Tree*: here we have the program imports, the Exports, the recognized functions, labels from program, and in case of C++ programs classes and namespaces. This information will be retrieved from program header and also in the case of the functions, the recognized functions through different algorithms.
    * Down: *Data Type Manager*: loaded data types by ghidra, these data types are commonly structures, enumerations and so on from different libraries, if the program contains symbols, structures defined by the program will be included, but here we can include our own data types.
* Center:
    * *Listing view*: here we have the main view of Code Browser, in this window we have the disassembly of the program, Ghidra separates the disassembly by functions, and in each function we have also references to data, the local variables as offsets of the stack with *EBP/RBP* or *ESP/RSP*, Ghidra allows us to rename the data from other sections, the local variables and also the function names.
* Right side:
    * *Decompiler*: Ghidra comes with a decompiler for different architectures, this tool tries to generate a pseudo-code as close as possible to the original source code, due to the all the information is lost in the compilation process, recoverying all the source code is not possible.

These windows can be re-organized, and more windows can be included if we go up to *Window* and open any other tool, then is just a matter of drag and drop in order to organize the windows, in my case the one I included is the *Defined Strings* window, that shows all the recognized strings from the program.

### GDB

This is the debugger de-facto of Linux, it has a tough interface as it is a command line tool instead of having a graphic user interface (gdb has a built-in terminal user interface with the flag *-tui* in the command line). As a way to improve the experience with gdb, we will use a modified version of *gdb-peda*, with this plugin of gdb, we will have on the screen the disassembly of the program, register values and the stack:

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/gdb-1.png"/>

Useful gdb commands can be summarized into a couple of cheat sheets:

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/gdb-2.jpg"/>

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/gdb-3.png"/>

