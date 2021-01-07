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

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/gdb-2.jpeg"/>

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/gdb-3.png"/>

Mainly we will use the next:

* *break*: set a breakpoint in an address, as address a symbol can be given or a raw address.
* *step*: execute next instruction (jump into functions).
* *next*: execute next instruction (jump over functions).
* *continue*: continue execution.
* *run*: start the execution of the program.
* *info breakpoints*: get all the breakpoints set.
* *delete*: delete a breakpoint.
* *x/nfu*: print the bytes from a given address.
* *info follow-fork-mode*: show the fork mode option of gdb.
* *set follow-fork-mode*: set the fork mode option of gdb.

## Assembly

Before starting with the assembly instructions, I have to difference between two syntax.

* AT&T: this is the most common assembly syntax on Linux tools like gdb, objdump, etc. Registers are prefixed by '%', and immediate values use '$' before of the number, memory access are done with parenthesis '(' and ')', instructions commonly are followed by the size of the operands, and also the biggest difference the source operand goes first and destination the second one.

```
movl $40233033h, %ecx ; copy long to ecx
movl (%eax), %ecx   ; copy long from address pointed
                    ; by eax to ecx
movl %ecx, %eax     ; copy value from ecx to eax
```

* Intel: the most used assembly syntax on windows and also on many tools used in reverse engineering, main differences with AT&T, no '%' nor '$', memory access is done through square brackets '[' and ']', finally destination operand goes first and source second one.

```
mov ecx, 40233033h ; copy long to ecx
mov ecx, [eax]     ; copy long from address pointed
                   ; by eax to ecx
mov eax, ecx       ; copy value from ecx to eax
```

From these two, we will use the latter as it's the one used by Ghidra and also by the plugin of gdb-peda.

### MOV instruction

MOV instruction copies a immediate value, or from memory or a register to another register, or to memory. Different type of MOV instructions are allowed:

* From immediate value to register:

```
mov eax, 40h ; copy the value 40 to eax
```

* From register to another register:

```
mov eax, ebx ; copy value from ebx to eax
```

* From immediate value to memory:

```
mov [04030201h], 33h ; copy value 33 to address
```

* From register to memory:

```
mov [04052233h], ebx ; copy value in ebx to address
```

* From memory to memory is only allowed in some instructions:

```
inc dword ptr [04032221h] ; increment value in memory
```

* Base pointer plus index (commonly used in arrays):

```
mov eax, [ebx+esi*4]
```

### LEA Instruction

LEA (Load Effective Address) this instruction instead of accessing a memory address, treat what is inside of square brackets as an expression, and the result number is copied into destination. So for example:

```
LEA ebx, [ebp + 3]
```

If this would be a mov, it would go to the address pointed by ebp + 3, it would take the value and would copy it to ebx, with LEA it takes the value of ebp, add 3, and copy the result to ebx. The LEA instruction make use of a mathematic co-processor, and can execute also multiplication instructions:

```
LEA edx, [eax * 5]
```

This takes the value of eax, multiply it by 5, and assign the result to edx.

### String operations

Different string operations exist in order to copy values from one address to other, load a value from source register address to accumulator, store value from accumulator to destination register address, comparison between values pointed by source and destination registers, and finally search value from accumulator in destination register address.

* MOVS: copy value from memory pointed by ESI/RSI to memory pointed by EDI/RDI. Different operations: MOVSB, MOVSW, MOVSD, MOVSQ.
* LODS: load a value from memory pointed by ESI/RSI to EAX/RAX. Different operations: LODSB, LODSW, LODSD, LODSQ.
* STOS: store a value from EAX/RAX to memory pointed by EDI/RDI. Different operations: STOSB, STOSW, STOSD, STOSQ.
* CMPS: compares values from memory pointed by ESI/RSI with memory pointed by EDI/RDI. Different operations: CMPSB, CMPSW, CMPSD, CMPSQ.
* SCAS: instruction compares value in AL/AX/EAX/RAX with memory pointed by EDI/RDI. Different operations: SCASB, SCASW, SCASD, SCASQ.

All these operations can be prefixed by REP instruction types:

* REP: unconditional repeat, repeats until CX is zero.
* REPE/REPZ: repeat until ZF is 0 or CX is zero.
* REPNE/REPNZ: repeat until ZF is 1 or CX is zero.

```
LEA esi, [04050607h + 03h]; esi = 0405060Ah
LEA edi, [04050600h + 02h]; edi = 04050602h
movsd; copy 4 bytes from 0405060Ah to 04050602h
```

### Arithmetic operations

* ADD

```
ADD eax, 02h; eax = eax + 2
```

* SUB

```
SUB eax, 20h; eax = eax - 0x20
```

* INC

```
INC eax; eax = eax + 1
```

* DEC

```
DEC eax; eax = eax - 1
```

### Logic operations

* AND

```
AND eax, 00000100h; 1 when both bits are 1
```

* OR

```
OR eax, FFFFFFFFh; 1 when any of the bits is 1
```

* XOR

```
XOR eax, eax; 1 when 1-0 or 0-1, 0 in other case
```

* NOT

```
NOT eax; turn all the bits
```

* SHL/SHR

```
SHL/SHR eax, <number/cl>; shift bits to left or to right n times
```

* ROL/ROR

```
ROL/ROR eax, <mnumber/cl>; rotate bits to left or right n times
```

### Multiplication and Division

Multiplication has different instructions with different use of registers:

* MUL <reg/mem> ; multiply given value with al, ax, eax or rax, and store in ax, dx:ax, edx:eax and rdx:rax
* IMUL <reg/mem> ; multiply given value with al, ax, eax or rax, and store in ax, dx:ax, edx:eax and rdx:rax
* IMUL <reg1>,<reg2/mem> ; reg1 = reg1 * reg2/mem
* IMUL <reg1>,<reg2/mem>,number; reg1 = reg2/mem * number

MUL = Unsigned multiplication
IMUL = Signed multiplication

With division we have something similar to previous case

* DIV <reg/mem> ; divide rdx:rax, edx:eax, dx:ax or ax with the given value, store esult in rax, eax, ax or al, and rest of division in rdx, edx, dx or ah.
* IDIV <reg/mem> ; divide rdx:rax, edx:eax, dx:ax or ax with the given value, store esult in rax, eax, ax or al, and rest of division in rdx, edx, dx or ah.

DIV = Unsigned division
IDIV = Signed division

### Memory for variables

The variables of a program can be found in different parts of the memory of a program, here I will explain a little bit of where we will find the different variables of the program, in order to later continue explaining instructions.

* *initialized global variables*: these variables are global to the program and have been initialized by the programmer in source code, in ELF we can find these variables in the *.data* section.
* *non-initialized global variables*: as the previous one, these are global variables that have no value in source code, for that reason, these variables does not exist on disk and only exist on memory, these variables in an ELF file reside in the *.bss* section.
* *strings*: the strings are asigned to a char pointer commonly, these are not modified and will be read-only, in an ELF file these are in *.rdata* section.
* *Dynamically allocated variables*: these variables are dynamically allocated by the programmer according to the necessity of the program, a special memory space exist for this purpose and follows a specific structure to manage the memory chunks, this memory is known as *heap* and in case more memory is necessary, the operating system can be queried for more memory using the system calls *brk* and *sbrk*.
* *Local variables*: these variables reside inside of the stack, we will talk about this memory later, but we can say now that this function stores the local variables of a function, as well as the parameters and return addresses.

Stack and heap grows one in opposite to the other as we can see in the next image:

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/process-memory.jpeg"/>

### The stack

As we previously said, the stack grows in opposite to the heap, and stores local variables, function parameters and return addresses. The stack starts at higher addresses and grows to lower addresses, let's going to see an example of an stack when a function is called.

```
+-------------------------+  ^  Lower Addresses
|                         |  |
|  Not allocated space    |  |
|                         |  |          ESP/RSP now
+-------------------------+  | <------+ points here
|                         |  |
|                         |  |
|                         |  |
|   char name[32]         |  |
|                         |  |
|                         |  |
|                         |  |
|                         |  |           EBP/RBP now
+-------------------------+  | <------+  points here
|                         |  |
|  Stored Base Pointer    |  |
|  EBP                    |  |
+-------------------------+  |
|                         |  |
|  Return Address         |  |
|  (EIP/RIP or RET)       |  |
+-------------------------+  |
|                         |  |
|  Function Parameters    |  |
|                         |  |
+-------------------------+  |
|                         |  |
|  Previous Stack Frame   |  |
|                         |  |
+-------------------------+  +  Higher Addresses
```

Previous image shows how would be a normal stack in a program like the next one:

```c
void function(int a, int b)
{
    char name[32];
}

int main()
{
    function(5,2);
}
```

Two registers are used together as stack pointers in order to divide the stack for each function, this division is known as "frame" here reside function's local variables. The base pointer register *EBP* or *RBP* points to the frame base, and the stack pointer register *ESP* or *RSP* points to the top of the stack, in this way local variables can be accessed as *ESP/RSP + <offset>* or *EBP/RBP - <offset>*. Parameters are accessed by base pointer, first parameter would be *EBP + 8* in 32 bits, and *RBP + 0x10* in 64 bits (to jump over the stored frame base pointer and return value).

From now on we will see the examples in 32 bits in order to reduce size of the post.

### Push & Pop

These instructions are used to push a value into the stack, and to pop it from the top of the stack, the syntax of each instruction is the next:

```
push <reg/mem/imm> ; push 4 bytes (in 32 bits)

This is the same than:
    sub esp, 4
    mov [esp], <reg/mem/imm>

pop <reg/mem> ; pop 4 bytes (in 32 bits)

This is the same than:
    mov <reg/mem>, [esp]
    add esp, 4
```

As we know in programming, functions are used to avoid code repetition, but once a program moves into a function it must know where to return after the function. Functions commonly have parameters that as we now know are passed through the stack. Then a function is called (Through a CALL instruction).
When the function is called, the return address is automatically pushed to the stack, and then a *prologue* code is executed in order to create a *frame* so the function has its own stack. The prologue allocates space for local variables substracting the necessary space to ESP.
Finally once the function has finished, the stack frame is "freed" setting the ESP value equals to EBP, a pop to EBP is executed to return previous stack frame, and a return instruction takes the return address from the stack. Finally parameters are also freed, we'll see different ways to do it depending on something acalled "calling convention".

**Calling Convention**

Three different calling convention exist, and we will see it with an example:

```c
int adder(int a, int b)
{
    int value;
    value = a+b;
    return value;
}

int main()
{
    adder(1,2);
}
```

**CDECL**

The *CDECL* calling convention pass the parameters from right to left (first b and then a), and the caller function is the one that must clean the stack once the function has finished. This is the most common calling convention on Linux in opposite to the next one

```
proc main
    push 2
    push 1
    call adder
    add esp, 8 ; clean the stack from parameters
endp

proc adder
    push ebp     ; 
    mov ebp, esp ; prologue
    sub esp, 4   ; allocates space
    mov eax, [ebp + 8]
    mov ebx, [ebp + C]
    mov [esp], ebx
    add [esp], eax
    mov eax, [esp]
    mov esp, ebp ; epilogue
    pop ebp      ;
    ret          ; return
endp
```

**STDCALL**

This calling convention is used mostly in Windows DLLs and is similar to previous one, parameters are passed from right to left too, but this time is the callee (function called) the one that cleans the stack.

```
proc main
    push 2
    push 1
    call adder
endp

proc adder
    push ebp     ; 
    mov ebp, esp ; prologue
    sub esp, 4   ; allocates space
    mov eax, [ebp + 8]
    mov ebx, [ebp + C]
    mov [esp], ebx
    add [esp], eax
    mov eax, [esp]
    mov esp, ebp ; epilogue
    pop ebp      ;
    ret 8        ; return & ; clean the stack from parameters
endp
```

**Fastcall**

This is a calling convention where registers are used together with the stack in order to pass the parameters, in 64 bits is used due to the fact that this architecture has more registers than in 32 bits. On Linux for 64 bits registers are in this order: *RDI, RSI, RDX, RCX, R8* and *R9*.

### Unconditionals and Conditional Jumps

These instructions are used to change control flow of a program. Two types of jumps exist:

* Unconditionals: are always taken (JMP instruction)
* Conditionals: depends on a condition (Jcc instructions).

We've already seen in previous examples an unconditional jump, the instruction CALL acts as an unconditional jump but pushing the next instruction address on the stack.

Conditional jumps depends on the EFLAGS/RFLAGS register we previously saw.

The EFLAGS/RFLAGS are modified after an arithmetic-logic instruction, the value of the flag will be or '0' or '1'.

Commonly the conditional jumps to set the flags use two types of comparison instructions:

* *CMP*: this comparison instruction use substraction between the two values but without storing the result.
* *TEST*: this one instead of substraction it applies an AND operation, again without storing the result.

Next flags can be set from the previous instructions:

* Zero Flag (ZF): result was 0.
* Carry Flag (CF): result generated carry bit that cannot fit into register.
* Sign Flag (SF): negative result.
* Overflow Flag (OF): signed number that change its sign.

| Conditional Jump | Description | EFLAGS used |
|:----------------:|:------------|:-----------:|
| JB/JNAE | Jump if below, or not greater nor equal, unsigned numbers | CF = 1 |
| JNB/JAE | Jump if not below, above or equal, unsigned numbers | CF = 0 |
| JE/JZ | Jump if equal or zero flag | ZF = 1 |
| JNE/JNZ | Jump if not equal, not zero | ZF = 0 |
| JL | Jump if lower than, signed numbers | (SF ^ OV) = 1 |
| JGE/JNL | Jump if greater or equal, if not lower, signed numbers | (SF ^ OV) = 0 |
| JG/JNLE | Jump if greater, if not lower or equal, signed numbers | ((SF ^ OV)\|ZF) = 0 |

## Code Constructions

Now we get the point where we will see real code, and more exactly we will see some code constructions in order to recognize them once we see common constructions that we can see in source code, but in assembly. Knowing about this will help us to think about how the source code looks, so if we detect the use of global variables for example we can rename them, in the same way if we detect a loop we can jump over it to next code, and so on.

The files will be available in: **TODO UPLOAD EXAMPLES**

Once you have downloaded the samples create a project on Ghidra for all the analysis.

### Different Data Types

Let's start by different data types we can find in a program and how are accessed, we will see the disassembly on Ghidra, also we will try to reconstruct some data as structures and arrays with Ghidra. 


#### Global Variables

As we previously said, we have two different types of global variables, those that are initialized and those that were not initialized, in both cases we will take it as the same type (because are accessed in the same way). Global variables are commonly accessed by its global address, we will load on Ghidra the example *global_var* and let's analyze the main function.

Once we've loaded the binary and analyze it, we will have the next entry point:

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/global_var1.png"/>

This is the common start for binaries compiled with gcc, libc start function is executed, we can find the *main* function as parameter in RDI (address *0x004004ad*). We can rename the function and include the common parameters from main and return value.

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/global_var2.png"/>

Now we can see the main function in the disassembler, as we can see one global variable is accessed as we said by its address (addresses 0x0040057b and 0x00400594), but those global variables that contain strings are renamed with the string as a name (addresses 0x00400585 and 0x0040058c). Also we can see how the function *puts* is called using a fastcall calling convention, setting the parameters in RDI and RSI, renamed by Ghidra as argc and argv due to the parameters of main functions.

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/global_var3.png"/>

Next pictures show these global variables before and after renaming:

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/global_var4.png"/>

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/global_var5.png"/>

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/global_var6.png"/>

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/global_var7.png"/>

Now if we see again the main function, we have the next:

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/global_var8.png"/>

Giving meaningful name to global addresses can help us to understand what a program is doing with them, also it will help the decompiler view to have better representation as we see in next image:

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/global_var9.png"/>

#### Local Variables

Now we'll see the local variables that in source code are declarated inside of a function, these are stored on the stack and will be accessed by ESP/RSP or EBP/RBP. As in the previous case we will load the binary in Ghidra, as we know how to go to main function we can directly go to this. Load the binary local_var go to main function and rename it:

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/local_var1.png"/>

As we can see Ghidra represent the local variables with the offset, this time it uses RBP to access the local variables, we can also rename the local variables:

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/local_var2.png"/>

This is a simple program that set the value 5 to the one local variable, and the value 2 to the other. The value 5 is used as dividend and it must be set in EAX, then DIV instruction is called using the value 2 as divisor, the quotient will be in EAX and remainder in EDX, these results are stored in two local variables. 


#### Global Structures

Now we move to another data type, now we'll see the structures, this data type is highly used as it can represent "real entities" as we would do with the classes in C++. Internally the binary does not understand about structures, nor variables with different fields, and everything is memory, so maybe a structure is just represent it as access to different variables. One of the approaches to "reconstruct" a structure is to follow the structure through functions where it's passed as parameter, commonly structures are passed as pointers, and its values are filled inside. The example we will see here is pretty simple, and I will give the structure that we will create on Ghidra in order to modify a variable type.

So now let's going to load the binary global_struct into Ghidra, analyze it and go to main function.

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/global_struct-1.png"/>

At first glance we can see some calls to API functions like *printf* or *fgets*, the function *fgets* reads the bytes specified as second argument from third argument (a file descriptor) and store the bytes into the buffer specified as first parameter, in this case the third argument is stdin so it reads 0x1d (29) bytes from keyboard to a global variable (at address 0x00601080). *printf* at the beginning ask user to write "user name" so we will say that probably this global variable is a buffer for name (a char buffer) with a size of 29 bytes. In case there's an error, the program we will see it returns -1 or 0xffffffff.

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/global_struct-2.png"/>

Previous image shows how the program ask for user age, it uses format "%d" so we can think that the global variable at address 0x006010a0 is an integer, this global variable is 32 bytes (0x20) after the previous one, this is due to the fact that there's an alignment in memory of the structure.

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/global_struct-3.png"/>

Now we have a global variable that is printed to the terminal which indicates the id that will be assigned to the user (address 0x00601070), the value from that variable is assigned to another global variable at address 0x006010a4, this variable follows the previous one from the structure and is assigned with AX, so this one is 2 bytes long (short type variable).

The complete execution of the program looks like next picture:

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/global_struct-4.png"/>

Let's going to create the structure on Ghidra, to do that we go to the *Data Type Manager* (down-left), we have to right click in the name of the binary we are analyzing *New* and *structure*:

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/global_struct-5.png"/>

We will have a window like the next one:

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/global_struct-6.png"/>

We will write a name like *user_t* and then we will start clicking in *DataType* and *Name* to write the data type and a name for the field. We will write *char[32]* and *name*, *int* and *age* and finally *short* and *id*. 

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/global_struct-7.png"/>

We must go to the first variable (the array of chars), and then we click twice to go to the data address, then we must right click in the global variable name, *data*->*choose data type*.

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/global_struct-8.png"/>

And finally in the prompted dialog we have to write *user_t*, ghidra will show us the data type just press Enter. 

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/global_struct-9.png"/>

The data has changed now and is not a bunch of unknown bytes. In the disassembler we will have some different fields, due to the fact that first field is also the beginning of the structure, is represented as the address of the structure. So just return to main function and see the differences.

With this we've seen how to modify data types from a variable and also how to create structures.

#### Local Structures

Let's move to next example, we will take similar code than previous in order to understand how a structure works on the stack instead of being a global variable. The structure will be the same in this case, let's load the binary *local_struct* into ghidra and analyze it.

Once you have opened the code browser and the binary analyzed, move to main function and rename it as we've done in all the previous cases. We will focus in the specific code that assigned values to the structure fields, first the call to fgets that was used to retrieve user name:

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/local_struct-1.png"/>

In opposite to previous case where the structure was global, now we have that *RBP* is used to access specific offset *RBP-0x30*, this is loaded in *RAX* using a LEA instruction, Ghidra includes the *=>local_38* in order to allow us write a name for the local variable, we could rename it as "name" but as we know is a structure, we will wait. Finally, RAX is copied into RDI (*argc* in the disassembler).

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/local_struct-2.png"/>

We move to the second field of the structure, this time we have that the code access to the same offset of *RBP*, but after the LEA instruction we have an ADD. This ADD moves the pointer 0x20 to higher address. This offset will be used by the function *scanf* to store the integer into the *age* field.

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/local_struct-3.png"/>

Finally we have the access to the *id* field, instead of using the offset -0x30 with *RBP* it uses the offset -0x14 (represented with the name *local_14* for renaming purposes), the compiler decided to use directly the offset instead of using an offset and an operation.

So now let's repeat previous operation, create a structure with the three fields and the name. Now in order to set the variable as the structure, we will have to go to the beginning of the function:

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/local_struct-4.png"/>

And remove the variables *local_18* and *local_14*, once we've removed those variables right clicking in the name and in *Function Variables* click in *Delete Local Variable*, we will right click in *local_38* and we will set the data type as we already saw with the structure *user_t*. We will have now the stack like the next picture:

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/local_struct-5.png"/>

If we rename it, and we go to the decompiler we will have the next (in order to show all the view in one picture):

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/local_struct-6.png"/>

As we can see, better presentation is done, and we have our structure, the value *DAT_00601070* is just a global counter.

#### Global Arrays

Now we move to arrays, these are similar to structures as internally are contiguous memory but this time, instead of being different data types together, are the same type, this make easier the access as there will not be different offsets, all the fields are accessed by the same offset. Commonly in low level, access to an array is made with a base pointer, and index where to access and this index multiplied by size of the field (for example an integer array would be index * 4). To know the type of the array, a clue is commonly the way the program access to each field, so the MOV instruction commonly uses in Intel Syntax different access like *dword ptr* (4 bytes), *word ptr* (2 bytes) or *byte ptr* (1 byte).

Let's load the binary *global_array* into ghidra, analyze it and rename *main* function.

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/global_array-1.png"/>

As we can see internally there are only access to different global variables, but these are followed. Also there are two different access, one is done by dwords (4 bytes), and the other is by bytes, commonly you initialize arrays through loops, but we will see them later.

As we did with structures, we can change data type of global variables, we will modify the first accessed (or lower address) variable, and we will set its data type as an integer array of size 4.

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/global_array-2.png"/>

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/global_array-3.png"/>

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/global_array-4.png"/>

We can rename it, and return to main function to see the difference:

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/global_array-5.png"/>

Now we have an array of bytes, we can see that Ghidra shows the data as hexadecimal values, but maybe another representation would show something different, if we right click in a value and then we click in *Convert*, we can see that as char the value is 'H', let's going to transform each byte for a char.

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/global_array-6.png"/>

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/global_array-7.png"/>

So now we can see that this array looks like a string defined as an array of chars, this is common in some malware in order to avoid string detection by tools like the disassemblers. we can go to the first char, and modify the data type by an array of chars of size 12.

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/global_array-8.png"/>

And if we go to the main function in the decompiler, we have the next:

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/global_array-9.png"/>

As we can see, now we don't have many different variables accessed, now we have two different arrays that are accessed index by index. This time with global variables, the program did not accessed the array as a base address + index as this would be the common way to access in a loop with an index value.

#### Local Arrays

Now we move to the stack representation of the arrays, again as in the previous case, we have that more than accessing an array, it looks like it access different local variables, but we can fix it modifying the stack variables in order to generate arrays. 

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/local_array-1.png"/>

In order to create an array of 4 integers in the variable *local_38* we will have to delete the variables *local_34, local_30, local_2c* as we did with the structures.

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/local_array-2.png"/>

Now we can create the array with no problems:

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/local_array-3.png"/>

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/local_array-4.png"/>

Disassembler now shows its representation as an array access, let's gonna do the same with the char array, and rename both fields:

<img src="https://raw.githubusercontent.com/K0deless/k0deless.github.io/master/assets/img/introduction-re/local_array-5.png"/>

As we've seen these are not very different from the global arrays, so once we have these concepts we will be able to recognize interesting data types, leaving just one to finish the explanation of data types.

#### Pointers


### Conditional constructions (if/else)


### Multiple paths (switch)


### Loops (for/do-while/while)


### Functions