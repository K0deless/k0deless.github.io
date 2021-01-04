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

