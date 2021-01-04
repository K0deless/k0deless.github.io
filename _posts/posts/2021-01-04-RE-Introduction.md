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

