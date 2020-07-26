import ctypes
from triton import TritonContext, ARCH, Instruction, MODE, REG

import sys

oracles_table = [
    {
        'oracles'   : [(0, 0, 0), (0, 1, 1), (1, 0, 1), (1, 1, 2)],
        'synthesis' : 'x + y'
    },
    {
        'oracles'   : [(0, 0, 0), (0, 1, -1), (1, 0, 1), (1, 1, 0)],
        'synthesis' : 'x - y'
    },
    {
        'oracles'   : [(0, 0, 0), (0, 1, 1), (1, 0, 1), (1, 1, 0)],
        'synthesis' : 'x ^ y'
    },
    {
        'oracles'   : [(0, 0, 0), (0, 1, 1), (1, 0, 1), (1, 1, 1)],
        'synthesis' : 'x | y'
    },
    {
        'oracles'   : [(0, 0, 0), (0, 1, 0), (1, 0, 0), (1, 1, 1)],
        'synthesis' : 'x & y'
    },
]

yansollvm_add = {
    0x004006a0: b'\x48\x89\xf0', #        MOV        RAX,RSI
    0x004006a3: b'\x48\x83\xf0\xff', #     XOR        RAX,-0x1
    0x004006a7: b'\x48\x09\xf8', #         OR         RAX,RDI
    0x004006aa: b'\x48\x89\xf9', #         MOV        RCX,RDI
    0x004006ad: b'\x48\x83\xf1\xff', #     XOR        RCX,-0x1
    0x004006b1: b'\x48\x21\xf1', #         AND        RCX,RSI
    0x004006b4: b'\x48\x89\xfa', #         MOV        RDX,RDI
    0x004006b7: b'\x48\x21\xf2', #         AND        RDX,RSI
    0x004006ba: b'\x48\x83\xf2\xff', #     XOR        RDX,-0x1
    0x004006be: b'\x48\x09\xf7', #         OR         RDI,RSI
    0x004006c1: b'\x48\x01\xc8', #         ADD        RAX,RCX
    0x004006c4: b'\x48\x29\xd0', #         SUB        RAX,RDX
    0x004006c7: b'\x48\x01\xf8', #         ADD        RAX,RDI
    0x004006ca: b'\xc3' #                 RET
}


yansollvm_sub = yansollvm_add 
yansollvm_sub.update(
    {
        0x004006d0 : b'\x50', # PUSH RAX
        0x004006d1 : b'\x48\x83\xf6\xff', # XOR RSI, -0x1
        0x004006d5 : b'\xe8\xc6\xff\xff\xff', # call yansollvm_add
        0x004006da : b'\x48\x83\xc0\x01', # ADD RAX,0x1
        0x004006de : b'\x59', # POP RCX
        0x004006df : b'\xc3' # RET
    }
)

yansollvm_and = {
    0x004006e0 : b'\x48\x89\xf9', # MOV RCX, RDI
    0x004006e3 : b'\x48\x21\xf1', # AND RCX,RSI
    0x004006e6 : b'\x48\x83\xf1\xff',# XOR RCX,-0x1
    0x004006ea : b'\x48\x89\xf8', # MOV RAX,RDI
    0x004006ed : b'\x48\x83\xf0\xff', # XOR RAX,-0x1
    0x004006f1 : b'\x48\x09\xf0', # OR RAX,RSI
    0x004006f4 : b'\x48\x83\xf6\xff', # XOR RSI,-0x1
    0x004006f8 : b'\x48\x21\xf7', # AND RDI,RSI
    0x004006fb : b'\x48\x01\xf8', # ADD RAX,RDI
    0x004006fe : b'\x48\x29\xc8', # SUB RAX,RCX
    0x00400701 : b'\xc3' # RET
}
        
Triton = TritonContext()

def run(ip, function):
    while ip in function:
        # Build an instruction
        inst = Instruction()

        # Setup opcode
        inst.setOpcode(function[ip])

        # Setup Address
        inst.setAddress(ip)

        # Process instruction
        Triton.processing(inst)

        # Display instruction
        #print('', inst)

        # Next instruction
        ip = Triton.getRegisterAst(
            Triton.getRegister(REG.X86_64.RIP)
            ).evaluate()

    rax = Triton.getRegisterAst(Triton.getRegister(REG.X86_64.RAX)).evaluate()
    return rax

def initContext(x,y):
    Triton.setConcreteRegisterValue(
        Triton.getRegister(REG.X86_64.RAX),
        0
    )
    Triton.setConcreteRegisterValue(
        Triton.getRegister(REG.X86_64.RBX),
        0
    )
    Triton.setConcreteRegisterValue(
        Triton.getRegister(REG.X86_64.RCX),
        0
    )
    Triton.setConcreteRegisterValue(
        Triton.getRegister(REG.X86_64.RDX),
        0
    )
    Triton.setConcreteRegisterValue(
        Triton.getRegister(REG.X86_64.RDI), 
        x)
    Triton.setConcreteRegisterValue(
        Triton.getRegister(REG.X86_64.RSI), 
        y)
    


if __name__ == '__main__':
    # Set architecture
    Triton.setArchitecture(ARCH.X86_64)

    # Symbolic optimization
    Triton.setMode(MODE.ALIGNED_MEMORY, True)

    print("YANSOllvm_Add:")
    for entry in oracles_table:
        valid = True

        print("Testing: ", entry['synthesis'])
        for oracle in entry['oracles']:
            # Init context memory
            initContext(oracle[0], oracle[1])

            # Emulate
            returned = ctypes.c_int64(run(0x004006a0, yansollvm_add)).value
            if returned != ctypes.c_int64(oracle[2]).value:
                print("Executed YANSOllvm_Add with %d and %d, returned = %d, expected = %d" % (oracle[0], oracle[1], returned, oracle[2]))
                valid = False
                break
                
            print("Executed YANSOllvm_Add with %d and %d, returned = %d, expected = %d" % (oracle[0], oracle[1], returned, oracle[2]))
        
        if valid is True:
            print("YANSOllvm_Add is equivalent to:", entry['synthesis'])
            print("\n\n")
            break

    print("YANSOllvm_Sub:")
    for entry in oracles_table:
        valid = True

        print("Testing: ", entry['synthesis'])

        for oracle in entry['oracles']:
            # Init context memory
            initContext(oracle[0], oracle[1])

            # Emulate
            returned = ctypes.c_int64(run(0x004006d0, yansollvm_sub)).value

            if returned != ctypes.c_int64(oracle[2]).value:
                print("Executed YANSOllvm_Sub with %d and %d, returned = %d, expected = %d" % (oracle[0], oracle[1], returned, oracle[2]))
                valid = False
                break
            
            print("Executed YANSOllvm_Sub with %d and %d, returned = %d, expected = %d" % (oracle[0], oracle[1], returned, oracle[2]))
        
        if valid is True:
            print("YANSOllvm_Sub is equivalent to:", entry['synthesis'])
            print("\n\n")
            break
    
    print("YANSOllvm_And:")
    for entry in oracles_table:
        valid = True

        print("Testing: ", entry['synthesis'])

        for oracle in entry['oracles']:
            # Init context memory
            initContext(oracle[0], oracle[1])

            # Emulate
            returned = ctypes.c_int64(run(0x004006e0, yansollvm_and)).value

            if returned != ctypes.c_int64(oracle[2]).value:
                print("Executed YANSOllvm_And with %d and %d, returned = %d, expected = %d" % (oracle[0], oracle[1], returned, oracle[2]))
                valid = False
                break
            
            print("Executed YANSOllvm_And with %d and %d, returned = %d, expected = %d" % (oracle[0], oracle[1], returned, oracle[2]))
        
        if valid is True:
            print("YANSOllvm_And is equivalent to:", entry['synthesis'])
            print("\n\n")
            break