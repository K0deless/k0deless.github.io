#!/usr/bin/env python
## -*- coding: utf-8 -*-


from __future__ import print_function

import sys
import ctypes

from triton import *


# Oracles table, each entry is structured as follow (x value, y value, result).
# More entries there are, more precise is the result for example checkout
# this table [0] or generate your own table with [1].
#
# [0] http://shell-storm.org/repo/Notepad/synthesis_tables.py
# [1] http://shell-storm.org/repo/Notepad/gen_synthesis_tables.py

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


sizes_table = {
    8:  ctypes.c_uint8,
    16: ctypes.c_uint16,
    32: ctypes.c_uint32,
    64: ctypes.c_uint64,
}


# Two vars synthetizing
def two_vars_synthetizing(ctx, expr, x, y):
    for entry in oracles_table:
        valid = True
        print("checking with entry: ", entry)
        for oracle in entry['oracles']:
            ctx.setConcreteVariableValue(x.getSymbolicVariable(), sizes_table[x.getBitvectorSize()](oracle[0]).value)
            ctx.setConcreteVariableValue(y.getSymbolicVariable(), sizes_table[y.getBitvectorSize()](oracle[1]).value)
            print("oracle[0] = %d\toracle[1] = %d\tresult = %d\tevaluated result = %d" % (oracle[0], oracle[1], oracle[2], expr.evaluate()))
            if expr.evaluate() != sizes_table[y.getBitvectorSize()](oracle[2]).value:
                valid = False
                break

        if valid is True:
            return eval(entry['synthesis'])

    return expr


# Constant synthetizing
def constant_synthetizing(ctx, expr, x):
    ast = ctx.getAstContext()
    c   = ast.variable(ctx.newSymbolicVariable(x.getBitvectorSize()))

    synth = [
        (x & c, 'x & c'),
        (x * c, 'x * c'),
        (x ^ c, 'x ^ c'),
        (x + c, 'x + c'),
        (x - c, 'x - c'),
        (c - x, 'c - x'),
    ]

    for op, s in synth:
        m = ctx.getModel(ast.forall([x], expr == op))
        if m:
            c = m[c.getSymbolicVariable().getId()].getValue()
            return eval(s)

    return expr


def synthetize(ctx, expr):
    ast       = ctx.getAstContext()
    variables = ast.search(expr, AST_NODE.VARIABLE)

    # There is no variable in the expression
    if len(variables) == 0:
        return expr

    elif len(variables) == 1:
        x = variables[0]
        return constant_synthetizing(ctx, expr, x)

    elif len(variables) == 2:
        x = variables[0]
        y = variables[1]
        return two_vars_synthetizing(ctx, expr, x, y)

    return expr

def YANSOllvm_Add(x, y):
    return ((x|~y) + (~x&y) - (~(x&y)) + (x|y))

def YANSOllvm_Sub(x,y):
    return (YANSOllvm_Add(x, ~y) + 1)

def YANSOllvm_And(x,y):
    return ((~x | y) + (x & (~y)) - ~(x & y))

def YANSOllvm_Or(x,y):
    return (((x^y) + y) - (~x & y))

def YANSOllvm_Xor(x,y):
    return ((x+y) - ((x & y) << 1))

def main():
    ctx = TritonContext(ARCH.X86_64)
    ast = ctx.getAstContext()

    ctx.setAstRepresentationMode(AST_REPRESENTATION.PYTHON)

    x = ast.variable(ctx.newSymbolicVariable(8))
    y = ast.variable(ctx.newSymbolicVariable(8))
    z = ast.variable(ctx.newSymbolicVariable(32))

    # Some obfuscated expressions
    obf_exprs = [
        YANSOllvm_Add(x,y),                 # x + y
        YANSOllvm_Sub(x,y),                 # x - y
        YANSOllvm_And(x,y),                 # x and y
        YANSOllvm_Or(x,y),                  # x or y
        YANSOllvm_Xor(x,y),                 # x xor y
    ]

    for expr in obf_exprs:
        (print('In: %s' %(expr)) if len(str(expr)) < 100 else print('In: %s ...' %(str(expr)[0:100])))
        expr = synthetize(ctx, expr)
        print('Out: %s' %(expr))
        print()

    return 0


if __name__ == '__main__':
    sys.exit(main())