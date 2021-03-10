# -*- coding: utf-8 -*-
import sys

import gdb
import re
import os

import pwndbg.arch
import pwndbg.regs
import pwndbg.events
import pwndbg.memoize
import pwndbg.memory
import pwndbg.proc
import pwndbg.remote
import pwndbg.color
import pwndbg.commands.telescope 

import pwndbg.chain
import pwndbg.color.memory
import pwndbg.disasm.x86
import pwndbg.disasm.arm
import pwndbg.disasm.mips
import pwndbg.disasm.ppc
import pwndbg.disasm.sparc
from capstone import x86_const
from capstone import arm_const
from capstone import mips_const
from capstone import ppc_const
from capstone import sparc_const


# class memoized(object):
#     """
#     Decorator. Caches a function's return value each time it is called.
#     If called later with the same arguments, the cached value is returned
#     (not reevaluated).
#     """
#     def __init__(self, func):
#         self.func = func
#         self.instance = None # bind with instance class of decorated method
#         self.cache = {}
#         self.__doc__ = inspect.getdoc(self.func)

#     def __call__(self, *args, **kwargs):
#         try:
#             return self.cache[(self.func, self.instance, args) + tuple(kwargs.items())]
#         except KeyError:
#             if self.instance is None:
#                 value = self.func(*args, **kwargs)
#             else:
#                 value = self.func(self.instance, *args, **kwargs)
#             self.cache[(self.func, self.instance, args) + tuple(kwargs.items())] = value
#             return value
#         except TypeError:
#             # uncachable -- for instance, passing a list as an argument.
#             # Better to not cache than to blow up entirely.
#             if self.instance is None:
#                 return self.func(*args, **kwargs)
#             else:
#                 return self.func(self.instance, *args, **kwargs)

#     def __repr__(self):
#         """Return the function's docstring."""
#         return self.__doc__

#     def __get__(self, obj, objtype):
#         """Support instance methods."""
#         if obj is None:
#             return self
#         else:
#             self.instance = obj
#             return self

#     def _reset(self):
#         """Reset the cache"""
#         # Make list to prevent modifying dictionary while iterating
#         for cached in list(self.cache.keys()):
#             if cached[0] == self.func and cached[1] == self.instance:
#                 del self.cache[cached]

# @memoized
# def examine_mem_reference(self, value):
#     """
#     Deeply examine a value in memory for its references

#     Args:
#         - value: value to examine (Int)

#     Returns:
#         - list of tuple of (value(Int), type(String), next_value(Int))
#     """
#     result = []
#     (v, t, vn) = self.examine_mem_value(value)
#     while vn is not None:
#         result += [(v, t, vn)]
#         if len(result) > 5 :
#             break
#         if v == vn or to_int(v) == to_int(vn): # point to self
#             break
#         if to_int(vn) is None:
#             break
#         if to_int(vn) in [to_int(v) for (v, _, _) in result]: # point back to previous value
#             break
#         (v, t, vn) = self.examine_mem_value(to_int(vn))

#     return result

# def execute_redirect(self, gdb_command, silent=False):
#     """
#     Execute a gdb command and capture its output

#     Args:
#         - gdb_command (String)
#         - silent: discard command's output, redirect to /dev/null (Bool)

#     Returns:
#         - output of command (String)
#     """
#     result = None
#     gdb.execute('set logging off') # prevent nested call
#     gdb.execute('set height 0') # disable paging
#     gdb.execute('set logging file %s' % logname)
#     gdb.execute('set logging overwrite on')
#     gdb.execute('set logging redirect on')
#     gdb.execute('set logging on')
#     try:
#         gdb.execute(gdb_command)
#         gdb.flush()
#         gdb.execute('set logging off')
#         if not silent:
#             logfd.flush()
#             result = logfd.read()
#         logfd.close()
#     except Exception as e:
#         gdb.execute('set logging off') #to be sure
#         if config.Option.get("debug") == "on":
#             msg('Exception (%s): %s' % (gdb_command, e), "red")
#             traceback.print_exc()
#         logfd.close()
#     if config.Option.get("verbose") == "on":
#         msg(result)
#     return result

def parse_and_eval(expr):
    print(pwndbg.regs)
    print(dir(pwndbg.regs))
    print(pwndbg.regs.pc)
    print(pwndbg.regs.rbp)

    """
    Work around implementation for gdb.parse_and_eval with enhancements

    Args:
        - exp: expression to evaluate (String)

    Returns:
        - value of expression
    """
    
    # (arch,bits) = peda.getarch()
    # if "aarch64" in arch :
    #     regs = REGISTERS["elf64-littleaarch64"]
    # elif "arm" in arch :
    #     regs = REGISTERS["elf32-littlearm"]
    # else :
    #     regs = REGISTERS["elf64-x86-64"] + REGISTERS["elf32-i386"] + REGISTERS[16] + REGISTERS[8]
    # for r in regs:
    #     if "$"+r not in exp and "e"+r not in exp and "r"+r not in exp:
    #         exp = exp.replace(r, "$%s" % r)

    # p = re.compile("(.*)\[(.*)\]") # DWORD PTR [esi+eax*1]
    # matches = p.search(expr)
    # if not matches:
    #     p = re.compile("(.*).s:(0x.*)") # DWORD PTR ds:0xdeadbeef
    #     matches = p.search(expr)

    # if matches:
    #     mod = "w"
    #     if "BYTE" in matches.group(1):
    #         mod = "b"
    #     elif "QWORD" in matches.group(1):
    #         mod = "g"
    #     elif "DWORD" in matches.group(1):
    #         mod = "w"
    #     elif "WORD" in matches.group(1):
    #         mod = "h"

    #     out = self.execute_redirect("x/%sx %s" % (mod, matches.group(2)))
    #     if not out:
    #         return None
    #     else:
    #         return out.split(":\t")[-1].strip()

    # else:
    #     out = self.execute_redirect("print %s" % exp)
    # if not out:
    #     return None
    # else:
    #     out = gdb.history(0).__str__()
    #     out = out.encode('ascii', 'ignore')
    #     out = decode_string_escape(out)
    #     return out.strip()

def refers(ins):
    # m = re.compile(r"\[[\S\s]*\]")
    ref = []
    # print(pwndbg.arch.current)
    current = pwndbg.arch.current
    # print(pwndbg.regs)
    # refers = x86_refers(ins)
    # print(refers)
    # 'x86-64', 'i386', 'mips', 'powerpc', 'sparc', 'aarch64'
    if current == 'x86-64' or current == 'i386':
        x86_assistant = pwndbg.disasm.x86.DisassemblyAssistant(current)
        ref = x86_refers(x86_assistant, ins)
    elif current == 'aarch64' or current == 'armcm' or current == 'arm':
        ref = arm_assistant = pwndbg.disasm.arm.DisassemblyAssistant(current)
    elif pwndbg.arch.current == 'ppc':
        ref = ppc_assistant = pwndbg.disasm.ppc.DisassemblyAssistant(current)
    elif pwndbg.arch.current == 'sparc':
        ref = sparc_assistant = pwndbg.disasm.sparc.DisassemblyAssistant(current)
    elif pwndbg.arch.current == 'sparc':
        ref = mips_assistant = pwndbg.disasm.mips.DisassemblyAssistant(current)
    else:
        ref = []

    return ref

def arm_refers(assistant,ins):
    pass

def ppc_refers(assistant,ins):
    pass

def mips_refers(assistant,ins):
    pass

def sparc_refers(assistant,ins):
    pass

def x86_refers(assistant, ins):
    output = []
    for operand in ins.operands:
        if operand.type == x86_const.X86_OP_INVALID:
            pass
        elif operand.type == x86_const.X86_OP_REG:
            regidx = operand.value.reg
            regvalue = assistant.regs(ins, regidx)
            regname = pwndbg.disasm.x86.regs[regidx].split('_')[-1].lower()
            if regvalue:
                chain = pwndbg.chain.format(regvalue)
                if chain:
                    output.append("$ %s : %s" % (regname, chain))
                else:
                    pass
            else:
                pass
        elif operand.type == x86_const.X86_OP_IMM:
            pass
        elif operand.type == x86_const.X86_OP_MEM:
            # TODO: Now support 
            # 0. disp: direct memory addressing mode
            # 1. base_reg: register based indirect addressing mode
            # 2. base_reg+disp: register relative addressing mode
            # 3. base_reg+index_reg: based indexed addressing mode 
            # 4. base_reg+index_reg+disp： relative based indexed addressing mode
            memvalue = assistant.memory(ins, operand)
            memory_sz = assistant.memory_sz(ins, operand)
            if memvalue:
                chain = pwndbg.chain.format(memvalue)
                if chain:
                    output.append('@ %s : %s' % (memory_sz, chain))
                else:
                    pass
            else:
                pass

    return output
    # asm = '%-06s %s' % (ins.mnemonic, ins.op_str)
    # m = m.findall(asm)

    # if m:
    #     print(m)
    #     expr = m[0][1:-1]
    #     print(expr)
    #     parse_and_eval(expr)

    #     exp = m[0][1:-1]
    #     if "rip" in exp :
    #         nextins = peda.next_inst(pc)
    #         nextaddr = nextins[0][0]
    #         inssize = nextaddr - pc
    #         exp += "+" + str(inssize)
    #     val = peda.parse_and_eval(exp)
    #     if val is not None:
    #         val = val.split()[0]
    #         chain = peda.examine_mem_reference(to_int(val))
    #         msg("%s : %s" % (purple(m[0],"light"),format_reference_chain(chain)))