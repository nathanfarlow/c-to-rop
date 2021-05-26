import angr
from angrop import angrop

from dataclasses import dataclass

import pickle

@dataclass
class Register:
    name: str
    # Can we load register from memory?
    load_from_mem: angrop.rop_chain.RopChain = None
    # Can we load register from immediate value?
    load_from_imm: angrop.rop_chain.RopChain = None
    # Can we write register to memory?
    write: angrop.rop_chain.RopChain = None

registers = {name: Register(name) for name in ('rax', 'rbx', 'rcx', 'rdx', 'rsi',
                                                'rdi', 'rbp', 'rsp', 'r8', 'r9',
                                                'r10', 'r11', 'r12', 'r13', 'r14',
                                                'r15')}

def find_loadable_imm(rop):
    for r in registers:
        try:
            registers[r].load_from_imm = rop.set_regs({r: 0xCAFEBABEDEADBEEF})
        except:
            pass

def find_loadable_mem(rop):
    for r in registers:
        try:
            registers[r].load_from_mem = rop.read_mem_to_register(0xCAFEBABEDEADBEEF, r)
        except Exception as e:
            pass

def find_writeable(rop):
    for r in registers:
        try:
            registers[r].write = rop.write_register_to_mem(0xCAFEBABEDEADBEEF, r)
        except Exception as e:
            pass

p = angr.Project('/bin/ls')
rop = p.analyses.ROP()
rop.find_gadgets()

find_loadable_mem(rop)
find_loadable_imm(rop)
find_writeable(rop)

directly_loadable_mem = [r for r in registers if registers[r].load_from_mem]
directly_loadable_imm = [r for r in registers if registers[r].load_from_imm]
directly_writable = [r for r in registers if registers[r].write]

print(f'Directly loadable from memory: {directly_loadable_mem}')
print(f'Directly loadable from immediate: {directly_loadable_imm}')
print(f'Directly writable to memory: {directly_writable}')
