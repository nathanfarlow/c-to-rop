from itertools import chain
import pickle
from gadgetfinder import GadgetFinder
import angr
from angrop.rop_chain import RopChain

import angrop
from dataclasses import dataclass

import os

import sys

import logging


logging.getLogger('angr').propagate = False
logging.getLogger("angrop.gadget_analyzer").setLevel(level=logging.DEBUG)

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
                                                'r15', 'rsp', 'rip')}


on_docker = os.path.exists('/code')

if on_docker:
    p = angr.Project('/lib/x86_64-linux-gnu/libc-2.31.so')
else:
    p = angr.Project('./test/test')

# p = angr.Project('/lib/x86_64-linux-gnu/libc-2.31.so')
rop = p.analyses.ROP()


filename = 'savedrops.bin'
if os.path.exists(filename) and on_docker:
    rop.load_gadgets(filename)
else:
    rop.find_gadgets()
    if on_docker:
        rop.save_gadgets(filename)

f = GadgetFinder(rop)

def gadget_to_string(g):
    try:
        chain = RopChain(p, None, rebase=rop._rebase, badbytes=rop.badbytes)

        chain.add_gadget(g)
        bytes_per_pop = rop.project.arch.bytes
        chain.add_value(g.addr, needs_rebase=True)
        for _ in range(g.stack_change // bytes_per_pop - 1):
            chain.add_value(rop._chain_builder._get_fill_val(), needs_rebase=False)

        return chain.payload_code()

    except:
        return None

def dump_gadgets(rop, filter=''):
    for g in rop.gadgets:
        as_str = gadget_to_string(g)
        if as_str is not None:
            as_str = as_str.replace('base_addr', 'base')
            if filter in as_str:
                print(as_str)
                sys.stdout.flush()

def test_add_regs():

    for reg1 in registers:
        for reg2 in registers:
            #print(f'Trying to find {reg_dest} = {reg1} + {reg2}...')
            chains = f.add_register_to_register(reg1, reg2)
            if len(chains) > 0:
                print(f'Can set {reg1} = {reg1} + {reg2} with')
                for chain in chains:
                    print(gadget_to_string(chain.gadget))

def test_add_reg_to_mem():
    for reg in registers:
        addr = 0xcafebabedeadbeef
        chains = f.add_register_to_mem(addr, reg)
        if len(chains) > 0:
            print(f'Can set *{hex(addr)} = *{hex(addr)} + {reg} with')
            for chain in chains:
                print(gadget_to_string(chain.gadget))

def test_read_from_mem():

    for chain in f.read_mem_to_register(0xcafebabedeadbeef, 'rax'):
        print(chain)

def test_write_to_mem():
    for chain in f.write_register_to_mem(0xcafebabedeadbeef, 'rax'):
        print(chain)

def test_add_mem_to_reg():
    for reg in registers:
        addr = 0xcafebabedeadbeef
        chains = f.add_mem_to_register(reg, addr)
        if len(chains) > 0:
            print(f'Can set {reg} = {reg} + *{hex(addr)} + with')
            for chain in chains:
                print(gadget_to_string(chain.gadget))

def test_cmp_reg_to_reg():
    for reg1 in registers:
        for reg2 in registers:
            print(f'Looking for cmp {reg1}, {reg2}')
            chains = f.cmp_reg_to_reg(reg1, reg2)
            if len(chains) > 0:
                print(f'Found cmp {reg1}, {reg2} with')
                for chain in chains: 
                    print(chain)
            sys.stdout.flush()

def test_pop():
    for i in range(16):
        chains = f.pop_bytes(i * 8)
        print(f'Found {len(chains)} gadgets that pop {i*8} bytes')

        if len(chains) > 0:
            print(gadget_to_string(chains[0].gadget))

def test_sete():
    for reg in registers:


        print(f'Looking for {reg}')
        sys.stdout.flush()

        chains = f.set_carry(reg)

        if len(chains) > 0:
            print(f'sete {reg} with')
            for chain in chains:
                print(chain.build())
        else:
            print(f"Couldn't find sete for {reg}")

        sys.stdout.flush()

def test_setl():
    for reg in registers:

        chains = f.set_less_than(reg)

        if len(chains) > 0:
            print(f'setl {reg} with')
            for chain in chains:
               print(chain.build())
               sys.stdout.flush()

def test_syscall():
    
    chains = f.syscall()
    
    for chain in chains:
        print(gadget_to_string(chain.gadget))

def test_mov_reg_reg():
    for reg1 in registers:
        for reg2 in registers:
            print(f'Looking for {reg1} = {reg2}')
            chains = f.mov_register_to_register(reg1, reg2)
            if len(chains) > 0:
                print(f'Found {reg1} = {reg2} with')
                for chain in chains: 
                    print(chain.build())
            sys.stdout.flush()

def test_xor_reg_reg():
    for reg1 in registers:
        for reg2 in registers:
            for bits in (32, 64):

                print(f'Looking for {reg1}[{bits-1}:0] ^= {reg2}[{bits-1}:0]')
                chains = f.xor_register_register(reg1, reg2, bits)
                if len(chains) > 0:
                    print(f'Found {reg1}[{bits-1}:0] ^= {reg2}[{bits-1}:0] with')
                    for chain in chains: 
                        print(chain.build())
                sys.stdout.flush()

def test_set_reg_val():
    for reg in registers:
        value = 0xcafebabedeadbeef
        chains = f.set_register_value(reg, value)
        if len(chains) > 0:
            print(f'Can set {reg} = {hex(value)} with')
            for chain in chains:
                print(chain.build(value))

def test_deref():

    dest, src = 'rax', 'rbx'

    gadgets = f.read_mem_ptr_to_register(dest, src)

    if len(gadgets) > 0:
        print(f'Found gadget for {dest} = *{src}')
        for gadget in gadgets:
            print(gadget.build())

def test_ptr():
    for dest in registers:
        for src in registers:
            gadgets = f.write_register_to_mem_ptr(dest, src)

            if len(gadgets) > 0:
                print(f'Found gadget for *{dest} = {src}')
                for gadget in gadgets:
                    print(gadget.build())

# for pivot in rop.stack_pivots:
#     print(pivot)
#     chain = RopChain(p, None, rebase=rop._rebase, badbytes=rop.badbytes)
#     chain.add_value(pivot.addr, needs_rebase=True)
#     print(chain)

f.analyze_gadgets(True)

for gadget in f.mov_register_to_rsp('rax'):
    print(gadget.build())
# test_ptr()
# test_mov_reg_reg()
# test_set_reg_val()
# dump_gadgets(rop)
# test_sete()
# test_xor_reg_reg()
# test_setl()
# test_syscall()
# test_pop()

# test_cmp_reg_to_reg()
# dump_gadgets(rop, filter='cmp')
# test_add_reg_to_mem()
# test_add_mem_to_reg()
# test_add_regs()
# test_add_reg_to_mem()
# rop.add_to_mem(0x8048f124, 0x41414141)
# test_read_from_mem()