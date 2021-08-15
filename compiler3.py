
import argparse
from chainfinder import ChainFinder

import angr
from eir.driver import Driver
from gadgetrepository import GadgetRepository

import logging

import os.path

if __name__ == '__main__':

    logging.getLogger('angr').setLevel(logging.ERROR)
    logging.getLogger('c-to-rop').setLevel(logging.INFO)


    gadget_repo = GadgetRepository()

    # bin_name = '/lib/x86_64-linux-gnu/libc-2.31.so'
    bin_name = './test/test'
    saved_name = './test.bin'
    # saved_name = 'savedlibc.bin'

    if not os.path.exists(saved_name):
        project = angr.Project(bin_name)
        gadget_repo.load_from_project(project)
        gadget_repo.save_to_file(saved_name)
    else:
        gadget_repo.load_from_file(saved_name)

    finder = ChainFinder(gadget_repo)

    # for reg in finder.gadgets.read_mem_to_register:
    #     for gadget in finder.gadgets.read_mem_to_register[reg]:
    #         print(gadget.build(0xcafebabedeadbeef))
    
    # for dest, src in gadget_repo.mov_register_to_register:

    #     if src != 'rsp':
    #         continue

    #     gadget_list = gadget_repo.mov_register_to_register[(dest, src)]

    #     for gadget in gadget_list:
    #         print(f'Can move {src} to {dest} with: ')
    #         print(gadget.build())


    # for chain in finder.mov_mem_to_mem():
    #     dest = 0xcafebabedeadbeef
    #     src = 0xaaaaaaaeaaaaaaaa
    #     print(f'Can move *{hex(src)} to *{hex(dest)} with:')
    #     built = chain.build(dest, src)
    #     print(built.payload_code())
    #     print()

    # for chain in sorted(finder.mov_imm_to_mem(), key=lambda chain: chain.compute_expected_value()):
    #     dest = 0xcafebabedeadbeef
    #     src = 0xaaaaaaaeaaaaaaaa
    #     print(f'Can move {hex(src)} into *{hex(dest)}')
    #     built = chain.build(dest, src)
    #     print(built.payload_code())
    #     print()

    # for chain in sorted(finder.add_mem_to_mem(), key=lambda chain: chain.compute_expected_value()):
    #     dest = 0xcafebabedeadbeef
    #     src = 0xaaaaaaaeaaaaaaaa
    #     print(f'Can set *{hex(dest)} += *{hex(src)} with:')
    #     built = chain.build(dest, src)
    #     print(built.payload_code())
    #     print()


    # for chain in sorted(finder.mov_deref_mem_ptr_to_mem(), key=lambda chain: chain.compute_expected_value()):
    #     dest = 0xcafebabedeadbeef
    #     src = 0xaaaaaaaeaaaaaaaa
    #     temp = 0x1111111111111111
    #     print(f'Can set *{hex(dest)} = **{hex(src)} when temp = {hex(temp)} with:')
    #     built = chain.build(dest, src)
    #     print(built.payload_code())
    #     print()


    # for chain in sorted(finder.mov_mem_to_deref_mem_ptr(), key=lambda chain: chain.compute_expected_value()):
    #     dest = 0xcafebabedeadbeef
    #     src = 0xaaaaaaaeaaaaaaaa
    #     temp = 0x1111111111111111
    #     print(f'Can set **{hex(dest)} = *{hex(src)} when temp = {hex(temp)} with:')
    #     built = chain.build(dest, src, temp)
    #     print(built.payload_code())
    #     print()

    # for chain in finder.sub_mem_by_mem():
    #     dest = 0xcafebabedeadbeef
    #     src = 0xaaaaaaaeaaaaaaaa
    #     temp = 0x1111111111111111
    #     print(f'Can set *{hex(dest)} -= *{hex(src)} when temp register={hex(temp)} with:')
    #     built = chain.build(dest, src, temp)
    #     print(built.payload_code())
    #     print()


    # for chain in finder.gt_mem_mem():
    #     dest = 0xcafebabedeadbeef
    #     src = 0xaaaaaaaeaaaaaaaa
    #     temp = 0x1111111111111111
    #     print(f'Can set *{hex(dest)} -= *{hex(src)} when temp register={hex(temp)} with:')
    #     built = chain.build(dest, src, temp)
    #     print(built.payload_code())
    #     print()


    # for chain in finder.jump_to_imm():
    #     dest = 0xcafebabedeadbeef
    #     print(f'Can jump to *{hex(dest)} with:')
    #     built = chain.build(dest)
    #     print(built.payload_code())
    #     print()

    for chain in finder.je_to_imm():
        jmp = 0x6969696969696969
        dest = 0xcafebabedeadbeef
        src = 0xaaaaaaaeaaaaaaaa
        temp = 0x1111111111111111
        temp2 = 0x2222222222222222
        print(f'Can jump to {hex(jmp)} if *{hex(dest)} == *{hex(src)} when temp register={hex(temp)}, temp2 = {hex(temp2)} with:')
        built = chain.build(jmp, dest, src, temp, temp2)
        print(built.payload_code())
        print()

    # for chain in finder.getchar_mem():
    #     src = 0xaaaaaaaeaaaaaaaa
    #     print(f'Can putchar at {hex(src)} with:')
    #     built = chain.build(src)
    #     print(built.payload_code())
    #     print()

    # for chain in finder.exit():
    #     print(f'Can exit with:')
    #     built = chain.build()
    #     print(built.payload_code())
    #     print()

    # for dest, src in gadget_repo.mov_register_to_register[64]:
    #     for gadget in gadget_repo.mov_register_to_register[64][(dest, src)]:
    #         print(f'Changed regs: {gadget.changed_registers}')
    #         print(gadget.build())