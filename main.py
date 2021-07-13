
import argparse

import angr
from eir.driver import Driver
from gadgetrepository import GadgetRepository

import logging

if __name__ == '__main__':

    logging.getLogger('angr').setLevel(logging.ERROR)
    logging.getLogger('c-to-rop').setLevel(logging.INFO)

    project = angr.Project('test/test')
    r = GadgetRepository()

    r.load_from_project(project)
    r.save_to_file('test.bin')
    r.load_from_file('test.bin')
    for i in ["mov_register_to_register", "write_register_to_mem", "read_mem_to_register", "add_register_to_register", "add_register_to_mem", "add_mem_to_register", "cmp_reg_to_reg", "set_equal", "set_less_than", "pop_bytes"]:
        print(i, r._count_gadgets(*getattr(r, i).values()))
    print("syscall", r._count_gadgets(r.syscall))
