
import argparse
import os
from chainfinder import ChainFinder

import angr
from eir.driver import Driver
from target_rop import RopTarget
from gadgetrepository import GadgetRepository

import logging

import sys


if __name__ == '__main__':

    logging.getLogger('angr').setLevel(logging.ERROR)
    logging.getLogger('c-to-rop').setLevel(logging.INFO)

    _, bin_name, saved_name, elvm_ir, data_base, rop_base, output_file = sys.argv

    data_base = int(data_base, 16)
    rop_base = int(rop_base, 16)

    gadget_repo = GadgetRepository()

    # bin_name = '/lib/x86_64-linux-gnu/libc-2.31.so'
    # saved_name = 'savedlibc.bin'

    if not os.path.exists(saved_name):
        project = angr.Project(bin_name)
        gadget_repo.load_from_project(project)
        gadget_repo.save_to_file(saved_name)
    else:
        gadget_repo.load_from_file(saved_name)

    finder = ChainFinder(gadget_repo)

    target = RopTarget(finder, data_base, rop_base)
    driver = Driver(elvm_ir, target)
    target.fill_jump_targets(driver.data_setup_inst_count)

    with open(output_file, 'w') as f:
        payload = target.build()
        f.write(payload)