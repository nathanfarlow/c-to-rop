
import argparse

import angr
from eir.driver import Driver
from target_rop import GadgetRepository, RopTarget

import logging

if __name__ == '__main__':

    logging.getLogger('angr').setLevel(logging.ERROR)
    logging.getLogger('c-to-rop').setLevel(logging.INFO)

    project = angr.Project('./test/test')
    r = GadgetRepository()

    r.load_from_project(project)
    r.save_to_file('test.bin')
    r.load_from_file('test.bin')