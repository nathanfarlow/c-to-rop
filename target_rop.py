from angr.project import Project
from angrop.rop import ROP
from typing import Dict, List, Tuple

from claripy.ast.bool import Bool

from chainfinder import ChainFinder, ParameterizedGadget
from eir.target import Target, ConditionCode, Immediate, Register

import pickle
import logging

from tqdm import tqdm

class GadgetRepository:
   
    logger = logging.getLogger('c-to-rop')

    mov_register_to_register: Dict[Tuple[str, str], List[ParameterizedGadget]]
    write_register_to_mem: Dict[str, List[ParameterizedGadget]]
    read_mem_to_register: Dict[str, List[ParameterizedGadget]]
    add_register_to_register: Dict[Tuple[str, str], List[ParameterizedGadget]]
    add_register_to_mem: Dict[str, List[ParameterizedGadget]]
    add_mem_to_register: Dict[str, List[ParameterizedGadget]]
    cmp_reg_to_reg: Dict[Tuple[str, str], List[ParameterizedGadget]]
    set_equal: Dict[str, List[ParameterizedGadget]]
    set_less_than: Dict[str, List[ParameterizedGadget]]
    pop_bytes: Dict[int, ParameterizedGadget]
    syscall: List[ParameterizedGadget]

    rop: ROP


    def save_to_file(self, filename: str):
        self.logger.info(f'Saving gadget repository to {filename}...')
        with open(filename, 'wb') as f:
            pickle.dump(self.__dict__, f)


    def load_from_file(self, filename: str):
        self.logger.info(f'Loading gadget repository from {filename}...')
        with open(filename, 'rb') as f:
            self.__dict__.update(pickle.load(f))

    def _all_registers(self, project: Project):
        yield from project.arch.default_symbolic_registers

    def _all_register_pairs(self, project: Project, include_when_same_register: Bool = False):
        for reg1 in self._all_registers(project):
            for reg2 in self._all_registers(project):
                if reg1 == reg2 and not include_when_same_register:
                    continue
                yield (reg1, reg2)

    def _count_gadgets(self, *lists):
        return sum(map(len, lists))

    def load_from_project(self, project: Project):
        self.logger.info('Searching for gadgets...')
        self.rop = project.analyses.ROP()
        self.rop.find_gadgets()

        self.logger.info('Performing initial analysis...')
        finder = ChainFinder(self.rop)
        finder.analyze_gadgets()

        self.logger.info('Searching for mov_register_to_register gadgets...')
        self.mov_register_to_register = {}
        for pair in tqdm(list(self._all_register_pairs(project))):
            self.mov_register_to_register[pair] = finder.mov_register_to_register(*pair)
        self.logger.info(f'Found {self._count_gadgets(*self.mov_register_to_register.values())} gadget(s).')

        self.logger.info('Searching for write_register_to_mem gadgets...')
        self.write_register_to_mem = {}
        for register in tqdm(list(self._all_registers(project))):
            self.write_register_to_mem[register] = finder.write_register_to_mem(register)
        self.logger.info(f'Found {self._count_gadgets(*self.write_register_to_mem.values())} gadget(s).')

        self.logger.info('Searching for read_mem_to_register gadgets...')
        self.read_mem_to_register = {}
        for register in tqdm(list(self._all_registers(project))):
            self.read_mem_to_register[register] = finder.read_mem_to_register(register)
        self.logger.info(f'Found {self._count_gadgets(*self.read_mem_to_register.values())} gadget(s).')

        self.logger.info('Searching for add_register_to_register gadgets...')
        self.add_register_to_register = {}
        for pair in tqdm(list(self._all_register_pairs(project))):
            self.add_register_to_register[pair] = finder.add_register_to_register(*pair)
        self.logger.info(f'Found {self._count_gadgets(*self.add_register_to_register.values())} gadget(s).')

        self.logger.info('Searching for add_register_to_mem gadgets...')
        self.add_register_to_mem = {}
        for register in tqdm(list(self._all_registers(project))):
            self.add_register_to_mem[register] = finder.add_register_to_mem(register)
        self.logger.info(f'Found {self._count_gadgets(*self.add_register_to_mem.values())} gadget(s).')

        self.logger.info('Searching for add_mem_to_register gadgets...')
        self.add_mem_to_register = {}
        for register in tqdm(list(self._all_registers(project))):
            self.add_mem_to_register[register] = finder.add_mem_to_register(register)
        self.logger.info(f'Found {self._count_gadgets(*self.add_mem_to_register.values())} gadget(s).')

        self.logger.info('Searching for cmp_reg_to_reg gadgets...')
        self.cmp_reg_to_reg = {}
        for pair in tqdm(list(self._all_register_pairs(project))):
            self.cmp_reg_to_reg[pair] = finder.cmp_reg_to_reg(*pair)
        self.logger.info(f'Found {self._count_gadgets(*self.cmp_reg_to_reg.values())} gadget(s).')

        self.logger.info('Searching for set_equal gadgets...')
        self.set_equal = {}
        for register in tqdm(list(self._all_registers(project))):
            self.set_equal[register] = finder.set_equal(register)
        self.logger.info(f'Found {self._count_gadgets(*self.set_equal.values())} gadget(s).')

        self.logger.info('Searching for set_less_than gadgets...')
        self.set_less_than = {}
        for register in tqdm(list(self._all_registers(project))):
            self.set_less_than[register] = finder.set_less_than(register)
        self.logger.info(f'Found {self._count_gadgets(*self.set_less_than.values())} gadget(s).')

        self.logger.info('Searching for pop_bytes gadgets...')
        self.pop_bytes = {}
        for words in range(32):
            num_bytes = words * project.arch.bytes
            self.pop_bytes[num_bytes] = finder.pop_bytes(num_bytes)
        self.logger.info(f'Found {self._count_gadgets(*self.pop_bytes.values())} gadget(s).')

        self.logger.info('Searching for syscall gadgets...')
        self.syscall = finder.syscall()
        self.logger.info(f'Found {self._count_gadgets(self.syscall)} gadget(s).')


class RopTarget(Target):
    def put_mov(self, dst: Register, src: Immediate):
        print("movRI")

    def put_mov(self, dst: Register, src: Register):
        print("movRR")

    def put_add(self, dst: Register, src: Immediate):
        print("addRI")

    def put_add(self, dst: Register, src: Register):
        print("addRR")

    def put_sub(self, dst: Register, src: Immediate):
        print("subRI")

    def put_sub(self, dst: Register, src: Register):
        print("subRR")

    def put_load(self, dst: Register, src: Immediate):
        print("loadRI")

    def put_load(self, dst: Register, src: Register):
        print("loadRR")

    def put_store(self, src: Register, dst: Immediate):
        print("storeRI")

    def put_store(self, src: Register, dst: Register):
        print("storeRR")

    def put_putc(self, src: Immediate):
        print("putcI")

    def put_putc(self, src: Register):
        print("putcR")

    def put_getc(self, dst: Register):
        print("getcR")

    def put_exit(self):
        print("exit")

    def put_conditional_jmp(self, jmp: Immediate, dst: Register, src: Immediate, cc: ConditionCode):
        print("cond_jmpIRI")

    def put_conditional_jmp(self, jmp: Immediate, dst: Register, src: Register, cc: ConditionCode):
        print("cond_jmpIRR")

    def put_unconditional_jmp(self, jmp: Immediate):
        print("jmpI")

    def put_cmp(self, dst: Register, src: Immediate, cc: ConditionCode):
        print("cmpRI")

    def put_cmp(self, dst: Register, src: Register, cc: ConditionCode):
        print("cmpRR")
