from angr.project import Project
from angrop.rop import ROP
import multiprocessing

from claripy.ast.bool import Bool

from gadgetfinder import GadgetFinder, ParameterizedGadget

import pickle
import logging

from tqdm import tqdm


class GadgetRepository:
   
    logger = logging.getLogger('c-to-rop')

    gadget_types = [
        ("mov_register_to_register", True),
        ("write_register_to_mem", False),
        ("read_mem_to_register", False),
        ("add_register_to_register", True),
        ("add_register_to_mem", False),
        ("add_mem_to_register", False),
        ("cmp_reg_to_reg", True),
        ("set_equal", False),
        ("set_signed", False),
        ("set_carry", False),
        ("set_less_than", False),
    ]

    mov_register_to_register: dict[tuple[str, str], list[ParameterizedGadget]]
    write_register_to_mem: dict[str, list[ParameterizedGadget]]
    read_mem_to_register: dict[str, list[ParameterizedGadget]]
    add_register_to_register: dict[tuple[str, str], list[ParameterizedGadget]]
    add_register_to_mem: dict[str, list[ParameterizedGadget]]
    add_mem_to_register: dict[str, list[ParameterizedGadget]]
    cmp_reg_to_reg: dict[tuple[str, str], list[ParameterizedGadget]]
    set_equal: dict[str, list[ParameterizedGadget]]
    set_signed: dict[str, list[ParameterizedGadget]]
    set_carry: dict[str, list[ParameterizedGadget]]
    set_less_than: dict[str, list[ParameterizedGadget]]
    pop_bytes: dict[int, list[ParameterizedGadget]]
    syscall: list[ParameterizedGadget]
    xor_register_register: dict[int, dict[tuple[str, str], list[ParameterizedGadget]]]

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
        finder = GadgetFinder(self.rop)
        finder.analyze_gadgets(show_progress=True)

        self.logger.info('Searching for %s gadgets...' % ', '.join(gadget_type for gadget_type, _ in GadgetRepository.gadget_types))
        num_registers = len(project.arch.default_symbolic_registers)
        num_invocations = sum(num_registers**2 if is_pair else num_registers for _, is_pair in GadgetRepository.gadget_types)
        progress = tqdm(total=num_invocations)

        pool = multiprocessing.Pool()
        for gadget_type, is_pair in GadgetRepository.gadget_types:
            setattr(self, gadget_type, {})
            finder_method = getattr(finder, gadget_type)
            for key in self._all_register_pairs(project) if is_pair else self._all_registers(project):
                def callback(gadget, gadget_type=gadget_type, key=key):
                    getattr(self, gadget_type)[key] = gadget
                    progress.update()
                pool.apply_async(finder_method, key if is_pair else (key,), callback=callback)
        pool.close()
        pool.join()

        progress.close()
        for gadget_type, is_pair in GadgetRepository.gadget_types:
            self.logger.info(f'Found {self._count_gadgets(*getattr(self, gadget_type).values())} {gadget_type} gadget(s).')

        self.logger.info('Searching for pop_bytes gadgets...')
        self.pop_bytes = {}
        for words in range(32):
            num_bytes = words * project.arch.bytes
            self.pop_bytes[num_bytes] = finder.pop_bytes(num_bytes)
        self.logger.info(f'Found {self._count_gadgets(*self.pop_bytes.values())} pop_bytes gadget(s).')

        self.logger.info('Searching for syscall gadgets...')
        self.syscall = finder.syscall()
        self.logger.info(f'Found {self._count_gadgets(self.syscall)} syscall gadget(s).')

        self.logger.info('Searching for word and half word xor_register_register gadgets...')
        self.xor_register_register = {}
        for bits in (self.rop.project.arch.bits, self.rop.project.arch.bits // 2):
            self.xor_register_register[bits] = {}
            for pair in tqdm(list(self._all_register_pairs(self.rop.project))):
                self.xor_register_register[bits][pair] = finder.xor_register_register(*pair, bits)
