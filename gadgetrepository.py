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
        ("write_register_to_mem", False, False),
        ("read_mem_to_register", False, False),
        ("add_register_to_register", True, False),
        ("add_register_to_mem", False, False),
        ("add_mem_to_register", False, False),
        ("cmp_reg_to_reg", True, False),
        ("set_register_value", False, False),
        ("set_equal", False, False),
        ("set_signed", False, False),
        ("set_carry", False, False),
        ("set_less_than", False, False),

        ("mov_register_to_register", True, True),
        ("xor_register_register", True, True)
    ]

    write_register_to_mem: dict[str, list[ParameterizedGadget]]
    read_mem_to_register: dict[str, list[ParameterizedGadget]]
    add_register_to_register: dict[tuple[str, str], list[ParameterizedGadget]]
    add_register_to_mem: dict[str, list[ParameterizedGadget]]
    add_mem_to_register: dict[str, list[ParameterizedGadget]]
    cmp_reg_to_reg: dict[tuple[str, str], list[ParameterizedGadget]]
    set_register_value: dict[str, list[ParameterizedGadget]]
    set_equal: dict[str, list[ParameterizedGadget]]
    set_signed: dict[str, list[ParameterizedGadget]]
    set_carry: dict[str, list[ParameterizedGadget]]
    set_less_than: dict[str, list[ParameterizedGadget]]
    pop_bytes: dict[int, list[ParameterizedGadget]]
    syscall: list[ParameterizedGadget]
    mov_register_to_register: dict[int, dict[tuple[str, str]], list[ParameterizedGadget]]
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

        self.logger.info('Searching for %s gadgets...' % ', '.join(gadget_type for gadget_type, _, _ in GadgetRepository.gadget_types))
        num_registers = len(project.arch.default_symbolic_registers)
        num_invocations = sum((1 + supports_half_word) * (num_registers**2-num_registers if is_pair else num_registers) for _, is_pair, supports_half_word in GadgetRepository.gadget_types)
        progress = tqdm(total=num_invocations)

        pool = multiprocessing.Pool()
        for gadget_type, is_pair, supports_half_word in GadgetRepository.gadget_types:
            setattr(self, gadget_type, {})
            finder_method = getattr(finder, gadget_type)
            for bits in ([self.rop.project.arch.bits, self.rop.project.arch.bits // 2] if supports_half_word else [self.rop.project.arch.bits]):

                if supports_half_word:
                    getattr(self, gadget_type)[bits] = {}

                for key in self._all_register_pairs(project) if is_pair else self._all_registers(project):

                    def callback(gadget, gadget_type=gadget_type, supports_half_word=supports_half_word, key=key, bits=bits):
                        if supports_half_word:
                            getattr(self, gadget_type)[bits][key] = gadget
                        else:
                            getattr(self, gadget_type)[key] = gadget
                        progress.update()
                    
                    args = key if is_pair else (key,)
                    if supports_half_word:
                        args = (*args, bits)
                    
                    pool.apply_async(finder_method, args, callback=callback)
        pool.close()
        pool.join()

        progress.close()
        
        for gadget_type, is_pair, supports_half_word in GadgetRepository.gadget_types:
            if supports_half_word:
                total = 0
                for gadgets in getattr(self, gadget_type).values():
                    total += self._count_gadgets(*gadgets.values())
            else:
                total = self._count_gadgets(*getattr(self, gadget_type).values())

            self.logger.info(f'Found {total} {gadget_type} gadget(s).')

        self.logger.info('Searching for pop_bytes gadgets...')
        self.pop_bytes = {}
        for words in range(32):
            num_bytes = words * project.arch.bytes
            self.pop_bytes[num_bytes] = finder.pop_bytes(num_bytes)
        self.logger.info(f'Found {self._count_gadgets(*self.pop_bytes.values())} pop_bytes gadget(s).')

        self.logger.info('Searching for syscall gadgets...')
        self.syscall = finder.syscall()
        self.logger.info(f'Found {self._count_gadgets(self.syscall)} syscall gadget(s).')
