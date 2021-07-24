from __future__ import annotations

from collections.abc import Callable, Generator

from gadgetfinder import ParameterizedGadget
from gadgetrepository import GadgetRepository

from angrop.rop import ROP
from angrop.rop_chain import RopChain


class ParameterizedChain:
    
    def __init__(self, rop: ROP, gadgets: list[tuple[ParameterizedGadget, str]] = None,
                    builder: Callable[..., RopChain] = None) -> None:
        self.rop = rop
        self.gadgets = gadgets or []
        self.builder = builder

    def _apply_args(self, chain_args: dict[str, tuple]):

        chain = RopChain(self.rop.project, self.rop)

        for parameterized, args_name in self.gadgets:
            gadget_args = chain_args.get(args_name, ())
            built = parameterized.build(*gadget_args)
            chain += built

        return chain

    def add_gadget(self, gadget: tuple[ParameterizedGadget, str]):
        self.gadgets.append(gadget)
    
    def add_all(self, gadgets: list[tuple[ParameterizedGadget, str]]):
        self.gadgets += gadgets

    def compute_expected_value(self) -> int:
        '''Compute the expected size this chain will occupy on the stack'''
        return sum(map(lambda pair: pair[0].expected_payload_len, self.gadgets))

    def build(self, *args):
        if not self.builder:
            return self._apply_args({})
        return self.builder(self, *args)


class ChainFinder:

    def __init__(self, gadgets: GadgetRepository) -> None:
        self.gadgets = gadgets

    def _mov_reg_to_reg(self, dest: str, src: str, bits, avoid=set()) -> Generator[ParameterizedChain]:

        if dest in avoid:
            return

        if dest == src:
            yield ParameterizedChain(self.gadgets.rop)
            return

        registers_that_write_to_dest = filter(lambda to_from: to_from[0] == dest and len(self.gadgets.mov_register_to_register[bits][to_from]) > 0,
                                                self.gadgets.mov_register_to_register[bits])

        for _, reg in registers_that_write_to_dest:
            for init_chain in self._mov_reg_to_reg(reg, src, bits, avoid | {dest}):
                for mov_to_dest_gadget in self.gadgets.mov_register_to_register[bits][(dest, reg)]:
                    full_chain = ParameterizedChain(self.gadgets.rop)
                    full_chain.add_all(init_chain.gadgets)
                    full_chain.add_gadget((mov_to_dest_gadget, None))
                    yield full_chain

    def find_mov_mem_to_mem(self) -> Generator[ParameterizedChain]:

        def build(chain, dest, src):
            return chain._apply_args({'dest': (dest,), 'src': (src,)})

        for reg_src in self.gadgets.read_mem_to_register:
            for read_mem_to_reg in self.gadgets.read_mem_to_register[reg_src]:

                for reg_dest in self.gadgets.write_register_to_mem:
                    for write_reg_to_mem in self.gadgets.write_register_to_mem[reg_dest]:

                        for mov_reg_to_reg in self._mov_reg_to_reg(reg_dest, reg_src, self.gadgets.rop.project.arch.bits):
                            result = ParameterizedChain(self.gadgets.rop, builder=build)
                            result.add_gadget((read_mem_to_reg, 'src'))
                            result.add_all(mov_reg_to_reg.gadgets)
                            result.add_gadget((write_reg_to_mem, 'dest'))
                            yield result

    def find_mov_imm_to_mem(self) -> Generator[ParameterizedChain]:

        def build(chain, dest, src):
            return chain._apply_args({'dest': (dest,), 'src': (src,)})

        for reg_src in self.gadgets.set_register_value:
            for set_register_value in self.gadgets.set_register_value[reg_src]:
                for reg_dest in self.gadgets.write_register_to_mem:
                    for write_reg_to_mem in self.gadgets.write_register_to_mem[reg_dest]:

                        for mov_reg_to_reg in self._mov_reg_to_reg(reg_dest, reg_src, self.gadgets.rop.project.arch.bits):
                            result = ParameterizedChain(self.gadgets.rop, builder=build)
                            result.add_gadget((set_register_value, 'src'))
                            result.add_all(mov_reg_to_reg.gadgets)
                            result.add_gadget((write_reg_to_mem, 'dest'))
                            yield result
