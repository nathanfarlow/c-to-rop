from __future__ import annotations

from collections.abc import Callable, Generator

from gadgetfinder import ParameterizedGadget
from gadgetrepository import GadgetRepository

from angrop.rop import ROP
from angrop.rop_chain import RopChain


class ParameterizedChain:
    
    def __init__(self, rop: ROP, build: Callable[..., RopChain], gadgets: list[tuple[ParameterizedGadget, str]] = []) -> None:
        self.rop = rop
        self.build = build
        self.gadgets = gadgets

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


class ChainFinder:

    def __init__(self, gadgets: GadgetRepository) -> None:
        self.gadgets = gadgets

    def find_mov_mem_to_mem(self) -> Generator[ParameterizedChain]:

        def build(chain, dest, src):
            return chain._apply_args({'dest': (dest,), 'src': (src,)})

        for reg_src in self.gadgets.read_mem_to_register:
            for read_mem_to_reg in self.gadgets.read_mem_to_register[reg_src]:

                for reg_dest in self.gadgets.write_register_to_mem:
                    for write_reg_to_mem in self.gadgets.write_register_to_mem[reg_dest]:

                        if reg_src == reg_dest:
                            yield ParameterizedChain(self.gadgets.rop, build, [
                                (read_mem_to_reg, 'src'),
                                (write_reg_to_mem, 'dest')
                            ])
                        else:
                            for mov_reg_reg_op in self.gadgets.mov_register_to_register[(reg_dest, reg_src)]:
                                yield ParameterizedChain(self.gadgets.rop, build, [
                                    (read_mem_to_reg, 'src'),
                                    (mov_reg_reg_op, None),
                                    (write_reg_to_mem, 'dest')
                                ])

