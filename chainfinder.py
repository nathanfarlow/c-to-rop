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

    def _preserve_registers(self, gadgets: list[ParameterizedGadget], *registers):
        return filter(lambda gadget: not gadget.changed_registers & set(registers), gadgets)

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
  
    def mov_mem_to_mem(self) -> Generator[ParameterizedChain]:

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

    def mov_imm_to_mem(self) -> Generator[ParameterizedChain]:

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

    def add_mem_to_mem(self) -> Generator[ParameterizedChain]:

        def build(chain, dest, src):
            return chain._apply_args({'dest': (dest,), 'src': (src,)})

        # Add reg, reg strategy

        # mov rega, [src]
        # mov regb, [dest]
        # mov regc, rega
        # mov regd, regb
        # add regc, regd
        # mov rege, regc
        # mov [dest], rege

        # mov rega, [src]
        for rega in self.gadgets.read_mem_to_register:
            for read_mem_to_rega in self.gadgets.read_mem_to_register[rega]:
                
                # mov regb, [dest]
                for regb in self.gadgets.read_mem_to_register:
                    for read_mem_to_regb in self._preserve_registers(self.gadgets.read_mem_to_register[regb], rega):

                        # add regc, regd
                        for regc, regd in self.gadgets.add_register_to_register:
                            for add_regc_regd in self.gadgets.add_register_to_register[(regc, regd)]:

                                # mov regc, rega
                                for mov_regc_rega in self._mov_reg_to_reg(regc, rega, self.gadgets.rop.project.arch.bits, {regb}):

                                    # mov regd, regb
                                    for mov_regb_regd in self._mov_reg_to_reg(regd, regb, self.gadgets.rop.project.arch.bits, {regc}):

                                        # mov [dest], rege
                                        for rege in self.gadgets.write_register_to_mem:
                                            for write_rege_to_mem in self.gadgets.write_register_to_mem[rege]:

                                                # mov rege, regc
                                                for mov_rege_regc in self._mov_reg_to_reg(rege, regc, self.gadgets.rop.project.arch.bits):

                                                    result = ParameterizedChain(self.gadgets.rop, builder=build)
                                                    result.add_gadget((read_mem_to_rega, 'src'))
                                                    result.add_gadget((read_mem_to_regb, 'dest'))
                                                    result.add_all(mov_regc_rega.gadgets)
                                                    result.add_all(mov_regb_regd.gadgets)
                                                    result.add_gadget((add_regc_regd, None))
                                                    result.add_all(mov_rege_regc.gadgets)
                                                    result.add_gadget((write_rege_to_mem, 'dest'))
                                                    yield result


        # Add reg, mem strategy

        # mov rega, [src]
        # mov regx, rega
        # Add regx, [dest]
        # mov regb, regx
        # mov [dest], regb

        
        # mov rega, [src]
        for rega in self.gadgets.read_mem_to_register:
            for mov_rega_src in self.gadgets.read_mem_to_register[rega]:

                # mov regx, rega
                for regb in self.gadgets.add_mem_to_register:
                    for mov_regb_rega in self._mov_reg_to_reg(regb, rega, self.gadgets.rop.project.arch.bits):

                        # add regx, [dest]
                        for add_regx_dest in self.gadgets.add_mem_to_register[regb]:

                            # mov [dest], regb
                            for regb in self.gadgets.write_register_to_mem:
                                for mov_dest_regb in self.gadgets.write_register_to_mem[regb]:

                                    # mov regb, regx
                                    for mov_regb_regx in self._mov_reg_to_reg(regb, regb, self.gadgets.rop.project.arch.bits):

                                        result = ParameterizedChain(self.gadgets.rop, builder=build)
                                        result.add_gadget((mov_rega_src, 'src'))
                                        result.add_all(mov_regb_rega.gadgets)
                                        result.add_gadget((add_regx_dest, 'dest'))
                                        result.add_all(mov_regb_regx.gadgets)
                                        result.add_gadget((mov_dest_regb, 'dest'))
                                        yield result


        # Add mem, reg strategy

        # mov rega, [src]
        # mov regb, rega
        # add [dest], regb

        # mov rega, [src]
        for rega in self.gadgets.read_mem_to_register:
            for mov_rega_src in self.gadgets.read_mem_to_register[rega]:
                
                # mov regb, rega
                for regb in self.gadgets.add_register_to_mem:
                    for mov_regb_rega in self._mov_reg_to_reg(regb, rega, self.gadgets.rop.project.arch.bits):

                        # add [dest], regb
                        for add_dest_regb in self.gadgets.add_register_to_mem[regb]:

                            result = ParameterizedChain(self.gadgets.rop, builder=build)
                            result.add_gadget((mov_rega_src, 'src'))
                            result.add_all(mov_regb_rega.gadgets)
                            result.add_gadget((add_dest_regb, 'dest'))
                            yield result

    def mov_deref_mem_ptr_to_mem(self) -> Generator[ParameterizedChain]:
        '''*dest = **src'''

        def build(chain, dest, src):
            return chain._apply_args({'dest': (dest,), 'src': (src,)})

        # mov rega, [src]
        # mov regb, rega
        # mov regc, [regb]
        # mov regd, regc
        # mov [dest], regd

        # mov rega, [src]
        for rega in self.gadgets.read_mem_to_register:
            for mov_rega_src in self.gadgets.read_mem_to_register[rega]:

                # mov regb, rega
                for regc, regb in self.gadgets.read_mem_ptr_to_register:
                    for mov_regb_rega in self._mov_reg_to_reg(regb, rega, self.gadgets.rop.project.arch.bits):

                        # mov regc, [regb]
                        for mov_regc_regb in self.gadgets.read_mem_ptr_to_register[(regc, regb)]:

                            # mov regd, regc
                            for regd in self.gadgets.write_register_to_mem:
                                for mov_regd_regc in self._mov_reg_to_reg(regd, regc, self.gadgets.rop.project.arch.bits):

                                    # mov [dest], regd
                                    for mov_dest_regd in self.gadgets.write_register_to_mem[regd]:

                                        result = ParameterizedChain(self.gadgets.rop, builder=build)
                                        result.add_gadget((mov_rega_src, 'src'))
                                        result.add_all(mov_regb_rega.gadgets)
                                        result.add_gadget((mov_regc_regb, None))
                                        result.add_all(mov_regd_regc.gadgets)
                                        result.add_gadget((mov_dest_regd, 'dest'))
                                        yield result

    def mov_mem_to_deref_mem_ptr(self) -> Generator[ParameterizedChain]:
        '''**dest = *src'''

        def build(chain, dest, src):
            return chain._apply_args({'dest': (dest,), 'src': (src,)})

        # mov rega, [dest]
        # mov regb, rega
        # mov regc, [regb]
        # mov regd, [src]
        # mov rege, regd
        # mov regf, regc
        # mov [regf], rege

        # mov rega, [dest]
        for rega in self.gadgets.read_mem_to_register:
            for mov_rega_dest in self.gadgets.read_mem_to_register[rega]:
                
                # mov regb, rega
                for regc, regb in self.gadgets.read_mem_ptr_to_register:
                    for mov_regb_rega in self._mov_reg_to_reg(regb, rega, self.gadgets.rop.project.arch.bits):
                        
                        # mov regc, [regb]
                        for mov_regc_regb in self.gadgets.read_mem_ptr_to_register[(regc, regb)]:

                            # mov regd, [src]
                            for regd in self.gadgets.read_mem_to_register:
                                for mov_regd_src in self._preserve_registers(self.gadgets.read_mem_to_register[regd], regc):

                                    # mov rege, regd
                                    for regf, rege in self.gadgets.write_register_to_mem_ptr:
                                        for mov_rege_regd in self._mov_reg_to_reg(rege, regd, self.gadgets.rop.project.arch.bits, {regc}):
                                            
                                            # mov regf, regc
                                            for mov_regf_regc in self._mov_reg_to_reg(regf, regc, self.gadgets.rop.project.arch.bits, {rege}):

                                                # mov [regf], rege
                                                for mov_regf_rege in self.gadgets.write_register_to_mem_ptr[(regf, rege)]:

                                                    result = ParameterizedChain(self.gadgets.rop, builder=build)
                                                    result.add_gadget((mov_rega_dest, 'dest'))
                                                    result.add_all(mov_regb_rega.gadgets)
                                                    result.add_gadget((mov_regc_regb, None))
                                                    result.add_gadget((mov_regd_src, 'src'))
                                                    result.add_all(mov_rege_regd.gadgets)
                                                    result.add_all(mov_regf_regc.gadgets)
                                                    result.add_gadget((mov_regf_rege, None))
                                                    yield result