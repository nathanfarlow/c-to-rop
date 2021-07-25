from __future__ import annotations

from collections.abc import Callable, Generator

from angrop.rop_utils import gadget_to_asmstring

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
  
    def mov_mem_to_mem(self, prefix) -> Generator[ParameterizedChain]:

        def build(chain, dest, src, prefix=prefix):
            return chain._apply_args({prefix + 'dest': (dest,), prefix + 'src': (src,)})

        for reg_src in self.gadgets.read_mem_to_register:
            for read_mem_to_reg in self.gadgets.read_mem_to_register[reg_src]:

                for reg_dest in self.gadgets.write_register_to_mem:
                    for write_reg_to_mem in self.gadgets.write_register_to_mem[reg_dest]:

                        for mov_reg_to_reg in self._mov_reg_to_reg(reg_dest, reg_src, self.gadgets.rop.project.arch.bits):
                            result = ParameterizedChain(self.gadgets.rop, builder=build)
                            result.add_gadget((read_mem_to_reg, prefix + 'src'))
                            result.add_all(mov_reg_to_reg.gadgets)
                            result.add_gadget((write_reg_to_mem, prefix + 'dest'))
                            yield result

    def mov_imm_to_mem(self, prefix='') -> Generator[ParameterizedChain]:

        def build(chain, dest, src, prefix=prefix):
            return chain._apply_args({prefix + 'dest': (dest,), prefix + 'src': (src,)})

        for reg_src in self.gadgets.set_register_value:
            for set_register_value in self.gadgets.set_register_value[reg_src]:

                for reg_dest in self.gadgets.write_register_to_mem:
                    for write_reg_to_mem in self.gadgets.write_register_to_mem[reg_dest]:

                        for mov_reg_to_reg in self._mov_reg_to_reg(reg_dest, reg_src, self.gadgets.rop.project.arch.bits):
                            result = ParameterizedChain(self.gadgets.rop, builder=build)
                            result.add_gadget((set_register_value, prefix + 'src'))
                            result.add_all(mov_reg_to_reg.gadgets)
                            result.add_gadget((write_reg_to_mem, prefix + 'dest'))
                            yield result

    def add_mem_to_mem(self, prefix='') -> Generator[ParameterizedChain]:

        def build(chain, dest, src, prefx=prefix):
            return chain._apply_args({prefix + 'dest': (dest,), prefix + 'src': (src,)})

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
                                                    result.add_gadget((read_mem_to_rega, prefix + 'src'))
                                                    result.add_gadget((read_mem_to_regb, prefix + 'dest'))
                                                    result.add_all(mov_regc_rega.gadgets)
                                                    result.add_all(mov_regb_regd.gadgets)
                                                    result.add_gadget((add_regc_regd, None))
                                                    result.add_all(mov_rege_regc.gadgets)
                                                    result.add_gadget((write_rege_to_mem, prefix + 'dest'))
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
                                        result.add_gadget((mov_rega_src, prefix + 'src'))
                                        result.add_all(mov_regb_rega.gadgets)
                                        result.add_gadget((add_regx_dest, prefix + 'dest'))
                                        result.add_all(mov_regb_regx.gadgets)
                                        result.add_gadget((mov_dest_regb, prefix + 'dest'))
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

    def mov_deref_mem_ptr_to_mem(self, prefix='') -> Generator[ParameterizedChain]:
        '''*dest = **src'''

        def build(chain, dest, src, prefix=prefix):
            return chain._apply_args({prefix + 'dest': (dest,), prefix + 'src': (src,)})

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
                                        result.add_gadget((mov_rega_src, prefix + 'src'))
                                        result.add_all(mov_regb_rega.gadgets)
                                        result.add_gadget((mov_regc_regb, None))
                                        result.add_all(mov_regd_regc.gadgets)
                                        result.add_gadget((mov_dest_regd, prefix + 'dest'))
                                        yield result

    def mov_mem_to_deref_mem_ptr(self, prefix='') -> Generator[ParameterizedChain]:
        '''**dest = *src'''

        def build(chain, dest, src, prefix=prefix):
            return chain._apply_args({prefix + 'dest': (dest,), prefix + 'src': (src,)})

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
                                                    result.add_gadget((mov_rega_dest, prefix + 'dest'))
                                                    result.add_all(mov_regb_rega.gadgets)
                                                    result.add_gadget((mov_regc_regb, None))
                                                    result.add_gadget((mov_regd_src, prefix + 'src'))
                                                    result.add_all(mov_rege_regd.gadgets)
                                                    result.add_all(mov_regf_regc.gadgets)
                                                    result.add_gadget((mov_regf_rege, None))
                                                    yield result

    def _sub_xor_step(self, prefix='') -> Generator[ParameterizedChain]:

        def build(chain, dest, prefix=prefix):
            return chain._apply_args({prefix + 'dest': (dest,), prefix + 'ffff': (-1,)})

        # mov rega, [dest]
        # mov regc, 0xffffffffffffffff
        # mov regb, rega
        # mov regd, regc
        # xor regb, regd
        # mov rege, regb
        # mov [dest], rege

        # mov rega, [temp1_high]
        for rega in self.gadgets.read_mem_to_register:
            for mov_rega_temp in self.gadgets.read_mem_to_register[rega]:

                # mov regc, 0xffffffffffffffff
                for regc in self.gadgets.set_register_value:
                    for mov_regc_ffff in self._preserve_registers(self.gadgets.set_register_value[regc], rega):

                        # mov regb, rega
                        for regb, regd in self.gadgets.xor_register_register[self.gadgets.rop.project.arch.bits // 2]:
                            for mov_regb_rega in self._mov_reg_to_reg(regb, rega, self.gadgets.rop.project.arch.bits, {regc}):

                                # mov regd, regc
                                for mov_regd_regc in self._mov_reg_to_reg(regd, regc, self.gadgets.rop.project.arch.bits, {regb}):

                                    # xor regb, regd
                                    for xor_regb_regd in self.gadgets.xor_register_register[self.gadgets.rop.project.arch.bits // 2][(regb, regd)]:

                                        # mov rege, regb
                                        for rege in self.gadgets.write_register_to_mem:
                                            for mov_rege_regb in self._mov_reg_to_reg(rege, regb, self.gadgets.rop.project.arch.bits):

                                                # mov [temp1_high], rege
                                                for mov_temp_rege in self.gadgets.write_register_to_mem[rege]:

                                                    result = ParameterizedChain(self.gadgets.rop, builder=build)
                                                    result.add_gadget((mov_rega_temp, prefix + 'dest'))
                                                    result.add_gadget((mov_regc_ffff, prefix + 'ffff'))
                                                    result.add_all(mov_regb_rega.gadgets)
                                                    result.add_all(mov_regd_regc.gadgets)
                                                    result.add_gadget((xor_regb_regd, None))
                                                    result.add_all(mov_rege_regb.gadgets)
                                                    result.add_gadget((mov_temp_rege, prefix + 'dest'))
                                                    yield result

    def sub_mem_by_mem(self, prefix='') -> Generator[ParameterizedChain]:
        
        def build(chain, dest, src, temp, prefix=prefix):
            return chain._apply_args({
                prefix + 'mov1_dest': (temp,),
                prefix + 'mov1_src': (src,),

                prefix + 'xor1_ffff': (-1,),
                prefix + 'xor1_dest': (temp,),

                prefix + 'mov2_dest': (temp - self.gadgets.rop.project.arch.bytes // 2,),
                prefix + 'mov2_src': (src - self.gadgets.rop.project.arch.bytes // 2,),

                prefix + 'xor2_ffff': (-1,),
                prefix + 'xor2_dest': (temp - self.gadgets.rop.project.arch.bytes // 2,),

                prefix + 'add_dest': (dest,),
                prefix + 'add_src': (temp,),

                prefix + 'mov3_dest': (temp,),
                prefix + 'mov3_src': (1,),
            })

        # mov [temp], [src]
        # _sub_xor_step [temp_low]

        # mov [temp - 4], [src - 4]
        # _sub_xor_step [temp_high]

        # add [dest], [temp]

        # mov [temp], 1        
        # add [dest], [temp]

        for mov_temp_src in self.mov_mem_to_mem(prefix + 'mov1_'):
            for sub_xor_step_low in self._sub_xor_step(prefix + 'xor1_'):
                for mov_temp_src_offset in self.mov_mem_to_mem(prefix + 'mov2_'):
                    for sub_xor_step_high in self._sub_xor_step(prefix + 'xor2_'):
                        for add_dest_temp in self.add_mem_to_mem(prefix + 'add_'):
                            for mov_temp_1 in self.mov_imm_to_mem(prefix + 'mov3_'):
                                for add_dest_temp2 in self.add_mem_to_mem(prefix + 'add_'):
                                    result = ParameterizedChain(self.gadgets.rop, builder=build)
                                    result.add_all(mov_temp_src.gadgets)
                                    result.add_all(sub_xor_step_low.gadgets)
                                    result.add_all(mov_temp_src_offset.gadgets)
                                    result.add_all(sub_xor_step_high.gadgets)
                                    result.add_all(add_dest_temp.gadgets)
                                    result.add_all(mov_temp_1.gadgets)
                                    result.add_all(add_dest_temp2.gadgets)
                                    yield result