from __future__ import annotations

from collections.abc import Callable, Generator

from angrop.rop_utils import gadget_to_asmstring, get_ast_controllers

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

        all_built = []

        for parameterized, args_name in self.gadgets:
            gadget_args = chain_args.get(args_name, ())
            # print(f'building with {args_name=}, have {gadget_args=}')
            built = parameterized.build(*gadget_args)
            # print(f'shit returned {built}')
            all_built.append((built.payload_len, str(built)))

        return all_built

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
  
    def mov_mem_to_mem(self, prefix='') -> Generator[ParameterizedChain]:

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
        # for rega in self.gadgets.read_mem_to_register:
        #     for mov_rega_src in self.gadgets.read_mem_to_register[rega]:

        #         # mov regx, rega
        #         for regb in self.gadgets.add_mem_to_register:
        #             for mov_regb_rega in self._mov_reg_to_reg(regb, rega, self.gadgets.rop.project.arch.bits):

        #                 # add regx, [dest]
        #                 for add_regx_dest in self.gadgets.add_mem_to_register[regb]:

        #                     # mov [dest], regb
        #                     for regb in self.gadgets.write_register_to_mem:
        #                         for mov_dest_regb in self.gadgets.write_register_to_mem[regb]:

        #                             # mov regb, regx
        #                             for mov_regb_regx in self._mov_reg_to_reg(regb, regb, self.gadgets.rop.project.arch.bits):

        #                                 result = ParameterizedChain(self.gadgets.rop, builder=build)
        #                                 result.add_gadget((mov_rega_src, prefix + 'src'))
        #                                 result.add_all(mov_regb_rega.gadgets)
        #                                 result.add_gadget((add_regx_dest, prefix + 'dest'))
        #                                 result.add_all(mov_regb_regx.gadgets)
        #                                 result.add_gadget((mov_dest_regb, prefix + 'dest'))
        #                                 yield result


        # # Add mem, reg strategy

        # # mov rega, [src]
        # # mov regb, rega
        # # add [dest], regb

        # # mov rega, [src]
        # for rega in self.gadgets.read_mem_to_register:
        #     for mov_rega_src in self.gadgets.read_mem_to_register[rega]:
                
        #         # mov regb, rega
        #         for regb in self.gadgets.add_register_to_mem:
        #             for mov_regb_rega in self._mov_reg_to_reg(regb, rega, self.gadgets.rop.project.arch.bits):

        #                 # add [dest], regb
        #                 for add_dest_regb in self.gadgets.add_register_to_mem[regb]:

        #                     result = ParameterizedChain(self.gadgets.rop, builder=build)
        #                     result.add_gadget((mov_rega_src, 'src'))
        #                     result.add_all(mov_regb_rega.gadgets)
        #                     result.add_gadget((add_dest_regb, 'dest'))
        #                     yield result

    def mov_deref_mem_ptr_to_mem(self, prefix='') -> Generator[ParameterizedChain]:
        '''*dest = **src'''

        def build(chain, dest, src, temp, base_addr, prefix=prefix):
            return chain._apply_args({
                prefix + 'dest': (dest,),
                prefix + 'src': (src,),
                
                prefix + 'mov1_dest': (dest,),
                prefix + 'mov1_src': (src,),

                prefix + 'add1_dest': (dest,),
                prefix + 'add1_src': (dest,),
                prefix + 'add1_zero': (0,),

                prefix + 'mov2_dest': (temp,),
                prefix + 'mov2_src': (base_addr,),

                prefix + 'add2_dest': (dest,),
                prefix + 'add2_src': (temp,),
                prefix + 'add2_zero': (0,),
            })

        # mov [dest], [src]
        # add [dest], [dest]
        # add [dest], [dest]
        # add [dest], [dest]
        # mov [temp], base_addr
        # add [dest], [temp]

        # mov rega, [dest]
        # mov regb, rega
        # mov regc, [regb]
        # mov regd, regc
        # mov [dest], regd

        for mov_dest_src in self.mov_mem_to_mem(prefix + 'mov1_'):
            for add_dest_dest in self.add_mem_to_mem(prefix + 'add1_'):
                for mov_temp_base_addr in self.mov_imm_to_mem(prefix + 'mov2_'):
                    for add_dest_temp in self.add_mem_to_mem(prefix + 'add2_'):

                        # mov rega, [dest]
                        for rega in self.gadgets.read_mem_to_register:
                            for mov_rega_dest in self.gadgets.read_mem_to_register[rega]:

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
                                                        result.add_all(mov_dest_src.gadgets)
                                                        result.add_all(add_dest_dest.gadgets)
                                                        result.add_all(add_dest_dest.gadgets)
                                                        result.add_all(add_dest_dest.gadgets)
                                                        result.add_all(mov_temp_base_addr.gadgets)
                                                        result.add_all(add_dest_temp.gadgets)

                                                        result.add_gadget((mov_rega_dest, prefix + 'dest'))
                                                        result.add_all(mov_regb_rega.gadgets)
                                                        result.add_gadget((mov_regc_regb, None))
                                                        result.add_all(mov_regd_regc.gadgets)
                                                        result.add_gadget((mov_dest_regd, prefix + 'dest'))
                                                        yield result


        # for regb in self.gadgets.read_mem_to_register:
        #     for gadget in self.gadgets.read_mem_to_register[regb]:

        #         def get_offset(sentinel, gadget=gadget):
        #             built = gadget.build(sentinel)

        #             if len(built._values) != 3:
        #                 raise ValueError('Cannot generalize gadget')
                    
        #             pop_gadget_addr, value, gadget_addr = built._concretize_chain_values()

        #             pop_gadget = built._gadgets[0]
        #             changed = pop_gadget.changed_regs - {'rsp', 'rip'}

        #             if len(changed) != 1:
        #                 raise ValueError('Cannot generalize gadget')

        #             return list(changed)[0], value[0] - sentinel

        #         try:
        #             offsets = list(map(get_offset, [0xbce64a141b97c43f, 0x3842d77f93df9b20]))
        #         except Exception as e:
        #             print(e)

        #         if all(offset == offsets[0] for offset in offsets):
        #             rega, offset = offsets[0]

        #             def build(chain, dest, src, temp, offset=offset, prefix=prefix):
        #                 return chain._apply_args({
        #                     prefix + 'mov1_dest': (temp,),
        #                     prefix + 'mov1_src': (offset,),

        #                     prefix + 'add_dest': (temp,),
        #                     prefix + 'add_src': (src,),

        #                     prefix + 'mov2_dest': (dest,),
        #                     prefix + 'mov2_src': (temp,),
        #                 })

        #             # mov rega, [src]
        #             # mov regc, rega
        #             # mov [temp], regc
        #             # mov [temp2], offset
        #             # add [temp], [temp2]


        #             # mov 
        #             # mov [temp], offset
        #             # add [temp], [src]
        #             # mov [dest], [temp]

        #             for mov_temp_offset in self.mov_imm_to_mem(prefix + 'mov1_'):
        #                 for add_temp_src in self.add_mem_to_mem(prefix + 'add_'):
        #                     for mov_dest_temp in self.mov_mem_to_mem(prefix + 'mov2_'):
        #                         result = ParameterizedChain(self.gadgets.rop, builder=build)
        #                         result.add_all(mov_temp_offset.gadgets)
        #                         result.add_all(add_temp_src.gadgets)
        #                         result.add_all(mov_dest_temp.gadgets)
        #                         yield result


    def mov_mem_to_deref_mem_ptr(self, prefix='') -> Generator[ParameterizedChain]:
        '''**dest = *src'''

        def build(chain, dest, src, temp, temp2, base_addr, prefix=prefix):
            return chain._apply_args({
                prefix + 'mov1_dest': (temp,),
                prefix + 'mov1_src': (dest,),

                prefix + 'add1_dest': (temp,),
                prefix + 'add1_src': (temp,),
                prefix + 'add1_zero': (0,),

                prefix + 'mov2_dest': (temp2,),
                prefix + 'mov2_src': (base_addr,),

                prefix + 'add2_dest': (temp,),
                prefix + 'add2_src': (temp2,),
                prefix + 'add2_zero': (0,),

                prefix + 'src': (src,),
                prefix + 'temp': (temp,)
            })


        # mov [temp], [dest]
        # add [temp], [temp]
        # add [temp], [temp]
        # add [temp], [temp]
        # mov [temp2], base_addr
        # add [temp], [temp2]
        
        # mov rega, [temp]
        # mov regb, [src]
        # mov regc, rega
        # mov regd, regb
        # mov [regc], regd

        for mov_temp_dest in self.mov_mem_to_mem(prefix + 'mov1_'):
            for add_temp_temp in self.add_mem_to_mem(prefix + 'add1_'):
                for mov_temp2_base_addr in self.mov_imm_to_mem(prefix + 'mov2_'):
                    for add_temp_temp2 in self.add_mem_to_mem(prefix + 'add2_'):

                        # mov rega, [temp]
                        for rega in self.gadgets.read_mem_to_register:
                            for mov_rega_temp in self.gadgets.read_mem_to_register[rega]:

                                # mov regb, [src]
                                for regb in self.gadgets.read_mem_to_register:
                                    for mov_regb_src in self._preserve_registers(self.gadgets.read_mem_to_register[regb], rega):

                                        # mov regc, rega
                                        for regc, regd in self.gadgets.write_register_to_mem_ptr:
                                            for mov_regc_rega in self._mov_reg_to_reg(regc, rega, self.gadgets.rop.project.arch.bits, {regb}):

                                                # mov regd, regb
                                                for mov_regd_regb in self._mov_reg_to_reg(regd, regb, self.gadgets.rop.project.arch.bits, {regc}):

                                                    # mov [regc], regd
                                                    for mov_regc_regd in self.gadgets.write_register_to_mem_ptr[(regc, regd)]:

                                                        result = ParameterizedChain(self.gadgets.rop, builder=build)

                                                        result.add_all(mov_temp_dest.gadgets)
                                                        result.add_all(add_temp_temp.gadgets)
                                                        result.add_all(add_temp_temp.gadgets)
                                                        result.add_all(add_temp_temp.gadgets)
                                                        result.add_all(mov_temp2_base_addr.gadgets)
                                                        result.add_all(add_temp_temp2.gadgets)

                                                        result.add_gadget((mov_rega_temp, prefix + 'temp'))
                                                        result.add_gadget((mov_regb_src, prefix + 'src'))
                                                        result.add_all(mov_regc_rega.gadgets)
                                                        result.add_all(mov_regd_regb.gadgets)
                                                        result.add_gadget((mov_regc_regd, None))
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

    def eq_mem_mem(self, prefix='') -> Generator[ParameterizedChain]:

        def build(chain, dest, src, temp, prefix=prefix):
            return chain._apply_args({prefix + 'dest': (dest,), prefix + 'src': (src,), prefix + 'zero': (0,)})

        # mov rega, [src]
        # mov regb, [dest]
        # mov regc, rega
        # mov regd, regb
        # cmp regc, regd
        # mov rege, 0
        # sete rege
        # mov regf, rege
        # mov [dest], regf

        for rega in self.gadgets.read_mem_to_register:
            for mov_rega_src in self.gadgets.read_mem_to_register[rega]:

                for regb in self.gadgets.read_mem_to_register:
                    for mov_regb_dest in self._preserve_registers(self.gadgets.read_mem_to_register[regb], rega):

                        for regc, regd in self.gadgets.cmp_reg_to_reg:
                            for mov_regc_rega in self._mov_reg_to_reg(regc, rega, self.gadgets.rop.project.arch.bits, {regb}):

                                for mov_regd_regb in self._mov_reg_to_reg(regd, regb, self.gadgets.rop.project.arch.bits, {regc}):

                                    for cmp_regc_regd in self.gadgets.cmp_reg_to_reg[(regc, regd)]:

                                        for rege in self.gadgets.set_equal:

                                            for mov_rege_0 in self._preserve_registers(self.gadgets.set_register_value[rege], regc, regd):

                                                # if mov_rege_0.gadget.modifies_flags:
                                                #     continue

                                                for sete_rege in self.gadgets.set_equal[rege]:

                                                    for regf in self.gadgets.write_register_to_mem:
                                                        for mov_regf_rege in self._mov_reg_to_reg(regf, rege, self.gadgets.rop.project.arch.bits):

                                                            for mov_dest_regf in self.gadgets.write_register_to_mem[regf]:

                                                                result = ParameterizedChain(self.gadgets.rop, builder=build)
                                                                result.add_gadget((mov_rega_src, prefix + 'src'))
                                                                result.add_gadget((mov_regb_dest, prefix + 'dest'))
                                                                result.add_all(mov_regc_rega.gadgets)
                                                                result.add_all(mov_regd_regb.gadgets)
                                                                result.add_gadget((cmp_regc_regd, None))
                                                                result.add_gadget((mov_rege_0, prefix + 'zero'))
                                                                result.add_gadget((sete_rege, None))
                                                                result.add_all(mov_regf_rege.gadgets)
                                                                result.add_gadget((mov_dest_regf, prefix + 'dest'))
                                                                yield result
    
    def lt_mem_mem(self, prefix='') -> Generator[ParameterizedChain]:

        def build(chain, dest, src, temp, prefix=prefix):
            return chain._apply_args({prefix + 'dest': (dest,), prefix + 'src': (src,), prefix + 'zero': (0,)})

        # mov rega, [dest]
        # mov regb, [src]
        # mov regc, rega
        # mov regd, regb
        # cmp regc, regd
        # mov rege, 0
        # setlt rege
        # mov regf, rege
        # mov [dest], regf

        for rega in self.gadgets.read_mem_to_register:
            for mov_rega_src in self.gadgets.read_mem_to_register[rega]:

                for regb in self.gadgets.read_mem_to_register:
                    for mov_regb_dest in self._preserve_registers(self.gadgets.read_mem_to_register[regb], rega):

                        for regc, regd in self.gadgets.cmp_reg_to_reg:
                            for mov_regc_rega in self._mov_reg_to_reg(regc, rega, self.gadgets.rop.project.arch.bits, {regb}):

                                for mov_regd_regb in self._mov_reg_to_reg(regd, regb, self.gadgets.rop.project.arch.bits, {regc}):

                                    for cmp_regc_regd in self.gadgets.cmp_reg_to_reg[(regc, regd)]:

                                        for rege in self.gadgets.set_equal:

                                            for mov_rege_0 in self._preserve_registers(self.gadgets.set_register_value[rege], regc, regd):

                                                # if mov_rege_0.gadget.modifies_flags:
                                                #     continue

                                                for setl_rege in self.gadgets.set_less_than[rege]:

                                                    for regf in self.gadgets.write_register_to_mem:
                                                        for mov_regf_rege in self._mov_reg_to_reg(regf, rege, self.gadgets.rop.project.arch.bits):

                                                            for mov_dest_regf in self.gadgets.write_register_to_mem[regf]:

                                                                result = ParameterizedChain(self.gadgets.rop, builder=build)
                                                                result.add_gadget((mov_rega_src, prefix + 'dest'))
                                                                result.add_gadget((mov_regb_dest, prefix + 'src'))
                                                                result.add_all(mov_regc_rega.gadgets)
                                                                result.add_all(mov_regd_regb.gadgets)
                                                                result.add_gadget((cmp_regc_regd, None))
                                                                result.add_gadget((mov_rege_0, prefix + 'zero'))
                                                                result.add_gadget((setl_rege, None))
                                                                result.add_all(mov_regf_rege.gadgets)
                                                                result.add_gadget((mov_dest_regf, prefix + 'dest'))
                                                                yield result

    def ne_mem_mem(self, prefix='') -> Generator[ParameterizedChain]:

        def build(chain, dest, src, temp, prefix=prefix):
            return chain._apply_args({
                prefix + 'eq1_dest': (dest,),
                prefix + 'eq1_src': (src,),
                prefix + 'eq1_zero': (0,),

                prefix + 'mov_dest': (temp,),
                prefix + 'mov_src': (0,),

                prefix + 'eq2_dest': (dest,),
                prefix + 'eq2_src': (temp,),
                prefix + 'eq2_zero': (0,),
            })

        # eq_mem_mem [dest], [src]
        # mov [temp], 0
        # eq_mem_mem [dest], [temp]

        for eq_mem_mem_dest_src in self.eq_mem_mem(prefix + 'eq1_'):
            for mov_temp_0 in self.mov_imm_to_mem(prefix + 'mov_'):
                for eq_mem_mem_dest_temp in self.eq_mem_mem(prefix + 'eq2_'):
                    result = ParameterizedChain(self.gadgets.rop, builder=build)
                    result.add_all(eq_mem_mem_dest_src.gadgets)
                    result.add_all(mov_temp_0.gadgets)
                    result.add_all(eq_mem_mem_dest_temp.gadgets)
                    yield result

    def gt_mem_mem(self, prefix='') -> Generator[ParameterizedChain]:

        def build(chain, dest, src, temp, prefix=prefix):
            return chain._apply_args({
                prefix + 'mov_dest': (temp,),
                prefix + 'mov_src': (dest,),

                prefix + 'eq_dest': (dest,),
                prefix + 'eq_src': (src,),
                prefix + 'eq_zero': (0,),

                prefix + 'lt_dest': (temp,),
                prefix + 'lt_src': (src,),
                prefix + 'lt_zero': (0,),

                prefix + 'add_dest': (dest,),
                prefix + 'add_src': (temp,),

                prefix + 'mov2_dest': (temp,),
                prefix + 'mov2_src': (0,),

                prefix + 'eq2_dest': (dest,),
                prefix + 'eq2_src': (temp,),
                prefix + 'eq2_zero': (0,),
            })

        # ne and nlt
        # eq == 0 and lt == 0
        # eq + lt = 0

        # mov [temp], [dest]
        # eq_mem_mem [dest], [src]
        # lt_mem_mem [temp], [src]
        # add [dest], [temp]
        # mov [temp], 0
        # eq_mem_mem [dest], [temp]

        for mov_temp_dest in self.mov_mem_to_mem(prefix + 'mov_'):
            for eq_mem_mem_dest_src in self.eq_mem_mem(prefix + 'eq_'):
                for lt_mem_mem_temp_src in self.lt_mem_mem(prefix + 'lt_'):
                    for add_dest_temp in self.add_mem_to_mem(prefix + 'add_'):
                        for mov_temp_0 in self.mov_imm_to_mem(prefix + 'mov2_'):
                            for eq_mem_mem_dest_temp in self.eq_mem_mem(prefix + 'eq2_'):
                                result = ParameterizedChain(self.gadgets.rop, builder=build)
                                result.add_all(mov_temp_dest.gadgets)
                                result.add_all(eq_mem_mem_dest_src.gadgets)
                                result.add_all(lt_mem_mem_temp_src.gadgets)
                                result.add_all(add_dest_temp.gadgets)
                                result.add_all(mov_temp_0.gadgets)
                                result.add_all(eq_mem_mem_dest_temp.gadgets)
                                yield result

    def le_mem_mem(self, prefix='') -> Generator[ParameterizedChain]:

        def build(chain, dest, src, temp, prefix=prefix):
            return chain._apply_args({
                prefix + 'mov_dest': (temp,),
                prefix + 'mov_src': (dest,),

                prefix + 'eq_dest': (dest,),
                prefix + 'eq_src': (src,),
                prefix + 'eq_zero': (0,),

                prefix + 'lt_dest': (temp,),
                prefix + 'lt_src': (src,),
                prefix + 'lt_zero': (0,),

                prefix + 'add_dest': (dest,),
                prefix + 'add_src': (temp,),

                prefix + 'mov2_dest': (temp,),
                prefix + 'mov2_src': (0,),

                prefix + 'ne_eq1_dest': (dest,),
                prefix + 'ne_eq1_src': (temp,),
                prefix + 'ne_eq1_zero': (0,),

                prefix + 'ne_mov_dest': (temp,),
                prefix + 'ne_mov_src': (0,),

                prefix + 'ne_eq2_dest': (dest,),
                prefix + 'ne_eq2_src': (temp,),
                prefix + 'ne_eq2_zero': (0,),
            })

        # eq == 1 or lt == 1
        # eq + lt != 0

        # mov [temp], [dest]
        # eq_mem_mem [dest], [src]
        # lt_mem_mem [temp], [src]
        # add [dest], [temp]
        # mov [temp], 0
        # ne_mem_mem [dest], [temp]

        for mov_temp_dest in self.mov_mem_to_mem(prefix + 'mov_'):
            for eq_mem_mem_dest_src in self.eq_mem_mem(prefix + 'eq_'):
                for lt_mem_mem_temp_src in self.lt_mem_mem(prefix + 'lt_'):
                    for add_dest_temp in self.add_mem_to_mem(prefix + 'add_'):
                        for mov_temp_0 in self.mov_imm_to_mem(prefix + 'mov2_'):
                            for ne_mem_mem_dest_temp in self.ne_mem_mem(prefix + 'ne_'):
                                result = ParameterizedChain(self.gadgets.rop, builder=build)
                                result.add_all(mov_temp_dest.gadgets)
                                result.add_all(eq_mem_mem_dest_src.gadgets)
                                result.add_all(lt_mem_mem_temp_src.gadgets)
                                result.add_all(add_dest_temp.gadgets)
                                result.add_all(mov_temp_0.gadgets)
                                result.add_all(ne_mem_mem_dest_temp.gadgets)
                                yield result

    def ge_mem_mem(self, prefix='') -> Generator[ParameterizedChain]:

        def build(chain, dest, src, temp, prefix=prefix):
            return chain._apply_args({
                prefix + 'lt_dest': (dest,),
                prefix + 'lt_src': (src,),
                prefix + 'lt_zero': (0,),

                prefix + 'mov_dest': (temp,),
                prefix + 'mov_src': (0,),

                prefix + 'eq_dest': (dest,),
                prefix + 'eq_src': (temp,),
                prefix + 'eq_zero': (0,),
            })

        # lt_mem_mem [dest], [src]
        # mov [temp], 0
        # eq_mem_mem [dest], [temp]

        for lt_mem_mem_dest_src in self.lt_mem_mem(prefix + 'lt_'):
            for mov_temp_0 in self.mov_imm_to_mem(prefix + 'mov_'):
                for eq_mem_mem_dest_temp in self.eq_mem_mem(prefix + 'eq_'):
                    result = ParameterizedChain(self.gadgets.rop, builder=build)
                    result.add_all(lt_mem_mem_dest_src.gadgets)
                    result.add_all(mov_temp_0.gadgets)
                    result.add_all(eq_mem_mem_dest_temp.gadgets)
                    yield result

    def jump_to_imm(self, prefix='') -> Generator[ParameterizedChain]:
        
        def build(chain, jmp, dest, src, temp, temp2, prefix=prefix):
            return chain._apply_args({prefix + 'jmp': (jmp,)})

        # mov rega, jmp
        # mov regb, rega
        # mov rsp, regb

        for rega in self.gadgets.set_register_value:
            for mov_rega_jmp in self.gadgets.set_register_value[rega]:

                for regb in self.gadgets.mov_register_to_rsp:
                    for mov_regb_rega in self._mov_reg_to_reg(regb, rega, self.gadgets.rop.project.arch.bits):

                        for mov_rsp_regb in self.gadgets.mov_register_to_rsp[regb]:
                            result = ParameterizedChain(self.gadgets.rop, builder=build)
                            result.add_gadget((mov_rega_jmp, prefix + 'jmp'))
                            result.add_all(mov_regb_rega.gadgets)
                            result.add_gadget((mov_rsp_regb, None))
                            yield result

    _ADD_RSP_LEN = 25 * 8

    def _last_jump_step(self, prefix='') -> Generator[ParameterizedChain]:


        def build(chain, jmp, temp, temp2, prefix=prefix):
            return chain._apply_args({
                prefix + 'add1_dest': (temp,),
                prefix + 'add1_src': (temp,),

                prefix + 'mov1_src': (self._ADD_RSP_LEN,),
                prefix + 'mov1_dest': (temp2,),

                prefix + 'add0_dest': (temp,),
                prefix + 'add0_src': (temp2,),

                prefix + 'add2_dest': (temp,),
                prefix + 'add2_src': (temp2,),

                prefix + 'temp': (temp,),
                prefix + 'temp2': (temp2,),
                prefix + 'jmp': (jmp,)
            })

        # add_mem_mem [temp], [temp]
        # add_mem_mem [temp], [temp]
        # add_mem_mem [temp], [temp]

        # mov temp2, ADD_RSP_LEN
        # add temp, temp2

        # mov rega, rsp
        # mov regb, rega
        # mov [temp2], regb
        # add_mem_mem [temp], [temp2]
        # mov regc, [temp]
        # mov regd, regc
        # mov rsp, regd

        # ret; ret; ret; to pad to ADD_RSP_LEN bytes

        # pop enough_bytes
        # mov rege, jmp
        # mov rsp, rege
        
        for add_temp_temp in self.add_mem_to_mem(prefix + 'add1_'):

            for mov_temp2_add_rsp_len in self.mov_imm_to_mem(prefix + 'mov1_'):
                for add_temp_temp2 in self.add_mem_to_mem(prefix + 'add0_'):

                    for rega, should_be_rsp in self.gadgets.mov_register_to_register[64]:
                        if should_be_rsp != 'rsp':
                            continue

                        for mov_rega_rsp in self.gadgets.mov_register_to_register[64][(rega, 'rsp')]:

                            for regb in self.gadgets.write_register_to_mem:
                                
                                for mov_regb_rega in self._mov_reg_to_reg(regb, rega, 64):

                                    for mov_temp2_regb in self.gadgets.write_register_to_mem[regb]:

                                        for add_temp_temp2 in self.add_mem_to_mem(prefix + 'add2_'):

                                            for regc in self.gadgets.read_mem_to_register:
                                                for mov_regc_temp in self.gadgets.read_mem_to_register[regc]:

                                                    for regd in self.gadgets.mov_register_to_rsp:
                                                        for mov_regd_regc in self._mov_reg_to_reg(regd, regc, 64):

                                                            for mov_rsp_regd in self.gadgets.mov_register_to_rsp[regd]:
                                                                
                                                                for nop in self.gadgets.pop_bytes[0]:
                                                                    for rege in self.gadgets.mov_register_to_rsp:

                                                                        for mov_rege_jmp in self.gadgets.set_register_value[rege]:

                                                                            for mov_rsp_rege in self.gadgets.mov_register_to_rsp[rege]:

                                                                                size = mov_rege_jmp.expected_payload_len + mov_rsp_rege.expected_payload_len

                                                                                for pop_bytes in self.gadgets.pop_bytes[size]:

                                                                                    result = ParameterizedChain(self.gadgets.rop, builder=build)
                                                                                    result.add_all(add_temp_temp.gadgets)
                                                                                    result.add_all(add_temp_temp.gadgets)
                                                                                    result.add_all(add_temp_temp.gadgets)
                                                                                    result.add_all(mov_temp2_add_rsp_len.gadgets)
                                                                                    result.add_all(add_temp_temp2.gadgets)
                                                                                    result.add_gadget((mov_rega_rsp, None))
                                                                                    result.add_all(mov_regb_rega.gadgets)
                                                                                    result.add_gadget((mov_temp2_regb, prefix + 'temp2'))
                                                                                    result.add_all(add_temp_temp2.gadgets)
                                                                                    result.add_gadget((mov_regc_temp, prefix + 'temp'))
                                                                                    result.add_all(mov_regd_regc.gadgets)
                                                                                    result.add_gadget((mov_rsp_regd, None))

                                                                                    padding_needed = self._ADD_RSP_LEN - sum(g.compute_expected_value() for g in [
                                                                                        mov_regb_rega,
                                                                                        add_temp_temp2,
                                                                                        mov_regd_regc,
                                                                                    ]) - sum(g.expected_payload_len for g in [
                                                                                        mov_temp2_regb,
                                                                                        mov_regc_temp,
                                                                                        mov_rsp_regd
                                                                                    ])

                                                                                    for _ in range(padding_needed // 8):
                                                                                        result.add_gadget((nop, None))

                                                                                    result.add_gadget((pop_bytes, None))
                                                                                    result.add_gadget((mov_rege_jmp, prefix + 'jmp'))
                                                                                    result.add_gadget((mov_rsp_rege, None))
                                                                                    yield result


    def je_to_imm(self, prefix='') -> Generator[ParameterizedChain]:

        def build(chain, jmp, dest, src, temp, temp2, prefix=prefix):
            return chain._apply_args({

                prefix + 'mov_dest': (temp,),
                prefix + 'mov_src': (dest,),

                prefix + 'eq_dest': (temp,),
                prefix + 'eq_src': (src,),
                prefix + 'eq_zero': (0,),

                prefix + 'jmp_add1_dest': (temp,),
                prefix + 'jmp_add1_src': (temp,),
                
                prefix + 'jmp_mov1_src': (self._ADD_RSP_LEN,),
                prefix + 'jmp_mov1_dest': (temp2,),

                prefix + 'jmp_add0_dest': (temp,),
                prefix + 'jmp_add0_src': (temp2,),

                prefix + 'jmp_add2_dest': (temp,),
                prefix + 'jmp_add2_src': (temp2,),

                prefix + 'jmp_temp': (temp,),
                prefix + 'jmp_temp2': (temp2,),
                prefix + 'jmp_jmp': (jmp,)
            })

        # mov [temp], [dest]
        # eq_mem_mem [temp], [src]
        # jump step
        
        for mov_temp_dest in self.mov_mem_to_mem(prefix + 'mov_'):
            for eq_mem_mem_temp_src in self.eq_mem_mem(prefix + 'eq_'):
                for jump_step in self._last_jump_step('jmp_'):
                    result = ParameterizedChain(self.gadgets.rop, builder=build)
                    result.add_all(mov_temp_dest.gadgets)
                    result.add_all(eq_mem_mem_temp_src.gadgets)
                    result.add_all(jump_step.gadgets)
                    yield result

    def jne_to_imm(self, prefix='') -> Generator[ParameterizedChain]:
        
        def build(chain, jmp, dest, src, temp, temp2, prefix=prefix):
            return chain._apply_args({

                prefix + 'mov_dest': (temp,),
                prefix + 'mov_src': (dest,),

                prefix + 'ne_eq1_dest': (temp,),
                prefix + 'ne_eq1_src': (src,),
                prefix + 'ne_eq1_zero': (0,),

                prefix + 'ne_mov_dest': (temp2,),
                prefix + 'ne_mov_src': (0,),

                prefix + 'ne_eq2_dest': (temp,),
                prefix + 'ne_eq2_src': (temp2,),
                prefix + 'ne_eq2_zero': (0,),

                prefix + 'jmp_add1_dest': (temp,),
                prefix + 'jmp_add1_src': (temp,),
                
                prefix + 'jmp_mov1_src': (self._ADD_RSP_LEN,),
                prefix + 'jmp_mov1_dest': (temp2,),

                prefix + 'jmp_add0_dest': (temp,),
                prefix + 'jmp_add0_src': (temp2,),

                prefix + 'jmp_add2_dest': (temp,),
                prefix + 'jmp_add2_src': (temp2,),

                prefix + 'jmp_temp': (temp,),
                prefix + 'jmp_temp2': (temp2,),
                prefix + 'jmp_jmp': (jmp,)
            })

        # mov [temp], [dest]
        # ne_mem_mem [temp], [src]
        # jump step
        
        for mov_temp_dest in self.mov_mem_to_mem(prefix + 'mov_'):
            for ne_mem_mem_temp_src in self.ne_mem_mem(prefix + 'ne_'):
                for jump_step in self._last_jump_step('jmp_'):
                    result = ParameterizedChain(self.gadgets.rop, builder=build)
                    result.add_all(mov_temp_dest.gadgets)
                    result.add_all(ne_mem_mem_temp_src.gadgets)
                    result.add_all(jump_step.gadgets)
                    yield result

    def jlt_to_imm(self, prefix='') -> Generator[ParameterizedChain]:
        def build(chain, jmp, dest, src, temp, temp2, prefix=prefix):
            return chain._apply_args({

                prefix + 'mov_dest': (temp,),
                prefix + 'mov_src': (dest,),

                prefix + 'lt_dest': (temp,),
                prefix + 'lt_src': (src,),
                prefix + 'lt_zero': (0,),

                prefix + 'jmp_add1_dest': (temp,),
                prefix + 'jmp_add1_src': (temp,),
                
                prefix + 'jmp_mov1_src': (self._ADD_RSP_LEN,),
                prefix + 'jmp_mov1_dest': (temp2,),

                prefix + 'jmp_add0_dest': (temp,),
                prefix + 'jmp_add0_src': (temp2,),

                prefix + 'jmp_add2_dest': (temp,),
                prefix + 'jmp_add2_src': (temp2,),

                prefix + 'jmp_temp': (temp,),
                prefix + 'jmp_temp2': (temp2,),
                prefix + 'jmp_jmp': (jmp,)
            })

        # mov [temp], [dest]
        # lt_mem_mem [temp], [src]
        # jump step
        
        for mov_temp_dest in self.mov_mem_to_mem(prefix + 'mov_'):
            for lt_mem_mem_temp_src in self.lt_mem_mem(prefix + 'lt_'):
                for jump_step in self._last_jump_step('jmp_'):
                    result = ParameterizedChain(self.gadgets.rop, builder=build)
                    result.add_all(mov_temp_dest.gadgets)
                    result.add_all(lt_mem_mem_temp_src.gadgets)
                    result.add_all(jump_step.gadgets)
                    yield result
    
    def jgt_to_imm(self, prefix='') -> Generator[ParameterizedChain]:
        
        def build(chain, jmp, dest, src, temp, temp2, prefix=prefix):
            return chain._apply_args({

                prefix + 'mov_dest': (temp,),
                prefix + 'mov_src': (dest,),

                prefix + 'gt_mov_dest': (temp,),
                prefix + 'gt_mov_src': (dest,),

                prefix + 'gt_eq_dest': (temp,),
                prefix + 'gt_eq_src': (src,),
                prefix + 'gt_eq_zero': (0,),

                prefix + 'gt_lt_dest': (temp2,),
                prefix + 'gt_lt_src': (src,),
                prefix + 'gt_lt_zero': (0,),

                prefix + 'gt_add_dest': (temp,),
                prefix + 'gt_add_src': (temp2,),

                prefix + 'gt_mov2_dest': (temp2,),
                prefix + 'gt_mov2_src': (0,),

                prefix + 'gt_eq2_dest': (temp,),
                prefix + 'gt_eq2_src': (temp2,),
                prefix + 'gt_eq2_zero': (0,),

                prefix + 'jmp_add1_dest': (temp,),
                prefix + 'jmp_add1_src': (temp,),
                
                prefix + 'jmp_mov1_src': (self._ADD_RSP_LEN,),
                prefix + 'jmp_mov1_dest': (temp2,),

                prefix + 'jmp_add0_dest': (temp,),
                prefix + 'jmp_add0_src': (temp2,),

                prefix + 'jmp_add2_dest': (temp,),
                prefix + 'jmp_add2_src': (temp2,),

                prefix + 'jmp_temp': (temp,),
                prefix + 'jmp_temp2': (temp2,),
                prefix + 'jmp_jmp': (jmp,)
            })

        # mov [temp], [dest]
        # jgt_mem_mem [temp], [src]
        # jump step
        
        for mov_temp_dest in self.mov_mem_to_mem(prefix + 'mov_'):
            for gt_mem_mem_temp_src in self.gt_mem_mem(prefix + 'gt_'):
                for jump_step in self._last_jump_step('jmp_'):
                    result = ParameterizedChain(self.gadgets.rop, builder=build)
                    result.add_all(mov_temp_dest.gadgets)
                    result.add_all(gt_mem_mem_temp_src.gadgets)
                    result.add_all(jump_step.gadgets)
                    yield result

    def jle_to_imm(self, prefix='') -> Generator[ParameterizedChain]:
        def build(chain, jmp, dest, src, temp, temp2, prefix=prefix):
            return chain._apply_args({

                prefix + 'mov_dest': (temp,),
                prefix + 'mov_src': (dest,),

                prefix + 'le_mov_dest': (temp2,),
                prefix + 'le_mov_src': (temp,),

                prefix + 'le_eq_dest': (temp,),
                prefix + 'le_eq_src': (src,),
                prefix + 'le_eq_zero': (0,),

                prefix + 'le_lt_dest': (temp2,),
                prefix + 'le_lt_src': (src,),
                prefix + 'le_lt_zero': (0,),

                prefix + 'le_add_dest': (temp,),
                prefix + 'le_add_src': (temp2,),

                prefix + 'le_mov2_dest': (temp2,),
                prefix + 'le_mov2_src': (0,),

                prefix + 'le_ne_eq1_dest': (temp,),
                prefix + 'le_ne_eq1_src': (temp2,),
                prefix + 'le_ne_eq1_zero': (0,),

                prefix + 'le_ne_mov_dest': (temp2,),
                prefix + 'le_ne_mov_src': (0,),

                prefix + 'le_ne_eq2_dest': (temp,),
                prefix + 'le_ne_eq2_src': (temp2,),
                prefix + 'le_ne_eq2_zero': (0,),

                prefix + 'jmp_add1_dest': (temp,),
                prefix + 'jmp_add1_src': (temp,),
                
                prefix + 'jmp_mov1_src': (self._ADD_RSP_LEN,),
                prefix + 'jmp_mov1_dest': (temp2,),

                prefix + 'jmp_add0_dest': (temp,),
                prefix + 'jmp_add0_src': (temp2,),

                prefix + 'jmp_add2_dest': (temp,),
                prefix + 'jmp_add2_src': (temp2,),

                prefix + 'jmp_temp': (temp,),
                prefix + 'jmp_temp2': (temp2,),
                prefix + 'jmp_jmp': (jmp,)
            })

        # mov [temp], [dest]
        # le_mem_mem [temp], [src]
        # jump step
        
        for mov_temp_dest in self.mov_mem_to_mem(prefix + 'mov_'):
            for le_mem_mem_temp_src in self.le_mem_mem(prefix + 'le_'):
                for jump_step in self._last_jump_step('jmp_'):
                    result = ParameterizedChain(self.gadgets.rop, builder=build)
                    result.add_all(mov_temp_dest.gadgets)
                    result.add_all(le_mem_mem_temp_src.gadgets)
                    result.add_all(jump_step.gadgets)
                    yield result

    def jge_to_imm(self, prefix='') -> Generator[ParameterizedChain]:
        def build(chain, jmp, dest, src, temp, temp2, prefix=prefix):
            return chain._apply_args({

                prefix + 'mov_dest': (temp,),
                prefix + 'mov_src': (dest,),

                prefix + 'ge_lt_dest': (temp,),
                prefix + 'ge_lt_src': (src,),
                prefix + 'ge_lt_zero': (0,),

                prefix + 'ge_mov_dest': (temp2,),
                prefix + 'ge_mov_src': (0,),

                prefix + 'ge_eq_dest': (temp,),
                prefix + 'ge_eq_src': (temp2,),
                prefix + 'ge_eq_zero': (0,),

                prefix + 'jmp_add1_dest': (temp,),
                prefix + 'jmp_add1_src': (temp,),
                
                prefix + 'jmp_mov1_src': (self._ADD_RSP_LEN,),
                prefix + 'jmp_mov1_dest': (temp2,),

                prefix + 'jmp_add0_dest': (temp,),
                prefix + 'jmp_add0_src': (temp2,),

                prefix + 'jmp_add2_dest': (temp,),
                prefix + 'jmp_add2_src': (temp2,),

                prefix + 'jmp_temp': (temp,),
                prefix + 'jmp_temp2': (temp2,),
                prefix + 'jmp_jmp': (jmp,)
            })

        # mov [temp], [dest]
        # ge_mem_mem [temp], [src]
        # jump step
        
        for mov_temp_dest in self.mov_mem_to_mem(prefix + 'mov_'):
            for ge_mem_mem_temp_src in self.ge_mem_mem(prefix + 'ge_'):
                for jump_step in self._last_jump_step('jmp_'):
                    result = ParameterizedChain(self.gadgets.rop, builder=build)
                    result.add_all(mov_temp_dest.gadgets)
                    result.add_all(ge_mem_mem_temp_src.gadgets)
                    result.add_all(jump_step.gadgets)
                    yield result

    def putchar_mem(self, prefix='') -> Generator[ParameterizedChain]:

        def build(chain, src, prefix=prefix):
            return chain._apply_args({
                prefix + 'src': (src,),
                prefix + 'rax': (1,),
                prefix + 'rdi': (1,),
                prefix + 'rdx': (1,)
            })

        # mov rega, 1
        # mov rdi, rega
        # mov regb, src
        # mov rsi, regb
        # mov regc, 1
        # mov rdx, regc
        # mov regd, 1
        # mov rax, regd
        # syscall

        for rega in self.gadgets.set_register_value:
            for mov_rega_val in self.gadgets.set_register_value[rega]:

                for mov_rdi_rega in self._mov_reg_to_reg('rdi', rega, 64):

                    for regb in self.gadgets.set_register_value:
                        for mov_regb_src in self._preserve_registers(self.gadgets.set_register_value[regb], 'rdi'):
                            
                            for mov_rsi_regb in self._mov_reg_to_reg('rsi', regb, 64, {'rdi'}):

                                for regc in self.gadgets.set_register_value:
                                    for mov_regc_val in self._preserve_registers(self.gadgets.set_register_value[regc], 'rdi', 'rsi'):
                                        
                                        for mov_rdx_regc in self._mov_reg_to_reg('rdx', regc, 64, {'rdi', 'rsi'}):

                                            for regd in self.gadgets.set_register_value:
                                                for mov_regd_val in self._preserve_registers(self.gadgets.set_register_value[regd], 'rdi', 'rsi', 'rdx'):
                                                    
                                                    for mov_rax_regd in self._mov_reg_to_reg('rax', regd, 64, {'rdi', 'rsi', 'rdx'}):
                                                        for syscall in self.gadgets.syscall:
                                                            if not syscall.gadget.starts_with_syscall:
                                                                continue
                                                            
                                                            result = ParameterizedChain(self.gadgets.rop, builder=build)
                                                            result.add_gadget((mov_rega_val, prefix + 'rdi'))
                                                            result.add_all(mov_rdi_rega.gadgets)
                                                            result.add_gadget((mov_regb_src, prefix + 'src'))
                                                            result.add_all(mov_rsi_regb.gadgets)
                                                            result.add_gadget((mov_regc_val, prefix + 'rdx'))
                                                            result.add_all(mov_rdx_regc.gadgets)
                                                            result.add_gadget((mov_regd_val, prefix + 'rax'))
                                                            result.add_all(mov_rax_regd.gadgets)
                                                            result.add_gadget((syscall, None))
                                                            yield result


    def getchar_mem(self, prefix='') -> Generator[ParameterizedChain]:

        def build(chain, dest, prefix=prefix):
            return chain._apply_args({
                prefix + 'zero': (0,),
                prefix + 'dest': (dest,),

                prefix + 'pc_src': (dest,),
                prefix + 'pc_rax': (0,),
                prefix + 'pc_rdi': (1,),
                prefix + 'pc_rdx': (1,)
            })

        # mov rega, 0
        # mov [dest], rega
        # pc

        for rega in self.gadgets.set_register_value:
            for mov_rega_0 in self.gadgets.set_register_value[rega]:
                for mov_src_rega in self.gadgets.write_register_to_mem[rega]:
                    for pc in self.putchar_mem('pc_'):
                        result = ParameterizedChain(self.gadgets.rop, builder=build)
                        result.add_gadget((mov_rega_0, prefix + 'zero'))
                        result.add_gadget((mov_src_rega, prefix + 'dest'))
                        result.add_all(pc.gadgets)
                        yield result

    def exit(self, prefix='') -> Generator[ParameterizedChain]:
        
        def build(chain):
            return chain._apply_args({'rax': (60,)})

        for mov_rax_val in self.gadgets.set_register_value['rax']:
            for syscall in self.gadgets.syscall:
                if not syscall.gadget.starts_with_syscall:
                    continue

                result = ParameterizedChain(self.gadgets.rop, builder=build)
                result.add_gadget((mov_rax_val, prefix + 'rax'))
                result.add_gadget((syscall, None))
                yield result
