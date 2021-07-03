import functools
from angrop_backup.angrop import rop_utils
import angr
from angrop import *
from angrop.rop_gadget import RopGadget
from angrop.rop_chain import RopChain
from angrop.errors import RopException

import claripy

from functools import partial

# NOTE: Some code in this file is directly copied/modified from angrop

class ChainFinder():

    def __init__(self, rop):
        self.rop = rop
        self.gadgets = rop.gadgets
        self.arch = rop.project.arch


    def _gadget_has_no_mem_reads(self, g: RopGadget):
        return len(g.mem_reads) == 0


    def _gadget_has_no_mem_writes(self, g: RopGadget):
        return len(g.mem_writes) + len(g.mem_changes) == 0
    

    def _gadget_has_no_mem_access(self, g: RopGadget):
        return self._gadget_has_no_mem_reads(g) and self._gadget_has_no_mem_writes(g)


    def _gadget_has_one_mem_access(self, g: RopGadget):
        return g.mem_reads + g.mem_writes + g.mem_changes == 1


    def _gadget_is_safe(self, g: RopGadget):
        return not g.bp_moves_to_sp and g.stack_change > 0 and not g.makes_syscall


    def _get_flags(self, post_state):
        '''return ZF, CF, SF, OF'''
        rflags = post_state.regs.rflags
        return rflags[6] == 1, rflags[0] == 1, rflags[7] == 1, rflags[11] == 1


    def _try_all_gadgets(self, gadgets, gadget_runner):
        valid = []

        for g in gadgets:
            try:
                chain = gadget_runner(g)
                if chain is not None:
                    valid.append(chain)
            except (RopException, angr.errors.SimEngineError):
                pass
        
        return sorted(valid, key=lambda x: x.payload_len)


    def _get_register_constraints(self, gadget, get_initial_constraints, get_final_constraints):
        chain = RopChain(self.rop.project, self.rop, rebase=self.rop._rebase, badbytes=self.rop.badbytes)

        arch_bytes = self.arch.bytes
        arch_endness = self.arch.memory_endness

        # Create the initial state. This is the state at the start of the gadget
        pre_state = self.rop._chain_builder._test_symbolic_state.copy()
        rop_utils.make_reg_symbolic(pre_state, self.rop._chain_builder._base_pointer)

        pre_state.regs.ip = gadget.addr
        pre_state.add_constraints(
            pre_state.memory.load(pre_state.regs.sp, arch_bytes, endness=arch_endness) == gadget.addr
        )
        pre_state.regs.sp += arch_bytes

        initial_constraints, registers_to_solve = get_initial_constraints(pre_state)
        final_constraints = get_final_constraints(pre_state)
        all_constraints = initial_constraints + final_constraints

        if len(all_constraints) == 0:
            raise ValueError('No constraints given in get_constraints')

        pre_state.add_constraints(*all_constraints)

        if not pre_state.solver.satisfiable():
            raise RopException('Attempted solution is not satisfiable at all')

        # Solve for the registers
        reg_vals = dict()
        for reg in set(registers_to_solve):
            reg_vals[reg] = pre_state.solver.eval(pre_state.registers.load(reg))
            pre_state.registers.store(reg, reg_vals[reg])

        pre_state.solver.constraints.clear()
        pre_state.solver.reload_solver()
        
        final_constraints = get_final_constraints(pre_state)

        complement = claripy.Not(claripy.And(*final_constraints))
        pre_state.add_constraints(complement)

        if pre_state.solver.satisfiable():
            raise RopException('Attempted solution is not satisfiable in all cases')

        # Build the chain
        if len(reg_vals) > 0:
            chain = self.rop.set_regs(use_partial_controllers=False, **reg_vals)
        
        chain.add_gadget(gadget)

        bytes_per_pop = self.arch.bytes
        chain.add_value(gadget.addr, needs_rebase=True)
        for _ in range(gadget.stack_change // bytes_per_pop - 1):
            chain.add_value(self.rop._chain_builder._get_fill_val(), needs_rebase=False)
        
        return chain


    def generic_mem_access_get_initial_constraints(self, mem_accesses, action, addr, ignore_registers, pre_state):
            # pre_state.options.discard(angr.options.AVOID_MULTIVALUED_READS)
            # pre_state.options.discard(angr.options.AVOID_MULTIVALUED_WRITES)

            post_state = rop_utils.step_to_unconstrained_successor(self.rop.project, pre_state)

            # Find the ast which is the mem read/write operation
            mem_access = mem_accesses[0]
            the_action = None
            for a in post_state.history.actions.hardcopy:
                if a.type != 'mem' or (action and action != a.action):
                    continue

                if set(rop_utils.get_ast_dependency(a.addr.ast)) == set(mem_access.addr_dependencies) or \
                    set(rop_utils.get_ast_dependency(a.data.ast)) == set(mem_access.data_dependencies):
                    the_action = a
                    break

            if the_action is None:
                raise RopException("Couldn't find the matching action")

            # Set up symbolic variable at memory location
            to_access = pre_state.solver.BVS('mem', pre_state.arch.bits)
            pre_state.memory.store(addr, to_access)

            # Constrain the address of the memory access
            initial_constraint = the_action.addr.ast == addr

            # Solve for all registers in dependencies, except for the one we control arbitrarily
            registers_to_solve = list(mem_access.addr_dependencies.union(mem_access.data_dependencies) - ignore_registers)

            return [initial_constraint], registers_to_solve
    

    @rop_utils.timeout(5)
    def _try_access_mem(self, is_read, addr, register, gadget):

        def get_final_constraints(pre_state):
            post_state = rop_utils.step_to_unconstrained_successor(self.rop.project, pre_state)
            
            if is_read:
                to_read = pre_state.memory.load(addr, self.arch.bytes, endness=self.arch.memory_endness)
                constraint = post_state.registers.load(register) == to_read
            else:
                write_to = post_state.memory.load(addr, self.arch.bytes, endness=self.arch.memory_endness)
                constraint = write_to == pre_state.registers.load(register)

            return [constraint]

        mem_accesses, action = (gadget.mem_reads, 'read') if is_read else (gadget.mem_writes, 'write')

        return self._get_register_constraints(gadget,
                        functools.partial(self.generic_mem_access_get_initial_constraints, mem_accesses, action, addr, {register}),
                        get_final_constraints)


    def _find_mem_access_gadgets(self, is_read, register):
        possible_gadgets = set()

        for g in self.gadgets:
            mem_accesses = g.mem_reads if is_read else g.mem_writes
            bad_accesses = g.mem_writes if is_read else g.mem_reads

            # If there's a read when we're writing, or if there's a write
            # when we're reading, or if we read/write more than once to memory,
            # then skip this gadget.
            # It may be possible to lighten these constraints in the future
            if len(bad_accesses) + len(g.mem_changes) > 0 or len(mem_accesses) != 1:
                continue

            if g.bp_moves_to_sp:
                continue

            if g.stack_change <= 0:
                continue

            for m_access in mem_accesses:
                access_dependencies = m_access.data_dependencies if is_read else m_access.data_controllers

                potentially_controllable = len(m_access.addr_controllers) > 0 and len(access_dependencies) > 0 \
                                            and register in access_dependencies
                independent = is_read or len(set(m_access.addr_controllers) & set(access_dependencies)) == 0
                correct_size = m_access.data_size == self.arch.bits

                if potentially_controllable and independent and correct_size:
                    possible_gadgets.add(g)
                    break

        return possible_gadgets


    def _access_mem(self, is_read, addr, register):
        return self._try_all_gadgets(self._find_mem_access_gadgets(is_read, register),
                                        partial(self._try_access_mem, is_read, addr, register))


    def read_mem_to_register(self, addr, register):
        return self._access_mem(True, addr, register)


    def write_register_to_mem(self, addr, register):
        return self._access_mem(False, addr, register)


    def _try_add_register_to_register(self, reg1, reg2, gadget):
        
        def get_initial_constraints(pre_state):
            return [], []
        
        def get_final_constraints(pre_state):
            post_state = rop_utils.step_to_unconstrained_successor(self.rop.project, pre_state)

            a = pre_state.registers.load(reg1)
            b = pre_state.registers.load(reg2)
            c = post_state.registers.load(reg2)

            return [a + b == c]

        return self._get_register_constraints(gadget, get_initial_constraints, get_final_constraints)


    def _find_add_register_to_register_gadgets(self, reg1, reg2):
        possible_gadgets = set()

        for g in self.gadgets:
            # Skip any mem accesses for now. In the future, we can add
            # support for if we control the mem access
            if not self._gadget_is_safe(g):
                continue

            if reg2 not in g.changed_regs or reg2 not in g.reg_dependencies:
                continue

            deps = g.reg_dependencies[reg2]

            if reg1 not in deps or reg2 not in deps:
                continue
        
            possible_gadgets.add(g)
        
        return possible_gadgets


    def add_register_to_register(self, reg1, reg2):
        '''reg2 = reg1 + reg2'''
        return self._try_all_gadgets(self._find_add_register_to_register_gadgets(reg1, reg2),
                                        partial(self._try_add_register_to_register, reg1, reg2))

    
    def _try_add_register_to_mem(self, reg, addr_dest, gadget):
        
        def get_final_constraints(pre_state):
            post_state = rop_utils.step_to_unconstrained_successor(self.rop.project, pre_state)

            a = pre_state.registers.load(reg)
            b = pre_state.memory.load(addr_dest, self.arch.bytes, endness=self.arch.memory_endness)
            c = post_state.memory.load(addr_dest, self.arch.bytes, endness=self.arch.memory_endness)

            return [a + b == c]

        return self._get_register_constraints(gadget,
                        partial(self.generic_mem_access_get_initial_constraints, gadget.mem_changes, None, addr_dest, {reg}),
                        get_final_constraints)
       

    def _find_add_register_to_mem_gadgets(self, reg):
        possible_gadgets = set()

        for g in self.gadgets:

            # TODO: We could better filter by checking the mem change depends on reg
            if len(g.mem_changes) != 1 or len(g.mem_reads) + len(g.mem_writes) > 0:
                continue

            if g.mem_changes[0].data_size != self.arch.bits:
                continue
            
            possible_gadgets.add(g)
        
        return possible_gadgets


    def add_register_to_mem(self, reg, addr_dest):
        '''*(int64_t*)addr_dest = reg + *(int64_t*)addr_dest'''
        return self._try_all_gadgets(self._find_add_register_to_mem_gadgets(reg),
                                        partial(self._try_add_register_to_mem, reg, addr_dest))


    def _try_add_mem_to_register(self, addr_src, reg, gadget):
        
        def get_final_constraints(pre_state):
            post_state = rop_utils.step_to_unconstrained_successor(self.rop.project, pre_state)

            a = pre_state.registers.load(reg)
            b = pre_state.memory.load(addr_src, self.arch.bytes, endness=self.arch.memory_endness)
            c = post_state.registers.load(reg)

            return [a + b == c]

        return self._get_register_constraints(gadget,
                        partial(self.generic_mem_access_get_initial_constraints, gadget.mem_reads, None, addr_src, {reg}),
                        get_final_constraints)
     

    def _find_add_mem_to_register_gadgets(self, reg):
        possible_gadgets = set()

        for g in self.gadgets:

            if reg not in g.changed_regs:
                continue

            if len(g.mem_reads) != 1 or len(g.mem_changes) + len(g.mem_writes) > 0:
                continue

            if g.mem_reads[0].data_size != self.arch.bits:
                continue
            
            possible_gadgets.add(g)
        
        return possible_gadgets


    def add_mem_to_register(self, addr_src, reg):
        '''reg = *(int64_t*)addr_src'''
        return self._try_all_gadgets(self._find_add_mem_to_register_gadgets(reg),
                                        partial(self._try_add_mem_to_register, addr_src, reg))


    def _try_cmp_register_to_register(self, reg1, reg2, gadget):

        def get_initial_constraints(pre_state):
            return [], []

        def get_regs(pre_state):
            r1, r2 = pre_state.registers.load(reg1), pre_state.registers.load(reg2)
            return r1, r2, r1 - r2

        def check_equal(pre_state):
            r1, r2, result = get_regs(pre_state)
            pre_state.add_constraints(r1 == r2)
            post_state = rop_utils.step_to_unconstrained_successor(self.rop.project, pre_state)
            ZF, CF, SF, OF = self._get_flags(post_state)
            constraints = [ZF]
            return constraints

        def check_not_equal(pre_state):
            r1, r2, result = get_regs(pre_state)
            pre_state.add_constraints(r1 != r2)
            post_state = rop_utils.step_to_unconstrained_successor(self.rop.project, pre_state)
            ZF, CF, SF, OF = self._get_flags(post_state)
            constraints = [claripy.Not(ZF)]
            return constraints

        def check_less_than(pre_state):
            r1, r2, result = get_regs(pre_state)
            pre_state.add_constraints(r1.SLT(r2))
            post_state = rop_utils.step_to_unconstrained_successor(self.rop.project, pre_state)
            ZF, CF, SF, OF = self._get_flags(post_state)
            constraints = [SF != OF]
            return constraints

        def check_greater_than(pre_state):
            r1, r2, result = get_regs(pre_state)
            pre_state.add_constraints(r1.SGT(r2))
            post_state = rop_utils.step_to_unconstrained_successor(self.rop.project, pre_state)
            ZF, CF, SF, OF = self._get_flags(post_state)
            constraints = [claripy.Not(ZF), SF == OF]
            return constraints

        for check in (check_less_than, check_greater_than,
                        check_equal, check_not_equal):
            ret = self._get_register_constraints(gadget, get_initial_constraints, check)
        
        return ret


    def _find_cmp_register_to_register_gadgets(self, reg1, reg2):
        possible_gadgets = set()

        for g in self.gadgets:
            if self._gadget_is_safe(g) and self._gadget_has_no_mem_access(g):
                # Really not proud of this hack, but we need to eliminate more gadgets.
                # Otherwise, analysis of a medium sized binary takes 17+ hours.
                # This kind of defeats the point of angr and is architecture dependent.
                # There are definitely better ways to do this symbolically by looking at the ast
                disassembly = rop_utils.gadget_to_asmstring(self.rop.project, g)

                # Yikes
                if 'cmp' in disassembly or 'sub' in disassembly:
                    possible_gadgets.add(g)

        return possible_gadgets


    def cmp_reg_to_reg(self, reg1, reg2):
        '''cmp reg1, reg2'''
        return self._try_all_gadgets(self._find_cmp_register_to_register_gadgets(reg1, reg2),
                                        partial(self._try_cmp_register_to_register, reg1, reg2))


    def _find_modify_register_gadgets(self, reg):
        possible_gadgets = set()

        for g in self.gadgets:
            if self._gadget_is_safe(g) and self._gadget_has_no_mem_access(g) and reg in g.changed_regs:
                possible_gadgets.add(g)

        return possible_gadgets

    def _try_set_equal(self, reg, gadget):

        def get_initial_constraints(pre_state):
            return [], []

        def check_zero_flag_set(ZF, pre_state):
            pre_state.registers.store('rflags', ZF << 6)
            post_state = rop_utils.step_to_unconstrained_successor(self.rop.project, pre_state)
            reg_val = post_state.registers.load(reg)[7:0]
            return [reg_val == ZF]

        for i in range(2):    
            ret = self._get_register_constraints(gadget, get_initial_constraints, partial(check_zero_flag_set, i))
        
        return ret


    def set_equal(self, reg):
        '''sete reg'''
        return self._try_all_gadgets(self._find_modify_register_gadgets(reg),
                                        partial(self._try_set_equal, reg))

    
    def _try_set_less_than(self, reg, gadget):

        def get_initial_constraints(pre_state):
            return [], []

        def check(SF, OF, pre_state):
            pre_state.registers.store('rflags', (SF << 7) | (OF << 11))
            post_state = rop_utils.step_to_unconstrained_successor(self.rop.project, pre_state)
            reg_val = post_state.registers.load(reg)[7:0]
            return [reg_val == SF ^ OF]

        for SF in range(2):
            for OF in range(2):
                ret = self._get_register_constraints(gadget, get_initial_constraints, partial(check, SF, OF))

        return ret

    def set_less_than(self, reg):
        '''setl reg'''
        return self._try_all_gadgets(self._find_modify_register_gadgets(reg),
                                        partial(self._try_set_less_than, reg))


    def pop_bytes(self, num_bytes):
        '''Find gadgets that increment the stack pointer'''

        possible_gadgets = set()

        for g in self.gadgets:
            if self._gadget_is_safe(g) and self._gadget_has_no_mem_access(g) and g.stack_change - self.arch.bytes == num_bytes:
                chain = RopChain(self.rop.project, None)
                chain.add_gadget(g)
                chain.add_value(g.addr, needs_rebase=True)
                possible_gadgets.add(chain)
        
        return possible_gadgets


    def syscall(self):
        possible_gadgets = set()

        for g in self.gadgets:
            if not g.bp_moves_to_sp and g.stack_change > 0 and self._gadget_has_no_mem_access(g) and g.makes_syscall:
                chain = RopChain(self.rop.project, None)
                chain.add_gadget(g)
                chain.add_value(g.addr, needs_rebase=True)
                possible_gadgets.add(chain)
        
        return possible_gadgets
