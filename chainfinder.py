from atexit import register
import functools
from os import write
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
        return g.mem_reads == 0


    def _gadget_has_no_mem_writes(self, g: RopGadget):
        return g.mem_writes + g.mem_changes == 0
    

    def _gadget_has_no_mem_access(self, g: RopGadget):
        return self._gadget_has_no_mem_reads(g) and self._gadget_has_no_mem_writes(g)


    def _gadget_has_one_mem_access(self, g: RopGadget):
        return g.mem_reads + g.mem_writes + g.mem_changes == 1


    def _gadget_is_safe(self, g: RopGadget):
        return not g.bp_moves_to_sp and g.stack_change > 0


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


    def add_mem_to_register(self, addr_src, reg):
        '''reg = *(int64_t*)addr_src'''
        pass
