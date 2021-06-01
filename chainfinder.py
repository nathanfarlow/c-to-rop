from angrop_backup.angrop.rop_gadget import RopGadget
from angrop_backup.angrop.chain_builder import ChainBuilder
from angrop_backup.angrop.errors import RopException
import angr
from angrop_backup.angrop import * 
from angrop_backup.angrop.rop_chain import RopChain

# from angrop.rop_chain import RopChain
# from angrop import rop_utils

# NOTE: Lots of code in this file is directly copied/modified from angrop

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

    def _get_register_constraints(self, gadget, f_apply_constraints):
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

        # Create the post state. This is the state after we step through the gadget with the applied constraints
        post_state = rop_utils.step_to_unconstrained_successor(self.rop.project, pre_state)

        # f_apply_constraints should apply more constraints to pre_state, and then return
        # a post_state that has been stepped through the gadget with those new constraints.
        # It should return a criteria, which is the target constraint which should be true for all
        # values. This should also return the registers that we will solve for the initial values
        post_state, criteria, registers_to_solve = f_apply_constraints(pre_state, post_state)

        pre_state_copy = pre_state.copy()
        pre_state.add_constraints(criteria)
        pre_state_copy.add_constraints(criteria == False)

        if not pre_state.solver.satisfiable():
            raise RopException('Attempted solution is not satisfiable at all')

        if pre_state_copy.solver.satisfiable():
            raise RopException('Attempted solution is not satisfiable in all cases')

        # Solve for the registers
        reg_vals = dict()
        for reg in set(registers_to_solve):
            reg_vals[reg] = pre_state.solver.eval(pre_state.registers.load(reg))

        # Build the chain
        if len(reg_vals) > 0:
            chain = self.rop.set_regs(use_partial_controllers=False, **reg_vals)
        
        chain.add_gadget(gadget)

        bytes_per_pop = self.arch.bytes
        chain.add_value(gadget.addr, needs_rebase=True)
        for _ in range(gadget.stack_change // bytes_per_pop - 1):
            chain.add_value(self.rop._chain_builder._get_fill_val(), needs_rebase=False)
        
        return chain

    @rop_utils.timeout(5)
    def _try_access_mem(self, is_read, gadget, addr, register):

        def apply_initial_constraints(pre_state, post_state):

            mem_accesses = gadget.mem_reads if is_read else gadget.mem_writes
            bad_accesses = gadget.mem_writes if is_read else gadget.mem_reads

            # Find the ast which is the mem read/write operation
            mem_access = mem_accesses[0]
            the_action = None
            for a in post_state.history.actions.hardcopy:
                if a.type != 'mem' or a.action != ('read' if is_read else 'write'):
                    continue

                if set(rop_utils.get_ast_dependency(a.addr.ast)) == set(mem_access.addr_dependencies) or \
                    set(rop_utils.get_ast_dependency(a.data.ast)) == set(mem_access.data_dependencies):
                    the_action = a
                    break

            if the_action is None:
                raise RopException("Couldn't find the matching action")

            if is_read:
                # Set up symbolic variable at memory location
                to_read = pre_state.solver.BVS('mem', pre_state.arch.bits)
                pre_state.memory.store(addr, to_read)

            # Constrain the address of the memory access
            pre_state.add_constraints(the_action.addr.ast == addr)
            pre_state.options.discard(angr.options.AVOID_MULTIVALUED_READS if is_read else angr.options.AVOID_MULTIVALUED_WRITES)
            post_state = rop_utils.step_to_unconstrained_successor(self.rop.project, pre_state)

            if is_read:
                # Criteria is that the pre state memory is equal to the post state register
                to_read = pre_state.memory.load(addr, self.arch.bytes, endness=self.arch.memory_endness)
                criteria = post_state.registers.load(register) == to_read
            else:
                # Criteria is that the post state memory is equal to the pre state register
                criteria = post_state.memory.load(addr, self.arch.bytes, endness=self.arch.memory_endness) == pre_state.registers.load(register)

            # Solve for all registers in dependencies, except for the one we control arbitrarily
            registers_to_solve = list(mem_access.addr_dependencies) + list(mem_access.data_dependencies)
            if register in registers_to_solve:
                registers_to_solve.remove(register)

            return post_state, criteria, registers_to_solve


        return self._get_register_constraints(gadget, apply_initial_constraints)

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
        valid = []
        for gadget in self._find_mem_access_gadgets(is_read, register):
            try:
                valid.append(self._try_access_mem(is_read, gadget, addr, register))
            except (RopException, angr.errors.SimEngineError):
                pass
        
        return sorted((chain for chain in valid if chain is not None), key=lambda x: x.payload_len)

    def read_mem_to_register(self, addr, register):
        return self._access_mem(True, addr, register)

    def write_register_to_mem(self, addr, register):
        return self._access_mem(False, addr, register)

    def _try_add_registers(self, gadget, reg1, reg2, reg_dest):
        
        def apply_initial_constraints(pre_state, post_state):

            a = pre_state.registers.load(reg1)
            b = pre_state.registers.load(reg2)
            c = post_state.registers.load(reg_dest)

            criteria = a + b == c

            return post_state, criteria, []

        return self._get_register_constraints(gadget, apply_initial_constraints)


    def _find_add_registers_gadgets(self, reg1, reg2, reg_dest):
        possible_gadgets = set()

        for g in self.gadgets:
            # Skip any mem accesses for now. In the future, we can add
            # support for if we control the mem access
            if not self._gadget_is_safe(g):
                continue

            if reg_dest not in g.changed_regs or reg_dest not in g.reg_dependencies:
                continue

            deps = g.reg_dependencies[reg_dest]

            if reg1 not in deps or reg2 not in deps:
                continue
        
            possible_gadgets.add(g)
        
        return possible_gadgets

    def add_reg_to_reg(self, reg1, reg2, reg_dest):
        
        valid = []
        for gadget in self._find_add_registers_gadgets(reg1, reg2, reg_dest):
            try:
                valid.append(self._try_add_registers(gadget, reg1, reg2, reg_dest))
            except (RopException, angr.errors.SimEngineError):
                pass
        
        return sorted((chain for chain in valid if chain is not None), key=lambda x: x.payload_len)
