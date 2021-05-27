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

        yield from possible_gadgets

    
    @rop_utils.timeout(5)
    def _try_access_mem(self, is_read, gadget, addr, register):
        chain = RopChain(self.rop.project, self.rop, rebase=self.rop._rebase, badbytes=self.rop.badbytes)
        
        mem_accesses = gadget.mem_reads if is_read else gadget.mem_writes
        bad_accesses = gadget.mem_writes if is_read else gadget.mem_reads

        arch_bytes = self.arch.bytes
        arch_endness = self.arch.memory_endness

        pre_gadget_state = self.rop._chain_builder._test_symbolic_state.copy()
        rop_utils.make_reg_symbolic(pre_gadget_state, self.rop._chain_builder._base_pointer)

        pre_gadget_state.regs.ip = gadget.addr
        pre_gadget_state.add_constraints(
            pre_gadget_state.memory.load(pre_gadget_state.regs.sp, arch_bytes, endness=arch_endness) == gadget.addr
        )
        pre_gadget_state.regs.sp += arch_bytes

        state = rop_utils.step_to_unconstrained_successor(self.rop.project, pre_gadget_state)

        mem_access = mem_accesses[0]
        the_action = None
        for a in state.history.actions.hardcopy:
            if a.type != 'mem' or a.action != ('read' if is_read else 'write'):
                continue

            if set(rop_utils.get_ast_dependency(a.addr.ast)) == set(mem_access.addr_dependencies) or \
                set(rop_utils.get_ast_dependency(a.data.ast)) == set(mem_access.data_dependencies):
                the_action = a
                break

        if the_action is None:
            raise RopException("Couldn't find the matching action")

        if is_read:
            to_read = pre_gadget_state.solver.BVS('mem', state.arch.bits)
            pre_gadget_state.memory.store(addr, to_read)

        # Constrain the address
        pre_gadget_state.add_constraints(the_action.addr.ast == addr)
        pre_gadget_state.options.discard(angr.options.AVOID_MULTIVALUED_READS if is_read else angr.options.AVOID_MULTIVALUED_WRITES)
        state = rop_utils.step_to_unconstrained_successor(self.rop.project, pre_gadget_state)

        if is_read:
            pre_gadget_state.add_constraints(state.registers.load(register) == to_read)
        else:
            pre_gadget_state.add_constraints(state.memory.load(addr, arch_bytes) == pre_gadget_state.registers.load(register))

        #test sat

        all_deps = list(mem_access.addr_dependencies) + list(mem_access.data_dependencies)
        reg_vals = dict()
        for reg in set(all_deps) - set([register]):
            reg_vals[reg] = pre_gadget_state.solver.eval(pre_gadget_state.registers.load(reg))
        
        chain = self.rop.set_regs(use_partial_controllers=False, **reg_vals)
        chain.add_gadget(gadget)

        bytes_per_pop = self.arch.bytes
        chain.add_value(gadget.addr, needs_rebase=True)
        for _ in range(gadget.stack_change // bytes_per_pop - 1):
            chain.add_value(self.rop._chain_builder._get_fill_val(), needs_rebase=False)
        
        return chain

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
