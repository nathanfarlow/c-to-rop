import logging
from eir.parser import Instr
from angrop.rop_chain import RopChain
from chainfinder import ChainFinder, ParameterizedChain
from eir.target import Target, ConditionCode, Immediate, Register

l = logging.getLogger('c-to-rop')

class Instruction:

    def __init__(self, chains: list[RopChain], jump_chain: ParameterizedChain = None, jump_target: int = None, jump_args = None) -> None:
        self.chains = chains
        self.jump_chain = jump_chain
        self.jump_target = jump_target
        self.jump_args = jump_args

    def add_chain(self, chain: RopChain):
        self.chains.append(chain)

    def __add__(self, other):
        return Instruction(self.chains + other.chains)

    def build_string(self):
        result = ''
        for chain in self.chains:
            result += str(chain)
        return result

    def compute_size(self):
        return sum(chain.payload_len for chain in self.chains)

class RopTarget(Target):

    SENTINEL = 0xcafebabedeadbeef

    instructions: list[Instruction]
    
    mov_imm_to_mem: list[ParameterizedChain]
    mov_mem_to_mem: list[ParameterizedChain]
    add_mem_to_mem: list[ParameterizedChain]
    mov_mem_to_deref_mem_ptr: list[ParameterizedChain]
    mov_deref_mem_ptr_to_mem: list[ParameterizedChain]
    sub_mem_by_mem: list[ParameterizedChain]
    eq_mem_mem: list[ParameterizedChain]
    lt_mem_mem: list[ParameterizedChain]
    ne_mem_mem: list[ParameterizedChain]
    gt_mem_mem: list[ParameterizedChain]
    le_mem_mem: list[ParameterizedChain]
    ge_mem_mem: list[ParameterizedChain]
    jump_to_imm: list[ParameterizedChain]
    je_to_imm: list[ParameterizedChain]
    jne_to_imm: list[ParameterizedChain]
    jlt_to_imm: list[ParameterizedChain]
    jgt_to_imm: list[ParameterizedChain]
    jle_to_imm: list[ParameterizedChain]
    jge_to_imm: list[ParameterizedChain]
    putchar_mem: list[ParameterizedChain]
    getchar_mem: list[ParameterizedChain]
    exit: list[ParameterizedChain]

    def __init__(self, finder: ChainFinder, data_address: int, rop_address: int, stack_offset=1000) -> None:
        self.finder = finder
        self.data_address = data_address
        self.rop_address = rop_address
        self.instructions = []

        for name in dir(self.finder):
            if name.startswith('_') or name == 'gadgets':
                continue

            result = [next(getattr(finder, name)())]
            setattr(self, name, result)

        self.put_mov(Register('SP'), Immediate(stack_offset))
    
    def fill_jump_targets(self, data_setup_inst_count):

        offsets = []
        len_so_far = sum(instruction.compute_size() for instruction in self.instructions[:data_setup_inst_count + 1])
        for instruction in self.instructions[data_setup_inst_count + 1:]:
            offsets.append(len_so_far)
            len_so_far += instruction.compute_size()
        
        for instruction in self.instructions:
            if instruction.jump_chain is not None:
                instruction.jump_target = self.rop_address + offsets[instruction.jump_target]
                instruction.chains[-1] = instruction.jump_chain.build(instruction.jump_target, *instruction.jump_args)

    def _temp1(self):
        '''temp register for chain finder operations'''
        return self.data_address + 4
    
    def _temp2(self):
        '''temp register for chain finder operations'''
        return self._temp1() + 12

    def _base_address(self):
        '''start of data for elvm'''
        return self._temp2() + 12

    def _select(self, chains):
        if len(chains) == 0:
            l.error('No chains available for instruction.')
            raise ValueError('No chains available for instruction.')
        return chains[0]

    def _imm_to_special(self, imm: Immediate):
        return Instruction([self._select(self.mov_imm_to_mem).build(self._resolve_reg('special'), int(imm))])

    def _resolve_reg(self, reg):
        lookup = ["special", "A", "B", "C", "D", "SP", "BP"]
        return lookup.index(reg) * 8 + self._base_address()

    def put_mov(self, dst: Register, src: Immediate):
        l.info(f'mov {dst}, {src}')
        built = self._select(self.mov_imm_to_mem).build(self._resolve_reg(dst), int(src))
        self.instructions.append(Instruction([built]))

    def put_mov(self, dst: Register, src: Register):
        l.info(f'mov {dst}, {src}')
        built = self._select(self.mov_mem_to_mem).build(self._resolve_reg(dst), self._resolve_reg(src))
        self.instructions.append(Instruction([built]))

    def put_add(self, dst: Register, src: Immediate):
        l.info(f'add {dst}, {src}')
        mov_to_special = self._imm_to_special(src)
        built = self._select(self.add_mem_to_mem).build(self._resolve_reg(dst), self._resolve_reg('special'))
        self.instructions.append(mov_to_special + Instruction([built]))

    def put_add(self, dst: Register, src: Register):
        l.info(f'add {dst}, {src}')
        built = self._select(self.add_mem_to_mem).build(self._resolve_reg(dst), self._resolve_reg(src))
        self.instructions.append(Instruction([built]))

    def put_sub(self, dst: Register, src: Immediate):
        self.put_add(dst, Immediate(-src))

    def put_sub(self, dst: Register, src: Register):
        l.info(f'sub {dst}, {src}')
        built = self._select(self.sub_mem_by_mem).build(self._resolve_reg(dst), self._resolve_reg(src), self._temp1())
        self.instructions.append(Instruction([built]))

    def put_load(self, dst: Register, src: Immediate):
        print("loadRI")

    def put_load(self, dst: Register, src: Register):
        print("loadRR")

    def put_store(self, src: Register, dst: Immediate):
        print("storeRI")

    def put_store(self, src: Register, dst: Register):
        print("storeRR")

    def put_putc(self, src: Immediate):
        l.info(f'putc {src}')
        mov_to_special = self._imm_to_special(src)
        built = self._select(self.putchar_mem).build(self._resolve_reg('special'))
        self.instructions.append(mov_to_special + Instruction([built]))

    def put_putc(self, src: Register):
        l.info(f'putc {src}')
        built = self._select(self.putchar_mem).build(self._resolve_reg(src))
        self.instructions.append(Instruction([built]))

    def put_getc(self, dst: Register):
        l.info(f'getc {dst}')
        built = self._select(self.getchar_mem).build(self._resolve_reg(dst))
        self.instructions.append(Instruction([built]))

    def put_exit(self):
        l.info(f'exit')
        built = self._select(self.exit).build()
        self.instructions.append(Instruction([built]))

    def put_conditional_jmp(self, jmp: Immediate, dst: Register, src: Immediate, cc: ConditionCode):
        l.info(f'jmp({cc}) {jmp}, {dst}, {src}')

        mov_to_special = self._imm_to_special(src)

        args = (self._resolve_reg(dst), self._resolve_reg('special'), self._temp1(), self._temp2())

        chain = {
            ConditionCode.EQ: self.je_to_imm,
            ConditionCode.GE: self.jge_to_imm,
            ConditionCode.GT: self.jgt_to_imm,
            ConditionCode.LE: self.jle_to_imm,
            ConditionCode.LT: self.jlt_to_imm,
            ConditionCode.NE: self.jne_to_imm
        }[cc]

        jump_chain = self._select(chain)
        built = jump_chain.build(int(jmp), *args)

        inst = Instruction(mov_to_special.chains + [built], jump_chain, int(jmp), args)
        self.instructions.append(inst)

    def put_conditional_jmp(self, jmp: Immediate, dst: Register, src: Register, cc: ConditionCode):
        l.info(f'jmp({cc}) {jmp}, {dst}, {src}')
        l.error('Tried to jump to register')
        raise NotImplementedError('c-to-rop does not support jumping to register yet')

    def put_unconditional_jmp(self, jmp: Immediate):
        args = (None, None, None, None)
        jump_chain = self._select(self.jump_to_imm)
        built = jump_chain.build(int(jmp), *args)
        self.instructions.append(Instruction([built], jump_chain, int(jmp), args))

    def put_cmp(self, dst: Register, src: Immediate, cc: ConditionCode):
        l.info(f'cmp({cc}) {dst}, {src}')
        mov_to_special = self._imm_to_special(src)

        func = {
            ConditionCode.EQ: self.eq_mem_mem,
            ConditionCode.GE: self.ge_mem_mem,
            ConditionCode.GT: self.gt_mem_mem,
            ConditionCode.LE: self.le_mem_mem,
            ConditionCode.LT: self.lt_mem_mem,
            ConditionCode.NE: self.ne_mem_mem
        }[cc]

        built = self._select(func).build(self._resolve_reg(dst), self._resolve_reg('special'), self._temp1())

        self.instructions.append(mov_to_special + Instruction([built]))

    def put_cmp(self, dst: Register, src: Register, cc: ConditionCode):
        l.info(f'cmp({cc}) {dst}, {src}')

        func = {
            ConditionCode.EQ: self.eq_mem_mem,
            ConditionCode.GE: self.ge_mem_mem,
            ConditionCode.GT: self.gt_mem_mem,
            ConditionCode.LE: self.le_mem_mem,
            ConditionCode.LT: self.lt_mem_mem,
            ConditionCode.NE: self.ne_mem_mem
        }[cc]

        built = self._select(func).build(self._resolve_reg(dst), self._resolve_reg(src), self._temp1())
        self.instructions.append(Instruction([built]))

    def build(self):
        ret = ''
        for instruction in self.instructions:
            ret += instruction.build_string()
        return 'from pwn import *\n\n' + ret.replace('\nchain = ""', '').replace('= ""', '= b""')
