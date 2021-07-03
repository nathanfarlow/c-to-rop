from multimethod import multimeta
from eir.types import ConditionCode, Immediate, JumpTarget, Register


class Compiler(metaclass=multimeta):
    def put_mov(self, dst: Register, src: Immediate):
        pass

    def put_mov(self, dst: Register, src: Register):
        pass

    def put_add(self, dst: Register, src: Immediate):
        pass

    def put_add(self, dst: Register, src: Register):
        pass

    def put_sub(self, dst: Register, src: Immediate):
        pass

    def put_sub(self, dst: Register, src: Register):
        pass

    def put_load(self, dst: Register, src: Immediate):
        pass

    def put_load(self, dst: Register, src: Register):
        pass

    def put_store(self, src: Register, dst: Immediate):
        pass

    def put_store(self, src: Register, dst: Register):
        pass

    def put_putc(self, src: Immediate):
        pass

    def put_putc(self, src: Register):
        pass

    def put_getc(self, dst: Register):
        pass

    def put_exit(self):
        pass

    def put_conditional_jmp(self, jmp: JumpTarget, dst: Register, src: Immediate, cc: ConditionCode):
        pass

    def put_conditional_jmp(self, jmp: JumpTarget, dst: Register, src: Register, cc: ConditionCode):
        pass

    def put_unconditional_jmp(self, jmp: JumpTarget):
        pass

    def put_cmp(self, dst: Register, src: Immediate, cc: ConditionCode):
        pass

    def put_cmp(self, dst: Register, src: Register, cc: ConditionCode):
        pass
