from eir.target import Target, ConditionCode, Immediate, Register


class RopTarget(Target):
    def put_mov(self, dst: Register, src: Immediate):
        print("movRI")

    def put_mov(self, dst: Register, src: Register):
        print("movRR")

    def put_add(self, dst: Register, src: Immediate):
        print("addRI")

    def put_add(self, dst: Register, src: Register):
        print("addRR")

    def put_sub(self, dst: Register, src: Immediate):
        print("subRI")

    def put_sub(self, dst: Register, src: Register):
        print("subRR")

    def put_load(self, dst: Register, src: Immediate):
        print("loadRI")

    def put_load(self, dst: Register, src: Register):
        print("loadRR")

    def put_store(self, src: Register, dst: Immediate):
        print("storeRI")

    def put_store(self, src: Register, dst: Register):
        print("storeRR")

    def put_putc(self, src: Immediate):
        print("putcI")

    def put_putc(self, src: Register):
        print("putcR")

    def put_getc(self, dst: Register):
        print("getcR")

    def put_exit(self):
        print("exit")

    def put_conditional_jmp(self, jmp: Immediate, dst: Register, src: Immediate, cc: ConditionCode):
        print("cond_jmpIRI")

    def put_conditional_jmp(self, jmp: Immediate, dst: Register, src: Register, cc: ConditionCode):
        print("cond_jmpIRR")

    def put_unconditional_jmp(self, jmp: Immediate):
        print("jmpI")

    def put_cmp(self, dst: Register, src: Immediate, cc: ConditionCode):
        print("cmpRI")

    def put_cmp(self, dst: Register, src: Register, cc: ConditionCode):
        print("cmpRR")
