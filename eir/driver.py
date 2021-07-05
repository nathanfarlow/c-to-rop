from .parser import Parser
from .types import ConditionCode, Immediate, Register


class Driver:
    def __init__(self, asmFilePath, compiler):
        self.parser = Parser(open(asmFilePath))
        self.data_setup_inst_count = 2 * len(self.parser.data_elements)

        # insert instructions to populate the data segment
        for addr, value in enumerate(self.parser.data_elements):
            compiler.put_mov(Register("A"), Immediate(value))
            compiler.put_store(Register("A"), Immediate(addr))

        for inst in self.parser.text_elements:
            print(inst.original_assembly)
            args = map(self._resolve, inst.args)
            if inst.opcode == "mov":
                compiler.put_mov(*args)
            elif inst.opcode == "add":
                compiler.put_add(*args)
            elif inst.opcode == "sub":
                compiler.put_sub(*args)
            elif inst.opcode == "load":
                compiler.put_load(*args)
            elif inst.opcode == "store":
                compiler.put_store(*args)
            elif inst.opcode == "putc":
                compiler.put_putc(*args)
            elif inst.opcode == "getc":
                compiler.put_getc(*args)
            elif inst.opcode == "exit":
                compiler.put_exit(*args)
            elif inst.opcode in ("jeq", "jne", "jlt", "jgt", "jle", "jge"):
                cc = ConditionCode[inst.opcode[1:].upper()]
                compiler.put_conditional_jmp(*self._offset_jump_target(args), cc)
            elif inst.opcode == "jmp":
                compiler.put_unconditional_jmp(*self._offset_jump_target(args))
            elif inst.opcode in ("eq", "ne", "lt", "gt", "le", "ge"):
                cc = ConditionCode[inst.opcode.upper()]
                compiler.put_cmp(*self._offset_jump_target(args), cc)

    def _resolve(self, arg):
        # maybe it's an integer?
        try:
            return Immediate(arg)
        except ValueError:
            pass
        # maybe it's a register
        if arg in ("A", "B", "C", "D", "SP", "BP"):
            return Register(arg)

        # maybe it's a symbol (lookup in symbol table and return immediate)
        try:
            return Immediate(self.parser.symbol_table[arg])
        except KeyError:
            raise RuntimeError("Undefined symbol: " + arg)

    def _offset_jump_target(self, args):
        args = list(args)
        args[0] = Immediate(args[0] + self.data_setup_inst_count)
        return args
