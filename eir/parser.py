from __future__ import annotations # PEP 563. It will become the default in Python 3.10.

import string
from typing import Dict, List, NamedTuple, TextIO, Union
from .types import ConditionCode, Immediate, JumpTarget, Register

class Instr(NamedTuple):
    opcode: str
    args: List[Union[Immediate, JumpTarget, Register]]

class Parser:
    def __init__(self, file: TextIO):
        self.symbol_table: Dict[str, int] = {}
        self.data_elements: List[int] = []
        self.text_elements: List[Instr] = []
        self.segment: str
        self.idx: int

        for self.line_num, self.line in enumerate(file):
            self._parse_line()

    def eat_whitespace(self):
        while self.idx < len(self.line) and self.peek() in ' \t':
            self.idx += 1

    def get_word(self):
        initial_index = self.idx
        while self.idx < len(self.line) and self.peek() in _WORD_CHARS:
            self.idx += 1
        result = self.line[initial_index:self.idx]
        return result

    def peek(self):
        return self.line[self.idx]

    def _parse_line(self) -> None:
        self.idx = 0
        self.eat_whitespace()

        if self.idx == len(self.line):
            return

        if self.peek() == "#":
            return

        first_word = self.get_word()
        if self.peek() == ":":
            # label
            assert self.idx == len(self.line) - 2
            elements = {"data": self.data_elements, "text": self.text_elements}[self.segment]
            self.symbol_table[first_word[:-1]] = len(elements)
        elif first_word[0] == ".":
            # pseudo-op
            if first_word == ".text":
                self.segment = "text"
            elif first_word == ".data":
                self.segment = "data"
            elif first_word == ".long":
                self.eat_whitespace()
                i = int(self.line[self.idx:])
                self.data_elements.append(i)
            elif first_word == ".string":
                self.eat_whitespace()
                if not (self.peek() == "\"" and self.line[-2] == "\""):
                    raise ParserError(self, "found .string but couldn't understand string literal")
                string = self.line[self.idx+1:-2]
                string = string.encode("ascii").decode("unicode_escape")
                self.data_elements.extend(string.encode("ascii"))
                self.data_elements.append(0)
            elif first_word in (".file", ".loc"):
                pass
            else:
                raise ParserError(self, "unknown pseudo-op: " + first_word)
        elif first_word in ("mov", "add", "sub", "load", "store", "putc", "getc", "exit",
                        "jeq", "jne", "jlt", "jgt", "jle", "jge", "jmp",
                        "eq", "ne", "lt", "gt", "le", "ge"):
            opcode = first_word
            self.eat_whitespace()
            args = []
            while True:
                arg = self.get_word()
                if len(arg) == 0:
                    break

                args.append(arg)

                if self.peek() == ",":
                    self.idx += 1
                    self.eat_whitespace()
                else:
                    assert self.peek() == "\n", ParserError(self, "unknown character: " + repr(self.peek()))
            self.text_elements.append(Instr(opcode, args))
        else:
            raise ParserError(self, "unknown instruction: " + repr(first_word))


class ParserError(RuntimeError):
    def __init__(self, parser: Parser, message: str):
        super().__init__(f"{message} at line {parser.line_num + 1}, col {parser.idx}")

_WORD_CHARS = '-.' + string.ascii_letters + string.digits
