from typing import Dict, List



class Parser:
    line: str
    idx: int
    segment: str
    data_symbols: Dict[str, int]
    text_symbols: Dict[str, int]
    data_elements: List[int]
    text_elements: List[Instr]

    def eat_whitespace(self):
        while self.idx < len(self.line) and self.peek() in ' \t':
            self.idx += 1

    def get_word(self):
        i = self.idx
        while i < len(self.line) and self.peek() not in ' \t':
            i += 1
        result = self.line[self.idx:i]
        self.idx = i
        return result

    def peek(self):
        return self.line[self.idx]

    def parse_file(self, file):
        self.data_symbols = {}
        self.text_symbols = {}
        for lineno, self.line in enumerate(file):
            self.idx = 0
            self.eat_whitespace()
            if self.idx == len(self.line):
                continue

            if self.peek() == "#":
                continue

            if self.peek() == ".":
                self.idx += 1
                pseudo = self.get_word()
                if pseudo == "text":
                    self.segment = "text"
                elif pseudo == "data":
                    self.segment = "data"
                elif pseudo == "long":
                    self.eat_whitespace()
                    i = int(self.line[self.idx:])
                    self.data_elements.append(i)
                elif pseudo == "string":
                    self.eat_whitespace()
                    if not (self.peek() == "\"" and self.line[-2] == "\""):
                        return "found .string but couldn't understand string literal"
                    string = self.line[self.idx+1:-2]
                    string = string.encode("ascii").decode("unicode_escape")
                    self.data_elements.extend(string.encode("ascii"))
                    self.data_elements.append(0)
                else:
                    return "bad pseudo-op"

            word = self.get_word()
            if self.peek() == ":":
                # label
                symbol_table, elements = {"data": (data_symbols, data_elements),
                                          "text": (text_symbols, text_elements)}[self.segment]
                symbol_table[word] = len(elements)
            elif word in ("mov", "add", "sub", "load", "store", "putc", "getc", "exit",
                          "jeq", "jne", "jlt", "jgt", "jle", "jge", "jmp"
                          "eq", "ne", "lt", "gt", "le", "ge"):
                opcode = word
                self.eat_whitespace()
                args = []
                while True:
                    arg = self.get_word()
                    assert len(arg) > 0
                    args.append(arg)
                    if self.peek() == "\n":
                        break

                    if self.peek() == ",":
                        self.eat_whitespace()
                    else:
                        return lineno, self.idx, "unknown character: " + repr(self.peek())
                # todo
            else:
                return "unknown instruction: " + word
