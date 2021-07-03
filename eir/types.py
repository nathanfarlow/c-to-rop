import enum


class ConditionCode(enum.Enum):
    EQ = enum.auto()
    NE = enum.auto()
    LT = enum.auto()
    GT = enum.auto()
    LE = enum.auto()
    GE = enum.auto()


class Immediate(int):
    def __repr__(self):
        return f"Immediate({super().__repr__()})"


class Register(str):
    def __repr__(self):
        return f"Register({super().__repr__()})"
