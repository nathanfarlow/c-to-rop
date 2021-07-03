import enum


class ConditionCode(enum.Enum):
    EQ = enum.auto()
    NE = enum.auto()
    LT = enum.auto()
    GT = enum.auto()
    LE = enum.auto()
    GE = enum.auto()


class Immediate(int):
    pass


class JumpTarget(int):
    pass


class Register(str):
    pass
