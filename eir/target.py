from abc import ABCMeta, abstractmethod
from multimethod import multimeta
from eir.types import ConditionCode, Immediate, Register


class ABCMultiMeta(ABCMeta, multimeta):
    pass


class Target(metaclass=ABCMultiMeta):
    @abstractmethod
    def put_mov(self, dst: Register, src: Immediate):
        raise NotImplementedError

    @abstractmethod
    def put_mov(self, dst: Register, src: Register):
        raise NotImplementedError

    @abstractmethod
    def put_add(self, dst: Register, src: Immediate):
        raise NotImplementedError

    @abstractmethod
    def put_add(self, dst: Register, src: Register):
        raise NotImplementedError

    @abstractmethod
    def put_sub(self, dst: Register, src: Immediate):
        raise NotImplementedError

    @abstractmethod
    def put_sub(self, dst: Register, src: Register):
        raise NotImplementedError

    @abstractmethod
    def put_load(self, dst: Register, src: Immediate):
        raise NotImplementedError

    @abstractmethod
    def put_load(self, dst: Register, src: Register):
        raise NotImplementedError

    @abstractmethod
    def put_store(self, src: Register, dst: Immediate):
        raise NotImplementedError

    @abstractmethod
    def put_store(self, src: Register, dst: Register):
        raise NotImplementedError

    @abstractmethod
    def put_putc(self, src: Immediate):
        raise NotImplementedError

    @abstractmethod
    def put_putc(self, src: Register):
        raise NotImplementedError

    @abstractmethod
    def put_getc(self, dst: Register):
        raise NotImplementedError

    @abstractmethod
    def put_exit(self):
        raise NotImplementedError

    @abstractmethod
    def put_conditional_jmp(self, jmp: Immediate, dst: Register, src: Immediate, cc: ConditionCode):
        raise NotImplementedError

    @abstractmethod
    def put_conditional_jmp(self, jmp: Immediate, dst: Register, src: Register, cc: ConditionCode):
        raise NotImplementedError

    @abstractmethod
    def put_unconditional_jmp(self, jmp: Immediate):
        raise NotImplementedError

    @abstractmethod
    def put_cmp(self, dst: Register, src: Immediate, cc: ConditionCode):
        raise NotImplementedError

    @abstractmethod
    def put_cmp(self, dst: Register, src: Register, cc: ConditionCode):
        raise NotImplementedError
