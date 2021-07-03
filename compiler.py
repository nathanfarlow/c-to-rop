
class Compiler:

    CONDITION_CODES = ['EQ', 'NE', 'LT', 'GT', 'LE', 'GE']

    def put_mov(dst, src):
        pass

    def put_add(dst, src):
        pass

    def put_sub(dst, src):
        pass

    def put_load(dst, src):
        pass

    def put_store(src, dst):
        pass

    def put_putc(src):
        pass

    def put_getc(dst):
        pass

    def put_exit(dst):
        pass

    def put_conditional_jmp(jmp, dst, src, cc):
        pass

    def put_unconditional_jmp(jmp):
        pass

    def put_cmp(dst, src, cc):
        pass

    def put_dump():
        pass
