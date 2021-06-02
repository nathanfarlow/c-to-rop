import angr
import angrop
import logging
import inspect
import os
l = logging.getLogger('ctorop')


class ROP():
    def __init__(self, file):
        p = angr.Project(file)
        angrop_rop = p.analyses.ROP()
        l.debug(f'Finding gadgets...')
        gadget_file = file.split('/')[-1] + '.gadgets'
        if os.path.exists(gadget_file):
            angrop_rop.load_gadgets(gadget_file)
        else:
            angrop_rop.find_gadgets()
            l.debug(f'Saving gadgets...')
            angrop_rop.save_gadgets(gadget_file)
        self.__rop = angrop_rop
        l.debug('Superclassing angrop...')
        for name, value in inspect.getmembers(self.__rop):
            if not name.startswith("__"):
                setattr(self, name, value)
        l.debug('Done.')


logging.getLogger('angr').setLevel('ERROR')
logging.getLogger('ctorop').setLevel('DEBUG')

rop = ROP("/bin/ls")

for g in rop.gadgets:
    for mem_access in g.mem_changes:
        if mem_access.op == '__add__':
            print(g)
