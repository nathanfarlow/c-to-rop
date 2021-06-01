import angr
import angrop
import logging
logging.getLogger('angr').setLevel('ERROR')

p = angr.Project("/bin/ls")
rop = p.analyses.ROP()
rop.find_gadgets()


for g in rop.gadgets:
    for mem_access in g.mem_changes:
        if mem_access.op == '__add__':
            print(g)
