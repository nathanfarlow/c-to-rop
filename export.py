from output import chain

fname = './chal_code/chal'

rop_chain = 0x13070
# objdump -D -F chal | grep '<rop_chain>'

print(f'Chain is {len(chain)} bytes')
print(f'Writing to {hex(rop_chain)} in {fname}')

with open(fname, 'r+b') as f:
    f.seek(rop_chain)
    # print(chain)
    f.write(chain)
