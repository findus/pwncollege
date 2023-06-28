#!/usr/bin/env python3
from pwn import *
from subprocess import *


res=subprocess.run(['scp','./pwncollege2.c', 'pwn:/tmp/'], text=True, capture_output=True)
print(res.stdout)
print(res.stderr)

s = ssh(host="pwn")

f2 = SSHPath('/tmp/nrzqjx', ssh=s)
f2.touch()
f2.write_text('lgwuuobv')

s.process(["gcc",'-o', '/home/hacker/pwncollege', "/tmp/pwncollege2.c"])

p = s.process(['/home/hacker/pwncollege'])
#r = p.clean(timeout=2)
p.sendline('lvtuadnh')
r=p.recvall()
res=repr(r)
print(res)

