#!/usr/bin/env python3
from pwn import *
from subprocess import *


res=subprocess.run(['scp','./pwncollege3.c', 'pwn:/tmp/'], text=True, capture_output=True)
print(res.stdout)
print(res.stderr)

s = ssh(host="pwn")

f3 = SSHPath('/tmp/nrzqjx', ssh=s)
f3.touch()
f3.write_text('lgwuuobv')

s.process(["gcc",'-o', '/home/hacker/pwncollege', "/tmp/pwncollege3.c"])

p = s.process(['/home/hacker/pwncollege'])
#r = p.clean(timeout=3)
p.sendline('lvtuadnh')
r=p.recvall()
res=repr(r)
print(res)

