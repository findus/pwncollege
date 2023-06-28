#!/usr/bin/env python3
from pwn import *
from subprocess import *


res=subprocess.run(['scp','./pwncollege.c', 'pwn:/tmp/'], text=True, capture_output=True)
print(res.stdout)
print(res.stderr)

s = ssh(host="pwn")

s.process(["gcc",'-o', '/home/hacker/pwncollege', "/tmp/pwncollege.c"])

p = s.process(['/home/hacker/pwncollege'])
r = p.clean(timeout=2)
#p.sendline('dremewyh')
res=repr(r)
print(res)

