#!/usr/bin/env python3
from pwn import *
from subprocess import *


res=subprocess.run(['scp','./pwncollege.c', 'pwn:/tmp/'], text=True, capture_output=True)
print(res.stdout)
print(res.stderr)

s = ssh(host="pwn")
f = SSHPath('/tmp/my_script.py', ssh=s)
f.touch()
f.write_text('import subprocess; subprocess.run(["/challenge/embryoio_level29"])')

f2 = SSHPath('/tmp/nrzqjx', ssh=s)
f2.touch()
f2.write_text('lgwuuobv')

s.process(["gcc",'-o', '/home/hacker/pwncollege', "/tmp/pwncollege.c"])

p = s.process(['/home/hacker/pwncollege'])
#p.sendline('dremewyh')
r = p.clean(timeout=2)
res=repr(r)
print(res)

