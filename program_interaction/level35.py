#!/usr/bin/env python3
from pwn import *
from subprocess import *


res=subprocess.run(['scp','./pwncollege7.c', 'pwn:/tmp/'], text=True, capture_output=True)
print(res.stdout)
print(res.stderr)

s = ssh(host="pwn")

f3 = SSHPath('/tmp/pojgrq', ssh=s)
f3.touch()
f3.write_text('igizdfha')

re=s.process(["gcc",'-o', '/home/hacker/pwncollege', "/tmp/pwncollege7.c"])
print(re.poll(True))

p = s.process(['/home/hacker/pwncollege'], stdin="/tmp/pojgrq", stdout="/tmp/iopcto")
#r = p.clean(timeout=3)
p.sendline('lvtuadnh')
r=p.recvall()
res=repr(r)
print(r)

